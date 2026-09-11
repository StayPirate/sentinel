# System Settings

## Purpose

System-wide configuration and administrative operations for the Sentinel
platform. The System Settings page provides settings that affect platform behavior
across all users and tickets.

## Access Control

All administration endpoints and UI pages require the `manage_settings`
capability.

## Service Module

System-setting persistence, bootstrap, reads, audit logging, and future
mutations are implemented in `backend/app/services/settings.py`.

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

When the Admin changes the default CVSS version, the PATCH endpoint
executes the following sequence:

1. **Validate** the new value against allowed values (`"3.1"`, `"4.0"`)
2. **No-op check**: if the current value equals the new value, return
   200 immediately with `recalculation_scheduled: false` (no audit
   event, no batch — consistent with the audit-trail-infrastructure
   cross-cutting rule for idempotent no-ops)
3. **Acquire recalculation slot**: `SET cvss_recalc_active <timestamp>
   NX EX 900` on Redis. This step serves as both a Redis liveness probe
   and an admission guard. The complete batch execution contract must replace
   or renew this admission state before the all-CVE operation is implemented so
   mutual exclusion lasts for the complete run:
   - If slot acquisition raises any `RedisError` → return 503
     `REDIS_UNAVAILABLE` (nothing committed)
   - If the key already exists (a recalculation is in progress) → return
     409 `CVSS_RECALC_ALREADY_IN_PROGRESS` (nothing committed)
4. **Commit** the new setting value and a `SettingAuditEvent` record to
   the database. If the commit fails: release the slot (`DEL
   cvss_recalc_active`) and return 500
5. **Enqueue** the batch recalculation Celery task
   (`recalculate_cvss_derived_state`) with the new version as an explicit
   argument. If the enqueue fails: release the slot and return 200 with
   `recalculation_scheduled: false` (the primary operation — the setting
   change — succeeded; the admin can use the manual re-run endpoint to
   trigger the batch)
6. Return 200 OK with `recalculation_scheduled: true`

**Commit-first rationale**: the `SettingAuditEvent` is always the first
durable record. No ticket mutation can occur without the setting change
being audited. This prevents phantom mutations (ticket audit events
without a recorded cause).

The batch operation (`recalculate_cvss_derived_state`) visits every persisted
CVE and calls `ticket_mutations.recalculate_cvss_chain()` in default-version
mode for each CVE in an independent database transaction. Failures on
individual CVEs are logged and skipped. It logs total, succeeded, and failed
counts. Task publication, mutual exclusion for the complete run, timeout,
completion cleanup, and crash recovery must form one execution contract whose
guard cannot expire while a run can still mutate data. The fixed 900-second
slot described by the current endpoint sequence does not by itself satisfy that
contract for the all-CVE semantic target and is not a guarantee that the
operation completes in that interval.

The CVSS resolution functions return pure resolved results; changing the
setting does not alter any assessment. The batch applies those results to
persisted derived state with this exhaustive side-effect matrix:

| Associated Ticket state | Batch effect |
|---|---|
| No Ticket | Recalculate `CVE.severity`; there is no Ticket audit target |
| `New` | Recalculate severity and every automatic Product occurrence; remain `New` and perform no gate reconciliation because system work never assigns |
| `Analysis`, `Analyzed`, `Resolved` | Recalculate severity and every automatic Product occurrence, then perform at most one final Ticket reconciliation. `Resolved` may regress normally to `Analyzed` or `Analysis` |
| `Ignored`, `Duplicated` | Recalculate `CVE.severity` only at the operational-state level; if it changed and a Ticket exists, create the direct system-attributed `severity_changed` event. Do not mutate Product eligibility, assignment, Ticket status, manual-zone state, or gates |

Every applicable gate-zone or `New` Product update uses current persisted
assessments, Product threshold and lifecycle inputs, and override markers;
manual overrides are skipped. Changed automatic occurrences create system-attributed
`product_eligibility_changed` events with `reason = cvss`, ordered by
`TicketPackageProduct.id`. An unchanged value creates no Product event.

`recalculate_cvss_chain()` creates a system-attributed `severity_changed`
record whenever an associated Ticket's old and new unified severity differ,
before any Product event. It never creates `cvss_assessment_changed`, because
the setting change does not alter an assessment. One CVE transaction uses one
UTC `evaluation_date`; any local settings, database, eligibility, audit, flush,
or reconciliation error rolls back that complete CVE unit and the batch
continues with the next CVE.

Visiting a `Resolved` Ticket may regress it through ordinary gate evaluation and
register the normal post-commit package-tree and fetcher catch-up. Visiting an
`Ignored` or `Duplicated` Ticket cannot exit its manual zone or register that
work; Product eligibility and gates for those Tickets converge only through the
owning manual-zone-exit workflow.

This section defines the semantic target and the existing task identity and
manual-recovery operation. It does not prescribe keyset pagination, persistent
progress, leases, or an impact-preview contract. The operational execution
contract must be reassessed separately for the all-CVE population; in
particular, this semantic target does not assert that one sequential pass can
complete within the current fixed slot and task lifetime.

The currently documented endpoint slot has a fixed TTL of 900 seconds (internal
constant). It remains the immediate admission guard for the endpoint sequence,
but the complete operation must not rely on expiry as permission for another
run while a prior run may still be active. The all-CVE execution contract owns
the corresponding completion release and crash-recovery behavior.

See `docs/features/tickets/cvss-scoring.md` (Persistence and Propagation
Boundary) for
additional details on the batch task behavior.

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

Validates the value against allowed values. On a value change, acquires
the recalculation slot, commits the setting and audit event, and
enqueues a batch recalculation task. See "Impact of changing the default
version" above for the full sequence.

**Note on PATCH with side effects**: this endpoint uses PATCH because
semantically it is a configuration field update — the setting changes
value and the response is returned immediately. The recalculation is an
asynchronous side effect (Celery background task) that does not block
the response. This is a documented deviation from the
`POST /resource/{id}/verb` convention for operations with side effects.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | A recalculation batch is already running (setting change blocked until current batch completes) |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete slot acquisition (setting change requires Redis availability) |

Response (200 OK): the settings object in the standard
`{"data": ...}` envelope. The `recalculation_scheduled` boolean field
is **always present** in the response:

```json
{
  "data": {
    "default_cvss_version": "4.0",
    "recalculation_scheduled": true
  }
}
```

Values of `recalculation_scheduled`:

- `true` — value changed and batch task successfully enqueued
- `false` — either (a) no-op (value unchanged, no batch needed), or
  (b) value changed but enqueue failed (transient broker failure after
  slot acquisition — admin should use
  `POST /api/v1/admin/settings/default-cvss-version/recalculate` to
  trigger the batch manually)

**`Capability: manage_settings`**

### Trigger CVSS Recalculation

```
POST /api/v1/admin/settings/default-cvss-version/recalculate
```

Manually triggers a CVSS recalculation batch for all persisted CVEs, using the
current `default_cvss_version` value. Used for
recovery after partial batch failures or as a general refresh mechanism.

The endpoint uses the same shared logic as the PATCH side-effect:

1. Read the current `default_cvss_version` from the database
2. Acquire the recalculation slot (`SET cvss_recalc_active <timestamp>
   NX EX 900`) as the current admission guard. This guard does not by itself
   provide complete-run mutual exclusion for the `all_cves` scope; the same
   future execution-contract requirement as the PATCH path applies
3. Enqueue `recalculate_cvss_derived_state(version)`. On failure: release slot
   and return 503
4. Return 202 Accepted

No setting change is made. No `SettingAuditEvent` is created.

**Request body**: none.

**Response** (202 Accepted):

```json
{
  "data": {
    "message": "Recalculation batch enqueued",
    "default_cvss_version": "4.0",
    "scope": "all_cves"
  }
}
```

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | A recalculation batch is already running (slot occupied) |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete slot acquisition |
| 503 | `CELERY_UNAVAILABLE` | Task could not be enqueued (slot released) |

**Idempotency**: safe to call multiple times. If no derived values have
changed since the last run, the batch produces no mutations or audit
events (guaranteed by `recalculate_cvss_chain()` idempotency).

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
