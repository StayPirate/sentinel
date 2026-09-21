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
manual-recovery operation. It does not prescribe the all-CVE execution's
keyset pagination, persistent progress, or leases. The operational execution
contract must be reassessed separately for the all-CVE population; in
particular, this semantic target does not assert that one sequential pass can
complete within the current fixed slot and task lifetime. The read-only
projection of these same effects is specified in "Default-CVSS Impact
Preview" below.

The currently documented endpoint slot has a fixed TTL of 900 seconds (internal
constant). It remains the immediate admission guard for the endpoint sequence,
but the complete operation must not rely on expiry as permission for another
run while a prior run may still be active. The all-CVE execution contract owns
the corresponding completion release and crash-recovery behavior.

See `docs/features/tickets/cvss-scoring.md` (Persistence and Propagation
Boundary) for
additional details on the batch task behavior.

## Default-CVSS Impact Preview

The read-only impact preview lets an administrator understand the expected
consequences of a proposed `default_cvss_version` change before mutating the
setting. It projects the same authoritative severity, eligibility, override,
lifecycle, and Ticket-gate outcomes that the batch operation applies, without
performing any mutation.

The preview is advisory. It creates no approval, reservation, snapshot token,
or prerequisite for `PATCH /api/v1/admin/settings`, and that endpoint neither
requires nor consumes a preview result.

### Preview Service

```python
async def get_default_cvss_version_impact(
    session: AsyncSession,
    proposed_version: Literal["3.1", "4.0"],
) -> DefaultCVSSVersionImpact:
    ...
```

`session` is the caller-owned asynchronous database session. `proposed_version`
is the proposed setting value. The function:

1. Reads the observed `default_cvss_version` once through
   `get_default_cvss_version(session)`.
2. Returns the no-op result when `proposed_version` equals the observed value.
3. Otherwise captures one UTC `evaluation_date` for the invocation and one
   internal high-water mark on `CVE.id` before evaluating any CVE.
4. Evaluates the persisted CVEs whose row `id` is less than or equal to the
   mark, using bounded internal keyset pagination. CVEs whose row `id` exceeds
   the mark are excluded from the invocation; a CVE whose `id` was assigned
   before the mark but that becomes visible during the scan may or may not be
   observed, per the per-unit observation model below. The page size is an
   internal implementation choice; it is not configuration and is not part of
   the API contract.
5. Projects each CVE's severity and Ticket-scoped effects using the proposed
   version and the complete, unfiltered assessment set of that CVE, and
   accumulates the aggregate counts defined below.
6. Returns one complete `DefaultCVSSVersionImpact` result.

The function performs no write of any kind: it creates, updates, or deletes no
setting, CVE, assessment, severity, Product, Ticket, assignment, audit, cache,
or post-commit state. It acquires no mutation lock, reads no Redis key,
publishes no task, and has no side effect on an active recalculation. It is
read-only and may be invoked repeatedly; each invocation observes the state
committed when its own units are read, so repeated previews may differ.

Exceptions: `RequiredSystemSettingMissingError` and database or schema errors
propagate unchanged, and a deadline expiry raises `CVSSPreviewTimeoutError`
defined below. The function raises no other domain exception.

### Result and Count Units

The result is one fixed-size aggregate object. It contains no CVE, Ticket,
package, track, Product, or occurrence identifier and no detail collection.

| Field | Type | Meaning |
|---|---|---|
| `observed_default_cvss_version` | string, `3.1` or `4.0` | Setting value read once at invocation start |
| `proposed_default_cvss_version` | string, `3.1` or `4.0` | Requested proposed value |
| `no_op` | boolean | `true` exactly when the proposal equals the observed value |
| `cves_evaluated` | integer | CVEs fully evaluated within the bounded population |
| `cve_severity_changes` | integer | Evaluated CVEs whose projected unified severity differs from the observed persisted `CVE.severity` |
| `product_eligibility_changes` | integer | `TicketPackageProduct` occurrences whose projected automatic `eligible` boolean differs from the observed persisted value |
| `product_eligibility_override_skips` | integer | Applicable occurrences with `is_eligible_override = true` that execution would preserve |
| `resolved_ticket_regressions` | integer | Tickets observed as `Resolved` whose projected highest valid gate result is `Analysis` or `Analyzed` |

- The count unit for eligibility is the `TicketPackageProduct` occurrence,
  never the catalog Product. One CVE may produce changes in multiple
  occurrences under its associated Ticket.
- An occurrence with `is_eligible_override = true` is never counted in
  `product_eligibility_changes`: its override is preserved, so it contributes
  only to `product_eligibility_override_skips` when applicable.
- "Applicable occurrence" means an occurrence whose Ticket state projects
  automatic Product eligibility (`New`, `Analysis`, `Analyzed`, `Resolved`),
  regardless of exclusion, EOL, or actionability.
- Categories may overlap. One CVE may contribute to `cve_severity_changes`,
  several `product_eligibility_changes` occurrences, several
  `product_eligibility_override_skips` occurrences, and one
  `resolved_ticket_regressions`.
- A projected effect that equals the observed persisted value receives no
  count. An evaluated CVE with no projected effect contributes only to
  `cves_evaluated`.
- An override skip is not a projected mutation; it records an occurrence that
  an execution would preserve.
- An empty population is a complete evaluation: `no_op` is `false`,
  `cves_evaluated` is `0`, and every impact count is `0`.
- `cves_evaluated` counts only a complete invocation. A preview that does not
  produce a complete result returns no counts at all.

### No-op Proposal

When `proposed_version` equals the observed setting value, the preview returns
the no-op result without scanning the population:

- `no_op` is `true` and every count, including `cves_evaluated`, is `0`;
- no CVE, Ticket, Product, assessment, or gate evaluation is performed;
- no audit event, cache entry, Redis access, task publication, or other effect
  occurs;
- the result has no relationship to the manual recalculation operation, which
  remains the separate recovery and refresh surface.

### Projected Impact Matrix

The preview projects the same exhaustive side-effect matrix as the batch
operation above, substituting projected values for persistence:

| Associated Ticket state | Projected effect |
|---|---|
| No Ticket | Unified severity only; no Ticket-scoped count |
| `New` | Unified severity and automatic Product eligibility; no gate projection |
| `Analysis`, `Analyzed`, `Resolved` | Unified severity, automatic Product eligibility, and the highest valid gate result. A Ticket observed as `Resolved` whose projected result is `Analysis` or `Analyzed` contributes one `resolved_ticket_regressions` count |
| `Ignored`, `Duplicated` | Unified severity only; no Product, assignment, gate, or manual-zone projection |

Projection rules:

- Severity and eligibility remain separate resolutions. The projected
  severity uses the Severity Resolution Cascade with the proposed version;
  the projected eligibility score uses the canonical SUSE assessment for the
  proposed version or the `10.0` fallback. Neither substitutes for the other.
- Automatic Product eligibility evaluates every applicable occurrence,
  including excluded, EOL, and otherwise non-actionable records, because
  exclusion, EOL, and actionability are not inputs of the eligibility
  formula. Rule 1 of the eligibility evaluator always preserves an occurrence
  with `is_eligible_override = true`; the preview reports it as a skip and
  changes no field.
- Product threshold and lifecycle inputs follow the authoritative
  package-model evaluator, including its Reactive Support, `NULL`-threshold,
  and `NULL`-lifecycle rules; this contract defines none of them.
- Gate projection reuses the exact Analyzed and Resolved predicates of
  `tickets.md`, substituting projected effective Product eligibility for the
  persisted boolean: the projected automatic result where no manual override
  applies, and the preserved persisted `eligible` value where
  `is_eligible_override = true`. It never calls `reconcile_ticket_status()`,
  never changes a status, and never registers the post-commit Ticket
  convergence workflow.
- The preview reads the setting once for the observed value. The proposed
  version is passed explicitly to the pure severity and eligibility
  resolutions; the preview does not read the setting again per unit.
- One UTC `evaluation_date` governs lifecycle, eligibility, actionability,
  and gate projection for the complete invocation.

### Consistency and Staleness

- The preview is one advisory bounded scan, not one coherent PostgreSQL
  snapshot of the complete population. Each CVE evaluation unit uses a
  coherent set of authoritative inputs for that unit; different units may
  observe different committed states. A unit's contribution must correspond
  entirely to one committed database observation: the implementation may read
  a single statement, a bounded page-level snapshot covering several CVEs, or
  use an equivalent mechanism, but it must not synthesize one unit from
  inputs observed on opposite sides of a concurrent commit. The observation
  mechanism, transaction shape, and page size remain internal implementation
  choices and are not part of the API contract.
- CVEs whose row `id` exceeds the captured high-water mark are excluded from
  the invocation. A CVE whose `id` does not exceed the mark may or may not be
  observed when it becomes visible during the invocation, and a committed
  change to an observed CVE may or may not be visible, depending on when that
  unit is read. CVE association, assignment, assessment, eligibility,
  lifecycle, and gate inputs are read from committed current state, not from a
  preview-time snapshot.
- The observed setting value is returned for orientation only. It does not
  block, freeze, or reserve a concurrent setting change, and the preview is
  not evidence that a later mutation will observe the same value.
- A repeated preview may return different counts. The preview result is not a
  snapshot token, reservation, approval, or binding prerequisite. A later
  `PATCH /api/v1/admin/settings` independently classifies its own current
  state and never receives, reuses, or trusts preview counts, the high-water
  mark, or any preview state.
- The high-water mark is internal to one invocation. It is neither persisted
  nor returned and is not shared between invocations.

### Active Recalculation Run

While an all-CVE recalculation is admitted, queued, or running, the preview
remains available and behaves as described above. It does not read Redis or
task state, does not report the run's progress, does not estimate remaining
work, and does not participate in run exclusion. It may observe a mix of
converged and not-yet-converged units; its result remains advisory.

### Timeout and Partial Results

The preview is bounded by one 30-second monotonic deadline started at Preview
Service function entry. Every blocking step of the invocation must respect the
remaining time. The deadline is a contract bound, not a performance target:
bounded internal paging is expected to project a representative persisted
population completely within it, and a population that cannot be projected
completely yields the timeout outcome below rather than a partial result. When
the deadline expires, the operation:

- raises `CVSSPreviewTimeoutError`;
- discards every intermediate count; and
- returns no partial result — an incomplete scan is never reported as a
  complete preview and never produces HTTP 200.

The preview has no resumable cursor, response pagination, continuation token,
persisted partial result, or progress resource.

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

API-facing exceptions:

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `CVSSPreviewTimeoutError` | 503 | `CVSS_PREVIEW_TIMEOUT` | The monotonic preview deadline expires before a complete result is available |

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
version" above for the full sequence. Changing the setting neither requires
nor consumes a prior impact preview; see "Default-CVSS Impact Preview".

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

### Get Default-CVSS Impact Preview

```
GET /api/v1/admin/settings/default-cvss-version/impact
```

**Request body**: none.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `proposed_version` | string | — (required) | Proposed `default_cvss_version`; exactly `3.1` or `4.0` |

A missing value, an unsupported value, or any other schema violation produces
the global `422 VALIDATION_ERROR` response. Undeclared query parameters are
ignored per the global undeclared-query convention.

**Behavior**: call `get_default_cvss_version_impact()` with the request
session and `proposed_version`, and return its complete aggregate result in
the standard `{"data": ...}` envelope. The endpoint is not paginated because
it returns one fixed-size aggregate object, and it has no `meta` object. A
`CVSSPreviewTimeoutError` is exposed as `503` `CVSS_PREVIEW_TIMEOUT`; an
incomplete scan is never returned as a partial success. A missing required
setting row propagates `RequiredSystemSettingMissingError` and is exposed
through the standard `500 INTERNAL_ERROR` response.

The preview evaluates the system-wide persisted-CVE population, including
ticketless CVEs and CVEs associated with confidential Tickets. The
`manage_settings` capability alone is sufficient: the preview introduces no
capability and applies no consumer Ticket visibility filtering, because it
must observe the same system-wide policy-migration set that the recalculation
operation targets. The aggregate count-only result exposes no Ticket or CVE
identifier and no protected Ticket content.

This disclosure boundary depends on `manage_settings` being held only by
all-scope roles. Any future capability split, new role, or scope change that
grants `manage_settings` to a limited-scope role requires reassessment of this
endpoint's authorization and filtering boundary before that role ships.

Response (200 OK):

```json
{
  "data": {
    "observed_default_cvss_version": "3.1",
    "proposed_default_cvss_version": "4.0",
    "no_op": false,
    "cves_evaluated": 120000,
    "cve_severity_changes": 1400,
    "product_eligibility_changes": 4700,
    "product_eligibility_override_skips": 82,
    "resolved_ticket_regressions": 37
  }
}
```

A no-op response has equal observed and proposed values, `no_op = true`, and
every count `0`.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 503 | `CVSS_PREVIEW_TIMEOUT` | The monotonic preview deadline expired before a complete result was available (all intermediate counts discarded) |

`CVSS_RECALC_ALREADY_IN_PROGRESS` does not apply: the preview is permitted
while a recalculation is admitted, queued, or running.

**Idempotency**: the endpoint is read-only and repeatable. Each invocation
reports the state it observes and creates no persistent effect.

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
- `docs/features/tickets/cvss-scoring.md` — pure severity and eligibility
  resolutions consumed by the impact preview
- `docs/features/tickets/ticket-mutations.md` — default-version state matrix
  projected read-only by the impact preview
- `docs/features/tickets/tickets.md` — Analyzed and Resolved gate predicates
  reused by the read-only gate projection
- `docs/features/packages/package-model.md` — automatic eligibility evaluator
  and manual override precedence
