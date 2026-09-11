# Fetcher Operations

## Purpose

Provide centralized monitoring and operational control for all data
fetchers in Sentinel. All users have visibility into fetcher health and
performance (no authentication required), while users with the
`manage_fetchers` capability have operational control (manual trigger,
enable/disable, configuration) and CLI commands for diagnostics and
troubleshooting.

This feature depends on the fetcher infrastructure defined in
`docs/features/platform/fetcher-infrastructure.md`. Read that spec first for the
`BaseFetcher` contract, data model (`FetcherRun`, `FetcherConfig`,
`FetcherAuditEvent`), concurrency control, and stale run detection.

## Scope

This specification defines the following fetcher endpoints:

1. `GET /api/v1/fetchers` — list all fetchers
2. `GET /api/v1/fetchers/{fetcher_name}/runs` — run history
3. `GET /api/v1/fetchers/{fetcher_name}/runs/{run_id}` — run detail
4. `GET /api/v1/fetchers/{fetcher_name}/timeline` — chart data
5. `POST /api/v1/fetchers/{fetcher_name}/trigger` — manual trigger
6. `GET /api/v1/fetchers/{fetcher_name}/config` — read config
7. `PATCH /api/v1/fetchers/{fetcher_name}/config` — update config
8. `GET /api/v1/fetchers/{fetcher_name}/audit-log` — admin audit trail

The `GET /api/v1/ibs-consumer/status` endpoint is defined in
`docs/features/integrations/ibs-rabbitmq-integration.md`, not here. It
observes the standalone IBS RabbitMQ consumer and is not a fetcher
operation.

The Ticket-scoped recovery action
`POST /api/v1/tickets/{ticket_id}/rerun-reactivation` is defined in
`docs/features/tickets/tickets.md`, not here. It dispatches the complete Ticket
convergence workflow: package and maintainership re-resolution followed by all
registered catch-ups. Triggering one fetcher through
`POST /api/v1/fetchers/{fetcher_name}/trigger` is not equivalent and cannot
replace that recovery action.

## Fetcher Operations Service

### Module Location

```
backend/app/services/fetcher_operations.py
```

### Ownership

This module owns all observation and administration operations on
fetchers. API endpoint handlers delegate to this service; CLI commands
delegate read operations to this service. No business logic resides in
route handlers or CLI command functions.

### Transaction Defaults

Unless stated per-function, the following defaults apply:

- **Read functions** (`list_fetchers`, `list_fetcher_runs`,
  `get_fetcher_run`, `get_fetcher_timeline`, `get_fetcher_config`,
  `list_fetcher_audit_events`): accept a caller-supplied `AsyncSession`,
  perform reads only, do not flush or commit, and are infallible beyond
  the exceptions listed per-function.
- **`update_fetcher_config`**: accepts a caller-supplied `AsyncSession`
  (caller-owned transaction). Acquires a pessimistic row lock, performs
  mutation and audit in the same transaction, flushes without committing.
  Returns a result indicating whether RedBeat propagation is needed and
  which changes to propagate. The API workflow commits, then executes
  post-commit RedBeat propagation using the returned result.
- **`trigger_fetcher`**: service-owned orchestration boundary. Does NOT
  accept a caller-supplied session. Creates its own short-lived sessions
  and manages two independent transactions (see Trigger Fetcher). The
  first transaction creates the manual run as `queued` — never
  `running` — per the lifecycle defined in
  `docs/features/platform/fetcher-infrastructure.md` (Concurrency
  Control). The API handler calls this function directly outside any
  request-scoped database session.

### Module-Level Exception Default

All public functions in this module propagate only the exceptions listed
in the Service Exceptions table below, plus standard database exceptions
that surface as HTTP 500 `INTERNAL_ERROR`. No function creates audit
events unless stated per-function.

### Service Exceptions

All exceptions inherit from `FetcherOperationsServiceError(ServiceError)`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `FetcherNotFoundError` | 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists (not in the registry and no `FetcherConfig` record), or the fetcher is in the registry but has no `FetcherConfig` row (bootstrap prerequisite for mutations) |
| `FetcherRunNotFoundError` | 404 | `FETCHER_NOT_FOUND` | The specified run does not exist or does not belong to the named fetcher |
| `FetcherDeregisteredError` | 409 | `FETCHER_DEREGISTERED` | Fetcher exists in DB but is not present in the registry (code removed) |
| `FetcherDisabledError` | 409 | `FETCHER_DISABLED` | Fetcher is disabled (`enabled = false`) |
| `FetcherAlreadyRunningError` | 409 | `FETCHER_ALREADY_RUNNING` | An active (`queued` or `running`, non-stale) run exists for this fetcher |
| `FetcherSettingUnknownError` | 422 | `FETCHER_SETTING_UNKNOWN` | Unknown key in `custom_settings` |
| `FetcherSettingInvalidError` | 422 | `FETCHER_SETTING_INVALID` | The candidate merged state (current stored values plus submitted changes) fails the `Settings` model's type/range/choices validation — the invalid field may be a value the caller did not submit |
| `FetcherBrokerUnavailableError` | 503 | `CELERY_UNAVAILABLE` | Task broker unavailable during manual trigger publication |

#### System-Internal Exceptions

No system-internal exceptions are defined in this module. Post-commit
RedBeat propagation failure is handled inline by the API workflow (log
WARNING, continue with 200 response) without raising or catching a
dedicated exception type.

### Public Functions

#### `list_fetchers`

**Q1 (inputs)**: `db: AsyncSession`, `has_manage_fetchers: bool`,
`celery_app: Celery` — the Celery application whose configured RedBeat
schedule is read to resolve `next_run_at` (see Q3, step 5).

**Q3 (behavior)**:

1. Query all `FetcherConfig` rows.
2. For each registered fetcher in `FETCHER_REGISTRY`, merge code-defined
   metadata (`description`, `default_schedule`, `cve_source_type`,
   `Settings` model) with the corresponding `FetcherConfig` row. If no
   `FetcherConfig` row exists (bootstrap not yet run), synthesize a
   response using registry defaults with `enabled = true` and empty
   `custom_settings`.
3. For each `FetcherConfig` row whose `fetcher_name` is NOT in the
   registry, return a deregistered fetcher entry with code-defined fields
   as `null`.
4. For each fetcher, resolve `last_run`: the most recent `FetcherRun`
   ordered by `created_at DESC, id DESC`. Ordering by `created_at`
   (rather than `started_at`) ensures a `queued` run — whose
   `started_at` is `NULL` — is still correctly selected and positioned
   chronologically. This includes runs with `status IN ('queued',
   'running')`. If no `FetcherRun` exists, `last_run` is `null`.
5. For each registered and enabled fetcher, attempt to read `next_run_at`
   from the RedBeat entry's `due_at` attribute. On any `RedisError`, set
   `next_run_at = null` for all fetchers and log WARNING (single attempt,
   no per-fetcher retry).
6. Sort the merged list by `fetcher_name` ascending (alphabetical).
7. For `last_run`, compute `stale: bool` using the threshold that
   matches the run's own status (see
   `docs/features/platform/fetcher-infrastructure.md`, Stale Run
   Detection):
   - `status = queued`: `true` when `now() - created_at > 600` seconds
     (Queued Stale Threshold).
   - `status = running`: `true` when
     `now() - started_at > hard_time_limit_seconds + 60` seconds
     (Running Stale Threshold, using the run's own persisted
     `hard_time_limit_seconds` column). If `hard_time_limit_seconds` is
     `NULL` (historical rows predating the column), fall back to the
     fetcher's `FetcherConfig.run_timeout`.
   - Any terminal status: `false`.
8. `custom_settings_count`: number of keys in
   `FetcherConfig.custom_settings` JSONB that exist in the current
   `Settings` schema (registered fetchers only). Orphaned keys are
   excluded. For deregistered fetchers: total JSONB key count (no schema
   to validate against).
9. If `has_manage_fetchers` is `false`, omit `triggered_by_user` from
   `last_run` (set to `null` regardless of actual value).

**Q6 (exceptions)**: none — the function always succeeds (Redis
degradation is handled internally).

#### `list_fetcher_runs`

**Q1 (inputs)**: `db: AsyncSession`, `fetcher_name: str`,
`has_manage_fetchers: bool`, `page: int`, `per_page: int`,
`status: str | None`, `from_date: datetime | None`,
`to_date: datetime | None`.

**Q2 (guards)**: raises `FetcherNotFoundError` if `fetcher_name` is
neither in the registry nor in `FetcherConfig`.

**Q3 (behavior)**:

1. Validate fetcher existence (registry OR `FetcherConfig`).
2. Query `FetcherRun` where `fetcher_name` matches, applying optional
   filters:
   - `status`: exact match. Valid values: `queued`, `running`,
     `success`, `failure`, `partial`.
   - `from_date` / `to_date`: filter on `created_at` (inclusive) — not
     `started_at`, so a `queued` run (whose `started_at` is `NULL`) is
     still selected by a date range covering its acceptance time.
3. Order: `created_at DESC, id DESC` (fixed, not client-controlled).
4. Apply pagination.
5. Exclude `error_detail` and `error_traceback` from all items.
6. If `has_manage_fetchers` is `false`, set `triggered_by_user` to
   `null` for all items.

**Q6 (exceptions)**: `FetcherNotFoundError`.

#### `get_fetcher_run`

**Q1 (inputs)**: `db: AsyncSession`, `fetcher_name: str`,
`run_id: UUID`, `has_manage_fetchers: bool`.

**Q2 (guards)**:
- `FetcherNotFoundError` if `fetcher_name` is unknown.
- `FetcherRunNotFoundError` if `run_id` does not exist or belongs to a
  different fetcher.

**Q3 (behavior)**:

1. Validate fetcher existence.
2. Query `FetcherRun` by `id` and `fetcher_name`.
3. Return all fields, including `created_at` and the nullable
   `started_at`/`finished_at`/`duration_seconds` (see
   `docs/features/platform/fetcher-infrastructure.md`, Data Model —
   FetcherRun, for their nullability by status). Include `error_detail`
   and `error_traceback` only if `has_manage_fetchers` is `true`;
   otherwise these fields are absent from the response.
4. If `has_manage_fetchers` is `false`, set `triggered_by_user` to
   `null`.

**Q6 (exceptions)**: `FetcherNotFoundError`, `FetcherRunNotFoundError`.

#### `get_fetcher_timeline`

**Q1 (inputs)**: `db: AsyncSession`, `fetcher_name: str`,
`has_manage_fetchers: bool`, `from_date: datetime`,
`to_date: datetime`.

**Q2 (guards)**:
- `FetcherNotFoundError` if `fetcher_name` is unknown.
- The date range validation (`DATE_RANGE_TOO_WIDE`) is performed by the
  API schema/dependency layer before the service is called.

**Q3 (behavior)**:

1. Validate fetcher existence.
2. Query `FetcherRun` records where `created_at` is within
   `[from_date, to_date]`, ordered by `created_at ASC, id ASC`.
   Filtering and ordering on `created_at` (rather than `started_at`)
   ensures `queued` runs — whose `started_at` is `NULL` — appear in the
   timeline in correct chronological position. Include runs with
   `status IN ('queued', 'running')` (duration will be `null` for
   both).
3. Derive disabled periods from `FetcherAuditEvent` records — see
   Disabled Period Derivation below.
4. If `has_manage_fetchers` is `false`, omit `disabled_by` and
   `enabled_by` from each disabled period (set to `null`).

**Q6 (exceptions)**: `FetcherNotFoundError`.

#### Disabled Period Derivation

The `disabled_periods` array represents time ranges when the fetcher was
disabled, derived from `FetcherAuditEvent` records with
`event_type IN ('disabled', 'enabled')`.

**Algorithm**:

1. Query all `FetcherAuditEvent` records for the fetcher where
   `event_type IN ('disabled', 'enabled')`, ordered by `id ASC` (fixed
   — no client-controlled sort). `id` is a UUIDv7 value, so this is
   equivalent to `created_at ASC` with a deterministic tiebreak, in a
   single column.
2. Walk the ordered events and pair each `disabled` event with the next
   `enabled` event to form an interval `[disabled_at, enabled_at]`.
   Consecutive `disabled` events without an intervening `enabled`: the
   earliest opens the interval, subsequent ones are ignored.
3. If the last event is `disabled` (no subsequent `enabled`), the
   interval is open-ended: `enabled_at = null`.
4. Include every interval that **intersects** the requested range
   `[from_date, to_date]`. An interval intersects if:
   `disabled_at <= to_date AND (enabled_at IS NULL OR enabled_at >= from_date)`.
5. Preserve the **actual event timestamps** — do NOT clip to the
   requested range boundaries. The consumer can clip for chart rendering;
   the API provides accurate data.
6. If no audit events exist or no events match, return an empty array.
7. If the first event in the database is `enabled` (implying the fetcher
   was disabled before any recorded event), there is no preceding
   `disabled` timestamp — this orphaned `enabled` event does not form a
   period and is ignored.

**Actor fields**:

- `disabled_by` / `enabled_by`: when `has_manage_fetchers` is `true`,
  return a User Reference Object
  (`{"id": "uuid", "username": "...", "full_name": "...", "active": bool}`).
  When `has_manage_fetchers` is `false`, both fields are `null`.
- This ensures a Public endpoint does not expose admin identities.

#### `get_fetcher_config`

**Q1 (inputs)**: `db: AsyncSession`, `fetcher_name: str`.

**Q2 (guards)**: `FetcherNotFoundError` if `fetcher_name` is neither in
the registry nor has a `FetcherConfig` row. Also raised if the fetcher
is in the registry but has no `FetcherConfig` row (bootstrap prerequisite
— consistent with `trigger_fetcher` and `update_fetcher_config`).

**Q3 (behavior)**:

1. Validate fetcher existence (must have a `FetcherConfig` row).
2. Return configuration fields from `FetcherConfig` merged with
   registry metadata.
3. For registered fetchers: include `settings_schema` from
   `Settings.model_json_schema()`.
4. For deregistered fetchers: `settings_schema = null`,
   `default_schedule = null`, raw stored `custom_settings`.

**Q6 (exceptions)**: `FetcherNotFoundError`.

#### `update_fetcher_config`

**Q1 (inputs)**: `db: AsyncSession`, `fetcher_name: str`,
`user_id: UUID`, `payload: UpdateConfigPayload` (all fields optional:
`enabled`, `schedule_override`, `run_timeout`, `request_delay`,
`custom_settings`).

**Q2 (guards)** (evaluated in this order after lock):
1. `FetcherNotFoundError` — fetcher unknown.
2. `FetcherDeregisteredError` — fetcher deregistered (in DB, not in
   registry).
3. `FetcherAlreadyRunningError` — `run_timeout` is changing AND a
   non-stale active (`queued` or `running`) run exists (see Run Timeout
   Active Guard below).
4. `FetcherSettingUnknownError` — unknown key in `custom_settings`.
5. `FetcherSettingInvalidError` — the candidate merged state (current
   stored values plus submitted changes) fails validation. The invalid
   field is not necessarily one the caller submitted — see
   `custom_settings` canonicalization below.

**Q3 (behavior)**:

1. **Input-only validation**: reject an empty request body (no fields
   provided) with `422 VALIDATION_ERROR` and the message "At least one
   field must be provided." Validate `schedule_override` cron syntax and
   its 50-character storage bound (`FetcherConfig.schedule_override` is
   `VARCHAR(50)`), `run_timeout` bounds (60–604800), `request_delay`
   bounds (0–300). These constraints are enforced at the request-schema
   layer (Pydantic validators) and produce the global `422
   VALIDATION_ERROR` response per `docs/api-spec.md`. They execute
   before any database operation and before the service function is
   called.
2. **Lock**: `SELECT ... FOR UPDATE` on `FetcherConfig` where
   `fetcher_name` matches. This is the first database operation.
3. **Guards**: evaluate guards 1–5 in order. On any failure, raise the
   corresponding exception — no mutations, audit events, or RedBeat
   propagation occur.
4. **Run Timeout Active Guard**: if `run_timeout` is present in the
   payload AND differs from the current value: query `FetcherRun` where
   `fetcher_name` matches AND `status IN ('queued', 'running')`. This
   guard covers both active statuses — not `running` alone — because a
   manual run's Celery task already has its `time_limit`/
   `soft_time_limit` fixed at publication time (an earlier, separate
   transaction), before adoption. If `run_timeout` were free to change
   while that run is still `queued`, the value captured at adoption
   would still be correct (per-run persistence), but the intent of the
   guard is defense-in-depth: preventing operator surprise by rejecting
   a change when an active run exists. Evaluate staleness using the
   row's own status: Queued Stale Threshold (`created_at`, fixed 600
   seconds) if `queued`; Running Stale Threshold (`started_at`,
   `hard_time_limit_seconds + 60`) if `running` — using the run's own
   persisted `hard_time_limit_seconds`. If `hard_time_limit_seconds` is
   `NULL` (historical rows), fall back to the current (pre-PATCH)
   `FetcherConfig.run_timeout`.
   - If **not stale**: raise `FetcherAlreadyRunningError`. The entire
     PATCH fails atomically — no field is modified, no audit event is
     created, no RedBeat propagation occurs.
   - If **stale**: finalize the stale run under the same lock (same
     semantics as the Queued/Running Stale Threshold in
     `docs/features/platform/fetcher-infrastructure.md`, Stale Run
     Detection, for the finalization message and fields). Proceed with
     mutation.
   - If `run_timeout` is present but equal to the current value: no-op
     for this field, guard does not apply.
5. **Compute diff**: for each field in the payload, compare with current
   persisted value. Only actually-changed fields proceed to mutation.
6. **Mutate**: apply all changed fields to the `FetcherConfig` row.
   - `custom_settings` merge: each key in the payload is applied
     individually. Keys set to `null` are removed from the JSONB column
     (reset to default). Keys not in the payload are unchanged. Keys
     with value equal to the currently stored value are no-ops.
   - **Custom settings canonicalization**: each non-null submitted key
     is validated by constructing the fetcher's `Settings` model over
     the candidate merged state (current stored values plus the
     submitted changes). Pydantic's own coercion rules apply (e.g., a
     submitted string `"500"` for an `int` field is accepted and
     coerced). The **new** value that is persisted, compared for the
     diff in step 5, and recorded in the audit event's `new_value`
     (step 7) is the **canonical value produced by the validated
     model** — via `model_dump(mode="json")`, extracting only the
     submitted, non-null keys — never the raw payload value. The
     **old** value recorded in the audit event's `old_value` is the
     previously stored value (already canonical, since every prior
     write persisted the canonical form). This guarantees the
     persisted JSONB, the value `get_setting()` returns at runtime, and
     the audited value always agree in type and representation. Only
     the submitted keys are extracted from the validated model's dump;
     unrelated declared fields (defaults) are never materialized into
     `custom_settings`, and omitted or orphaned keys already stored are
     left untouched.
7. **Audit events**: create one `FetcherAuditEvent` per actually-changed
   field, in deterministic order:
   1. `enabled` → event type `disabled` or `enabled`
   2. `schedule_override` → `config_changed`
   3. `run_timeout` → `config_changed`
   4. `request_delay` → `config_changed`
   5. Custom settings keys in alphabetical order → `config_changed`
   All events share the same `created_at` and `user_id`.
8. **No-op detection**: if no field actually changed (all submitted
   values equal the current values), skip mutation, audit, and RedBeat.
   Do not update `updated_at`. The function returns a result indicating
   no propagation is needed.
9. **Flush** (without commit): expose generated IDs and ensure constraint
   violations surface before the caller commits.
10. **Return**: the updated config state plus a propagation descriptor
    indicating which RedBeat changes are needed (if any).

**Audit value serialization** (for `custom_settings`):

Values are serialized as canonical JSON scalars:
- Strings: `"value"` (JSON-quoted)
- Integers: `123`
- Floats: `1.5`
- Booleans: `true` / `false`
- Null (reset): stored as SQL `NULL` in `new_value`

The canonical form uses `json.dumps(value, sort_keys=True,
separators=(",", ":"), ensure_ascii=False)` for non-null values. This
ensures deterministic comparison and avoids ambiguity between `"true"`
(string) and `true` (boolean).

Standard fields (`schedule_override`, `run_timeout`, `request_delay`)
store their `str()` representation as `old_value`/`new_value`. A `NULL`
value (e.g., `schedule_override` reset to default) is stored as SQL
`NULL` — not as the string `"None"`.

**Q5 (re-invocation)**: conditionally idempotent. If all submitted
values match current state, the function is a no-op (no mutation, no
audit, no propagation). If values differ, each call produces new audit
events.

**Q6 (exceptions)**: `FetcherNotFoundError`, `FetcherDeregisteredError`,
`FetcherAlreadyRunningError`, `FetcherSettingUnknownError`,
`FetcherSettingInvalidError`.

#### RedBeat Post-Commit Propagation

After the API workflow commits the transaction containing
`update_fetcher_config` mutations:

1. Read the propagation descriptor returned by the service function.
2. If no schedule-affecting field changed: skip propagation.
3. Evaluate propagation with the following **precedence** (first
   matching rule wins):
   - If `enabled` changed to `false`: delete the RedBeat entry. All
      other field changes in the same PATCH are moot for scheduling —
      skip remaining propagation. A disabled fetcher has no entry.
      Disabling does not interrupt a run already adopted by a worker
      (`running`) — it completes normally. A run still `queued` at the
      moment of disable is NOT interrupted either, but does not
      complete normally: when a worker eventually reaches it, the
      Atomic Run Acquisition Protocol's disabled-fetcher branch
      finalizes it as `failure` (`error_message = "Fetcher disabled
      between trigger and execution"` — see
      `docs/features/platform/fetcher-infrastructure.md`, Atomic Run
      Acquisition Protocol, step 2, and "Note on trigger-then-disable
      race condition" below). The disable takes effect for scheduled
      triggers from the next scheduled cycle.
   - If `enabled` changed to `true`: create the RedBeat entry with the
     effective schedule and time limit options (incorporating any
     `schedule_override` or `run_timeout` changes from the same PATCH).
   - If `schedule_override` or `run_timeout` changed (without `enabled`
     change) **and the fetcher is currently enabled**: upsert the entry
     with updated values. If the fetcher is disabled (and stays
     disabled), skip — no entry exists to update.
4. On any `RedisError`: log WARNING, do NOT roll back the committed
   PostgreSQL change. The system self-heals at the next Beat restart.
   Note: concurrent PATCHes on the same fetcher may also propagate out
   of order (the row lock serializes mutations but not post-commit Redis
   writes). The same self-healing mechanism applies — the Beat restart
   reconciles from the authoritative PostgreSQL state.
5. The API response is transmitted AFTER the propagation attempt
   completes (success or failure) — guaranteed by the
   `scope="function"` transaction dependency.

No Redis or network I/O occurs while the `FetcherConfig` row lock is
held. The lock is released at commit (step before propagation).

**No-op PATCH limitation**: a PATCH that submits only values identical
to the current state is a no-op (step 8) and does NOT trigger RedBeat
propagation. This means a no-op PATCH cannot be used to repair a missing
RedBeat entry for an already-enabled fetcher. The remedy for a missing
entry is a Beat restart (which reconciles all entries from PostgreSQL —
see `docs/features/platform/fetcher-infrastructure.md`, "Startup
Reconciliation").

#### `list_fetcher_audit_events`

**Q1 (inputs)**: `db: AsyncSession`, `fetcher_name: str`, `page: int`,
`per_page: int`, `event_type: list[str] | None`,
`actor: str | None`, `from_date: datetime | None`,
`to_date: datetime | None`.

**Q2 (guards)**: `FetcherNotFoundError` if unknown.

**Q3 (behavior)**:

1. Validate fetcher existence.
2. Query `FetcherAuditEvent` with optional filters:
   - `event_type`: OR semantics (any of the provided values). Invalid
     enum values are handled per `docs/api-spec.md` (Enum Filter
     Validation).
   - `actor`: User Identifier Resolution (UUID or username). Returns
     events by the specified user. Unknown actor returns empty results,
     not 404.
   - `from_date` / `to_date`: filter on `created_at` (inclusive).
3. Order: `id DESC` (fixed, not client-controlled). `id` is a UUIDv7
   value, so this is equivalent to `created_at DESC` with a
   deterministic tiebreak, in a single column.
4. Apply pagination.
5. Actor field in response: always a User Reference Object (this
   endpoint requires `manage_fetchers`).

**Q6 (exceptions)**: `FetcherNotFoundError`.

#### `trigger_fetcher`

**Q1 (inputs)**: `fetcher_name: str`, `user_id: UUID`,
`session_factory: async_sessionmaker`.

Note: this function does NOT accept a caller-supplied `AsyncSession`. It
is a service-owned orchestration boundary that manages its own sessions
and transactions.

**Q2 (guards)** (evaluated in this order, under lock):
1. `FetcherNotFoundError` — fetcher name not in registry AND no
   `FetcherConfig` row.
2. `FetcherDeregisteredError` — `FetcherConfig` exists but name not in
   registry.
3. `FetcherDisabledError` — `FetcherConfig.enabled = false`.
4. `FetcherAlreadyRunningError` — a non-stale active (`queued` or
   `running`) `FetcherRun` exists.

**Q3 (behavior)**:

##### First Transaction (short, under lock)

1. Open session from `session_factory`.
2. `SELECT ... FOR UPDATE` on `FetcherConfig` where `fetcher_name`
   matches. If no row exists: check registry — if not in registry
   either, raise `FetcherNotFoundError`; if in registry (bootstrap not
   run), raise `FetcherNotFoundError` (config row is a prerequisite
   for triggering).
3. Evaluate guards 2–4 in order.
4. **Stale run handling**: if an active (`queued` or `running`) run
   exists and IS stale — evaluated using the threshold matching its
   own status: Queued Stale Threshold (`created_at`, 600 seconds) if
   `queued`, Running Stale Threshold (`started_at`,
   `hard_time_limit_seconds + 60`) if `running` — using the run's own
   persisted `hard_time_limit_seconds` (falling back to
   `FetcherConfig.run_timeout` for historical rows where the column is
   `NULL`) — finalize it per
   `docs/features/platform/fetcher-infrastructure.md` (Stale Run
   Detection) — `status = failure`, specified error message, computed
   fields (a stale `queued` run keeps `started_at` and
   `duration_seconds` `NULL`). This finalization occurs under the same
   lock before creating the new run.
5. Create `FetcherRun`:
   - `fetcher_name`: from input
   - `status`: `queued`
   - `triggered_by`: `manual`
   - `triggered_by_user_id`: from input (`user_id`)
   - `started_at`: `NULL` (set only when a worker later adopts the run)
   - All other fields: `null` / zero
6. Create `FetcherAuditEvent`:
   - `event_type`: `triggered`
   - `fetcher_name`: from input
   - `user_id`: from input
   - `old_value`, `new_value`, `detail`: all `null`
7. Flush, then commit. The `queued` `FetcherRun` and its `triggered`
   audit event are now durable.
8. Close session (releases lock).

##### Celery Publication (after commit, no lock held)

9. Call `run_fetcher.apply_async(kwargs={...}, time_limit=...,
   soft_time_limit=..., queue=...)` using:
   - `fetcher_name`: from input
   - `triggered_by`: `"manual"`
   - `user_id`: `str(user_id)`
   - `run_id`: `str(committed_run.id)`
   - `time_limit`: `max(5, run_timeout)` (from locked config snapshot)
   - `soft_time_limit`: `max(1, floor(run_timeout * 0.95))`
   - `queue`: from `FETCHER_REGISTRY[name].queue` (or omitted if `None`)

##### Success Path

10. Return the committed `run_id` (status `queued`) and confirmation
    message.

##### Publication Failure Path (second transaction)

11. If `apply_async` raises any exception:
    a. Open a new session from `session_factory`.
    b. Attempt a **conditional atomic UPDATE**: `UPDATE FetcherRun SET
       status = 'failure', finished_at = now(),
       error_message = ..., error_detail = ..., error_traceback = ...
       WHERE id = :run_id AND status = 'queued'`. `started_at` and
       `duration_seconds` are not touched by this UPDATE — they remain
       `NULL`, since the run was never adopted. If zero rows are
       affected (a worker already adopted the run — ambiguous
       acknowledgement, outcome 2 below): log WARNING and skip to
       step 11g.
    c. The update uses:
       - `error_message`: fixed sanitized message:
         `"Manual run could not be dispatched to the task broker"`
       - `error_detail`: `type(exc).__name__` only (e.g.,
         `"OperationalError"`). Do NOT include the exception string —
         broker connection errors routinely contain host:port, connection
         URIs, or credentials in their string representation. Diagnostic
         detail belongs in the API process logs.
       - `error_traceback`: `NULL`. Tracebacks contain the full exception
         string on their final line, defeating any redaction applied to
         `error_detail`. Operational debugging uses structured logs, not
         persisted tracebacks for this code path.
    d. Commit.
    e. Close session.
    f. The `triggered` audit event created in step 6 is **retained**
       regardless of publication outcome.
    g. Raise `FetcherBrokerUnavailableError`.

##### Process Crash Between Commit and Enqueue

If the API process is killed (OOM, pod eviction, node failure) after
step 7 commits but before step 9 executes, `apply_async` never runs and
the Publication Failure Path never fires. The pre-created `FetcherRun`
remains at `status = queued` (never adopted) with no corresponding
Celery task.

This is covered by the Queued Stale Threshold (600 seconds — see
`docs/features/platform/fetcher-infrastructure.md`, Stale Run
Detection): the orphaned row becomes *eligible* for finalization once
it crosses that threshold, but finalization itself is lazy — it only
happens when some subsequent acquisition attempt for the same fetcher
actually runs: the next scheduled acquisition, a manual trigger attempt
(guard 4, "Stale run handling"), or a `PATCH .../config` request that
changes `run_timeout` (Run Timeout Active Guard, which evaluates the
same threshold, and applies regardless of whether the fetcher is
currently disabled — see below).

**Before** the row crosses the 600-second threshold:
- Scheduled triggers are silently discarded (active `queued` run) —
  unless the fetcher is disabled, in which case no scheduled attempt
  exists at all.
- Manual triggers return `409 FETCHER_ALREADY_RUNNING` — unless the
  fetcher is disabled or deregistered, in which case guards 2–3 reject
  the request before stale handling is ever reached, leaving the
  orphaned row untouched.

**Once** the row crosses the threshold, the first of the three attempts
above that actually reaches stale evaluation finalizes it and proceeds:
a scheduled acquisition marks it `failure` and starts its own run (no
caller to notify); a manual trigger marks it `failure` and returns
**202 Accepted** for the new run; a `run_timeout` PATCH marks it
`failure` under the same guard and applies the configuration change.
Guards 2–3 still apply first: a **deregistered** fetcher rejects both
the trigger and the PATCH before stale handling is reached, leaving the
orphan untouched regardless of staleness. A **disabled** (but still
registered) fetcher has no scheduled attempt and rejects a manual
trigger, but a `run_timeout` PATCH is not blocked by the disabled state
(no such guard exists in `update_fetcher_config`) — it still reaches
the Run Timeout Active Guard and finalizes the orphan.

Until one of those attempts occurs, `GET /api/v1/fetchers` shows
`stale: true` once the threshold is reached, alerting the operator
regardless of the fetcher's enabled/registered state.

This crash scenario is functionally equivalent to the "worker dies
before adopting the task" case that Queued Stale Detection is designed
to cover. 600 seconds (10 minutes) is the eligibility threshold, not a
guaranteed recovery latency: a **deregistered** fetcher has no
acquisition attempt or PATCH that can trigger finalization (guard 2
rejects both), so its orphaned `queued` row remains visible as
active-and-stale (via `stale: true`) until the fetcher is
re-registered. No additional mechanism (outbox, heartbeat, lease, or
background reaper) is introduced to bound this further — the
operator-visible `stale: true` signal is the intended recovery path for
this residual case.

##### Ambiguous Broker Acknowledgement

If `apply_async` raises an exception but the broker actually accepted
the task (network error after broker acknowledgement), the following
race can occur:

- The worker receives the task and attempts to adopt the `FetcherRun`
  via the Atomic Run Acquisition Protocol's conditional UPDATE
  (`queued -> running`, step 6 of that protocol).
- Concurrently, step 11 above attempts its own conditional UPDATE
  (`queued -> failure`).

Both are conditional atomic UPDATEs against the same precondition
(`WHERE id = :run_id AND status = 'queued'`) on the same `FetcherRun`
row. PostgreSQL's ordinary row-level locking on `UPDATE` makes this
race safe without any additional coordination: whichever transaction's
`UPDATE` commits first changes `status` away from `queued`; the other
transaction's `UPDATE`, evaluated against the row's now-committed
state, matches zero rows and is a no-op. No `FetcherConfig` lock is
needed for this specific race — the row-level lock implicitly acquired
by each `UPDATE` on the single contended row is the entire
serialization mechanism. Because the transition is `queued -> running`
(not a no-op on an already-`running` row, as in the pre-`queued`
model), this holds regardless of how long the worker has been
executing by the time step 11 runs — the compensation can only ever
race the moment of adoption itself, never a moment during or after
execution.

Two outcomes are possible:

1. **Compensation wins**: the conditional UPDATE in step 11 succeeds
   (the run was still `queued`). The run is finalized as `failure`.
   The worker's later adoption attempt finds `status != queued` and
   skips execution without error — see
   `docs/features/platform/fetcher-infrastructure.md` (Atomic Run
   Acquisition Protocol, step 6, duplicate/already-finalized
   handling). `BaseFetcher.run()` is never invoked for this run.
2. **Worker wins**: the worker's adoption UPDATE (`queued -> running`)
   commits first. Step 11's UPDATE then matches zero rows and is a
   no-op; the run continues executing and is finalized normally by
   `BaseFetcher.run()`. The API still returns 503 because the
   publication error already occurred — a benign false-negative: the
   operator sees a 503 but the run executes (and may complete)
   successfully. The operator can verify via the run list.

No new database column, additional status value, or distributed lock
is introduced to eliminate this race — the `queued` status itself,
combined with ordinary conditional-UPDATE row locking, is sufficient.
The residual ambiguity in outcome 2 (a 503 response paired with a run
that still executes) is accepted because:
- The race window is extremely narrow (network error timing between
  broker acknowledgement and the worker's adoption).
- Both outcomes leave the system in a consistent state — exactly one
  execution occurs, or none.
- The single-instance invariant is preserved in both outcomes.
- The audit trail accurately records what happened.
- The operator can verify via the run list whether execution occurred.

**Q4 (audit events)**: one `triggered` event, always — even on broker
failure. Created in the first transaction.

**Q5 (re-invocation)**: NOT idempotent. Each call creates a new
`FetcherRun` and audit event (guards permitting).

**Q6 (exceptions)**: `FetcherNotFoundError`, `FetcherDeregisteredError`,
`FetcherDisabledError`, `FetcherAlreadyRunningError`,
`FetcherBrokerUnavailableError`.

## API Endpoints

### List Fetchers

```
GET /api/v1/fetchers
```

**`Access: Public`**
**`Authentication: Optional`**

Returns all fetchers — both registered (present in the in-memory
`FETCHER_REGISTRY`) and deregistered (removed from the codebase but
with a `FetcherConfig` record still in the database). See
`docs/features/platform/fetcher-infrastructure.md`, "Deregistered
Fetcher Lifecycle" for background on how deregistered fetchers arise.

**Data source**: delegates to `list_fetchers()`.

**Pagination**: not paginated. The total number of fetchers (registered
+ deregistered) is bounded — registered fetchers are expected <30, and
deregistered fetchers grow at most by units over the application's
lifetime (see `fetcher-infrastructure.md`). The full list is always
returned.

**Sorting**: fixed `fetcher_name` ascending (alphabetical).
Client-controlled sorting is not supported — the bounded dataset has a
single natural ordering. Registered and deregistered fetchers are
interleaved alphabetically; the `registered` field provides the
distinction.

**Response** (200 OK):

```json
{
  "data": [
    {
      "fetcher_name": "sync_nvd_cves",
      "registered": true,
      "description": "Incremental CVE sync from NVD",
      "enabled": true,
      "effective_schedule": "0 */6 * * *",
      "schedule_is_override": false,
      "default_schedule": "0 */6 * * *",
      "cve_source_type": "nvd",
      "next_run_at": "2025-04-20T18:00:00Z",
      "custom_settings_count": 0,
      "last_run": {
        "id": "uuid",
        "created_at": "2025-04-20T11:59:58Z",
        "started_at": "2025-04-20T12:00:00Z",
        "finished_at": "2025-04-20T12:03:45Z",
        "duration_seconds": 225.0,
        "status": "success",
        "items_created": 12,
        "items_updated": 45,
        "items_failed": 0,
        "triggered_by": "schedule",
        "triggered_by_user": null,
        "error_message": null,
        "stale": false
      }
    },
    {
      "fetcher_name": "old_fetcher",
      "registered": false,
      "description": null,
      "enabled": true,
      "effective_schedule": null,
      "schedule_is_override": null,
      "default_schedule": null,
      "cve_source_type": null,
      "next_run_at": null,
      "custom_settings_count": 1,
      "last_run": {
        "id": "uuid",
        "created_at": "2026-01-15T07:59:59Z",
        "started_at": "2026-01-15T08:00:00Z",
        "finished_at": "2026-01-15T08:00:45Z",
        "duration_seconds": 45.0,
        "status": "success",
        "items_created": 3,
        "items_updated": 10,
        "items_failed": 0,
        "triggered_by": "schedule",
        "triggered_by_user": null,
        "error_message": null,
        "stale": false
      }
    }
  ]
}
```

**Fields**:

- `registered`: `true` if the fetcher class is present in the
  `FETCHER_REGISTRY`, `false` if the class has been removed from the
  codebase (deregistered). Deregistered fetchers cannot be triggered,
  configured, or scheduled — only their historical data is accessible.
- `description`: human-readable description from the fetcher class.
  `null` for deregistered fetchers (the class no longer exists).
- `cve_source_type`: the `CVESourceType` identifier for CVE fetchers
  (`BaseCVEFetcher` subclasses), e.g., `"nvd"`, `"mitre"`. `null` for
  non-CVE fetchers and deregistered fetchers.
- `enabled`: whether the fetcher is active. For deregistered fetchers,
  reflects the stored DB value — it has no practical effect.
- `effective_schedule`: the effective schedule (override if set, otherwise
  default). For deregistered fetchers: the stored `schedule_override` if
  set, otherwise `null`.
- `schedule_is_override`: `true` if the effective schedule comes from
  `FetcherConfig`. `null` for deregistered fetchers.
- `default_schedule`: the schedule defined in code. `null` for
  deregistered fetchers.
- `next_run_at`: calculated from the RedBeat entry's `due_at`. `null` if
  the fetcher is disabled, deregistered, or Redis is unavailable. See
  `docs/features/platform/fetcher-infrastructure.md` (Celery Beat
  Schedule Synchronization — `next_run_at` Calculation).
- `custom_settings_count`: number of persisted custom setting keys
  recognized by the current schema (registered) or total JSONB key count
  (deregistered). See service function for counting logic.
- `last_run`: the most recent `FetcherRun` record (by `created_at DESC,
  id DESC`), or `null` if never run. Includes runs with
  `status IN ('queued', 'running')`.
  - `created_at`: when the run was accepted (manual) or created
    (scheduled). Always non-`null`.
  - `started_at`: when a worker adopted the run. `null` while
    `status = queued`.
  - For a `queued` or `running` run: `finished_at = null`,
    `duration_seconds = null`.
  - `stale`: `true` when the run's elapsed time exceeds the threshold
    for its own status — `now() - created_at > 600` for `queued`,
    `now() - started_at > hard_time_limit_seconds + 60` for `running`
    (using the run's own persisted limit; falling back to
    `FetcherConfig.run_timeout` for historical rows where the column is
    `NULL` — see `docs/features/platform/fetcher-infrastructure.md`,
    Stale Run Detection). Always `false` for a terminal status.
  - `triggered_by_user`: User Reference Object when `triggered_by` is
    `manual` AND the caller has `manage_fetchers`. Otherwise `null`.
  - `error_message`: sanitized public message (never contains raw
    broker, database, or system details). `null` for successful runs.
  - `error_detail` and `error_traceback` are NOT included in this
    endpoint.

### List Fetcher Runs

```
GET /api/v1/fetchers/{fetcher_name}/runs
```

**`Access: Public`**
**`Authentication: Optional`**

Returns paginated run history for a specific fetcher.

**Path parameters**:

| Parameter | Type | Description |
|---|---|---|
| `fetcher_name` | string | Fetcher identifier |

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number |
| `per_page` | int | 20 | Items per page (max 100) |
| `status` | string | — | Filter by status (`queued`, `running`, `success`, `failure`, `partial`) |
| `from_date` | datetime | — | Filter runs accepted/created on or after this datetime |
| `to_date` | datetime | — | Filter runs accepted/created on or before this datetime |

**Sorting**: fixed `created_at DESC, id DESC` (most recent first).
Client-controlled sorting is not supported — run history has a single
natural chronological ordering, and the deterministic `id` tiebreaker
ensures stable pagination. Ordering (and the `from_date`/`to_date`
filters above) uses `created_at` rather than `started_at` so that a
`queued` run — whose `started_at` is `null` until worker adoption —
still appears in its correct chronological position.

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "fetcher_name": "sync_nvd_cves",
      "created_at": "2025-04-20T11:59:58Z",
      "started_at": "2025-04-20T12:00:00Z",
      "finished_at": "2025-04-20T12:03:45Z",
      "duration_seconds": 225.0,
      "status": "success",
      "items_created": 12,
      "items_updated": 45,
      "items_failed": 0,
      "error_message": null,
      "triggered_by": "schedule",
      "triggered_by_user": null,
      "stale": false
    }
  ],
  "meta": {
    "total": 150,
    "page": 1,
    "per_page": 20
  }
}
```

**Notes**:
- `error_detail` and `error_traceback` are NOT included in list responses
- `triggered_by_user`: User Reference Object
  (`{"id": "uuid", "username": "...", "full_name": "...", "active": bool}`)
  when `triggered_by` is `manual` AND the caller has `manage_fetchers`.
  Otherwise `null`
- For a run with `status = queued`: `started_at = null`,
  `finished_at = null`, `duration_seconds = null`
- For a run with `status = running`: `finished_at = null`,
  `duration_seconds = null`
- `stale`: `true` when the run's elapsed time exceeds the threshold for
  its own status — `now() - created_at > 600` for `queued`,
  `now() - started_at > hard_time_limit_seconds + 60` for `running`
  (using the run's own persisted limit; falling back to
  `FetcherConfig.run_timeout` for historical rows where the column is
  `NULL`). Always `false` for a terminal status

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists (not in the registry and no `FetcherConfig` record in the database) |

### Get Fetcher Run Detail

```
GET /api/v1/fetchers/{fetcher_name}/runs/{run_id}
```

**`Access: Public`**
**`Authentication: Optional`**

Returns full detail for a single run.

**Response** (200 OK):

```json
{
  "data": {
    "id": "uuid",
    "fetcher_name": "sync_nvd_cves",
    "created_at": "2025-04-20T11:59:58Z",
    "started_at": "2025-04-20T12:00:00Z",
    "finished_at": "2025-04-20T12:03:45Z",
    "duration_seconds": 225.0,
    "status": "failure",
    "items_created": 12,
    "items_updated": 45,
    "items_failed": 3,
    "error_message": "3 items failed during processing",
    "error_detail": "TimeoutError: NVD API request timed out after 30s for CVE-2025-1234",
    "error_traceback": "Traceback (most recent call last):\n  ...",
    "triggered_by": "schedule",
    "triggered_by_user": null,
    "stale": false
  }
}
```

**Fields**:
- All fields from the list response, plus:
- `error_detail`: included ONLY if the requesting user has the
  `manage_fetchers` capability. The field is **absent from the response
  body** for callers without this capability (not `null` — absent).
- `error_traceback`: same visibility rule as `error_detail`.

**Failure drill-down**: for CVE fetchers (where `cve_source_type` is
defined in the fetcher registry response), the run detail view can link
to `GET /api/v1/cve-sources?source={cve_source_type}&status=failure&from_date={started_at}&to_date={finished_at}`
to show individual CVEs that failed during the run. For runs still in
`running` status, omit `to_date` for a live view of accumulated
failures. If `started_at` is `null` (a `queued` run finalized as
`failure` before any worker adopted it, or a run still `queued`), omit
this drill-down entirely — no execution window exists to query. See
`docs/features/tickets/cve-service.md` (Global CVE Source
Listing).

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists, or the specified run was not found for this fetcher |

### Get Fetcher Run Timeline Data

```
GET /api/v1/fetchers/{fetcher_name}/timeline
```

**`Access: Public`**
**`Authentication: Optional`**

Returns time-series data optimized for chart rendering. Each data point
represents an individual `FetcherRun` record.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `from_date` | datetime | 7 days ago | Start of the time range |
| `to_date` | datetime | now | End of the time range |

**Date range constraint**: the maximum allowed interval between
`from_date` and `to_date` is **1825 days** (5 years). If the requested
interval exceeds this limit, the endpoint returns 400 Bad Request with
code `DATE_RANGE_TOO_WIDE`.

**Pagination**: not paginated. The response size is bounded by the
maximum date-range interval above combined with fetcher execution
frequency (~1–4 runs/day yields ~7,300 points for a full 5-year window).
Aggressive schedule overrides (e.g., `*/5 * * * *`) or frequent manual
triggers can produce larger responses; this is an admin-created
condition and the endpoint does not enforce a point-count ceiling.
External rate limiting (proxy layer) mitigates abuse of the public
endpoint.

**Response** (200 OK):

```json
{
  "data": {
    "points": [
      {
        "run_id": "uuid",
        "timestamp": "2025-04-19T12:00:00Z",
        "duration_seconds": 210.5,
        "items_created": 8,
        "items_updated": 32,
        "items_failed": 0,
        "status": "success"
      },
      {
        "run_id": "uuid",
        "timestamp": "2025-04-20T12:00:00Z",
        "duration_seconds": null,
        "items_created": 5,
        "items_updated": 20,
        "items_failed": 0,
        "status": "running"
      },
      {
        "run_id": "uuid",
        "timestamp": "2025-04-20T12:05:00Z",
        "duration_seconds": null,
        "items_created": 0,
        "items_updated": 0,
        "items_failed": 0,
        "status": "queued"
      }
    ],
    "disabled_periods": [
      {
        "disabled_at": "2025-03-15T10:00:00Z",
        "disabled_by": null,
        "enabled_at": "2025-03-17T08:30:00Z",
        "enabled_by": null
      }
    ]
  }
}
```

**Fields**:
- `points[].run_id`: UUID of the `FetcherRun` record
- `points[].timestamp`: `created_at` of the `FetcherRun` — not
  `started_at`, so a `queued` point (whose `started_at` is `null`) is
  still placed at its correct chronological position. Named
  `timestamp` (not `created_at`) as a deliberate chart-axis alias — the
  chart consumer interprets this as "the x-axis value" without needing to
  know the underlying column name
- `points[].status`: `queued`, `running`, `success`, `failure`, or
  `partial`
- `points[].duration_seconds`: actual execution duration. `null` for
  runs with `status IN ('queued', 'running')`, and for any run whose
  `started_at` is `null`
- `points[].items_created/updated/failed`: actual counts
- `disabled_periods`: derived from `FetcherAuditEvent` records (see
  Disabled Period Derivation). `disabled_by` / `enabled_by` are `null`
  without `manage_fetchers`, User Reference Objects with it

**Sorting**: fixed chronological order (`timestamp ASC, run_id ASC`,
i.e. `created_at ASC, id ASC`). Client-controlled sorting is not
supported — chart data must be in chronological order.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 400 | `DATE_RANGE_TOO_WIDE` | Requested interval exceeds 1825 days |
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists |

### Trigger Fetcher

```
POST /api/v1/fetchers/{fetcher_name}/trigger
```

**`Capability: manage_fetchers`**

Enqueues a manual run of the specified fetcher. Delegates to
`trigger_fetcher()` service function (orchestration boundary).

**Request body**: None.

**Response** (202 Accepted):

```json
{
  "data": {
    "run_id": "uuid",
    "message": "Fetcher 'sync_nvd_cves' has been queued for execution"
  }
}
```

The returned `run_id` identifies a `FetcherRun` already committed with
`status = queued`. It transitions to `running` once a worker adopts it
— see `docs/features/platform/fetcher-infrastructure.md` (Concurrency
Control).

**Progress tracking**: poll run status via
`GET /api/v1/fetchers/{fetcher_name}/runs/{run_id}` using the returned
`run_id`.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists |
| 409 | `FETCHER_DEREGISTERED` | Fetcher exists in DB but code removed |
| 409 | `FETCHER_DISABLED` | Fetcher is disabled |
| 409 | `FETCHER_ALREADY_RUNNING` | A non-stale active (`queued` or `running`) run exists. If the active run is stale, it is finalized and the new run proceeds (returns 202) |
| 503 | `CELERY_UNAVAILABLE` | Task broker unavailable — run record marked as failed only if it had not already been adopted by a worker (see "Ambiguous Broker Acknowledgement" under `trigger_fetcher`) |

**503 response body**: uses a fixed sanitized detail message
(`"Manual run could not be dispatched to the task broker"`). The
`FetcherRun.error_detail` field (visible only with `manage_fetchers` via
the run detail endpoint) stores only the broker exception's class name
(e.g., `"OperationalError"`) — never the exception's string
representation, which routinely contains hostname, IP, port, a Redis
URI, or credentials. `error_traceback` is always `NULL` for this failure
path — a traceback's final line reproduces the same unsafe exception
string. The 503 response itself carries none of this: it MUST NOT
contain hostname, IP, port, Redis URL, socket path, or traceback
information under any caller capability.

**Note on trigger-then-disable race condition**: if an admin triggers a
fetcher (passing the enabled check) and another admin disables the
fetcher before the Celery worker picks up the task, the `run_fetcher`
task wrapper detects the disabled state during the acquisition protocol
(step 2) and attempts a conditional `queued -> failure` transition on
the pre-created `FetcherRun`. See `fetcher-infrastructure.md`, "Atomic
Run Acquisition Protocol" step 2.

**Note on on-demand CVE fetch**: when Sentinel encounters an unknown
CVE-ID during ticket creation or CVE association, it triggers on-demand
single-CVE fetches via standalone Celery tasks (not through this trigger
endpoint). These on-demand fetches are sub-operations that do not create
`FetcherRun` records. See `docs/features/tickets/cve-service.md`,
"On-Demand Fetch: fetch_single_cve".

**Note on Ticket convergence**: this endpoint always executes one named
fetcher's normal complete scope and creates a `FetcherRun`. It does not
enumerate one Ticket's package markers, preserve Ticket convergence ordering,
or dispatch the complete per-Ticket catch-up roster. Use
`POST /api/v1/tickets/{ticket_id}/rerun-reactivation` for that operation; its
root task ID is transient and is not a `FetcherRun`.

### Get Fetcher Config

```
GET /api/v1/fetchers/{fetcher_name}/config
```

**`Capability: manage_fetchers`**

Returns the current configuration for a fetcher, including any
fetcher-specific custom settings and the schema that describes them.

**Response** (200 OK):

```json
{
  "data": {
    "fetcher_name": "sync_redhat_cves",
    "enabled": true,
    "schedule_override": null,
    "default_schedule": "0 3 * * *",
    "effective_schedule": "0 3 * * *",
    "run_timeout": 3600,
    "request_delay": 0,
    "custom_settings": {
      "results_per_page": 500
    },
    "settings_schema": {
      "type": "object",
      "title": "Settings",
      "properties": {
        "results_per_page": {
          "type": "integer",
          "default": 2000,
          "minimum": 100,
          "maximum": 2000,
          "description": "Number of CVE records per API page."
        }
      }
    },
    "updated_at": "2025-04-20T10:00:00Z"
  }
}
```

**Fields**:
- `custom_settings`: current values stored in the DB. Keys not explicitly
  set by an admin are absent (the fetcher code falls back to schema
  defaults via `get_setting()`). An empty object `{}` means all settings
  use their defaults.
- `settings_schema`: standard JSON Schema generated by the fetcher's
  `Settings` Pydantic model (`Settings.model_json_schema()`). Read-only,
  not stored in DB. `null` if the fetcher declares no `Settings` class
  or if the fetcher is deregistered.
- `default_schedule`: the schedule defined in code. `null` for
  deregistered fetchers.
- `effective_schedule`: the effective schedule (override if set, otherwise
  default). For deregistered fetchers: the stored `schedule_override` if
  set, otherwise `null`.

**Deregistered fetcher behavior**: when called for a deregistered fetcher
(present in DB but not in the registry), the response is a read-only
snapshot. `settings_schema` and `default_schedule` are `null`.
`custom_settings` contains raw stored values without schema context.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists |

### Update Fetcher Config

```
PATCH /api/v1/fetchers/{fetcher_name}/config
```

**`Capability: manage_fetchers`**

Modifies fetcher configuration. Partial updates are supported — only
include the fields to change. Delegates to `update_fetcher_config()`
with a caller-owned transaction.

**Request body** (all fields optional):

```json
{
  "enabled": false,
  "schedule_override": "0 */4 * * *",
  "run_timeout": 600,
  "request_delay": 2.0,
  "custom_settings": {
    "results_per_page": 500
  }
}
```

**Validation rules**:
- An empty request body (no fields provided) returns `422
  VALIDATION_ERROR` with the message "At least one field must be
  provided."
- `schedule_override`: must be a valid 5-field cron expression of at
  most 50 characters (matching the `VARCHAR(50)` storage column), or
  `null` to revert to the default schedule. Validated by constructing a
  `celery.schedules.crontab` object — the same parser used by RedBeat at
  runtime — ensuring that any value accepted at PATCH time is guaranteed
  parseable at Beat startup
- `run_timeout`: must be an integer between 60 and 604800 (1 minute
  to 7 days). Controls Celery hard/soft time limits and the stale run
  detection threshold. Default: 3600 (1 hour)
- `request_delay`: must be a float >= 0 and <= 300
- `custom_settings`: each key must exist in the fetcher's `Settings`
  model. Unknown keys → 422 `FETCHER_SETTING_UNKNOWN`. Partial merge:
  omitted keys unchanged, `null` resets a key to its `Settings` field
  default. The submitted, non-null keys are validated together with
  the fetcher's current stored values (candidate merged state, see
  `update_fetcher_config`, step 6) — if the merged state fails
  validation, the response is 422 `FETCHER_SETTING_INVALID`, and the
  invalid field named in `detail` may be a previously stored value the
  caller did not submit in this request

**Response** (200 OK): the updated config object (same schema as GET
config response).

**Side effects**: see `update_fetcher_config()` service function for the
complete mutation, audit, and propagation contract.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists |
| 409 | `FETCHER_DEREGISTERED` | Fetcher exists in DB but code removed |
| 409 | `FETCHER_ALREADY_RUNNING` | `run_timeout` change while a non-stale run is active |
| 422 | `FETCHER_SETTING_UNKNOWN` | Unknown key in `custom_settings` |
| 422 | `FETCHER_SETTING_INVALID` | The candidate merged state fails validation — the invalid field may not be one the caller submitted |

### Get Fetcher Audit Log

```
GET /api/v1/fetchers/{fetcher_name}/audit-log
```

**`Capability: manage_fetchers`**

Returns the audit trail of admin actions for a fetcher.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number |
| `per_page` | int | 20 | Items per page (max 100) |
| `event_type` | string (repeatable) | — | Filter by event type. Multiple values use OR semantics. See `docs/api-spec.md` (Enum Filter Validation) |
| `actor` | string | — | Filter by actor: user UUID or username. Follows User Identifier Resolution. Unknown actor → empty results, not 404 |
| `from_date` | datetime | — | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date` | datetime | — | ISO 8601 date/datetime. Include events up to this date (inclusive) |

**Sorting**: fixed `id` descending (most recent first). `id` is a
UUIDv7 value, so this is equivalent to `created_at` descending with a
deterministic tiebreak, in a single column. Client-controlled sorting
is not supported — audit trail has a single natural
reverse-chronological ordering consistent with other audit log
endpoints in the system (`identity-audit-log.md`,
`system-settings.md`).

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "fetcher_name": "sync_nvd_cves",
      "event_type": "config_changed",
      "actor": {
        "id": "uuid",
        "username": "jdoe",
        "full_name": "John Doe",
        "active": true
      },
      "old_value": "0 */6 * * *",
      "new_value": "0 */4 * * *",
      "detail": {"field": "schedule_override"},
      "created_at": "2025-04-18T14:31:00Z"
    },
    {
      "id": "uuid",
      "fetcher_name": "sync_nvd_cves",
      "event_type": "disabled",
      "actor": {
        "id": "uuid",
        "username": "jdoe",
        "full_name": "John Doe",
        "active": true
      },
      "old_value": null,
      "new_value": null,
      "detail": null,
      "created_at": "2025-04-18T14:30:00Z"
    }
  ],
  "meta": {
    "total": 5,
    "page": 1,
    "per_page": 20
  }
}
```

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `FETCHER_NOT_FOUND` | No fetcher with this name exists |

## Access Control

| Action | Required |
|---|---|
| View fetcher list | Public |
| View fetcher run history | Public |
| View fetcher timeline | Public |
| View run error messages (sanitized) | Public |
| View run error details (raw) | `manage_fetchers` |
| View run error tracebacks | `manage_fetchers` |
| View triggered_by_user identity | `manage_fetchers` |
| View disabled_by/enabled_by actors | `manage_fetchers` |
| Trigger manual run | `manage_fetchers` |
| Enable/disable fetcher | `manage_fetchers` |
| Modify fetcher config | `manage_fetchers` |
| View fetcher config | `manage_fetchers` |
| View audit log | `manage_fetchers` |

**`has_manage_fetchers` derivation**: the four Public endpoints accept an
optional principal (via the optional authentication mechanism defined in
`docs/api-spec.md`, Optional Authentication on Public Endpoints). The
`has_manage_fetchers` boolean passed to the service is derived as follows:
- If no authenticated principal is present (anonymous request):
  `has_manage_fetchers = false`.
- If an authenticated principal is present: `has_manage_fetchers = true`
  if and only if the capabilities resolved from the principal's current
  roles include `manage_fetchers`.
- This derivation never produces a 401 or 403 on Public endpoints — it
  only controls field-level visibility (null vs populated, present vs
  absent).

## Background Tasks

### run_fetcher

Generic Celery task that executes any registered fetcher by name.

| Property | Value |
|---|---|
| Task name | `run_fetcher` |
| Parameters | `fetcher_name` (str), `triggered_by` (str), `user_id` (str, optional), `run_id` (str, optional) |
| Schedule | per-fetcher, from `FetcherConfig.schedule_override` or `BaseFetcher.default_schedule` |
| Idempotency | Only one instance per fetcher can run at a time (database-level `SELECT ... FOR UPDATE` — see `fetcher-infrastructure.md`, Concurrency Control) |

The task contract (registration, argument validation, acquisition
protocol, and finalization) is owned by
`docs/features/platform/fetcher-infrastructure.md`.

## CLI Commands

The `sentinel fetcher` command group provides read-only diagnostic
access to the fetcher infrastructure from the command line. It is
designed for troubleshooting and quick status checks. All mutations
(trigger, enable/disable, configuration changes) are done exclusively
through the API.

Both commands delegate to the `fetcher_operations` service module for
data retrieval. They use the shared CLI infrastructure session mechanism
(`docs/features/platform/cli-infrastructure.md`) with a single
`asyncio.run()` per invocation.

### `sentinel fetcher list`

Lists all fetchers (registered and deregistered) with their current
state.

```
sentinel fetcher list
```

**Output** (human-readable table to stdout):

```
Name                       Enabled   Last Run              Status                       Settings
sync_nvd_cves              yes       2026-04-27 12:00 UTC  running (1m 30s elapsed)     —
sync_smelt_products        yes       2026-04-26 06:00 UTC  success (45s)                —
detect_ibs_track_releases  no        2026-04-25 02:00 UTC  failure                      —
sync_ibs_requests          yes       2026-04-27 02:30 UTC  success (2m 15s)             —
sync_redhat_cves           yes       2026-04-27 12:10 UTC  queued (5s elapsed)          —

Deregistered (historical data only):
Name                       Last Run              Status
old_fetcher                2026-01-15 08:00 UTC  success (45s)
```

The deregistered section is displayed only when deregistered fetchers
exist. If there are none, the section is omitted.

**Ordering**:
- Registered fetchers: `name` ascending (alphabetical).
- Deregistered fetchers: `name` ascending (alphabetical).
- Registered always precede deregistered (separate sections).

**Settings column** (registered fetchers only):
- Shows `N custom` where N is the count of persisted custom setting
  keys recognized by the current `Settings` schema. Orphaned keys
  (stored but no longer in the schema) are excluded from the count.
- Shows `—` if the fetcher has no `Settings` model or if no recognized
  keys are stored (JSONB is `{}` or all stored keys are orphaned).

**Status column** (applies to both registered and deregistered):

1. If a `FetcherRun` with `status = queued` exists:
   - Show `queued ({elapsed} elapsed)` where elapsed is calculated
     from `created_at` relative to now.
   - Elapsed formatting: `Xs` for <60s, `Xm Ys` for <60m,
     `Xh Ym` for >=60m. Always rounded down to the nearest whole unit.
   - If elapsed exceeds 600 seconds (the Queued Stale Threshold —
     see `docs/features/platform/fetcher-infrastructure.md`, Stale Run
     Detection), append `, stale?` — e.g., `queued (11m 2s elapsed, stale?)`.
2. Else if a `FetcherRun` with `status = running` exists:
   - Show `running ({elapsed} elapsed)` where elapsed is calculated
     from `started_at` relative to now.
   - Elapsed formatting: same rules as above.
   - If elapsed exceeds `hard_time_limit_seconds + 60` (the Running
     Stale Threshold — using the run's own persisted limit, falling back
     to `FetcherConfig.run_timeout` for historical rows), append
     `, stale?` — e.g., `running (1h 2m elapsed, stale?)`.
3. Else if any `FetcherRun` records exist: show the status of the most
   recent `FetcherRun` (by `created_at DESC, id DESC` — not
   `started_at`, so a `queued -> failure` pre-adoption run, whose
   `started_at` is `NULL`, is still correctly ordered) with its
   duration:
   - `success (Xm Ys)`, `failure (Xm Ys)`, `partial (Xm Ys)`
   - Duration formatting uses the same rules as elapsed.
   - For `failure` without `duration_seconds` (including a
     `queued -> failure` pre-adoption failure): show `failure` alone.
4. If no `FetcherRun` records exist: show `never run`.

**Enabled column** (registered fetchers only): reads from
`FetcherConfig.enabled`. If no `FetcherConfig` record exists, defaults
to `yes`.

**Last Run column**: `created_at` in `YYYY-MM-DD HH:MM UTC` format —
not `started_at`, so a `queued` run (whose `started_at` is `NULL`) is
still displayed. `—` if no runs exist.

**Idempotency**: Idempotent. Read-only command; safe to re-run.

**Exit codes**: 0 on success, 2 on system error (database unreachable).

**Output channels**: table to stdout. `"Error: ..."` messages to stderr.

### `sentinel fetcher config <name>`

Displays the full configuration of a fetcher, including custom settings
with their current values, defaults, and descriptions.

```
sentinel fetcher config sync_redhat_cves
```

**Output** (to stdout):

```
Fetcher: sync_redhat_cves
Enabled: yes
Schedule: 0 3 * * * (default)
Timeout: 3600s
Request delay: 0s

Custom settings:
  results_per_page = 500  (default: 2000, range: 100–2000)
    Number of CVE records per API page.
```

For a fetcher with no custom settings schema:

```
Fetcher: sync_nvd_cves
Enabled: yes
Schedule: 0 */6 * * * (default)
Timeout: 3600s
Request delay: 0s

No custom settings available for this fetcher.
```

For a deregistered fetcher:

```
Fetcher: old_fetcher (deregistered)
Enabled: yes
Schedule override: 0 */6 * * *
Timeout: 3600s
Request delay: 0s

Custom settings (schema unavailable — raw stored values):
  results_per_page = 500
```

**Ordering of custom settings**: alphabetical by key name (both
registered and deregistered).

**Value display** (registered fetchers):
- If a setting is explicitly configured (key in JSONB and in schema):
  show `key = value  (default: X, range: Y–Z)`
- If a setting uses its default (key absent from JSONB): show
  `key = value  (default, range: Y–Z)`
- If a key exists in JSONB but is absent from the current `Settings`
  schema (orphaned key): display in a separate sub-section
  `"Orphaned settings (no longer in schema):"` as raw `key = value`
  without defaults, ranges, or descriptions. This alerts the operator
  that stored values exist for a removed setting. Orphaned keys cannot
  be removed via the PATCH endpoint (unknown keys are rejected); manual
  database cleanup is required if removal is desired.
- `range` shown only for `int`/`float` with `ge`/`le` constraints
- `choices` shown as `choices: a, b, c` for fields with enum/Literal

**Value rendering**: scalars are displayed in their natural form:
- Strings: unquoted (e.g., `api_url = https://example.com`)
- Integers: `500`
- Floats: `1.5`
- Booleans: `true` / `false`
- Null (should not appear in stored values; shown as `null` if present)

**Deregistered output differences**:
- Header includes `(deregistered)` after the name.
- "Schedule" becomes "Schedule override" (only stored override shown;
  `—` if none stored).
- Custom settings shown as raw key-value pairs without defaults, ranges,
  or descriptions. If `custom_settings` is empty: `"No custom settings
  stored."`

**Error messages**:
- Unknown fetcher: `Error: Fetcher '<name>' not found.` (to stderr)

**Idempotency**: Idempotent. Read-only command; safe to re-run.

**Exit codes**:

| Code | Meaning |
|------|---------|
| 0    | Success (including deregistered fetchers) |
| 1    | User error: unknown fetcher name |
| 2    | System error: database unreachable |

**Output channels**: configuration to stdout. `"Error: ..."` messages
to stderr.

## System Metrics (Future Iteration)

The following metrics are planned for a future iteration and are NOT part
of the initial implementation:

- Memory usage (start, end, peak) via `psutil`
- CPU utilization during the run
- Database connection count

When implemented, these will be stored in a `system_metrics` JSONB column
on `FetcherRun`.

## Dependencies

- Click (CLI framework) — see `docs/conventions.md` for CLI conventions

## Cross-references

- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
- `docs/features/platform/fetcher-infrastructure.md` — fetcher runtime
  contracts (BaseFetcher, FetcherConfig, FetcherRun, FetcherAuditEvent,
  concurrency control, stale detection, RedBeat scheduling, audit trail)
- `docs/features/platform/audit-trail-infrastructure.md` — shared audit
  trail conventions (immutability, `apply_date_filters()`,
  `filter_by_actor()` resolution)
- `docs/features/platform/cli-infrastructure.md` — shared CLI session
  mechanism, error-to-exit-code mapping
- `docs/features/tickets/cve-service.md` — Global CVE Source Listing
  endpoint (failure drill-down from fetcher runs)
- `docs/features/identity/rbac.md` — Endpoint Permission Map
