# Logging Infrastructure

## Purpose & Scope

This specification defines Sentinel's **operational/diagnostic
logging** model: the transient, developer/operator-facing log stream
emitted to stdout/stderr by every runtime process role.

**This specification does not apply to audit trail events**, which are
defined and persisted per
`docs/features/platform/audit-trail-infrastructure.md`. Audit trails
(`TicketAuditEvent`, `IdentityAuditEvent`, `SettingAuditEvent`,
`FetcherAuditEvent`) are authoritative historical evidence: persisted in
PostgreSQL, queryable, and retained indefinitely, but not authoritative current
operational state. Operational logs, by
contrast, are diagnostic: transient, never persisted by the
application, and consumed via an external log collector/aggregator (if
any). The two systems serve different purposes and MUST NOT be
conflated — a service operation that requires an audit trail per
Guardrail #11 still requires the `AuditEvent` record regardless of what
this specification says about logging.

This specification governs: log format, log levels, correlation IDs,
the standard log record schema, third-party logger integration,
secrets/PII discipline, and configuration. It does not govern *what*
individual services log at *which* level for their specific business
logic — those decisions remain in each feature spec's own prose (e.g.,
"log a WARNING when X occurs"), governed by the level semantics defined
here.

## Principles

1. **Structured logging via `structlog` on top of stdlib `logging`.**
   Application code uses `structlog` for context binding
   (`bind()`/`contextvars`-based). `structlog` is configured to funnel
   through the stdlib `logging` module so that third-party libraries
   (uvicorn, Celery, SQLAlchemy, httpx) that log via stdlib `logging`
   are captured in the same pipeline, format, and output stream —
   not orphaned in a separate, inconsistent format.
2. **stdout/stderr only, never files.** The application never writes
   log files, never rotates files, never manages log backup. This is
   the only choice consistent with `docs/architecture.md` (Design
   Constraints: "Application containers must not rely on local
   persistent filesystem state for correctness") and 12-factor
   app logging (treat logs as event streams, not files). Rotation,
   aggregation, retention, and backup of log *output* are the
   deployment platform's responsibility — see `docs/deployment.md`
   (Log Aggregation) for how each supported deployment context
   (container runtime, Kubernetes) surfaces and retains this stream. This
   directly answers the question raised in `docs/drafts/ideas.md`
   ("where are logs saved / rotated / backed up"): **nowhere, by the
   application; the platform owns it.**
3. **Two independent output formats, selectable via `LOG_FORMAT`**: a
   structured JSON renderer (`json`, intended for production/staging,
   machine-parseable) and a human-readable colorized console renderer
   (`console`, intended for local development). See Configuration
   below for the `auto`-detection default.

## Log Levels

Standard Python/structlog levels are used with the following semantic
guidance for choosing a level:

| Level | Usage |
|-------|-------|
| `DEBUG` | High-volume diagnostic detail useful only when actively troubleshooting (e.g., full request/response bodies to external services, cascade step-by-step resolution). Not expected to be enabled in production continuously. |
| `INFO` | Normal lifecycle events: fetcher run start/end, scheduled task execution, successful startup, significant state transitions worth a operator-visible trail (without needing the full audit trail). |
| `WARNING` | Recoverable anomalies: a retried HTTP call that eventually succeeded, a fallback path taken (e.g., cascade fallback), a non-fatal configuration issue detected at startup. |
| `ERROR` | Failures requiring operator attention: an unhandled exception in a background task, a fetcher run ending in `failure` status, a external service call that exhausted retries. |
| `CRITICAL` | Failures that abort a process or a critical subsystem: fail-fast startup validation failures, unrecoverable database connectivity loss. |

For batch operations processing a large number of items (indicatively
>100), per-item success logs SHOULD use DEBUG; aggregate results SHOULD report
terminal succeeded/failed counts separately from durable created/updated
effects at INFO. These are finalized-run diagnostics, not a live-progress
stream. This keeps the INFO stream
focused on lifecycle events and operator-actionable signals, while
per-item detail remains available at DEBUG for drill-down diagnostics.

`LOG_LEVEL` (see Configuration) controls the minimum level emitted, for
**all** loggers uniformly — application code and third-party libraries
alike. There are no per-logger overrides, no conditional pins, and no
interaction with the `DEBUG` setting (see "Relationship with `DEBUG`"
below).

### Startup Validation

An invalid `LOG_LEVEL` value (not one of `DEBUG`, `INFO`, `WARNING`,
`ERROR`, `CRITICAL`) or an invalid `LOG_FORMAT` value (not one of
`auto`, `json`, `console`) MUST cause the process to refuse to start
(fail-fast), consistent with the project's existing fail-fast
precedents (invalid `JWT_SECRET_KEY` length, non-UTC Celery timezone).
The error MUST be emitted as a plain-text message on stderr — not
through the structured renderer, which may itself be the source of the
misconfiguration (e.g., if `LOG_FORMAT` itself is the invalid value).
Both variables are case-insensitive at parse time (e.g., `debug`,
`DEBUG`, `Debug` are equivalent).

### Relationship with `DEBUG`

`DEBUG` and `LOG_LEVEL` are **fully orthogonal** — two independent
configuration axes with no interaction in either direction:

| Variable | Meaning | Effect on the other |
|----------|---------|----------------------|
| `DEBUG` | Application behavior mode: enables verbose error responses (`FastAPI(debug=True)`, stack traces in API error bodies) | None. `DEBUG` never influences log levels or log output. |
| `LOG_LEVEL` | Log verbosity for all loggers (Sentinel code and third-party alike) | None. `LOG_LEVEL` never influences application error-response behavior. |

There is no "pin" or "release" mechanism coupling the two. Setting
`LOG_LEVEL=DEBUG` in production is a valid, explicit operator choice
independent of `DEBUG`, and vice versa.

**PII/credential risk at `LOG_LEVEL=DEBUG`**: when set to `DEBUG`,
third-party loggers (notably `sqlalchemy.engine` and `httpx`) emit
sensitive data (SQL statements with bound parameters, full HTTP URLs
which may embed tokens). This is accepted as an operator-initiated
action: the operator explicitly requests maximum verbosity and accepts
the consequences. See "Secrets and PII Discipline" below and
`docs/deployment.md` (Log Aggregation) for the corresponding
operational guidance. No code-level safety mechanism restricts
`LOG_LEVEL` — the protection is operational, not architectural.

**Log level changes require a process restart.** `LOG_LEVEL` is read
once at process startup. Runtime log level modification without
restart is not specified here.

## Standard Log Record Schema

Every log record emitted through the structured pipeline includes the
following fields:

| Field | Type | Always present? | Description |
|-------|------|------------------|--------------|
| `timestamp` | string (UTC, `Z` suffix) | Yes | Time the record was emitted, per the "UTC everywhere" convention in `docs/conventions.md`. |
| `level` | string | Yes | One of `debug`, `info`, `warning`, `error`, `critical` (lowercase). |
| `logger` | string | Yes | Dotted module path of the logger (e.g., `app.services.package_service`). |
| `event` | string | Yes | The human-readable log message. |
| `app` | string | Yes | Value of `APP_NAME`. Distinguishes Sentinel's own log lines from other applications once logs from multiple services are aggregated into a shared collector/index. This is distinct from "process role" (see below) and is retained regardless of role identification strategy. |
| `request_id` | string (UUID or validated client-supplied value) | Only during API request processing | See Correlation IDs. |
| `celery_task_id` | string (UUID) | Only during Celery task execution | See Correlation IDs. |
| `fetcher_run_id` | string (UUID) | Only during a fetcher's `execute()` and the surrounding finalization phase of `run()` | See Correlation IDs. |
| `ibs_event_id` | string (UUIDv7) | Only while the IBS RabbitMQ consumer handles one delivered message | See Correlation IDs. |
| `exception` | string (traceback) | Only when logged with `exc_info` | See below. |

Correlation fields (`request_id`, `celery_task_id`, `fetcher_run_id`,
`ibs_event_id`) are **omitted entirely** from the record when not bound
for the current unit of work — they are never serialized as `null`.

**No process-role field.** The record does not include a field
identifying which of the 5 runtime roles (`api`, `celery-worker`,
`git-worker`, `beat`, `ibs-consumer` — per `docs/deployment.md`,
Container Images) emitted it. Role identification is the log
collector's responsibility via platform-provided container/pod
metadata (Kubernetes pod/container labels, or the Docker Compose
service name), not an application-level concern. See
`docs/deployment.md` (Log Aggregation) for the operational detail.

**Exception field.** The `exception` field (a rendered traceback) is
typically present on `ERROR`/`CRITICAL` records raised from an
exception context (i.e., logged with `exc_info=True` or inside an
`except` block using `logger.exception(...)`). The pipeline does not
strip `exc_info` from lower-level records — developers MAY use
`exc_info=True` at `WARNING` for diagnostically valuable tracebacks of
recoverable errors (e.g., a retryable HTTP failure logged before
proceeding to the next item). Guidance: reserve routine use of
`exc_info` for `ERROR`/`CRITICAL`; use it at `WARNING` sparingly, only
when the traceback adds diagnostic value not available from the
message alone.

## Correlation IDs

Log entries produced in the following contexts carry the corresponding
correlation field, propagated via Python's `contextvars` module (not
thread-locals — the API layer is async/FastAPI, and thread-locals do
not propagate correctly across `await` boundaries):

| Context | Field | Value source |
|---------|-------|---------------|
| API request | `request_id` | Adopts the incoming `X-Request-ID` header if present, otherwise generates a UUID. Realizes the existing contract in `docs/api-spec.md` (Request Tracing) — see "Relationship to the API Request Tracing contract" below. |
| Celery task | `celery_task_id` | `task.request.id` (Celery's native task identifier), bound via the `task_prerun`/`task_postrun` signals. |
| Fetcher run | `fetcher_run_id` | Bound by `BaseFetcher.run()` (the non-overridable lifecycle wrapper — see `docs/features/platform/fetcher-infrastructure.md`) after the `FetcherRun` record is acquired. |
| IBS RabbitMQ delivery | `ibs_event_id` | A new local UUIDv7 generated and bound by the standalone consumer when handling begins. See `docs/features/integrations/ibs-rabbitmq-integration.md` (Correlation Scope). |

### Relationship to the API Request Tracing contract

The middleware that binds `request_id` realizes **both** existing
promises already made in `docs/api-spec.md` (Request Tracing) from a
single adopted-or-generated value: the `X-Request-ID` response header
(present on every response) and the log-propagation contract ("the
request ID is propagated to all log entries produced during request
processing"). This is not a new API contract — it is the concrete
mechanism implementing a promise that predates this specification. The
middleware validates the client-supplied `X-Request-ID` per the rules
defined in `docs/api-spec.md` (Request Tracing) before adopting it as
`request_id`; a value that fails validation is discarded and a UUIDv7 is
generated instead.

### Scope boundary: per-execution-unit, no cross-enqueue propagation

Each correlation ID is valid only for the lifetime of its own unit of
execution — one HTTP request, one Celery task, one fetcher `run()` call,
or one IBS RabbitMQ delivery. Correlation IDs do **not** automatically
propagate across an `apply_async()` enqueue boundary: a Celery task
enqueued by an API request or by a fetcher starts a fresh correlation
scope with its own `celery_task_id`; it does not inherit the parent's
`request_id` or `fetcher_run_id`. This is a deliberate simplicity choice
for the current contract — cross-boundary propagation (e.g., injecting the parent
`request_id` as a task header and re-binding it in `task_prerun`) may be
added in a future revision if operational experience shows the need. The
"request-scoped debugging" wording in `docs/api-spec.md` (Request
Tracing) describes the synchronous request-processing lifecycle, not
asynchronous work it may enqueue.

### Fetcher run binding detail

`fetcher_run_id` is bound after the `FetcherRun` record is acquired
(see `docs/features/platform/fetcher-infrastructure.md`, `run()`
lifecycle) and covers both `execute()` and the finalization phase of
`run()` that follows it (status determination, cursor persistence), so
log lines emitted during finalization also carry it. Log lines emitted
by `run()` **before** the `FetcherRun` record is acquired (e.g., the
disabled-fetcher skip message) carry no `fetcher_run_id`. Sub-operation
tasks that do not create their own `FetcherRun` record (`fetch_single()`,
`catch_up()`, invoked on-demand rather than via `run()`) carry no
`fetcher_run_id` — they are correlated via `celery_task_id` only.

### Celery retry semantics

Celery preserves `task.request.id` across retry attempts
(`self.retry()` re-enqueues with the same ID). Consequently, all
execution attempts of a retried task share the same `celery_task_id`,
enabling operators to see the full history of a task — including
retries — with a single filter.

### Reset requirement

Each correlation ID MUST be reset (via the token returned by
`contextvars.ContextVar.set()`) at the end of its unit of work. This
prevents a stale value from leaking into subsequent log lines in
reused processes — Celery prefork workers, in particular, execute
multiple tasks in the same OS process over their lifetime.

To guarantee cleanup even when `task_postrun` is skipped (hard time
limit kill, unhandled exception in the signal handler itself),
`task_prerun` MUST unconditionally clear all correlation ContextVars —
`request_id`, `celery_task_id`, and `fetcher_run_id` —
before binding the new `celery_task_id`. The `task_postrun` reset remains
as defense-in-depth but is not the sole cleanup mechanism.

For API requests specifically, "end of its unit of work" means
completion of the full ASGI request lifecycle, including any Starlette
`BackgroundTask` attached to the response, if present. The reset MUST
NOT occur at response-send when a `BackgroundTask` is pending — the
middleware's `try`/`finally` must encompass the entire scope Starlette
executes for the request, so log lines produced by a `BackgroundTask`
still carry `request_id`. Sentinel does not currently use
`BackgroundTask` anywhere, but the middleware contract must be correct
for this case regardless, since nothing prevents a future handler from
using it.

### IBS RabbitMQ delivery binding detail

The standalone IBS RabbitMQ consumer binds a fresh `ibs_event_id` before
decoding each delivered message. The binding covers parsing, relevance
selection, inline reconciliation, settlement, and cleanup for that
delivery. The ID is local diagnostic metadata only: it is not persisted,
returned by an API, sent upstream, or used for deduplication.

The handler resets `ibs_event_id` in `finally` with the context-variable
token returned by the bind operation. This reset is required for every
outcome, including malformed input, irrelevance, success, exception,
cancellation, connection loss, and shutdown, so the ID cannot leak into
the next delivery or into connection-lifecycle logs. The complete
per-delivery contract is defined in
`docs/features/integrations/ibs-rabbitmq-integration.md` (Correlation
Scope).

## Integration with Third-Party Loggers

All third-party loggers captured via the stdlib `logging` bridge (D1)
follow `LOG_LEVEL` unconditionally — no pins, no conditional levels.
`LOG_LEVEL` controls every logger uniformly:

| Logger | Typical output at `DEBUG` | PII/credential risk |
|--------|----------------------------|----------------------|
| `sqlalchemy.engine` | SQL statements with bound parameters | Yes — may include credentials |
| `httpx` / `httpcore` | Full request URLs, headers | Yes — URLs may embed tokens |
| `celery` | Task execution details | Low |
| `uvicorn.access` | HTTP access log entries | Low |

Celery MUST be configured with `worker_hijack_root_logger=False`, but
this alone is insufficient: Celery's `Logging.setup_logging_subsystem`
(invoked by every Celery-based process during its own startup) still
reconfigures the root logger's *level* whenever `worker_hijack_root_logger`
is `False`, which would silently override `LOG_LEVEL` regardless of the
structlog pipeline already configured by `configure_logging()`. Celery
skips its entire built-in logging setup only when at least one receiver
is connected to its `setup_logging` signal. The Celery app factory
(`backend/app/celery_app.py`) therefore connects a `setup_logging`
receiver that calls `configure_logging(settings)`, making the
structlog/stdlib pipeline the sole logging configuration for every
Celery-based process — Celery's own setup never runs.

**Operational note** (see also `docs/deployment.md`, Log Aggregation):
setting `LOG_LEVEL=DEBUG` in production causes third-party loggers to
emit sensitive data. This is an explicit operator choice, not an
accidental side effect. Operators should use `LOG_LEVEL=DEBUG` in
production only for time-bounded diagnostics and revert promptly.

Per-logger override env vars (e.g., `LOG_LEVEL_SQLALCHEMY`) are not
currently specified. If production experience shows
the need for "verbose httpx only, quiet everything else", per-logger
vars can be added without breaking changes.

### Scope of this pipeline

The structlog pipeline configuration applies to the long-running
runtime processes: API server, Celery worker, Git worker, Beat, IBS
consumer. CLI (Click) processes do **not** invoke it — they rely on
the Python stdlib logging default (stderr), which keeps stdout
reserved for the CLI Output Contract (`docs/conventions.md`) without
requiring any CLI-specific logging configuration.

When CLI processes invoke shared service or utility code that uses
`structlog.get_logger()`, a minimal structlog configuration MUST be
applied at Click group initialization. This configuration routes
structlog output through stdlib `logging` to stderr, uses plain-text
format (not JSON, not colorized console), and sets the level to WARNING
or above — so that DEBUG/INFO messages from service code do not pollute
CLI output. Correlation IDs (`request_id`, `celery_task_id`,
`fetcher_run_id`, `ibs_event_id`) are not bound in CLI processes and are
omitted from log records. stdout remains reserved exclusively for CLI
Output Contract output (`docs/conventions.md`).

Alembic keeps its own independent logging configuration
(`alembic.ini`, `fileConfig`), because it is a one-shot migration tool
outside the application runtime, not part of this specification's
scope. Its plain-text output is a deliberate exception to the
structured-format principle: operators locate a failed-migration error
via the migration job's exit code and its plain-text stdout/stderr, not
via the structured pipeline.

### Bootstrap constraint

Log messages emitted during `Settings` initialization (e.g.,
configuration validators warning about non-fatal issues such as
unusually long token lifetimes or missing optional credentials) use
Python stdlib's default plain-text format on stderr. The structured
pipeline cannot be active at this point because it requires the
configuration values that `Settings` itself is still loading
(chicken-and-egg). This is accepted as an inherent bootstrap
limitation — a small, fixed number of one-shot messages at process
startup. Log collectors handle non-JSON lines gracefully (Fluent Bit
passes them through unparsed; Vector and Promtail have configurable
fallback behavior). No architectural change is needed.

## Secrets and PII Discipline

Log statements MUST NEVER include:

- Values obtained via `SecretStr.get_secret_value()` or any other raw
  credential material (per `docs/conventions.md`, Secret Field
  Typing).
- Personal data, except as already permitted by the placeholder rules
  in `docs/conventions.md` ("Example Data in Documentation") and
  Guardrail #23.

**Internal pseudonymous identifiers are not personal data.** UUIDs
generated and managed by Sentinel as internal record identifiers (user
IDs, fetcher run IDs) are internal pseudonymous identifiers — they
require database access to resolve to a person and are not directly
identifying. They are classified identically to `request_id` and
`celery_task_id` and are always permitted in log records. Note: session
IDs are excluded from this classification because they appear directly
in the JWT authentication token — logging them would create a
correlation path to active credentials.

**Documented PII exceptions.** In narrowly scoped security-event
scenarios where `request_id` correlation alone is insufficient and the
log serves an active defense purpose, a feature specification MAY
document an exception permitting a specific personal identifier (e.g.,
source IP for brute-force detection). Each exception MUST be documented
in the owning feature spec with the rationale and scope. See
`docs/features/identity/authentication.md` (API key validation) for the
canonical example.

### Investigability

Every log event related to authentication, authorization, or session
lifecycle MUST carry at least one identifier that allows an
administrator to correlate the event to a specific request or actor.
Typically this is:

- `request_id` — present automatically on all API request processing
  (see Correlation IDs above)
- `user_id` (UUID) — added as a structured field when the actor is
  known

Events where no actor can be identified (e.g., lockout triggered for a
non-existent username) rely on `request_id` alone. The combination of
`request_id` and platform-provided metadata (timestamps, process role)
provides sufficient context for operational investigation without
requiring personal identifiers in the log stream.

**Third-party logger gap.** The rule above governs only the
application's own log statements. It does not, by itself, prevent
third-party loggers captured by the stdlib bridge — notably
`sqlalchemy.engine` (SQL statements with bound parameters at
`DEBUG`/`INFO`) and `httpx`/`httpcore` (full request URLs, which may
embed credentials, at `DEBUG`) — from emitting sensitive data when
`LOG_LEVEL=DEBUG`. This is accepted as an explicit operator choice:
setting `LOG_LEVEL=DEBUG` is a deliberate request for maximum
verbosity, and the operator accepts the PII/credential exposure risk.
See `docs/deployment.md` (Log Aggregation) for the corresponding
operational note.

The future redaction processor, when implemented, MUST operate at the
root/handler level of the pipeline (not only on application-issued log
records) so it also covers records captured from third-party loggers —
providing defense-in-depth for environments where maximum verbosity is
needed but credential leakage must still be mitigated.

## Configuration

| Env Var | Type | Default | Notes |
|---------|------|---------|-------|
| `LOG_LEVEL` | enum | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive). Controls all loggers (application and third-party) uniformly. Fully independent of `DEBUG` — see "Relationship with `DEBUG`" above. Invalid values cause the process to fail fast at startup (plain-text error on stderr). |
| `LOG_FORMAT` | enum | `auto` | One of `auto`, `json`, `console` (case-insensitive). `json` selects the structured JSON renderer (production/staging). `console` selects the human-readable colorized renderer (local development). `auto` selects the format based on `sys.stdout.isatty()`: `True` → `console`, `False` → `json`. An explicit `LOG_FORMAT=json` or `LOG_FORMAT=console` always overrides auto-detection. Invalid values cause the process to fail fast at startup (plain-text error on stderr). |

No process-role variable is defined. Process/container identification
for log filtering purposes is delegated to platform-provided metadata
(Kubernetes pod/container labels, Docker Compose service name), not to
an application env var — see "Standard Log Record Schema" above for the
rationale (most cross-process correlation is already solved by
`request_id`/`celery_task_id`/`fetcher_run_id`; the one ambiguous case,
distinguishing `celery-worker` from `git-worker`, is already resolved
by the fact that the two roles always run in separate containers per
`docs/deployment.md`, Process Architecture).

## Consumption Model

Logs are filtered and correlated by `request_id`, `celery_task_id`,
`fetcher_run_id`, or `ibs_event_id` at the collector/query layer.
Process-role/container filtering is done via platform-provided metadata
(Kubernetes pod/container labels, Docker Compose service name) at the
collector/orchestrator level — not via any field emitted by the
application (see "No process-role field" above).

Rotation, long-term retention, and backup of the log stream are the
platform's responsibility, not the application's. Concrete
per-orchestrator commands, logging-driver configuration, and
collector/shipper setup are documented in `docs/deployment.md` (Log
Aggregation) — this specification defines the application-side
contract only.

## Testing

Once implemented, logging configuration and correlation-ID propagation
are expected to be tested as follows:

- **Format/level selection**: unit tests verifying that `LOG_FORMAT=auto`
  resolves to `console` when `sys.stdout.isatty()` is `True` and to
  `json` otherwise, and that explicit `LOG_FORMAT` values override
  auto-detection.
- **Startup validation**: unit tests verifying that an invalid
  `LOG_LEVEL` or `LOG_FORMAT` value causes the process to fail fast
  with a plain-text stderr message.
- **Correlation ID propagation**: a dedicated test verifying the ASGI
  middleware adopts the client-supplied `X-Request-ID` when present and
  generates a UUID otherwise, and that the value appears both in the
  response header and in log records emitted during that request
  (using `structlog.testing.capture_logs` or equivalent).
- **Reset behavior**: tests verifying that `request_id`/
  `celery_task_id`/`fetcher_run_id` do not leak into log records emitted
  by a subsequent, unrelated unit of work in the same process (relevant
  for Celery prefork workers), and that `ibs_event_id` is reset after
  every delivery outcome and cancellation path.
- Application-level log assertions (e.g., "a WARNING is logged when
  X occurs", prescribed by individual feature specs) use `caplog`
  (pytest) or `structlog.testing.capture_logs` as appropriate.

## Cross-references

- `docs/api-spec.md` (Request Tracing) — the `X-Request-ID` contract
  this specification implements.
- `docs/architecture.md` (Design Constraints) — the
  stateless-container principle.
- `docs/deployment.md` (Container Images) — the 5 runtime roles
  referenced throughout this document.
- `docs/conventions.md` (Timestamps & Timezones, Secret Field Typing,
  Logging) — the UTC convention and secret-handling rules this
  specification builds on.
- `docs/deployment.md` (Log Aggregation) — operational detail for how
  each deployment context surfaces, collects, and retains the log
  stream.
- `docs/features/platform/audit-trail-infrastructure.md` — contrasted
  system (persisted business audit events vs. transient operational
  logs).
- `docs/features/platform/fetcher-infrastructure.md` — `run()` binds
  `fetcher_run_id`; see its own contract for the exact binding point.
- `docs/features/integrations/ibs-rabbitmq-integration.md` — owns the
  per-delivery `ibs_event_id` lifecycle and allowed consumer log context.
