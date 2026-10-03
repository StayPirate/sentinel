# IBS RabbitMQ Integration

## Purpose

The IBS RabbitMQ consumer reduces the latency of two polling-owned workflows:

- package-commit events accelerate IBS track-level release reconciliation; and
- request events accelerate IBS submission and release-request reconciliation.

RabbitMQ is a wake-up transport, not a source of durable or ordered domain
state. The consumer obtains current authoritative state from the IBS REST API
and PostgreSQL before applying an outcome. The periodic fetchers remain the
correctness and recovery owners for messages lost while the transient queue is
absent, deliveries that fail processing, request reopens, and other missed
observations.

The consumer is a continuous event-driven integration, not a `BaseFetcher` and
not a Celery worker.

### Goals

- Reconcile represented IBS package tracks within seconds of a package commit.
- Reconcile relevant IBS requests within seconds of request creation or a
  conclusive state change.
- Preserve the same idempotency, transaction, and authority boundaries used by
  polling.
- Keep delivery failure bounded and observable without an unbounded AMQP
  redelivery loop.
- Expose process liveness and activity through an ephemeral Redis heartbeat and
  a public status endpoint.

### Non-Goals

- Discovering CVEs, Tickets, packages, tracks, or Products from events.
- Treating event payload order, revision fields, action arrays, or AMQP
  metadata as authoritative domain state.
- Product-level release detection. Product repository reconciliation remains
  polling-only under
  `docs/features/packages/ibs-product-release-detection.md`.
- Replacing either periodic recovery fetcher.
- Durable message storage, replay, dead-lettering, or an event inbox.
- Publishing Celery tasks or messages.

## Ownership Boundaries

The package-commit path selects existing represented tracks and delegates to
the reconciliation contract in
`docs/features/packages/ibs-track-release-detection.md`. It does not alter
delivery status or Product state.

The request paths point-fetch the request and delegate to the shared
authoritative request reconciliation in
`docs/features/packages/ibs-submission-tracking.md`. They do not infer request
state or action identity from the RabbitMQ event.

The periodic `detect_ibs_track_releases` and `sync_ibs_requests` fetchers use
the same respective reconciliation boundaries. Successful event processing is
therefore an idempotent no-op when polling has already accepted the current
state, and the next complete polling run can recover a missed or failed event
while sufficient upstream evidence remains available.

## AMQP Contract

### Connection and Topology

The consumer connects to the URL in `IBS_RABBITMQ_URL` over AMQPS. It uses the
combined trust store from `build_tls_context()` as specified in
`docs/features/platform/networking.md` and requests an AMQP heartbeat interval
of **60 seconds**.

After each connection, the consumer establishes exactly this topology:

| Resource | Required declaration |
|---|---|
| Exchange | Name `pubsub`, type `topic`, `passive=True`, `durable=True` |
| Queue | Server-named (`name=""`), `exclusive=True`, `durable=False`, `auto_delete=True` |
| QoS | Per-consumer `prefetch_count=1` |

The exchange is IBS-managed. Sentinel must not create, modify, or publish to
it. The server-named queue exists only for the current AMQP connection. It is
deleted when that connection ends, so messages published while the queue is
absent are not recoverable from RabbitMQ.

The consumer creates exactly three bindings, with no wildcards:

1. `suse.obs.package.commit`
2. `suse.obs.request.create`
3. `suse.obs.request.state_change`

The bindings are fixed production constants. They are not configurable. This
prevents accidental intake of unrelated, high-volume, personal-data-bearing,
or non-JSON event families.

`prefetch_count=1` and a single handler provide sequential processing. While a
handler performs IBS or PostgreSQL I/O, later deliveries remain queued by the
broker as long as the AMQP session and exclusive queue remain alive. No second
delivery is processed concurrently in the same consumer process.

### Message Encoding

All three routing keys use AMQP content type `application/octet-stream`; the
body is UTF-8 encoded JSON. The consumer:

1. verifies the routing key is one of the three fixed bindings;
2. requires content type `application/octet-stream`;
3. decodes the complete body as strict UTF-8;
4. parses one complete JSON value; and
5. requires the root value to be a JSON object.

An unsupported routing key, different content type, invalid UTF-8, malformed
JSON, or non-object root is a malformed delivery. Raw message bytes and parsed
payloads are never logged or persisted.

AMQP `message_id`, `correlation_id`, and timestamp are not required and are not
used. Delivery tags and `redelivered` are transport metadata only. They are not
deduplication keys, domain identifiers, checkpoints, or evidence of event
ordering.

## Consumed Events

### Package Commit

Routing key: `suse.obs.package.commit`.

The consumer validates and consumes only these payload fields:

| Field | Required value |
|---|---|
| `project` | Non-empty JSON string |
| `package` | Non-empty JSON string |

Whitespace-only values are invalid, and so is a value containing U+0000 under
External String Admissibility (`docs/conventions.md`), because both values are
exact-match query parameters. An invalid value makes the delivery malformed.
Every other payload field is ignored without validation. In particular, `rev`,
`requestid`, `srcmd5`, sender, user, comment, and file data are neither
consumed nor persisted.

`project` and `package` form a wake-up identity only. They do not prove a
source revision or release. For a valid event, the handler:

1. selects existing tracks that satisfy the scope in
   `ibs-track-release-detection.md` and whose IBS project and logical package
   exactly equal `project` and `package`;
2. treats an empty selection as irrelevant and performs no IBS HTTP request;
3. passes the selected track IDs to `reconcile_ibs_track_releases()`; and
4. considers the delivery successful only when every selected track has an
   `updated` or `no_op` outcome.

A `failed` track outcome makes the delivery a terminal application failure,
even if sibling tracks committed successfully. Successfully committed sibling
outcomes are retained. The failed track keeps its prior checkpoint and is
recoverable through a later event or the polling owner.

The handler performs no reverse-link fan-out. An event for an unrepresented
linked target, snapshot package, or related package is irrelevant. The
periodic track detector remains responsible for observing changed expanded
source state for represented logical packages.

### Request Create and State Change

Routing keys:

- `suse.obs.request.create`
- `suse.obs.request.state_change`

Both handlers validate and consume only `number`, which must be a positive JSON
integer. Boolean values, strings, zero, negative values, and fractional numbers
are invalid. All other event fields are ignored without validation, including
state, timestamps, actor fields, action arrays, action order, and event-only
action IDs.

For a valid request number, the handler performs one inline application-level
reconciliation attempt:

1. point-fetch the current request detail from the IBS REST API by `number`;
2. validate the complete current REST representation under
   `docs/features/integrations/ibs-integration.md`; and
3. invoke the shared authoritative request reconciliation from
   `ibs-submission-tracking.md` for that request number.

The shared HTTP transport applies its bounded timeout and retry policy before
an HTTP failure reaches this handler. The consumer does not add an outer retry,
an in-memory retry, or a Celery retry. Current REST and PostgreSQL state make a
duplicate or out-of-order request event an idempotent no-op. A request that has
no relevant represented active-Ticket IBS track is irrelevant.

Request-event handling is inline. It does not publish a correlation or
discovery task and does not depend on a Celery broker.

One request can select multiple track scopes. Any failed selected scope makes
the delivery a terminal application failure even when sibling scope
transactions committed successfully; committed siblings remain committed.

## Per-Delivery Processing

### Correlation Scope

At the start of every delivered message, the consumer generates a new UUIDv7
and binds it to logging context as `ibs_event_id`. The ID is local diagnostic
metadata only. It is never persisted, returned by an API, sent upstream, or
used for deduplication.

The handler resets `ibs_event_id` in `finally` using the context-variable token
from the bind operation. Reset occurs after every outcome, including malformed
input, irrelevance, success, exception, cancellation, and shutdown. A delivery
can therefore never leak its correlation ID into the next delivery or into
connection-lifecycle logs.

Application log records produced while handling a delivery include
`ibs_event_id` in addition to the standard logging fields. Logs may contain a
validated request number, sanitized project/package identity, internal track
UUID, routing key, and bounded reason category. They must not contain raw
payloads, credentials, actor fields, comments, descriptions, file lists,
upstream exception text that can contain response data, or another personal
identifier.

### One-Attempt Rule

Each delivery receives exactly one application-level attempt. Individual HTTP
operations inside that attempt retain the shared transport's bounded retries;
the AMQP handler adds no further attempt after those retries are exhausted.

Database work follows the owning reconciliation transaction contract. An
exception rolls back the incomplete local transaction. Independently committed
per-track outcomes remain committed. No IBS, Redis, or AMQP operation occurs
while a pessimistic PostgreSQL row lock is held.

### Settlement Policy

The consumer deliberately uses ACK-only terminal settlement. It never
intentionally issues `basic.nack`, `basic.reject`, or a requeue request.

When the channel remains live, the handler ACKs exactly once after any of these
terminal outcomes:

| Outcome | Counter effect | Settlement |
|---|---|---|
| Relevant processing succeeds | Increment `events_relevant` and `events_processed` | ACK |
| Relevant processing is an idempotent no-op | Increment `events_relevant` and `events_processed` | ACK |
| Event is valid but irrelevant | No relevant/processed/failed increment | ACK |
| Routing key or payload is malformed/unsupported | Log sanitized warning; no relevant/processed/failed increment | ACK |
| Application processing fails after the one attempt | Increment `events_relevant` and `processing_failed`, set `last_error`, log sanitized error | ACK |

`events_received` increments once when handling begins, before decoding. A
request is counted as relevant only when authoritative reconciliation selects
at least one represented track scope. A package event is relevant only when its
exact project/package identity selects at least one eligible represented track.

ACK of a failed delivery means only that this transient delivery will not be
retried by RabbitMQ. It does not mark failed domain work complete. The owning
periodic fetcher supplies recovery. If that fetcher is disabled, lost and
terminally failed events, and request reopens, have no automatic recovery until
it is re-enabled.

This policy avoids an unbounded poison-message or infrastructure-failure loop.
No durable message ID, verified dead-letter exchange, inbox, or durable attempt
counter exists from which bounded redelivery could be implemented safely.

### Connection Loss and Consumer Cancellation

Connection loss, channel loss, heartbeat timeout, or broker-side consumer
cancellation invalidates the delivery channel. The consumer must:

1. stop accepting deliveries from that channel;
2. cancel the one in-flight handler and await its cleanup;
3. roll back any incomplete local transaction and close handler-owned
   resources;
4. reset `ibs_event_id` in the handler's `finally` block;
5. make no ACK, NACK, reject, or requeue call on the dead channel;
6. close remaining channel/connection resources best-effort; and
7. enter the reconnect loop and establish a new exclusive queue and bindings.

Any already committed PostgreSQL transaction remains authoritative. An
unsettled delivery and other messages held by the old exclusive queue may be
lost when that queue is deleted. Polling owns recovery; AMQP redelivery is not
assumed. If local work committed before the channel died, the process-scoped
counters retain that successful outcome even though no ACK can be sent.

## Process Lifecycle

### Runtime Independence

The consumer, implemented as `IBSEventConsumer`, runs as a standalone
long-lived process from the same Sentinel image as the other process roles. Its
entrypoint imports only the configuration,
logging, database, Redis-heartbeat, AMQP, IBS-client, and owning service
boundaries it needs.

The process must not import the Celery application, fetcher discovery for its
side effects, or any Celery task module. It does not consume or publish Celery
messages and has no runtime dependency on `CELERY_BROKER_URL`, a Celery result
backend, Redbeat, the fetcher registry, or broker publication. Celery timezone
and Redbeat lock-sentinel validation are not consumer startup steps.

PostgreSQL is required for authoritative selection and domain reconciliation.
Redis is not authoritative and is used only for best-effort process heartbeat
publication through `REDIS_URL`.

### Startup

The process performs these steps in order:

1. Load and validate consumer, TLS, database, Redis, and logging configuration.
2. If `IBS_RABBITMQ_ENABLED=false`, log an INFO lifecycle event and exit with
   code 0. Do not connect to PostgreSQL, Redis, IBS, or RabbitMQ.
3. Configure logging and initialize process-scoped heartbeat state and counters.
4. Verify PostgreSQL connectivity with a bounded `SELECT 1`. Failure is
   CRITICAL and terminates with a non-zero exit; the consumer cannot perform
   domain reconciliation without PostgreSQL.
5. Start the best-effort heartbeat loop. Initial RabbitMQ connection attempts
   are represented as `reconnecting`, so an unavailable broker is
   distinguishable from a dead consumer process.
6. Build a fresh TLS context and connect to RabbitMQ with the 60-second
   heartbeat.
7. Passively declare `pubsub`, declare the server-named queue, apply QoS, create
   the three exact bindings, and begin sequential consumption.

Startup does not require a successful Redis `PING`. A Redis connection or write
failure logs a WARNING and leaves event processing enabled.

### Reconnection

Transient RabbitMQ failures use exponential backoff beginning at 5 seconds and
capped at 300 seconds. Once capped, attempts continue every 300 seconds until
shutdown or successful connection. Each attempt builds a fresh TLS context so
a rotated CA file can be picked up without process restart.

SIGTERM or SIGINT interrupts an in-progress reconnect backoff wait immediately;
shutdown never waits for the remaining delay.

The consumer writes `disconnected` immediately after an established connection
is lost. It writes `reconnecting` when reconnection begins and while waiting or
attempting. A successful connection, topology setup, and consumer start changes
the status to `connected` and resets the delay to 5 seconds. Process counters,
including `reconnect_attempts`, do not reset.

`reconnect_attempts` increments whenever a reconnect attempt starts after the
initial connection attempt has failed or an established connection has been
lost. The initial connection attempt itself is not a reconnect attempt.

### Fatal and Transient Failures

Failure classification is explicit:

| Condition | Classification and behavior |
|---|---|
| Corrupt/unparseable local CA file or another local TLS-context configuration error | Fatal; log CRITICAL and exit non-zero |
| TLS certificate or hostname verification failure | Fatal; never disable verification or reconnect indefinitely |
| RabbitMQ authentication or authorization rejection | Fatal; log CRITICAL without credentials and exit non-zero |
| Passive `pubsub` declaration reports a missing exchange | Fatal topology error; exit non-zero |
| Exchange type/durability mismatch, queue/QoS/binding precondition failure, or incompatible topology | Fatal topology error; exit non-zero |
| DNS, TCP, timeout, broker-unavailable, heartbeat-timeout, connection-reset, channel-loss, or broker cancellation without a permanent protocol rejection | Transient; clean up and reconnect with backoff |
| PostgreSQL unavailable during startup | Fatal startup failure; exit non-zero |
| PostgreSQL, IBS REST, validation, or local reconciliation failure for one live-channel delivery | Terminal application failure for that delivery; roll back incomplete work, ACK, and continue |
| Redis heartbeat write failure | Monitoring degradation; log WARNING and continue without pausing consumption |

A missing `SUSE_CA_CERT_PATH` retains the shared networking behavior: build a
system-only context and warn. A resulting certificate-verification failure is
fatal. Fatal errors rely on the deployment orchestrator to restart after an
operator or infrastructure correction; they do not enter the internal
reconnect loop.

### Graceful Shutdown

On SIGTERM or SIGINT, the consumer:

1. stops requesting or accepting new deliveries;
2. cancels the broker consumer while keeping the live channel available for the
   current handler;
3. gives the single in-flight handler at most **30 seconds** to complete its
   normal transaction and settlement;
4. if the deadline expires, cancels the handler, rolls back incomplete local
   work, resets its correlation context, and makes no deliberate NACK/requeue;
5. stops the heartbeat loop; and
6. closes the queue channel and AMQP connection best-effort.

If the in-flight handler finishes within the deadline, it applies the ordinary
ACK policy. If the channel dies during shutdown, the dead-channel rule applies:
no settlement is attempted. Shutdown does not wait for queued deliveries in the
exclusive queue and must complete after the fixed handler deadline plus
best-effort resource closure.

## Configuration

| Variable | Type | Default | Contract |
|---|---|---|---|
| `IBS_RABBITMQ_URL` | credential-bearing URL | `amqps://suse:suse@rabbit.suse.de` | RabbitMQ connection URL; excluded from settings representations and never logged |
| `IBS_RABBITMQ_ENABLED` | boolean | `true` | Enables the standalone consumer process and controls the API-synthesized `disabled` status |
| `IBS_RABBITMQ_RECONNECT_INITIAL` | positive integer seconds | `5` | Initial transient reconnect delay |
| `IBS_RABBITMQ_RECONNECT_MAX` | positive integer seconds | `300` | Reconnect delay cap; must be greater than or equal to the initial delay |

`DATABASE_URL`, `REDIS_URL`, and `SUSE_CA_CERT_PATH` retain their cross-cutting
contracts. `REDIS_URL` is the only Redis URL used by the heartbeat. The
consumer does not read `CELERY_BROKER_URL`.

The exchange name, exchange type, queue properties, three routing keys,
60-second AMQP heartbeat, prefetch count, and 30-second shutdown deadline are
fixed integration constants, not environment variables.

## Monitoring and Observability

### Heartbeat Storage

The consumer writes the application-owned Redis key
`sentinel:ibs_consumer_status` through `REDIS_URL`.

Each heartbeat is one atomic Redis `SET` of the complete JSON document with an
expiry of **60 seconds**. The consumer refreshes it every **30 seconds** and
also writes immediately after every consumer status change. It never updates
individual fields or extends the TTL separately from writing the complete
value.

The JSON value has this exact schema:

| Field | Type | Contract |
|---|---|---|
| `status` | string | One of `connected`, `disconnected`, `reconnecting` |
| `heartbeat_at` | UTC datetime | Time this complete value was written |
| `process_started_at` | UTC datetime | Consumer process start time; constant for the process |
| `status_since` | UTC datetime | Time the current `status` began |
| `events_received` | non-negative integer | Deliveries whose handlers started |
| `events_relevant` | non-negative integer | Deliveries selecting at least one authoritative represented track scope |
| `events_processed` | non-negative integer | Relevant deliveries completed successfully, including idempotent no-ops |
| `processing_failed` | non-negative integer | Relevant deliveries with a terminal application failure |
| `reconnect_attempts` | non-negative integer | Reconnect attempts started after the initial connection attempt |
| `next_retry_seconds` | non-negative integer or null | Current scheduled reconnect delay; null when connected or no retry wait is scheduled |
| `last_error` | string or null | Most recent bounded error category from the table below |
| `last_error_at` | UTC datetime or null | Time `last_error` was recorded; null exactly when `last_error` is null |

Allowed `last_error` categories are:

- `rabbitmq_connection_failed`
- `rabbitmq_connection_lost`
- `package_reconciliation_failed`
- `request_reconciliation_failed`

The category and timestamp retain the latest process-lifetime failure until a
later failure replaces them or the process restarts. They are not cleared by a
successful message or reconnect. Raw exception text is never stored in Redis.
PostgreSQL failures during delivery processing use the package or request
reconciliation category for the path that failed; the heartbeat does not expose
a second overlapping database-specific category.
Fatal startup failures may terminate before a heartbeat can report them and
remain observable through process exit and CRITICAL logs.

All counters start at zero once per process start and are monotonically
non-decreasing for that process. They do not reset on reconnect. They are
ephemeral diagnostics, not durable domain metrics, and disappear with the
heartbeat after process death or prolonged Redis unavailability.

Example connected heartbeat:

```json
{
  "status": "connected",
  "heartbeat_at": "2026-09-08T15:42:30Z",
  "process_started_at": "2026-09-08T14:00:00Z",
  "status_since": "2026-09-08T15:40:12Z",
  "events_received": 12847,
  "events_relevant": 342,
  "events_processed": 338,
  "processing_failed": 4,
  "reconnect_attempts": 2,
  "next_retry_seconds": null,
  "last_error": "request_reconciliation_failed",
  "last_error_at": "2026-09-08T15:31:04Z"
}
```

Every Redis operation catches `RedisError`. A failed write logs one bounded
WARNING and leaves the in-memory status and counters available for the next
scheduled write. Redis unavailability never changes domain processing or AMQP
settlement.

### Consumer States

| Status | Producer | Meaning |
|---|---|---|
| `connected` | Consumer | Connection, topology, and broker consumer are active |
| `disconnected` | Consumer | An established connection was just lost and cleanup precedes reconnect |
| `reconnecting` | Consumer | Initial connection recovery or a reconnect attempt/wait is active |
| `disabled` | Status API | `IBS_RABBITMQ_ENABLED=false`; no consumer is expected to run |
| `unreachable` | Status API | Consumer liveness cannot be established from a valid fresh heartbeat |

`disabled` and `unreachable` are never written by the consumer.

## Status API

### Get IBS Consumer Status

**`GET /api/v1/ibs-consumer/status`**

**`Access: Public`**

**`Authentication: Optional`**

The endpoint has no query parameters. It returns the standard single-resource
envelope and HTTP 200 for every operational status.

#### Behavior

1. If `IBS_RABBITMQ_ENABLED=false`, return `disabled` without reading Redis.
   This rule ignores any stale key left by a previously enabled process.
2. Otherwise, read `sentinel:ibs_consumer_status` through `REDIS_URL`.
3. Return `unreachable` when Redis raises any `RedisError`, the key is absent,
   the value is not a JSON object matching the complete heartbeat schema, a
   timestamp is invalid or in the future, timestamp ordering is invalid, or
   `heartbeat_at` is more than 60 seconds old.
4. For a valid fresh heartbeat, return its consumer-written status and fields.

Valid timestamp ordering requires
`process_started_at <= status_since <= heartbeat_at`. Counters must satisfy the
non-negative integer types above. `events_processed` and `processing_failed`
must each be no greater than `events_relevant`, and `events_relevant` must be no
greater than `events_received`. Unknown status or error-category values make
the heartbeat invalid. Additional JSON fields are ignored; missing required
fields are invalid.

The endpoint does not return `REDIS_UNAVAILABLE`: inability to read Redis is a
successful observation that consumer liveness cannot be confirmed, as allowed
by the status-reporting exception in `docs/api-spec.md`.

#### Response Schema

| Field | Type | `disabled` / `unreachable` | Consumer-written states |
|---|---|---|---|
| `status` | string | Required | Required |
| `heartbeat_at` | datetime or null | `null` | Heartbeat value |
| `process_started_at` | datetime or null | `null` | Heartbeat value |
| `status_since` | datetime or null | `null` | Heartbeat value |
| `events_received` | integer or null | `null` | Heartbeat value |
| `events_relevant` | integer or null | `null` | Heartbeat value |
| `events_processed` | integer or null | `null` | Heartbeat value |
| `processing_failed` | integer or null | `null` | Heartbeat value |
| `reconnect_attempts` | integer or null | `null` | Heartbeat value |
| `next_retry_seconds` | integer or null | `null` | Heartbeat value or `null` |
| `last_error` | string or null | `null` | Heartbeat value or `null` |
| `last_error_at` | datetime or null | `null` | Heartbeat value or `null` |

The API never returns stale or partially valid heartbeat fields alongside
`unreachable`. This prevents clients from mistaking expired process counters
for current observations.

Connected response example:

```json
{
  "data": {
    "status": "connected",
    "heartbeat_at": "2026-09-08T15:42:30Z",
    "process_started_at": "2026-09-08T14:00:00Z",
    "status_since": "2026-09-08T15:40:12Z",
    "events_received": 12847,
    "events_relevant": 342,
    "events_processed": 338,
    "processing_failed": 4,
    "reconnect_attempts": 2,
    "next_retry_seconds": null,
    "last_error": "request_reconciliation_failed",
    "last_error_at": "2026-09-08T15:31:04Z"
  }
}
```

Disabled response example:

```json
{
  "data": {
    "status": "disabled",
    "heartbeat_at": null,
    "process_started_at": null,
    "status_since": null,
    "events_received": null,
    "events_relevant": null,
    "events_processed": null,
    "processing_failed": null,
    "reconnect_attempts": null,
    "next_retry_seconds": null,
    "last_error": null,
    "last_error_at": null
  }
}
```

The `unreachable` response has the same null field values as `disabled`, with
`"status": "unreachable"`.

## Error and Recovery Summary

| Condition | Immediate outcome | Recovery owner |
|---|---|---|
| Malformed or unsupported delivery | Sanitized warning and ACK | None required; poison input is discarded |
| Valid irrelevant delivery | ACK | None required |
| Duplicate or out-of-order delivery | Current-state no-op and ACK | None required |
| IBS HTTP failure after shared retries | Roll back incomplete work, count failure, ACK | Corresponding periodic fetcher or later event |
| PostgreSQL failure during delivery | Roll back, count failure, ACK | Corresponding periodic fetcher or later event |
| Partial per-track package reconciliation | Keep committed siblings, count delivery failure, ACK | Track fetcher or later event for failed tracks |
| Partial per-track request reconciliation | Keep committed siblings, count delivery failure, ACK | Request fetcher or later event for failed tracks |
| Connection loss or broker cancellation | Cancel handler, no dead-channel settlement, reconnect with a new queue | Corresponding periodic fetcher for lost messages |
| Redis unavailable | Continue consumption; heartbeat/status degrades | Next heartbeat write after Redis recovers |
| Fatal TLS, authentication, exchange, or topology condition | Exit non-zero | Operator correction and orchestrator restart |
| Consumer or corresponding fetcher disabled | No event acceleration or polling recovery from that component | Operator re-enables the component |

## Security

- TLS verification is always enabled and uses the shared combined trust store.
- `IBS_RABBITMQ_URL` can contain credentials and is never emitted in logs,
  heartbeat data, API responses, or settings representations.
- Sentinel has consume-only behavior: it never publishes to `pubsub` or any
  other AMQP exchange.
- Fixed exact bindings minimize intake of unrelated payloads and personal data.
- Only the minimal event identity fields are parsed. Current domain state is
  obtained through authenticated IBS REST operations under their owning
  contract.
- Raw payloads, actor identities, comments, descriptions, file lists, and raw
  upstream errors are neither persisted nor logged.
- The public status endpoint exposes only process state, timestamps, bounded
  categories, and aggregate process-scoped counters. It exposes no broker URL,
  credential, payload identity, request content, project, or package.

## Testing Requirements

Implementation tests must cover:

- passive durable topic-exchange declaration, server-named exclusive
  non-durable auto-delete queue, exact bindings, heartbeat 60, and prefetch 1;
- rejection and ACK of unsupported routing keys, wrong content type, invalid
  UTF-8, malformed JSON, non-object JSON, and invalid required field types;
- package parsing that consumes only non-empty `project` and `package` and
  ignores all other fields;
- request parsing that consumes only a positive integer `number`, point-fetches
  current REST truth, and never trusts event state or actions;
- sequential handling and absence of a second in-flight delivery;
- one application attempt after shared HTTP retries, with no NACK, reject,
  requeue, in-memory retry, Celery task, or broker publication;
- ACK behavior for success, idempotent no-op, irrelevance, malformed input, and
  terminal application failure;
- per-delivery UUIDv7 `ibs_event_id` binding and reset for every terminal and
  cancellation path;
- rollback of incomplete work and retention of independently committed sibling
  outcomes;
- cancellation cleanup and no settlement after channel or connection death;
- transient reconnect delay, cap, fresh queue creation, and process-scoped
  counter retention across reconnects;
- fatal TLS/authentication/exchange/topology classification versus transient
  broker/network classification;
- graceful completion within the 30-second shutdown deadline and forced
  cancellation after it;
- PostgreSQL startup requirement and Redis-independent event processing;
- atomic heartbeat writes through `REDIS_URL`, 30-second refresh, 60-second
  TTL, immediate state writes, process-start counter reset, and `RedisError`
  degradation;
- status API `connected`, `disconnected`, `reconnecting`, `disabled`, and
  `unreachable` responses, including HTTP 200 for absent, malformed, stale, or
  unreadable heartbeat state;
- heartbeat invariant validation and omission of stale fields from an
  `unreachable` response;
- no Celery app, task, broker, result backend, Redbeat, or fetcher-registry
  dependency; and
- sanitized logs, heartbeat values, and API responses with no raw message,
  credential, or personal identifier.

## Known Limitations

- The exclusive queue is intentionally transient. Deliveries queued during a
  connection failure can be lost when the queue disappears.
- A slow IBS or PostgreSQL operation can build a broker-side backlog because
  processing is sequential. Bounded HTTP timeouts and retries prevent an HTTP
  operation from waiting indefinitely; the design intentionally avoids
  concurrent handlers.
- RabbitMQ does not emit a complete request transition history, including
  request reopens. Request polling remains mandatory for automatic convergence.
- Recovery is available only while the corresponding polling owner is enabled
  and sufficient authoritative IBS evidence remains discoverable.
- The consumer cannot reconcile a package, track, or Product that Sentinel has
  not already represented. Package-tree recovery remains outside this
  integration.

## Cross-References

- `docs/architecture.md` — continuous event-driven integration and process
  boundaries
- `docs/api-spec.md` — public optional authentication, response envelopes, and
  status-reporting behavior
- `docs/conventions.md` — transaction hygiene, Redis keys/errors, external
  contract verification, and specification rules
- `docs/data-sources.md` — IBS RabbitMQ and IBS REST source catalog
- `docs/features/integrations/ibs-integration.md` — authoritative IBS REST
  request and source contracts
- `docs/features/packages/ibs-submission-tracking.md` — request reconciliation,
  delivery state, persistence, and polling recovery
- `docs/features/packages/ibs-track-release-detection.md` — package-commit
  selection and shared track reconciliation
- `docs/features/packages/ibs-product-release-detection.md` — independent
  polling-only Product release detection
- `docs/features/platform/logging.md` — structured logs and correlation context
- `docs/features/platform/networking.md` — shared HTTP retries, timeouts, and
  TLS trust store
