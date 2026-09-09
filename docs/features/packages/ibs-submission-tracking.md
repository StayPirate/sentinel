# IBS Submission Tracking

## Purpose

Track the current IBS maintenance-request lifecycle and its relationship to
Ticket package tracks. The feature gives consumers action-level visibility into
submission requests (SRs) and release requests (RRs), and derives the
`TicketPackageTrack.delivery_status` dimension from authoritative IBS evidence.

Submission tracking does not change package affectedness or Product release
confirmation:

- `TicketPackageTrack.status` remains owned by analysis and track release
  detection.
- `TicketPackageTrack.delivery_status` is derived here from the SR/incident/RR
  lifecycle.
- `TicketPackageProduct.eligible` remains independently derived from Product
  lifecycle and CVSS inputs.
- `TicketPackageProduct.released_at` remains owned by Product release detection.

These dimensions meet only at the observation points defined in
`package-model.md`. An IBS request observation never changes affectedness,
eligibility, Product release state, or a package-tree exclusion marker.

## Scope

This specification covers the IBS maintenance-update workflow represented by
`TicketPackageTrack.workflow_type = ibs`. It does not cover Git/SLFO submission
or delivery mechanisms.

All recurring IBS request work is rooted in tracks belonging to active Tickets
(`New`, `Analysis`, or `Analyzed`). Within an active Ticket, direct or inherited
VA exclusion, Product lifecycle, actionability, affectedness status, and Product
eligibility do not narrow factual request or delivery reconciliation. Inactive
Tickets retain previously recognized evidence but do not contribute recurring
work. Reactivation invokes the targeted catch-up defined below.

The persisted workflow discriminator is authoritative. A Git track's
`reference` is never sent to an IBS request, source-history, or diff operation
and never receives an IBS request-action correlation or delivery mutation.

## Domain Model

An IBS request is a parent containing one or more actions. Neither action array
position nor the RabbitMQ-only numeric `action_id` is a durable identity.
Requests can contain multiple relevant actions, and event action arrays can be
truncated. Sentinel therefore normalizes the parent and each relevant action.

The maintenance incident remains an implicit upstream concept. Sentinel stores
its positive number on actions when it can be established, but does not create a
`MaintenanceIncident` entity.

### Maintenance Lifecycle

1. A maintainer creates a `maintenance_incident` action in an SR.
2. Acceptance creates or updates an incident such as
   `SUSE:Maintenance:12345`. A later accepted SR can replace the incident's
   effective source contents.
3. A `maintenance_release` action in an RR releases incident contents toward a
   codestream.
4. Acceptance of the RR is delivery evidence only when source and target
   provenance proves that the RR released the effective SR contents.

IBS permits multiple actions in each request, multiple SRs for one incident,
and multiple historical RRs for an incident. Sentinel never assumes one request
equals one package, one codestream, or one action.

## Request States

Sentinel persists the exact current IBS state without a collapsed local state.

| State | Meaning for reconciliation |
|---|---|
| `new` | Current request is newly created and may progress. |
| `review` | Current request is under review and may progress. |
| `accepted` | IBS accepted and executed the request. Provenance still determines the delivery meaning of an accepted action. |
| `declined` | IBS declined the request. The request can later return to `new` or `review`. |
| `revoked` | IBS withdrew the request. It does not establish current delivery progress. |
| `superseded` | IBS replaced the request. `superseded_by_request_number` identifies the successor that must be traversed. |
| `deleted` | IBS explicitly reports the request as deleted. The retained local record is not physically deleted. |

Current request detail is the state authority. Request events are wake-ups and
their state is never applied directly. Consequently, a delayed or out-of-order
event cannot regress local state. An authoritative detail response may replace
any previously persisted known state with its current known state, including a
`declined` request returning to `new` or `review`.

Sentinel does not impose a narrower local transition allowlist. Any of the seven
known persisted states may be replaced by any different known current state
returned by authoritative detail, because Sentinel may have missed intermediate
upstream transitions. Repeated observation of the same state and normalized
content is an idempotent no-op.

For `superseded`, a positive successor request number is required. The field is
forbidden for every other state. An unknown state, a superseded response without
a valid successor, or conflicting state data makes the observation incomplete;
it does not modify retained state. A detail 404 does not prove `deleted`, because
absence cannot distinguish deletion, retention, visibility, or a request that
never existed. Sentinel persists `deleted` only when an authoritative response
explicitly supplies that state.

IBS timestamps without an offset are interpreted as UTC. The request's
upstream `created` value becomes `upstream_created_at`; the current state
`when` value becomes `upstream_updated_at`. Local `created_at` and `updated_at`
remain Sentinel row chronology and are never substituted for upstream time.

## Data Model

This feature introduces exactly three entities: `IBSRequest`,
`IBSRequestAction`, and `IBSRequestActionTrack`. It introduces no incident,
correlation-status, attempt, event-inbox, failure, cursor, or progress entity.

All UUID primary keys are UUIDv7. Enumerated state/action columns use `VARCHAR`
and the constraints below; PostgreSQL enum types are not used.

### IBSRequest

One normalized IBS request parent.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PK | Local identifier. |
| `request_number` | INTEGER | UNIQUE, NOT NULL, positive | Public stable IBS request number. |
| `state` | VARCHAR(20) | NOT NULL, CHECK | Exact state: `new`, `review`, `accepted`, `declined`, `revoked`, `superseded`, or `deleted`. |
| `superseded_by_request_number` | INTEGER | nullable, positive | Successor request number; present if and only if `state = superseded`, different from `request_number`. It is not an FK because the successor need not yet be retained. |
| `upstream_created_at` | TIMESTAMPTZ | NOT NULL | IBS request creation time, normalized to UTC. |
| `upstream_updated_at` | TIMESTAMPTZ | NOT NULL | Time of the current IBS state, normalized to UTC. |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Local row creation time. |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Local row update time. |

`state` is a state-machine enum and has a database CHECK constraint. A separate
logical CHECK enforces the `superseded_by_request_number` state relationship and
self-reference prohibition.

No author, actor, comment, description, review, event payload, or raw response
is retained.

### IBSRequestAction

One normalized relevant action belonging to one `IBSRequest`.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PK | Local action identifier. |
| `ibs_request_id` | UUID | FK(`ibs_request.id`) ON DELETE RESTRICT, NOT NULL | Parent request. |
| `action_type` | VARCHAR(32) | NOT NULL | `maintenance_incident` or `maintenance_release`; classification validated by `IBSRequestActionType`. |
| `source_project` | VARCHAR(255) | nullable | Exact normalized action source project. |
| `source_package` | VARCHAR(255) | nullable | Exact normalized physical source package. |
| `target_project` | VARCHAR(255) | nullable | Exact normalized target project. For an accepted SR this may be the incident project. |
| `target_package` | VARCHAR(255) | nullable | Exact normalized physical target package. |
| `target_release_project` | VARCHAR(255) | nullable | Exact SR target release project. |
| `logical_package` | VARCHAR(255) | NOT NULL | Validated Sentinel logical package name. |
| `codestream_name` | VARCHAR(255) | NOT NULL | Exact IBS track reference represented by this action. |
| `incident_number` | INTEGER | nullable, positive | Incident established from accepted-SR target or RR source provenance. Required for a retained RR action. |
| `source_revision` | VARCHAR(255) | nullable | Action source revision when supplied. |
| `accepted_revision` | VARCHAR(255) | nullable | Action `acceptinfo` target revision. |
| `accepted_srcmd5` | VARCHAR(32) | nullable, lowercase hexadecimal | Accepted target source checksum. |
| `accepted_xsrcmd5` | VARCHAR(32) | nullable, lowercase hexadecimal | Accepted expanded source checksum. |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Local row creation time. |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Local row update time. |

Type-specific structural checks require:

- `maintenance_incident`: non-null `source_project`, `source_package`, and
  `target_release_project`; `codestream_name` equals the validated target
  release project. `target_project`, `target_package`, incident, revision, and
  acceptinfo fields may be absent until IBS exposes them.
- `maintenance_release`: non-null `source_project`, `source_package`,
  `target_project`, `target_package`, and `incident_number`;
  `codestream_name` equals the validated target project.

Optional fields are omitted by IBS rather than represented as null. A later
complete observation may fill a retained nullable provenance field. Omission in
a later response never erases retained provenance. A conflicting non-null
immutable identity or acceptinfo value makes that scope incomplete and rolls
back its local outcome.

The type-specific structural CHECK has one branch for each
`IBSRequestActionType` value and therefore rejects unknown action types while
also enforcing the field requirements below. The durable semantic identities
are conceptually request plus action type and the fields below. The
partial-index predicate fixes the action type, so that redundant column is
omitted from each key:

- maintenance incident: `(ibs_request_id, source_project,
  source_package, target_release_project)`;
- maintenance release: `(ibs_request_id, target_project,
  target_package)`.

Each identity has a type-specific unique partial index. For an SR,
`target_project` and `target_package` are excluded from identity because
acceptance can change or add them. Array position and event `action_id` are
never stored or used. If a current representation has a different semantic
identity, Sentinel retains the old recognized action and treats the new identity
as a distinct action; it does not silently rewrite identity.

### IBSRequestActionTrack

Correlates one exact request action to one exact `TicketPackageTrack`.
It is used for both SR and RR actions.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PK | Local identifier. |
| `ibs_request_action_id` | UUID | FK(`ibs_request_action.id`) ON DELETE RESTRICT, NOT NULL | Relevant normalized action. |
| `ticket_package_track_id` | UUID | FK(`ticket_package_track.id`) ON DELETE RESTRICT, NOT NULL | Exact Ticket/CVE/package/codestream occurrence. |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Time Sentinel first recognized the correlation. |

The pair `(ticket_package_track_id, ibs_request_action_id)` is unique. Track is
the leading column because ticket-scoped APIs, maintainer projections, and
reconciliation load correlations from the exact track scope.
One action can correlate to multiple tracks when its diff names multiple Ticket
CVEs or the same CVE/package/codestream occurs in multiple Tickets. Multiple
actions can correlate to one track.

### Retention and Deletion

Recognized relevant requests, actions, and action-track correlations are
retained indefinitely. They are factual domain evidence, not transient fetcher
progress. A valid diff with no matching Ticket CVE does not create a correlation
and never causes deletion of an existing request, action, or correlation.

An upstream `deleted` state changes only `IBSRequest.state`; it does not delete
the local row. Package-tree exclusion is soft deletion and leaves correlations
intact. Restrictive FKs prevent request, action, or track deletion from
cascading away recognized evidence. There is no routine physical-deletion
workflow for these entities.

Retained evidence is not by itself current-state authority. Delivery is derived
from a complete current observation plus retained provenance. A newer complete
upstream observation can establish that retained historical actions are no
longer effective without deleting them.

## Upstream Evidence

### Request Discovery and Detail

The reconciler uses narrowly bounded searches rooted in the finite local track
scope. It never depends on an unordered global `limit`/`offset` collection scan.

For each track it may use all of these roots:

- retained exact request and action identities;
- exact request IDs in package or incident source history;
- narrow ID-only search for `maintenance_incident` actions in `new` or
  `review`, using an exact retained physical package or a source-package prefix
  rooted in `{logical_package}.`;
- incident-scoped `maintenance_release` search;
- current package and patchinfo issue evidence; and
- released-binary or published-advisory evidence as optional discovery or
  corroboration only.

A narrow ID search is complete only when the response reports all matches and
does not hit the upstream search-result limit. Every returned ID is point-fetched
and each action is validated against the exact logical package, codestream, and
semantic identity. Prefix matching proposes candidates; it never proves package
identity. The common physical-package suffix transformation is not universal
and is not used as a completeness assumption.

Every retained or candidate request is point-fetched. Current detail supplies
the authoritative parent state and complete REST action set available upstream.
RabbitMQ action content is never used to fill or replace detail. Supersession is
closed by point-fetching each positive `superseded_by_request_number`, with a
visited set and a finite cycle check. A cycle, missing required successor, or
unknown successor state is incomplete evidence.

Source-history traversal follows the IBS history operation until the available
history is exhausted, using its exact revision and backward-traversal controls.
No wall-clock cutoff is applied. Upstream retention can still make old evidence
unavailable; that condition is handled as incomplete evidence, not as absence.

### Action-Scoped CVE Evidence

Request diffs are evaluated per action. An issue is positive correlation
evidence only when all of these hold:

- it belongs to the exact action's `sourcediff`;
- `tracker = cve`;
- `state` is `added` or `changed`; and
- canonical `label` exactly equals the Ticket CVE ID.

The tracker-native `name` is not reinterpreted as a CVE ID. `deleted` is not
positive correlation evidence. `changed` is accepted because a later SR can
replace incident contents while retaining an existing CVE reference.

A completely parsed action diff with no qualifying issue is a successful
no-match for that action. An absent diff for an action that does not have one is
not an error unless that diff is required to determine correlation or effective
contents. A malformed, unavailable, truncated, or ambiguous required diff is
incomplete and never deletes retained history or proves a negative.

### Effective SR

An accepted SR is effective for an incident only when action acceptinfo,
incident/package source history, and request IDs identify that action as the
source of the incident contents under evaluation. When multiple accepted SRs
populate the same incident, source-history order and matching accepted expanded
source state select the most recent SR that produced those contents. A later SR
whose effective diff no longer has positive evidence for the Ticket CVE makes
an older SR historical rather than current progress.

An SR in `new` or `review` can establish current progress directly after exact
action and CVE correlation. A `superseded` SR does not establish progress by
itself; its successor chain inherits the role only if traversal completes and a
successor action is relevant to the same track and CVE. `declined`, `revoked`,
and `deleted` requests do not establish current progress.

If the current effective incident contents cannot be identified uniquely,
provenance is incomplete and the previous delivery state is preserved.

### Accepted RR Provenance

RR acceptance alone is insufficient for `RELEASED`. Sentinel must prove this
chain for the exact effective SR and track:

```text
effective SR accepted_xsrcmd5
    == accepted RR action source_revision
    -> RR state is accepted
    -> RR accepted_revision / accepted_srcmd5
    == codestream target history revision / srcmd5
    -> the matching target-history entry identifies the RR request number
```

Every comparison must be exact and belong to the same action, incident, package,
and codestream. If `source_revision`, `accepted_revision`, or
`accepted_srcmd5` required by this chain is absent, the proof is incomplete; no
other acceptinfo field is substituted. A relevant RR in any state is correlated
directly to the track through `IBSRequestActionTrack`; only the complete accepted
provenance chain establishes release.

Current patchinfo, released binaries, and published advisories can discover or
corroborate candidates. They cannot alone prove the historical contents at RR
acceptance and this feature never uses them to set
`TicketPackageProduct.released_at`.

## Observation Outcomes

Each track-scope reconciliation produces exactly one classification:

| Outcome | Meaning | Local effect |
|---|---|---|
| Complete positive | All required roots and artifacts were validated and relevant current SR/incident/RR evidence exists. | Atomically upsert relevant domain evidence and derive delivery. |
| Complete no-match | All required roots were exhausted successfully and no relevant current delivery evidence exists. | Retain history; a non-stale negative may derive `PENDING`. |
| Incomplete | Required evidence is absent, retention-limited, truncated, contradictory, unknown, malformed, search-limited, cyclic, or ambiguous. | Preserve request/action/correlation and delivery state exactly. |
| Failed | A required external or local operation failed. | Roll back the scope and preserve prior state. |

Examples of incomplete evidence include a required detail 404, unknown request
or action type, missing accepted provenance, non-exhaustive search, unavailable
source history, an unresolved physical package mapping, conflicting equal-time
request detail, and a direct source modification with no request provenance.
None is translated into a negative result.

No upstream source guarantees indefinite retention. The feature converges while
enough request, diff, source-history, issue, binary, or advisory evidence remains
discoverable. If all required evidence has disappeared, preserving the last
established local delivery state is the intentional safe result.

## Delivery Derivation

The three delivery values retain the meanings established by
`package-model.md`:

| Delivery status | Authoritative meaning here |
|---|---|
| `PENDING` | Sentinel has not established relevant current delivery progress. It does not prove no SR exists or that synchronization succeeded. |
| `IN_PROGRESS` | Complete authoritative evidence establishes a relevant current SR or effective incident chain, but no accepted RR has been proven to release the effective SR contents. |
| `RELEASED` | Exact accepted-RR and source/target provenance proves release of the effective SR contents to the track codestream. |

For a complete observation, derive the strongest proven state:

1. Proven accepted RR provenance yields `RELEASED`.
2. Otherwise, a relevant `new`/`review` SR, effective accepted SR/incident, or
   complete relevant supersession successor yields `IN_PROGRESS`.
3. Otherwise, a complete authoritative no-match yields `PENDING`.

`RELEASED` is irreversible. An incomplete or failed observation never changes
delivery. `IN_PROGRESS -> PENDING` is permitted only after complete negative
reconciliation and the stale-negative guard below. A missed history can converge
directly from `PENDING` to the proven final outcome; when the centralized
package mutation contract requires adjacent transitions, the transaction
applies `PENDING -> IN_PROGRESS -> RELEASED` atomically.

All effective changes use `package_service.set_track_delivery_status()` with
system attribution. Delivery changes create no Ticket audit event and do not
invoke affectedness or Product-release mutations.

## Shared Authoritative Reconciliation

The same track-scoped operation is used by the daily fetcher, package-add
acceleration, Ticket-reactivation catch-up, and RabbitMQ request-number
wake-ups. No caller has a reduced correlation or delivery algorithm.

### Scope Identity

One scope is the exact semantic locator:

```text
(Ticket.id, Ticket CVE, TicketPackage.id, logical package,
 TicketPackageTrack.id, codestream)
```

The selected track must belong to an active Ticket and have
`workflow_type = ibs`. Package and track exclusion, actionability, affectedness,
eligibility, and Product lifecycle do not remove it from scope.

### Algorithm

For each selected scope:

1. Capture `observation_started_at` in UTC and read the retained exact
   request/action roots and the track's persisted `delivery_status` needed to
   plan external queries without locking the Ticket. Retain the latter as the
   pre-I/O delivery baseline.
2. Discover current package, request, supersession, incident, and RR candidates
   using the complete evidence rules above.
3. Point-fetch current request detail and required action-scoped diffs and source
   histories. Validate every consumed field, exhaust every required root, and
   classify the observation. No database mutation occurs for an incomplete or
   failed observation.
4. For a complete observation, begin one independent local transaction and lock
   the parent Ticket first.
5. Reload the exact Ticket, CVE, package, track, workflow type, codestream, and
   relevant retained request/action evidence. If the Ticket is no longer active,
   the track no longer exists, its workflow is no longer IBS, or the semantic
   scope no longer matches, return a successful stale/inapplicable no-op.
6. Conditionally lock or upsert each existing request/action identity that this
   scope will mutate. Reject the observation as stale if a newer authoritative
   request observation has already committed. For equal
   `upstream_updated_at`, identical normalized content is idempotent;
   conflicting content is incomplete and rolls back.
7. Upsert every validated relevant `IBSRequest` and `IBSRequestAction`, then
   upsert each exact `IBSRequestActionTrack` pair. Unknown and irrelevant
   actions are not persisted. Existing provenance omitted by IBS is retained;
   contradictory immutable provenance rolls back the scope.
8. Derive delivery from the complete observation and the reloaded retained
   evidence. For a complete negative observation, do not regress
   `IN_PROGRESS` if any relevant request, action, or correlation row changed
   after `observation_started_at`, or if the track's delivery value differs from
   the value observed before external I/O.
9. Apply any effective delivery transition through
   `package_service.set_track_delivery_status()` with the complete Ticket,
   package, and track locator in the same transaction. Consume `changed` or
   `no_op` from locked-current state; delivery has no `rejected` outcome.
10. Flush and commit the request, action, correlation, and delivery outcome
    atomically. On any local failure, roll back all changes for this scope.

All IBS HTTP work completes before the Ticket lock. No IBS, Redis, AMQP, or
Celery I/O occurs while the lock is held. Each track scope has its own
transaction, so successful siblings remain committed when another scope is
incomplete or fails. The operation is idempotent; unchanged current evidence
produces no write or delivery mutation.

Concurrent callers serialize on the Ticket and database uniqueness constraints.
Because one IBS request can correlate to tracks under different Tickets, every
request/action upsert is also conditional on the currently stored upstream
timestamp and normalized content; a Ticket lock alone is not treated as a
cross-Ticket request lock. The timestamp/content checks prevent an older
point-fetch from replacing newer request truth. Uniqueness conflicts on a
concurrently inserted identity are resolved by reloading and applying the same
condition, not by replacing the winner. The post-scan evidence and expected-
delivery checks prevent a stale negative result from overwriting positive event
or polling work committed after the scan began. Audit history is never queried
for current state, idempotency, or provenance.

## Accelerators

### Package Addition

After `add_package_to_ticket()` commits at least one new IBS track, it registers
one best-effort post-commit invocation of the existing generic
`run_catch_up("sync_ibs_requests", ticket_id)` mechanism. Creating only Products,
Git tracks, maintainers, or no package-tree rows registers no request catch-up.

The catch-up observes committed package-tree state. Publication failure is
logged with sanitized Ticket and operation identity and does not roll back the
package addition. The daily complete fetcher remains the permanent recovery
owner. There is no `correlate_submission_request` or
dedicated submission-correlation or discovery Celery task.

### Ticket Reactivation

`SyncIbsRequests.participates_in_catch_up = True`. The established reactivation
workflow re-resolves package trees first and then invokes this fetcher's
`catch_up(ticket_id, session)` through the generic `run_catch_up` wrapper. The
catch-up silently returns when the Ticket or relevant IBS tracks do not exist.

It applies the complete shared algorithm to every IBS track now belonging to
that Ticket, with independent per-track mutations and failures. It recovers
current authoritative request and delivery facts rather than replaying every
transition that occurred while inactive.

Request catch-up cannot create a track omitted by failed SMELT resolution. That
broader package-tree recovery limitation remains owned by `package-model.md` and
`package-service.md`.

### RabbitMQ Request Wake-Ups

Both `suse.obs.request.create` and `suse.obs.request.state_change` are
acceleration signals only. For either routing key the consumer:

1. Decodes the UTF-8 JSON body and validates only a positive numeric `number`.
2. Ignores event state, timestamps, actors, action content, action order, and
   RabbitMQ delivery metadata for domain decisions.
3. Point-fetches current request detail by public request number.
4. Selects every active-Ticket IBS track represented by validated current
   actions and retained exact roots, including all relevant actions in a
   multi-action request.
5. Invokes the shared authoritative reconciliation inline for each selected
   scope, with independent transactions.

The event handler does not publish a Celery correlation or discovery task.
Duplicate and out-of-order deliveries converge through current detail and
idempotent reconciliation. If point lookup or reconciliation fails after the
shared bounded HTTP transport retries, the consumer rolls back incomplete local
work, records the sanitized failure, acknowledges according to the RabbitMQ
integration contract, and continues. The next complete fetcher run owns
recovery while required evidence remains upstream.

A first-observed maintenance-incident action whose physical source package
cannot be mapped unambiguously to one represented logical package from retained
roots and current detail selects no scope in the event path. The delivery is an
irrelevant acceleration no-op; the next complete `sync_ibs_requests` scan starts
from each known logical package and owns discovery. Event fields never supply a
fallback mapping.

## Fetcher: sync_ibs_requests

### Properties

| Property | Value |
|---|---|
| Fetcher name | `sync_ibs_requests` |
| Class name | `SyncIbsRequests` |
| Description | Synchronize IBS maintenance request actions and reconcile track delivery state |
| Schedule | `30 2 * * *` (daily at 02:30 UTC) |
| Source | IBS |
| Scope | Distinct IBS tracks belonging to active Tickets, including excluded and lifecycle-non-actionable tracks |
| Auth | Existing IBS HTTP Basic authentication or API token through the shared IBS client |
| `participates_in_catch_up` | `True` |
| Custom settings | No |
| Cursor | None; `FetcherRun.cursor` remains NULL |

The fetcher has no temporal lookback setting or fixed historical window.
It declares no inner `Settings` model, accepts no custom setting, and leaves
`FetcherConfig.custom_settings = {}`. It does not read `previous_cursor` or set
a cursor during execution.
`FetcherConfig` continues to provide only the generic enabled, schedule,
timeout, and request-delay controls. The first run, a run after re-enable, and a
run after a long gap use the same complete state-based algorithm.

### Algorithm

1. Select the distinct finite track scopes belonging to active Tickets where
   `workflow_type = ibs`. Include every affectedness and delivery status and all
   exclusion/actionability states.
2. Process each selected track with the shared authoritative reconciliation.
3. Commit each complete local scope independently. Roll back and continue after
   an incomplete or failed scope.
4. Let `SoftTimeLimitExceeded` and `MemoryError` escape as whole-run signals;
   they are never converted into per-scope failures.
5. Return normally after all scopes have been attempted. `BaseFetcher` derives
   success, partial, or failure from the non-overlapping metrics below.

A complete valid no-match and an idempotent no-op are successful scope outcomes.
The algorithm needs no special first-run branch, durable cursor, per-track
progress row, or global request-history scan. Source retention can still limit
what a long-gap run can prove; incomplete scopes preserve prior delivery.

### Error Handling

| Failure | Behavior |
|---|---|
| One track has a transport, timeout, rate-limit, HTTP, parse, validation, search-completeness, retention, ambiguity, or local transaction failure | Roll back that scope, increment `record_failed` once, log the track/Ticket/request identities and sanitized category, and continue. Raw response bodies, URLs, credentials, and personal identifiers are not logged. |
| Scope enumeration or another whole-run database prerequisite fails | Raise so `BaseFetcher` finalizes the run as failure. Public `error_message` uses the infrastructure's sanitized generic category; restricted error fields retain diagnostics. |
| Every selected scope fails | Return normally after counting failures; the `BaseFetcher` all-items-failed rule records run failure. |
| Some scopes complete and some fail | Return normally; `BaseFetcher` records a partial run when at least one completed scope created or updated data. If successful scopes were all no-ops, the all-items-failed safety rule still records failure because every counted work item failed. |
| Soft or hard run time limit | `SoftTimeLimitExceeded` reaches `BaseFetcher`; it records the sanitized timeout failure. The worker enforces the hard limit. No cursor advances. |

The generic `run_fetcher` task has no top-level retry. The next daily execution,
or the existing generic manual fetcher trigger, repeats the complete idempotent
scan. No SR/RR-specific retry, discovery, correlation, or operator endpoint is
introduced.

When the fetcher is disabled, successful RabbitMQ events can still reduce
latency, but lost events, terminal event-processing failures, and request
reopens have no automatic recovery. Re-enabling the fetcher restores recovery;
its next complete run processes all still-discoverable evidence.

### Metrics

Metrics use one selected track scope as the unit and are mutually exclusive:

- `record_created`: increment once when a successful scope transaction creates
  at least one relevant `IBSRequest`, `IBSRequestAction`, or
  `IBSRequestActionTrack`, even if that transaction also updates existing data
  or delivery.
- `record_updated`: increment once when a successful scope transaction creates
  no domain row but changes existing request state/provenance/correlation or
  effectively changes delivery.
- `record_failed`: increment once when a selected scope is incomplete or fails,
  regardless of the number of failed external calls or validation findings in
  that scope.
- A complete no-match and idempotent no-op increment no metric.

The per-ticket `catch_up()` sub-operation creates no `FetcherRun` and reports no
fetcher metrics, as required by the generic catch-up contract. Its per-item logs
identify terminal failures; partial success returns normally, while an
all-scopes infrastructure failure may propagate to `run_catch_up` for its
shared bounded retry policy.

## Public API

The feature keeps two existing ticket-scoped read operations. Both return one
deduplicated relevant action projection per item. Multiple joins from the same
action into the requested Ticket never duplicate that action. Persisted history
is returned regardless of current Ticket status, track affectedness, exclusion,
or actionability.

Both endpoints inherit the ticket accessibility check. Anonymous callers can
read non-confidential Tickets; confidential Ticket existence and data remain
hidden according to the shared visibility contract.

### Common Query Rules

Both endpoints support standard `page` (default 1) and `per_page` (default 20,
maximum 100) pagination. Filters combine with AND semantics.

`state` accepts one exact value from `new`, `review`, `accepted`, `declined`,
`revoked`, `superseded`, or `deleted`. Invalid enum values follow the shared
enum-filter rule: an invalid value is removed and an empty valid filter set
returns an empty result. Package and codestream filters are case-sensitive exact
matches against normalized action fields.

Client-controlled sorting is limited to:

| Parameter | Values | Default |
|---|---|---|
| `sort_by` | `upstream_created_at`, `upstream_updated_at` | `upstream_updated_at` |
| `sort_order` | `asc`, `desc` | `desc` |

The selected upstream timestamp is the primary key and
`IBSRequestAction.id` is the deterministic secondary key in the same direction.
Invalid sort values return the shared `422 VALIDATION_ERROR`.

### List Submission Requests

```http
GET /api/v1/tickets/{ticket_id}/submission-requests
```

**`Access: Public`**

**`Authentication: Optional`**

Returns distinct correlated `maintenance_incident` actions.

**Filters**:

| Parameter | Type | Required | Semantics |
|---|---|---|---|
| `package_name` | string | No | Exact `logical_package`. |
| `codestream_name` | string | No | Exact action codestream. |
| `state` | request state | No | Exact current parent request state. |

**Response: 200**

```json
{
  "data": [
    {
      "id": "00000000-0000-7000-8000-000000000101",
      "action_type": "maintenance_incident",
      "request_number": 410001,
      "state": "accepted",
      "superseded_by_request_number": null,
      "package_name": "example-package",
      "codestream_name": "SUSE:SLE-15-SP6:Update",
      "incident_number": 45001,
      "ibs_url": "https://build.suse.de/request/show/410001",
      "incident_url": "https://build.suse.de/project/show/SUSE:Maintenance:45001",
      "upstream_created_at": "2026-08-10T09:15:00Z",
      "upstream_updated_at": "2026-08-10T11:30:00Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "per_page": 20
  }
}
```

**Item schema**:

| Field | Type | Contract |
|---|---|---|
| `id` | UUID | Local `IBSRequestAction.id`; stable action projection identity. |
| `action_type` | literal `maintenance_incident` | Action classification. |
| `request_number` | positive integer | Public IBS request number. |
| `state` | request state | Exact current persisted IBS state. |
| `superseded_by_request_number` | positive integer or null | Current successor when state is `superseded`; otherwise null. |
| `package_name` | string | Validated logical package. |
| `codestream_name` | string | Exact IBS track reference. |
| `incident_number` | positive integer or null | Established incident, if available. |
| `ibs_url` | string | Computed request link using `request_number`. |
| `incident_url` | string or null | Computed incident-project link; null without an incident. |
| `upstream_created_at` | UTC datetime | IBS request creation time. |
| `upstream_updated_at` | UTC datetime | Time of the current IBS request state. |

### List Release Requests

```http
GET /api/v1/tickets/{ticket_id}/release-requests
```

**`Access: Public`**

**`Authentication: Optional`**

Returns distinct correlated `maintenance_release` actions. RR actions are
queried through their direct `IBSRequestActionTrack` correlation, not inferred
at response time from request-level incident equality.

**Filters**:

| Parameter | Type | Required | Semantics |
|---|---|---|---|
| `package_name` | string | No | Exact `logical_package`. |
| `codestream_name` | string | No | Exact action codestream. |
| `state` | request state | No | Exact current parent request state. |
| `incident_number` | positive integer | No | Exact incident number. |

**Response: 200**

```json
{
  "data": [
    {
      "id": "00000000-0000-7000-8000-000000000102",
      "action_type": "maintenance_release",
      "request_number": 410101,
      "state": "review",
      "superseded_by_request_number": null,
      "package_name": "example-package",
      "codestream_name": "SUSE:SLE-15-SP6:Update",
      "incident_number": 45001,
      "ibs_url": "https://build.suse.de/request/show/410101",
      "incident_url": "https://build.suse.de/project/show/SUSE:Maintenance:45001",
      "upstream_created_at": "2026-08-11T08:00:00Z",
      "upstream_updated_at": "2026-08-11T08:20:00Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "per_page": 20
  }
}
```

**Item schema**:

| Field | Type | Contract |
|---|---|---|
| `id` | UUID | Local `IBSRequestAction.id`; stable action projection identity. |
| `action_type` | literal `maintenance_release` | Action classification. |
| `request_number` | positive integer | Public IBS request number. |
| `state` | request state | Exact current persisted IBS state. |
| `superseded_by_request_number` | positive integer or null | Current successor when state is `superseded`; otherwise null. |
| `package_name` | string | Validated logical package. |
| `codestream_name` | string | Exact IBS target codestream. |
| `incident_number` | positive integer | Source maintenance incident. |
| `ibs_url` | string | Computed request link using `request_number`. |
| `incident_url` | string | Computed incident-project link. |
| `upstream_created_at` | UTC datetime | IBS request creation time. |
| `upstream_updated_at` | UTC datetime | Time of the current IBS request state. |

Neither endpoint exposes request author, actor, comments, descriptions, raw
source/target fields, acceptinfo, RabbitMQ metadata, or local row timestamps.
They introduce no endpoint-specific errors.

No new endpoint, capability, or error code is introduced. The existing generic
fetcher trigger remains the only API operation for an operator to rerun the
complete fetcher.

The request and incident links use the fixed IBS web origin
`https://build.suse.de`; they are not derived from `IBS_API_URL` and introduce no
new configuration. `ibs_url` appends `/request/show/{request_number}`. An
incident link reconstructs the established project identity as
`SUSE:Maintenance:{incident_number}` and appends it to `/project/show/`.

## Testing Requirements

Implementation coverage must include:

- all seven request states, including `declined -> new|review`, explicit
  `deleted`, incomplete 404 handling, and supersession cycles;
- multi-action parsing and semantic-identity constraints without array position
  or RabbitMQ `action_id`;
- action-scoped `added`/`changed` CVE correlation, valid no-match, malformed and
  missing diff evidence, and unknown action/state handling;
- effective-SR and accepted-RR provenance success, mismatch, unavailable
  history, missing acceptinfo, and retention-limited outcomes;
- every delivery transition, irreversible `RELEASED`, complete-negative
  regression, and stale-negative concurrency with independent sessions;
- atomic request/action/join/delivery commit and rollback, including successful
  sibling scopes when another fails;
- first run, long gap, re-enable, package-add and reactivation catch-up,
  duplicate/out-of-order event acceleration, and fetcher metric precedence;
- API authentication, confidential-Ticket visibility, action deduplication,
  exact filters, pagination, deterministic sorting, and response schemas; and
- log, API, and persistence assertions proving that authors, actors, comments,
  descriptions, raw payloads, credentials, and raw response bodies are absent.

## Security and Privacy

- The public read endpoints process optional authentication and enforce the
  shared confidential-Ticket visibility rules before querying actions.
- IBS HTTP requests use existing configured credentials and the shared TLS and
  HTTP-client contracts. Credentials never enter persisted request evidence,
  API output, metrics, or logs.
- Personal identifiers and free text from IBS are neither persisted nor
  returned. Logs never include raw event payloads, raw response bodies, actors,
  comments, descriptions, credentials, or credential-bearing URLs.
- RabbitMQ event action arrays and personal fields are ignored. Only the public
  positive request number is consumed as the request wake-up identity.

## Recovery Guarantees

The complete daily state-based scan is the permanent recovery owner for active
Ticket IBS tracks. While sufficient upstream evidence remains, it covers first
enablement, long disablement, missed or duplicate events, transient queue loss,
failed package-add acceleration, tracks added after older requests, request
reopens, supersession, and partial prior runs without a cursor or temporal
window.

Package-add catch-up, Ticket-reactivation catch-up, manual generic fetcher runs,
and RabbitMQ events only reduce latency. They all use the same idempotent
reconciliation and cannot establish a different domain result.

No mechanism can reconstruct facts after every relevant request detail, action
diff, source-history entry, issue index, binary, and advisory artifact has
disappeared upstream. Such a scope is incomplete and preserves the last proven
delivery state. Synchronization health is represented by `FetcherRun`, consumer
status, metrics, and sanitized logs, never by another delivery state.

## Scope Exclusions

- Git/SLFO submission or event tracking.
- Creating or modifying IBS requests.
- Manual action-to-track correlation or unlinking.
- Persisting unrelated requests or actions with no established relevant track.
- A separate maintenance-incident entity.
- Dedicated Celery correlation or discovery tasks.
- A durable event inbox, retry-attempt table, failure table, cursor, or
  per-track request progress row.
- Product publication detection or mutation of `released_at`.
- A dedicated SR/RR recovery API, CLI-only operation, capability, or error code.
- Periodic SMELT package-tree discovery; request reconciliation cannot create a
  missing track.

## Cross-References

- `docs/api-spec.md` - API envelopes, optional authentication, filtering,
  pagination, deterministic sorting, and derived responses.
- `docs/data-model.md` - canonical database schema.
- `docs/features/identity/rbac.md` - confidential Ticket visibility and the
  Endpoint Permission Map.
- `docs/features/integrations/ibs-integration.md` - IBS request, diff, search,
  and source-history client contracts.
- `docs/features/integrations/ibs-rabbitmq-integration.md` - request wake-up,
  acknowledgement, process, and heartbeat contracts.
- `docs/features/packages/package-model.md` - orthogonal dimensions, strict IBS
  applicability, active-Ticket scope, and reactivation ordering.
- `docs/features/packages/package-service.md` - centralized delivery mutation
  and Ticket locking.
- `docs/features/packages/ibs-track-release-detection.md` - independent
  affectedness release detection.
- `docs/features/packages/ibs-product-release-detection.md` - independent
  Product publication detection.
- `docs/features/platform/fetcher-infrastructure.md` - `BaseFetcher`, generic
  trigger, metrics, catch-up, transaction, and error-sanitization contracts.
- `docs/features/platform/networking.md` - shared HTTP transport retries and
  retry classification.
