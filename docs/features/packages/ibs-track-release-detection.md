# IBS Track-Level Release Detection

## Purpose

Reconcile whether fixes for CVEs already represented by Sentinel have landed in
their existing IBS package tracks. The detector observes expanded package
source state and may transition an existing `TicketPackageTrack` to `FIXED`; it
does not discover CVEs, Tickets, packages, tracks, or Products.

The detector is the permanent polling recovery owner for IBS package commits.
The scheduled fetcher, per-Ticket catch-up, and IBS RabbitMQ package-commit
processing use the same reconciliation rules. RabbitMQ reduces latency but is
not required for eventual convergence.

For the two independent release levels, see `package-model.md` (Release
Tracking). Product repository release detection is specified separately in
`ibs-product-release-detection.md`.

## Scope

An ordinary scheduled run selects `TicketPackageTrack` records that satisfy all
of the following:

- `workflow_type = ibs`;
- `status` is `ANALYSIS` or `AFFECTED`;
- the parent Ticket has a CVE; and
- the parent Ticket status is `New`, `Analysis`, or `Analyzed`.

VA exclusion, Product lifecycle actionability, and EOL state do not narrow this
scope. They affect operational decisions, not the factual observation that a
fix reference is present in IBS. A Git/SLFO track never reaches an IBS source
operation.

The detector processes only the logical source package already stored in the
parent `TicketPackage.package_name` and the IBS project already stored in
`TicketPackageTrack.reference`. An IBS package that is not represented by that
pair is outside scope. In particular, linked targets, internal snapshot
packages, and related packages such as a debug package are not inferred as new
Sentinel packages.

The detector never:

- scans an IBS project for arbitrary CVEs;
- creates or enriches a CVE;
- creates a Ticket;
- calls `add_package_to_ticket()`;
- creates a package, track, or Product occurrence;
- changes `delivery_status` or Product `released_at`; or
- creates `ticket_created` or `package_added` audit events.

CVE ingestion and package association remain owned by the CVE and package
resolution specifications. SR/RR delivery tracking remains owned by
`ibs-submission-tracking.md`.

## Authoritative IBS Evidence

Release evidence comes from two authenticated IBS HTTP operations documented in
`../integrations/ibs-integration.md`:

1. Targeted source info:

   ```text
   GET /source/{project}?view=info&nofilename=1&package={package}...
   ```

   `sourceinfo.srcmd5` is the expanded source-tree state. For a linked package,
   a target change can therefore change `srcmd5` even when the local link
   revision (`lsrcmd5`) does not change. `lsrcmd5`, `verifymd5`, and revision
   numbers are not release checkpoints.

2. Expanded source diff with issue extraction:

   ```text
   POST /source/{project}/{package}
     ?cmd=diff&view=xml&onlyissues=1&expand=1
     &orev={previous_srcmd5_or_0}&rev={current_srcmd5}
   ```

   `orev=0` represents an empty source tree and yields the structured issue
   references present in the selected current expanded state.

Only an issue satisfying every condition below is release evidence:

- `tracker = "cve"`;
- `state` is `added` or `changed`;
- `label` is a canonical CVE ID accepted by `is_valid_cve_id()`; and
- `label` equals the CVE ID of the existing parent Ticket.

`issue.label`, not tracker-native `issue.name`, is the CVE identity. `deleted`
does not prove that a fix landed. `bnc` and all other trackers are ignored and
are not treated as malformed CVEs. Duplicate qualifying issue entries are
equivalent to one entry.

`changed` proves only that the structured CVE reference changed between the two
source states. Sentinel does not claim that it distinguishes a second changelog
entry from modification of an earlier entry.

## Track Release Checkpoint

`TrackReleaseCheckpoint` is operational PostgreSQL state with at most one row
per `TicketPackageTrack`. It contains:

- `ticket_package_track_id` — the unique parent track;
- `srcmd5` — the expanded IBS source state last successfully examined for that
  track; and
- `last_seen_at` — when that checkpoint value was accepted.

The checkpoint is not Ticket domain history. It is not included in normal
Ticket or package API responses, does not create a Ticket audit event, and does
not update `TicketPackageTrack.updated_at`. Observing the same `srcmd5` again is
a no-op and need not rewrite `last_seen_at`.

A checkpoint belongs to one track rather than to a global `(project, package)`
pair because tracks for the same package may enter Sentinel at different times
or complete different prior attempts. The per-track state also preserves a VA
correction of an automatic `FIXED` result until IBS supplies later source
evidence.

## Shared Reconciliation Boundary

Polling, catch-up, and package-commit processing provide existing semantic
track locators to the same service-layer reconciliation boundary. Each locator
identifies the expected Ticket, package occurrence, and track occurrence; its
concrete in-memory representation is an implementation choice. The boundary
returns one terminal outcome per supplied track: updated, successfully examined
without a domain update, or failed. It may group external work,
but each track retains an independent database and metric outcome.

Conceptual signature:

```python
async def reconcile_ibs_track_releases(
    tracks: Collection[TrackReleaseLocator],
) -> Sequence[TrackReleaseOutcome]:
    ...
```

Each locator contains the existing track ID plus sufficient expected Ticket and
package identity for locked ownership revalidation. Duplicate track IDs are
processed once. An empty collection returns an empty sequence without
IBS or database work. Each outcome identifies the input `track_id` and exactly
one result:

| Result | Meaning |
|---|---|
| `updated` | This invocation transitioned the track to `FIXED` and committed its checkpoint |
| `no_op` | No domain update was required: current source was already examined, a valid examination produced no transition, the track had become final, or concurrent work had already accepted the same state |
| `failed` | External validation or the per-track local transaction did not complete; the prior checkpoint was retained |

The result sequence preserves no input ordering guarantee. Callers use it only
to determine per-track metrics and whether all event-selected outcomes
completed; it is not persisted or exposed through an API.

This is a system-only idempotent operation. It creates no audit event directly;
an effective status transition delegates its one event to `package_service`.
Known source, parser, history, scope-race, concurrency, and local-transaction
failures are converted to per-track outcomes so siblings continue.
`SoftTimeLimitExceeded`, `MemoryError`, a database failure that prevents
reliable candidate/scope enumeration, and an unexpected failure that prevents
the boundary from assigning trustworthy per-track outcomes propagate to the
workflow owner. Re-invocation re-reads current IBS and PostgreSQL state and
either advances from the retained predecessor or produces an idempotent no-op.

Source-info results may be reused among tracks with the same `(IBS project,
logical package)`. A source diff may be reused only among tracks with the same
project, logical package, effective baseline (`0` or checkpoint `srcmd5`), and
current expanded `srcmd5`. Tracks sharing a package can have different
checkpoints and therefore can require different diffs.

The implementation may partition targeted source-info requests into multiple
requests. Every selected logical package must be requested exactly once per
current-state observation, and partitioning must not change per-package
validation or outcome semantics.

## Scheduled Reconciliation Algorithm

`DetectIbsTrackReleases.execute()` performs the following steps:

1. Select the eligible tracks defined in [Scope](#scope). Snapshot each track
   ID, Ticket CVE ID, logical package name, IBS project, and current checkpoint
   value for external-work grouping. Candidate selection acquires no Ticket
   mutation lock.
2. Group candidates by IBS project and request source info only for represented
   logical package names, using `view=info&nofilename=1`. Do not enumerate every
   package in the project.
3. Validate the complete source-info response before applying any local
   outcome. A requested package with no single usable expanded `srcmd5` fails
   every dependent track while valid sibling packages may continue.
4. For each track whose checkpoint equals the current expanded `srcmd5`, record
   a successful unchanged-source no-op. No source diff or database write is
   required.
5. For each remaining unique baseline/current group:
   - use `orev=0` when the track has no checkpoint;
   - otherwise use the checkpoint `srcmd5` as `orev`;
   - always use `expand=1` and the current expanded `srcmd5` as `rev`.
6. Parse and validate the complete diff before applying local outcomes. Retain
   only canonical CVE labels relevant to dependent tracks; unrelated valid
   references do not need to remain in memory.
7. If IBS authoritatively reports that a persisted historical `srcmd5` is no
   longer available, apply [Unavailable History Fallback](#unavailable-history-fallback).
   Other HTTP 4xx responses are failures and do not trigger fallback.
8. Apply [Per-Track Local Outcome](#per-track-local-outcome) independently to
   every dependent track. Commit or roll back each track as its own transaction
   unit. A failed track does not roll back a successful sibling.
9. Return normally after mixed success and failure so `BaseFetcher` finalizes
   the run from the recorded metrics. An exception that prevents reliable
   candidate enumeration or all further processing escapes and produces the
   ordinary fetcher failure outcome.

### Source-Info Validation

The source-info parser accepts only a well-formed, completely consumed XML
document. For each requested package:

- exactly one `sourceinfo` entry must identify that package;
- `srcmd5` must be a 32-character hexadecimal string;
- an entry containing an upstream `error` child is unusable even if it also
  contains checksum attributes; and
- a missing entry, duplicate entry, missing or malformed required field, or
  unusable entry fails that package's dependent tracks.

An unrequested package entry does not create work and is ignored. Malformed XML
or an interrupted response invalidates the complete response and fails every
dependent track in that request. No affected checkpoint advances.

### Source-Diff Validation

The diff parser accepts only a well-formed, completely consumed XML document.
An issue without a usable `tracker` or `state`, or with an unrecognized
structural shape, is a data-quality failure. For `tracker="cve"` and `state`
`added` or `changed`, a missing or non-canonical `label` emits one bounded
warning and that entry is ignored; it is never accepted or interpreted from
`name`. Valid `bnc` and other tracker entries, and valid `deleted` entries, are
ignored without a malformed-CVE warning.

A malformed or interrupted diff fails every dependent track using that diff
and leaves their previous checkpoints unchanged. An empty valid diff is a
successful no-match outcome.

### Per-Track Local Outcome

External IBS I/O and XML parsing complete before any Ticket lock is acquired.
For one track, the local transaction then:

1. locks the parent Ticket and reloads the track and checkpoint;
2. verifies that the persisted checkpoint is still the predecessor examined by
   this invocation;
3. re-evaluates the track's current status under the lock;
4. when the Ticket CVE has qualifying evidence and the track is still
   `ANALYSIS` or `AFFECTED`, calls
   `package_service.set_track_status(...)` with the complete semantic locator,
   `FIXED`, and `acting_user_id=None`;
5. when no qualifying evidence exists, or the current track status is already
   final, leaves affectedness unchanged; and
6. creates or advances the checkpoint to the examined current expanded
   `srcmd5`, then commits once.

The status mutation, its service-owned `track_status_changed` event, Ticket
status reconciliation, and checkpoint advancement are atomic. If any one of
them fails, all local effects for that track roll back and the old checkpoint
remains. The detector never creates a second audit event.

If the Ticket moved to `Ignored` or `Duplicated` before the local transaction,
the package-service operability guard rejects the mutation; the track fails and
retains its old checkpoint. A track selected while active may still complete a
factual update after a concurrent transition to `Resolved`, consistent with the
operable-Ticket mutation and in-flight catch-up contracts.

If the track no longer exists, no longer belongs to the expected Ticket/package
scope, or has lost its Ticket CVE association, the reconciliation fails and no
checkpoint advances. If its status became `NOT_AFFECTED`, `FIXED`, or
`WONT_FIX`, the package service returns the protected no-op result; successful
examination advances the checkpoint without changing status, assigning,
reconciling, or creating an audit event. This prevents old evidence from
overriding a later VA decision if the track subsequently returns to a non-final
status. A `rejected` result is a local workflow failure and does not advance the
checkpoint; this is defensive, because this detector always requests `FIXED`.

### Checkpoint Concurrency

Periodic polling, catch-up, RabbitMQ processing, and retries must not regress a
checkpoint or mark source state as examined by failed local work.

Each local outcome is conditional on the checkpoint predecessor captured for
its external comparison. Concurrent handlers for the same track either
serialize or use an equivalent conditional write. If another handler has
already changed the predecessor:

- equality with the proposed current `srcmd5` is an already-completed no-op;
- otherwise the stale handler must not write its result or overwrite the newer
  checkpoint. It re-evaluates from the new predecessor outside the Ticket lock,
  or reports that track as failed so an event, manual run, catch-up, or the next
  scheduled run retries it.

A worker that fetched an older source state can therefore never overwrite a
checkpoint accepted by another worker. No distributed lock, Redis guard, or
generic progress table is required. No IBS call, Redis operation, or task
enqueue occurs while a Ticket lock is held.

## First Observation and VA Correction

A new track has no checkpoint. Its first check compares `orev=0` with the
current expanded source state and evaluates only its parent Ticket CVE. A fix
that predates Ticket or package-tree creation can therefore set the represented
track to `FIXED` without turning track release detection into a CVE discovery
pipeline.

A VA may later change an automatically `FIXED` track back to `AFFECTED` or
`ANALYSIS` when the evidence was insufficient. The checkpoint remains at the
source state that produced the automatic result:

- if IBS source state is unchanged, no old reference is reapplied;
- when a later expanded source state appears, the diff from the saved
  checkpoint may contain new `added` or `changed` evidence and set the track to
  `FIXED` again.

No override boolean, evidence timestamp, or audit-history reconstruction is
used.

## Unavailable History Fallback

When IBS authoritatively reports that the persisted checkpoint revision is no
longer available:

1. emit a sanitized `ibs_track_release_history_unavailable` warning with
   `codestream`, `package_name`, `track_id`, and `reason_category`;
2. request a new expanded diff from `orev=0` to the same current `srcmd5`;
3. evaluate only the existing Ticket CVE under the ordinary issue rules; and
4. accept the current `srcmd5` only after the per-track local outcome completes.

Fallback success is a recovered reconciliation, not a failed item. Fallback
failure leaves the previous checkpoint unchanged and fails the track.

The exact IBS status and sanitized error shape that distinguish unavailable
history from other 400/404 responses must be verified against a representative
live response before implementation. Until that discriminator is verified, an
ambiguous 400/404 is an ordinary failure and must not invoke fallback.

`orev=0` identifies references present in current source, not when they first
appeared. Consequently, if a VA corrected `FIXED` and the saved historical
revision later becomes unavailable, fallback can interpret the retained old CVE
reference as current evidence and set the track to `FIXED` again. This
conservative ambiguity is accepted and made observable by the warning above.

## RabbitMQ Package-Commit Acceleration

A `suse.obs.package.commit` message is a wake-up hint, not source revision
authority. The package-commit path uses the event's validated project and
package identity only to select existing eligible tracks with the exact same
`TicketPackageTrack.reference` and `TicketPackage.package_name`. It then obtains
authoritative current `srcmd5` through source info and invokes the shared
reconciliation boundary.

An event package with no exact represented Sentinel package is ignored. This
includes related packages and internal linked targets such as snapshot package
names. Sentinel does not perform reverse-link fan-out. A target change that
affects the expanded state of a represented logical linked package is still
detected by the next scheduled source-info check, with ordinary latency of up
to 24 hours.

The package-commit path does not consume event `srcmd5`, does not rely on event
`rev`, and cannot regress a checkpoint when messages are duplicate or out of
order. Message acknowledgment and consumer retry/lifecycle behavior remain
owned by `../integrations/ibs-rabbitmq-integration.md`.

## Catch-Up

`DetectIbsTrackReleases.catch_up(ticket_id, session)` is a custom non-CVE
catch-up under the shared `BaseFetcher` contract. After package-tree
re-resolution has attempted its units, catch-up selects the specified Ticket's
existing IBS tracks in `ANALYSIS` or `AFFECTED` whose parent Ticket has a CVE,
and invokes the same per-track checkpoint algorithm:

- a track without a checkpoint uses `orev=0`;
- a track with an equal current checkpoint is a no-op;
- a changed or unusable checkpoint follows the ordinary diff or fallback path;
  and
- each track is an independent transaction unit.

Per-item failures are logged and processing continues. Partial success returns
normally; when every selected track fails, `catch_up()` propagates according to
the shared `run_catch_up` contract. Duplicate catch-up and concurrent periodic
or event processing are safe under the checkpoint concurrency rules.

The next scheduled fetcher run retries failed eligible tracks. An administrator
can accelerate a full retry through the existing generic manual fetcher trigger.
No detector-specific endpoint or durable catch-up progress state is introduced.

## XML and Response Safety

The IBS client's incremental parsing, DTD/entity prohibition, complete-document
validation, and no-arbitrary-cap contract are defined in
`../integrations/ibs-integration.md`. For this detector, the parser retains only
requested source-info entries and canonical labels needed by dependent tracks.
A timeout, interrupted body, malformed document, or parser failure invalidates
the affected request and leaves dependent checkpoints unchanged.

Raw XML, response bodies, credentials, issue URLs, and event user/file fields
are never written to logs. Package names, codestream names, internal track UUIDs,
HTTP status codes, and bounded reason categories may be logged.

## Error Handling

| Condition | Per-track behavior | Recovery |
|---|---|---|
| IBS transport failure, timeout, 5xx, or rate limit after shared handling | `record_failed()` once for each dependent eligible track; keep checkpoints | Later event, manual run, catch-up, or scheduled run |
| Source-info requested package missing, duplicate, malformed, or carrying an error | Fail each dependent track; valid sibling packages may continue | Same as above |
| Malformed or interrupted source-info XML | Fail every dependent track in that request | Same as above |
| Source diff HTTP or parser failure | Fail every dependent track sharing that diff | Same as above |
| Persisted history authoritatively unavailable | Warn and use `orev=0`; fail only if fallback fails | Current-state fallback, then ordinary retry |
| Ticket becomes `Ignored`/`Duplicated`, track disappears, or scope identity changes | Roll back local work and fail that track | Reactivation or later corrected invocation |
| Concurrent checkpoint predecessor changed | Already-complete no-op, re-evaluate, or fail without writing stale state | Current or later invocation |
| Status becomes final during I/O | Leave status unchanged; accept examined checkpoint | None |
| No matching CVE evidence | Leave status unchanged; accept examined checkpoint | None |

One external failure shared by multiple tracks is logged at the request level
and counts each affected track once, not once per parsing stage or retry attempt.
Known failures use bounded sanitized reason categories. Unexpected exceptions
follow `BaseFetcher` error sanitization and must not expose raw upstream data in
the public `FetcherRun.error_message`.

### Structured Logs

Detector logs use these event names and fields. Standard correlation fields are
added by the logging infrastructure and are not repeated here.

| Event | Level | Required fields | Optional fields |
|---|---|---|---|
| `ibs_track_release_source_info_failed` | WARNING | `codestream`, `affected_track_count`, `reason_category` | `http_status` |
| `ibs_track_release_package_source_invalid` | WARNING | `codestream`, `package_name`, `affected_track_count`, `reason_category` | — |
| `ibs_track_release_diff_failed` | WARNING | `codestream`, `package_name`, `affected_track_count`, `reason_category` | `http_status` |
| `ibs_track_release_issue_ignored` | WARNING | `codestream`, `package_name`, `reason_category="invalid_cve_label"` | — |
| `ibs_track_release_history_unavailable` | WARNING | `codestream`, `package_name`, `track_id`, `reason_category` | `http_status` |
| `ibs_track_release_track_failed` | WARNING | `codestream`, `package_name`, `track_id`, `reason_category` | — |

`reason_category` is a bounded internal classification, not an upstream error
string. At minimum it distinguishes transport, HTTP status, malformed XML,
interrupted response, missing package, duplicate package, upstream package
error, invalid source checksum, invalid issue structure, invalid CVE label,
history unavailable, scope changed, Ticket not operable, stale checkpoint, and
database/audit failure. Shared request failures produce one request-level log;
the metric still counts each affected track once. The detector does not log raw
CVE label text when it is invalid.

## Background Fetcher

### Fetcher: `detect_ibs_track_releases`

| Property | Value |
|---|---|
| Fetcher name | `detect_ibs_track_releases` |
| Class name | `DetectIbsTrackReleases` |
| Base class | `BaseFetcher` |
| Description | Reconcile existing active-Ticket IBS tracks against expanded package source state |
| Schedule | Daily at 02:00 UTC (`0 2 * * *`) |
| Source | IBS HTTP API (`IBS_API_URL`) |
| Scope | Existing IBS tracks in `ANALYSIS` or `AFFECTED` under active Tickets with a CVE; exclusions, EOL, and actionability do not narrow scope |
| Auth | Configured IBS HTTP Basic/API-token credentials |
| `participates_in_catch_up` | `True` — custom per-Ticket catch-up |
| Custom settings | None |

### Metrics and Run Status

- `record_created()` is never called. The detector creates no domain record.
- `record_updated()` is called once for each track effectively transitioned to
  `FIXED` by this invocation.
- `record_failed()` is called at most once for each selected track whose
  reconciliation did not complete. Shared request failures count every affected
  track once because the track is the reconciliation unit.
- Every `no_op` outcome, including unchanged source, valid no-match,
  final-status race, checkpoint-already-advanced, and repeated idempotent work,
  leaves created and updated unchanged.

Fetcher status follows the shared `BaseFetcher` precedence. In particular, a
normal return with failures and no effective track transitions is `failure`
under the all-items-failed metric rule, even when other examined tracks were
successful no-ops. Failures plus at least one effective transition produce
`partial`; no failures produce `success`.

## Audit and Transaction Guarantees

The only detector-triggered Ticket audit event is the
`track_status_changed` event created by `package_service.set_track_status()` for
an effective transition. It has `user_id = NULL`, the true old status and
`FIXED` as values, `comment = NULL`, and the standard track/package `detail`.

Checkpoint creation, advancement, equality, fallback, and failure create no
Ticket audit event. Audit history is never read as current checkpoint or VA
override state.

## Testing Requirements

Future implementation tests must cover:

- strict active-Ticket, CVE-present, and `workflow_type = ibs` selection;
- no Ticket/package/track/Product creation and no call to
  `add_package_to_ticket()`;
- first observation from `orev=0`, equal-checkpoint no-op, and ordinary
  incremental comparison;
- linked package expanded `srcmd5`, required `expand=1`, and ignored
  unrepresented linked-target events;
- `added`, `changed`, `deleted`, `bnc`, other tracker, invalid label, duplicate,
  empty, and multi-CVE diff outcomes;
- missing, duplicate, error-bearing, and malformed source-info entries;
- malformed, interrupted, and safely streamed XML with DTD/entity expansion
  disabled;
- unavailable-history fallback, fallback failure, and the documented VA
  correction ambiguity;
- preservation of a VA `FIXED` to `AFFECTED`/`ANALYSIS` correction until new
  source evidence;
- one atomic status/audit/Ticket-reconciliation/checkpoint transaction and
  rollback when any local step fails;
- independent sibling success, exact metrics, and inherited run statuses;
- concurrent polling, catch-up, event, and retry anti-regression using
  independent database sessions;
- status and Ticket-state races under the Ticket lock;
- no external HTTP, Redis, or task publication while a Ticket lock is held;
- exactly one service-owned audit event for an effective transition and none
  for checkpoint-only or idempotent outcomes; and
- sanitized logs and public fetcher errors with no raw response, credential, or
  personal data.

## External Contract Verification

Verified behavior and remaining implementation gates are summarized in
`../integrations/ibs-integration.md` and `../../data-sources.md`. Before parser
implementation, retain a sanitized live fixture for every consumed source-info
and diff shape. The exact unavailable-history discriminator remains unverified.

Sanitized aggregate verification on 2026-09-08 covered 9,620 deployed
`suse.obs.package.commit` deliveries. Every delivery had non-empty string
`project` and `package` values, every observed `rev` was a string, no payload
contained `srcmd5`, and 3,000 deliveries repeated a previously observed
byte-equivalent payload. This closes the package-commit parser evidence gate.
The detector consumes only `project` and `package`; the event remains a wake-up
hint, while source info supplies authoritative current `srcmd5`. Event `rev`,
delivery order, and duplicate delivery are not checkpoint authority.

## Cross-references

- `package-model.md` — workflow scope, active Tickets, release dimensions,
  reactivation, and checkpoint safety
- `package-service.md` — status mutation, Ticket locking, audit ownership, and
  Ticket reconciliation
- `../integrations/ibs-integration.md` — IBS HTTP and XML contracts
- `../integrations/ibs-rabbitmq-integration.md` — package-commit acceleration
  and consumer lifecycle
- `../platform/fetcher-infrastructure.md` — `BaseFetcher`, catch-up, metrics,
  manual triggering, and error sanitization
- `../platform/networking.md` — HTTP timeout, retry, and TLS behavior
- `../platform/testing-strategy.md` — integration and concurrency testing
- `../tickets/ticket-audit-log.md` — `track_status_changed` field contract
- `../../data-model.md` — `TrackReleaseCheckpoint` schema
