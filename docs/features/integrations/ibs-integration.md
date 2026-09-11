# OBS / IBS Integration

## Purpose

Integration with Open Build Service instances for package source monitoring,
maintenance-request tracking, and release detection. Sentinel interacts with
two separate OBS instances:

- **IBS** (Internal Build Service, `build.suse.de`): used for SUSE commercial
  products. This is the primary integration for codestream-level release
  detection.
- **OBS** (public, `build.opensuse.org`): used for openSUSE distributions.
  Not currently integrated — see Future Considerations.

## IBS Integration

### Workflow boundary

Sentinel invokes IBS package, source, diff, request, and repository operations
only for package-tree occurrences whose persisted parent
`TicketPackageTrack.workflow_type` is `ibs`. `TicketPackageTrack.reference` is
not sufficient evidence: it may instead identify a Git branch. An IBS consumer
MUST filter by the workflow discriminator before passing the reference as an
IBS project. Git tracks receive no IBS source checksum, diff, request
correlation, RabbitMQ-driven mutation, or IBS release mutation.

Product-level IBS repository processing qualifies each
`TicketPackageProduct` through its parent IBS track. The same catalog Product
below a Git track is outside IBS scope. Package maintainership is not an IBS
consumer: Sentinel obtains it exclusively from SMELT for both IBS and Git/SLFO
package occurrences.

The complete active-ticket, Ticket-convergence, acceleration, and recovery ownership
contract is defined in `docs/features/packages/package-model.md` (IBS Workflow
Applicability and Convergence).

### Origins and Authentication

- The IBS API at `IBS_API_URL` uses HTTP Basic Auth or API tokens.
  `IBS_USERNAME` and `IBS_PASSWORD` are stored as environment variables, never
  in code. Empty or unset credentials do not block application startup;
  credentialed IBS API consumers fail at runtime.
- `IBS_DOWNLOAD_BASE_URL` is a separate anonymous HTTPS Product-repository
  front door (default: `https://download.suse.de/ibs`). Product release
  detection does not send IBS API credentials, an `Authorization` header, or
  another credential to the download front door or its permitted redirect
  target. Its complete validation, path, and redirect contract is defined in
  `docs/features/packages/ibs-product-release-detection.md`.

### Key API Operations

The following credentialed IBS API endpoints are used by Sentinel for
codestream-level release detection (see
`docs/features/packages/ibs-track-release-detection.md`) and submission request
tracking (see `docs/features/packages/ibs-submission-tracking.md`). Product-level
release detection uses the separate anonymous repository-download boundary
below, not these API endpoints.

#### Project Source Info

```
GET /source/{project}?view=info&nofilename=1&package={package}...
```

Returns an XML document with one `<sourceinfo>` element for each selected
package. The `package` query parameter is repeatable. Track release detection
requests only logical package names already represented by eligible Sentinel
tracks; it does not enumerate an entire project. `nofilename=1` avoids recipe
and filename processing that is unrelated to release observation.

Consumed fields:

- `package` — requested logical source package name;
- `srcmd5` — checksum of the current **expanded** source tree;
- optional `lsrcmd5` — local link revision, used only as link context; and
- optional `linked` children — source packages contributing to the expanded
  state, used only as link context.

`verifymd5`, `lsrcmd5`, and revision numbers are not persisted release
checkpoints. For a linked package, `srcmd5` can change when a target changes
even if `lsrcmd5` remains unchanged.

Example response:

```xml
<sourceinfolist>
  <sourceinfo package="fictional-package"
              srcmd5="0123456789abcdef0123456789abcdef"
              lsrcmd5="fedcba9876543210fedcba9876543210">
    <linked project="SUSE:SLE-15-SP6:Update"
            package="fictional-package.snapshot"/>
  </sourceinfo>
</sourceinfolist>
```

The response must be well-formed and completely consumed. Each requested
package must appear exactly once with a 32-character hexadecimal `srcmd5` and
without an upstream `error` child. A missing requested entry, duplicate entry,
malformed required field, or error-bearing entry makes that package unusable;
dependent tracks fail without advancing their checkpoints. Valid sibling
packages may continue when the parser can isolate the invalid entry. Malformed
or interrupted XML invalidates the complete request. Unrequested entries are
ignored and never create detector scope.

#### Source Diff with Issue Extraction

```
POST /source/{project}/{package}?cmd=diff&view=xml&onlyissues=1&expand=1&orev={old_md5_or_0}&rev={new_md5}
```

Returns an XML document listing structured issue-reference changes between
two expanded source states. `onlyissues=1` asks IBS to extract issue references
from the source changes. `expand=1` is required so linked packages are compared
using their expanded source trees. `orev=0` represents an empty source tree and
is used for a track's first observation and unavailable-history fallback.

Example response:

```xml
<sourcediff>
  <issues>
    <issue tracker="cve" name="2025-1234" label="CVE-2025-1234" state="added"/>
    <issue tracker="bnc" name="1234567" state="added"/>
    <issue tracker="cve" name="2024-9999" label="CVE-2024-9999" state="changed"/>
  </issues>
</sourcediff>
```

Parameters:
- `orev` — the previous expanded `srcmd5`, or `0` for an empty source tree
- `rev` — the current expanded `srcmd5`

For track release detection, only `tracker="cve"` with `state="added"` or
`state="changed"` enters CVE matching. `label` is the canonical CVE identity;
`name` is tracker-native and is not used as a CVE ID. `state="deleted"`, `bnc`,
and every other tracker are ignored. A malformed canonical CVE label is logged
with bounded sanitized context and ignored; it is never interpreted as a CVE.

The complete XML document must parse successfully before dependent local
outcomes are committed. A malformed or interrupted response fails every track
depending on that diff. A valid empty issue set is a successful no-match.

IBS can return 400 or 404 when a historical revision is unavailable. Before
implementation, a representative live response must establish the exact
status/body discriminator that distinguishes unavailable history from malformed
input, authorization failure, or another client error. Only a positively
identified unavailable-history response permits the detector's `orev=0`
fallback; an ambiguous 4xx is an ordinary failure.

Both source-info and source-diff XML are processed incrementally with DTDs,
external entities, and parser network access disabled. Sentinel does not impose
an arbitrary response-byte or issue-count cap, but never accepts a truncated or
partially parsed document. The shared request and fetcher-run timeouts remain
the execution bounds.

#### Track-Release Contract Verification Status

Sanitized read-only verification against IBS on 2026-09-03 established:

- source-info supports repeatable package selection and
  `view=info&nofilename=1`;
- `srcmd5` is the expanded source state, while linked packages may also expose
  a distinct local `lsrcmd5` and `linked` elements;
- linked-package source diffs require `expand=1` to expose the relevant
  structured issues;
- `orev=0` is accepted as an empty source tree;
- source diff entries expose `tracker`, `state`, tracker-native `name`, and
  canonical `label`, including empty, mixed-tracker, multi-CVE, `added`,
  `changed`, and `deleted` results; and
- unavailable historical references can produce 400 or 404, depending on the
  reference form.

OBS source inspection established that `added`, `changed`, and `deleted`
describe changes to issue references extracted from package changes files. The
exact sanitized IBS error discriminator for an unavailable historical checksum
is still unverified and remains the implementation gate stated above.

#### Request ID Search

```text
GET /search/request/id?match={typed_narrow_predicate}
```

This ID-only search is the request-discovery operation. Sentinel constructs the
XPath predicate from typed exact values; callers never supply arbitrary XPath.
The supported predicate inputs are:

| Input | Required | Contract |
|---|---|---|
| `action_type` | Yes | Exact `maintenance_incident` or `maintenance_release`. |
| `states` | No | Non-empty subset of the seven request states below. |
| `source_project` | No | Exact source project. Used for incident-scoped RR discovery. |
| `source_packages` | No | Non-empty collection of exact physical source-package names. |
| `source_package_prefix` | No | Non-empty prefix used only to propose SR candidates. |

At least one source-project or source-package constraint is required. The two
approved searches are:

- open SR discovery: `maintenance_incident`, states `new` and `review`, and an
  exact retained physical source package or a prefix rooted in
  `{logical_package}.`; and
- incident-scoped RR discovery: `maintenance_release` and the exact incident
  source project.

`source_project`, `source_packages`, and `source_package_prefix` are alternative
search shapes rather than broadening options: one call supplies exactly one of
them. Multiple exact `source_packages` are ORed within that predicate; action
type and each supplied state are combined with the package predicate so only
the requested action/state/package shape can match. The caller uses the prefix
shape only when retained exact physical package identities are insufficient.

The response is an XML collection with a required non-negative `matches` count
and zero or more positive request IDs. The result is complete only when every
entry is structurally valid, IDs are distinct, and the returned count equals
`matches`. A count mismatch, malformed successful response, or ambiguous
candidate set is incomplete evidence, never a negative result. The client does
not need to distinguish an upstream result-limit rejection from another
non-authentication search rejection: after shared rate-limit handling, any 4xx
from this read-only search except `401` or `403` is an incomplete
`RequestEvidenceResult`. Authentication and authorization failures propagate as
HTTP errors. The endpoint has no offset-pagination contract.

Every returned ID is point-fetched. A source-package prefix proposes candidates
but does not establish logical package identity. The detail must validate the
exact action, physical package mapping, and codestream. In particular, Sentinel
does not include `target/@releaseproject` in the search predicate because the
deployed search engine rejects that predicate; it validates the field from
point detail instead.

`GET /request?view=collection` may apply `limit` and `offset` without a stable
ordering. Sentinel MUST NOT use it as a global scan, a pagination cursor, or
proof that no request exists. The old `project={codestream}` collection query
does not discover actions whose codestream is represented by
`target/@releaseproject` and is not part of the submission-tracking contract.

#### Request Point Detail

```text
GET /request/{request_number}
```

`request_number` is a positive public IBS request number. The response root is
one `<request>` whose positive `id` must equal the requested number. It contains
exactly one current `<state>` and zero or more repeated `<action>` elements.
The parser completely consumes the document and returns typed parent and action
values; it never returns XML elements.

Required parent fields:

| XML field | Typed field | Contract |
|---|---|---|
| `request/@id` | `request_number` | Positive integer equal to the point-lookup input. |
| `state/@name` | `state` | Exactly `new`, `review`, `accepted`, `declined`, `revoked`, `superseded`, or `deleted`. |
| `state/@created` | `upstream_created_at` | IBS request creation timestamp. |
| `state/@when` | `upstream_updated_at` | Timestamp of the current IBS state. |
| `state/@superseded_by` | `superseded_by_request_number` | Required positive number different from the request number only for `superseded`; omitted for every other state. |

IBS emits request timestamps as offset-less `YYYY-MM-DDTHH:MM:SS`. Sentinel
interprets those values as UTC and produces timezone-aware UTC datetimes. An
explicitly offset value, if supplied, is normalized to UTC. An invalid date,
unknown state, missing required state field, response ID different from the
requested number, or invalid supersession relationship invalidates the detail.
A declined request may later point-return `new` or `review`; the point detail is
current-state authority.

Sentinel consumes these action shapes:

| Action | Required fields | Optional, omitted fields |
|---|---|---|
| `maintenance_incident` | `action/@type`, `source/@project`, `source/@package`, `target/@releaseproject` | `source/@rev`, `target/@project`, `target/@package`, and `acceptinfo` fields |
| `maintenance_release` | `action/@type`, `source/@project`, `source/@package`, `target/@project`, `target/@package` | `source/@rev`, `target/@releaseproject`, and `acceptinfo` fields |

When `<acceptinfo>` is present, Sentinel consumes optional non-empty `rev` and
optional 32-character hexadecimal `srcmd5` and `xsrcmd5` attributes. Other
acceptinfo attributes are not consumed. Missing optional elements or attributes
are represented as absent typed values, not empty strings. Omission can make
provenance incomplete, but it is not by itself malformed response data. Unknown
elements and attributes and known non-maintenance action types such as `delete`
and `patchinfo` are ignored. An unrecognized action type makes the request
observation incomplete. A supported action with a missing or malformed required
field also makes the observation incomplete; a known non-maintenance action
never becomes a Sentinel request action.

Action order and the RabbitMQ-only `action_id` are not identities. The durable
semantic identities recoverable from point detail are:

- maintenance incident: request number, action type, source project, source
  package, and target release project; and
- maintenance release: request number, action type, target project, and target
  package.

For an accepted incident action, `target/@project` may change to the incident
project and `target/@package` may appear, so neither belongs to that action's
identity. A changed semantic identity is an old action no longer present plus a
new action; Sentinel does not infer continuity from order or mutable fields.
Author, actor, review, comment, description, and other free-text fields are not
consumed, persisted, returned, or logged.

A 404 point response means only that detail is unavailable. It cannot
distinguish an upstream `deleted` request from retention, visibility, or a
number that never existed. It therefore produces an incomplete-evidence outcome
and never synthesizes `state = deleted` or erases retained state. Sentinel
persists `deleted` only when a valid detail explicitly returns it.

Supersession is traversed from an explicit `superseded_by` value using repeated
point lookups. The caller keeps a visited request-number set. A cycle, invalid
successor, successor 404, or otherwise incomplete successor detail makes the
chain incomplete and preserves prior local state; it is never a complete
negative observation.

#### Action-Scoped Request Diff

```text
POST /request/{request_number}?cmd=diff&withissues=1&view=xml
```

This POST is semantically read-only. The root is `<request>`, and each repeated
`<action>` independently contains its own optional `<sourcediff>`. The parser
matches each supported diff action to point detail by the semantic identity
above; it never combines issue references across actions or uses array
position. An unrelated action may validly have no `<sourcediff>`.

Example, with fictional identifiers:

```xml
<request id="410001">
  <action type="maintenance_incident">
    <source project="home:fictional" package="fictional-package.SUSE_SLE-15-SP6_Update"/>
    <target releaseproject="SUSE:SLE-15-SP6:Update"/>
    <sourcediff>
      <issues>
        <issue tracker="cve" name="2026-1234"
               label="CVE-2026-1234" state="changed"/>
        <issue tracker="bnc" name="1234567" state="added"/>
      </issues>
    </sourcediff>
  </action>
</request>
```

Each consumed issue requires non-empty `tracker` and `state`. For correlation,
positive evidence requires `tracker="cve"`, `state="added"` or
`state="changed"`, and a canonical CVE identity in `label`. `name` is
tracker-native and is never reinterpreted as a CVE ID. `deleted`, `bnc`, and
other trackers are not positive evidence. `changed` is positive because a later
SR can replace incident contents while retaining an existing CVE reference.
An otherwise structural issue with a missing or malformed canonical `label` is
ignored as a non-qualifying issue and logged with bounded sanitized context; it
does not invalidate an otherwise complete action diff.

A completely parsed action diff with no qualifying issue is a successful
no-match for that action. A missing diff is acceptable for an action that does
not require one, but is incomplete evidence when correlation or effective
contents depend on it. A malformed, interrupted, unmatched, or partially parsed
required action diff, and every 404 diff response, is incomplete evidence. None
deletes or invalidates retained request/action history.

#### Package Source History

```text
GET /source/{project}/{package}/_history?rev={revision}
GET /source/{project}/{package}/_history?limit={limit}[&startbefore={revision}]
```

Source history supplies request provenance for incident and codestream package
contents. `project` and `package` are non-empty exact identities. Exact-revision
lookup uses a non-empty `rev`. Backward traversal uses a positive bounded
`limit` and optional non-empty `startbefore`; exact `rev` and traversal controls
are mutually exclusive.

The response is a completely consumed `<revisionlist>`. Each consumed
`<revision>` requires:

| Field | Contract |
|---|---|
| `rev` | Non-empty revision identity. |
| `srcmd5` | 32-character hexadecimal source checksum. |
| `time` | Non-negative Unix seconds, converted to an aware UTC datetime. |
| `requestid` | Optional positive public request number; omission is preserved as absence. |

Traversal follows `startbefore` backward until the available history is
exhausted. Every non-empty page must make strict revision progress; duplicates,
loops, conflicting repeated revisions, malformed entries, or a page that does
not advance make the observation incomplete. An exact revision not returned,
a 404, or unavailable required older history is an unavailable-history outcome,
not an empty successful match.

For submission delivery, history and point-detail provenance are compared
exactly. The required proof is:

```text
effective SR acceptinfo.xsrcmd5
    == accepted RR action source.rev
    -> RR state is accepted
    -> RR acceptinfo revision/srcmd5
    == target package history revision/srcmd5 with the RR requestid
```

Missing `acceptinfo`, a direct source change without `requestid`, unavailable
history, or a checksum/revision mismatch is incomplete evidence and preserves
the prior delivery state. Current patchinfo, binary, or advisory data may
discover or corroborate candidates but does not replace this provenance chain
and does not mutate Product release state.

#### Request Contract Verification Status

Sanitized read-only verification and deployed OBS source inspection on
2026-09-08 established the point-detail, ID-search, request-diff, timestamp,
state, semantic-identity, source-history, and provenance shapes above. In
particular:

- requests are multi-action parents and event action arrays are not complete;
- point detail exposes no stable action ID or action-order identity;
- the exact seven states include `deleted`, while declined requests may reopen;
- offset-less request timestamps represent UTC;
- narrow ID search reports a total without stable global offset pagination;
- request diffs place issue evidence under individual actions and expose
  canonical `issue.label`; and
- source history exposes revision, checksum, Unix time, and optional request ID.

IBS does not guarantee indefinite retention of detail, diff, or source history.
The resulting unavailable-evidence outcomes are part of the contract, not an
authorization to infer a negative result.

### Data Model

IBS-related data is stored in the following tables (see `docs/data-model.md`):

- `TrackReleaseCheckpoint`: operational state storing the last expanded
  `srcmd5` successfully examined for one `TicketPackageTrack`. At most one row
  exists per track. Polling, catch-up, and package-commit acceleration share
  this state without using it as Ticket audit history. See
  `docs/features/integrations/ibs-rabbitmq-integration.md`.
- `IBSRequest`: one retained request parent identified by its positive public
  request number, with the exact seven-state IBS value, optional superseding
  request number, upstream UTC timestamps, and separate local row timestamps.
- `IBSRequestAction`: one typed `maintenance_incident` or
  `maintenance_release` action. It stores the source, target, release-project,
  logical-package, codestream, incident, revision, and acceptinfo fields needed
  for semantic identity, correlation, and provenance. It does not store event
  action IDs, array positions, authors, actors, comments, descriptions, or raw
  payloads.
- `IBSRequestActionTrack`: the unique correlation between one exact request
  action and one exact `TicketPackageTrack`. Both SR and RR actions use this
  relationship.
- `TicketPackageTrack.reference`: stores the IBS project name
  (e.g., `SUSE:SLE-15-SP6:Update`) as a string. Tracks are not
  maintained as a separate table.
- `ProductRepository.repo_name`: stores SMELT repository project names
  that map to anonymous IBS Product repository URLs. Used by
  `detect_ibs_product_releases`.

### Service Layer

#### IBSClient (`backend/app/services/ibs_client.py`)

Dedicated client for IBS API communication. Separate from any potential
future `OBSClient` for the public OBS instance, since they would have
independent credentials and may diverge in API behavior.

Methods:

- `get_source_info(project: str, packages: Collection[str]) -> Mapping[str,
  SourceInfoResult]`: calls targeted
  `GET /source/{project}?view=info&nofilename=1` with one repeatable `package`
  parameter per requested logical package. It returns one validated expanded
  `srcmd5` result or one explicit validation failure per requested package;
  malformed document-level XML raises an IBS response-data error for the whole
  call. An empty package collection is rejected without an HTTP request.
- `get_diff_issues(project: str, package: str, old_md5: str,
  new_md5: str) -> list[DiffIssue]`: calls the source diff endpoint with
  `expand=1` (`old_md5` is either a 32-character expanded checksum or the
  literal string `"0"`), parses the complete XML response, and returns structured issue
  fields sufficient for the detector to evaluate `tracker`, `state`, and
  `label`. It does not reinterpret `bnc` names as CVE IDs. A positively
  identified unavailable `old_md5` raises a distinct internal condition used
  by the detector's fallback; every other HTTP or response-data failure remains
  distinct from successful empty results.
- `search_request_ids(action_type: IBSRequestActionType, *, states:
  Collection[IBSRequestState] | None = None, source_project: str | None = None,
  source_packages: Collection[str] | None = None, source_package_prefix: str |
  None = None) -> RequestEvidenceResult[RequestIdSearchResult]`: calls the
  ID-only search with an internally constructed narrow predicate. It rejects
  unsupported action types, empty state/package collections, calls without a
  source-project or source-package bound, and calls supplying more than one of
  `source_project`, `source_packages`, or `source_package_prefix` before HTTP
  I/O. A complete result contains distinct positive request numbers and the
  reported match count.
- `get_request(request_number: int) ->
  RequestEvidenceResult[IBSRequestDetail]`: point-fetches one positive request
  number. A complete result contains the typed parent plus every supported
  typed action exposed by the complete REST detail. It validates the exact
  seven-state value, UTC timestamp interpretation, state/supersession
  relationship, action-required fields, and semantic action identities. A
  detail 404 is an incomplete result rather than a synthetic deleted state.
- `get_request_action_diffs(request_number: int, expected_actions:
  Collection[RequestActionIdentity]) ->
  RequestEvidenceResult[Mapping[RequestActionIdentity, RequestActionDiff]]`:
  calls the semantically read-only request-diff POST and completely parses the
  request and each action-scoped diff. `expected_actions` is the non-empty set
  obtained from current point detail. A complete result returns typed issues
  keyed by those semantic identities and preserves `tracker`, `state`, `name`,
  and `label` for the owning reconciliation to evaluate. It does not merge
  issues across actions or filter out `changed` evidence. An expected action
  missing, duplicated, or unmatched in the diff is an incomplete result.
- `get_source_history_page(project: str, package: str, *, revision: str | None =
  None, limit: int | None = None, start_before: str | None = None) ->
  RequestEvidenceResult[SourceHistoryPage]`: performs either exact-revision
  lookup or one bounded backward page. It rejects empty identities, non-positive
  limits, mixed exact and traversal controls, and `start_before` without
  `limit` before HTTP I/O. A complete result contains typed revision, checksum,
  UTC time, and optional request-number entries. The caller repeats bounded
  pages until exhaustion and enforces strict backward progress as specified
  above.

All result and nested values are typed internal records rather than raw XML
elements. `IBSRequestState` has exactly `new`, `review`, `accepted`, `declined`,
`revoked`, `superseded`, and `deleted`; `IBSRequestActionType` has exactly
`maintenance_incident` and `maintenance_release`. A `SourceInfoResult` contains
either one validated `SourceInfo` or one bounded package-validation reason,
never both. A `RequestEvidenceResult[T]` contains either one complete typed
value or one bounded incomplete-evidence reason, never both. An incomplete
result is not an exception and is not a successful negative observation.

The methods have these escaping outcomes:

| Condition | Signal to caller |
|---|---|
| Invalid or empty method input, including an unbounded request search or invalid source-history control combination | `ValueError` before HTTP I/O |
| Transport failure, timeout, rate limit, or HTTP error other than an operation-specific incomplete-evidence response after shared retry handling | The corresponding `httpx` exception propagates with the response body excluded from application logs |
| Malformed/interrupted source-info or source-diff XML, or its document-level schema failure | `IBSResponseDataError` |
| One requested source-info package missing, duplicated, error-bearing, or carrying an invalid `srcmd5` | A per-package failed result in the returned mapping; valid sibling package results remain usable |
| Source diff old revision positively identified as unavailable | `IBSHistoricalRevisionUnavailable` |
| Source diff contains an issue with an unusable structural shape | `IBSResponseDataError` |
| Source diff is valid and contains no qualifying issue | Empty list |
| Request ID search reports inconsistent successful-response completeness or leaves candidate identity ambiguous | Incomplete `RequestEvidenceResult` |
| Request ID search receives a non-authentication 4xx after shared rate-limit handling, including an upstream result-limit or predicate rejection | Incomplete `RequestEvidenceResult`; it never proves a negative |
| Request detail is 404, has an unknown state or action type, has an invalid supersession relationship, or omits a required supported-action field | Incomplete `RequestEvidenceResult` |
| Request detail contains only known non-maintenance actions | Complete typed parent with an empty supported-action collection |
| Required request action diff is 404, absent, unmatched, malformed, or partial | Incomplete `RequestEvidenceResult`; retained correlation and delivery evidence is not invalidated |
| Required source-history revision/page is 404, unavailable, non-progressing, conflicting, or malformed | Incomplete `RequestEvidenceResult` |
| Request action diff is complete and has no positive `added` or `changed` canonical CVE issue for an action | A valid typed action diff with no qualifying issue; the owning reconciler treats it as that action's successful no-match |

`IBSResponseDataError` and `IBSHistoricalRevisionUnavailable` are internal
integration exceptions caught by the Track detector; they never reach an API
handler. Submission reconciliation consumes incomplete `RequestEvidenceResult`
values and preserves prior request, action, correlation, and delivery state for
that scope. It does not convert unavailable evidence into a no-match.
`IBSHistoricalRevisionUnavailable` is emitted only after the live status/body
discriminator required above has been verified. Until then, an ambiguous
source-diff 400/404 remains the original HTTP error.

All request-search, point-detail, request-diff, and source-history XML uses the
same incremental parsing safety boundary as source release data: DTDs, external
entities, and parser network access are disabled, and no result is accepted
until the complete document has parsed. Raw XML, response bodies, actor data,
and free text never enter logs. A parser or interrupted-body failure produces
the error or incomplete result assigned to that operation above.

Every method is deterministic for one complete response and has no local or
upstream mutation side effect. Re-invocation repeats the external read and may
observe newer IBS state. Repeated identical issue references are equivalent to
one issue. Duplicate or conflicting parent, semantic-action, or history
identities make request evidence incomplete under the operation-specific rules.
No method writes PostgreSQL, Redis, Celery, RabbitMQ, or IBS, and none creates
an audit event. Persistence, delivery derivation, transaction ownership, and
recovery belong to `ibs-submission-tracking.md` and the release-detector
specifications.

Configuration is injected via the application settings (`IBS_API_URL`,
`IBS_USERNAME`, `IBS_PASSWORD`).

**HTTP client infrastructure**: `IBSClient` uses the standalone HTTP
client factory (`backend/app/services/http_client.py`) directly, with
the following overrides:

- `Accept: application/xml` (IBS API returns XML, not JSON)
- TLS validated against the SUSE Trust Root CA via the combined trust
  store (see `networking.md`, TLS Trust Store
  Configuration)
- Transport-level retry active (4 attempts for 5xx/timeout/connection
  errors)
- Long-lived client: instantiated per-process, not per-request

#### Product Repository Download Boundary

`detect_ibs_product_releases` uses the shared `BaseFetcher` HTTP client for
anonymous GET requests rooted at `IBS_DOWNLOAD_BASE_URL`; it does not use
`IBSClient`. It requests and validates:

- `repodata/repomd.xml`: exact repomd namespace, one optional updateinfo data
  entry, artifact location, compressed/open checksums and sizes, and metadata
  timestamp; and
- the selected `updateinfo.xml.gz`: one bounded gzip member containing the
  complete no-namespace `updates` document, stable security advisory fields,
  exact CVE references, issued Unix seconds, and validated `src`/`nosrc` package
  entries.

The download boundary exposes successful non-match, validated snapshot, and
bounded failure outcomes to the detector; it does not mutate local state. HTTP
404 for `repomd.xml` and valid metadata without updateinfo are successful
non-matches. Transport/HTTP, path/redirect, checksum/size, decompression,
snapshot-consistency, and XML/advisory failures remain distinguishable bounded
failure categories. The owning Product detector specification defines every
field, resource limit, path constraint, redirect rule, retry effect, and
mutation consequence; this integration overview does not redefine them.

**Retry safety for POST operations**: IBSClient's `cmd=diff` POST operations for
source and request diffs are semantically read-only; they compute a response
without modifying IBS server state. The client therefore opts these calls into
the shared retry mechanism for otherwise non-idempotent HTTP methods. A retry
has the same side-effect contract as the first attempt, although it can observe
newer upstream state. See `docs/features/platform/networking.md`
(Transport-Level Retry, Method Safety).

#### Track Release Reconciliation

`reconcile_ibs_track_releases()` reconciles supplied existing IBS track IDs by obtaining authoritative current
source info, comparing each track's own checkpoint, and applying atomic local
outcomes. The periodic fetcher, per-Ticket catch-up, and RabbitMQ package-commit
path use this same boundary. Full behavior is documented in
`docs/features/packages/ibs-track-release-detection.md`.

### Background Tasks

- `detect_ibs_track_releases`: periodic task (every 24 hours at 02:00
  UTC via Celery Beat) that invokes the `DetectIbsTrackReleases` fetcher via
  the inherited `BaseFetcher.run()` lifecycle. Its `execute()` method delegates
  to `reconcile_ibs_track_releases()`. The fetcher is a `BaseFetcher` subclass with `name`, `description`, and
  `default_schedule` attributes. Serves as a catch-up mechanism for
  events missed by the `IBSEventConsumer`. See
  `docs/features/platform/fetcher-infrastructure.md` for the BaseFetcher
  infrastructure and `docs/features/integrations/ibs-rabbitmq-integration.md` for the
  real-time consumer that complements this periodic fetcher.
- `sync_ibs_requests` (`SyncIbsRequests`): periodic task (every 24 hours
  at 02:30 UTC) that performs complete state-based request/action discovery,
  correlation, provenance, and delivery reconciliation for the finite set of
  active-Ticket IBS tracks. It has no cursor or temporal lookback setting. The
  existing generic fetcher catch-up accelerates the same reconciliation after
  package addition and Ticket convergence. Request RabbitMQ events invoke it
  inline for relevant track scopes; there is no dedicated correlation or
  discovery Celery task. See
  `docs/features/packages/ibs-submission-tracking.md`.
- `detect_ibs_product_releases`: periodic `BaseFetcher` task (daily at 04:00
  UTC) that reconciles unreleased Product occurrences through the anonymous
  Product repository download boundary. See
  `docs/features/packages/ibs-product-release-detection.md`.

### Business Rules

1. Credentialed IBS API consumers warn when IBS credentials are empty or unset;
   anonymous Product repository downloads never consume those credentials
2. IBS mutations use their owning service and audit contracts; read-only
   external operations use bounded operational logging rather than audit events
3. Track release reconciliation only modifies records with status
   `AFFECTED` or `ANALYSIS` (soft-deleted tracks in these statuses are
   still modified — see `docs/features/packages/package-service.md`,
   Package-tree exclusion and actionability)
4. Every IBS consumer selects `TicketPackageTrack.workflow_type = ibs`; a Git
   reference is never interpreted as an IBS project
5. Ordinary IBS polling covers active Tickets only. Ticket convergence first
   reconciles its package tree, then runs targeted source-specific catch-up
6. Track release detection reconciles only existing represented tracks. It
   never discovers CVEs or creates Tickets, packages, tracks, or Products
7. Request search, point detail, action diff, and source history are read-only
   evidence operations. They never create or modify an IBS request
8. Incomplete, unavailable, retention-limited, malformed, or ambiguous request
   evidence preserves previously established local request and delivery state;
   only a complete observation may prove a negative
9. Submission request reconciliation does not modify track affectedness,
   Product eligibility, or Product `released_at`; those contracts remain owned
   by their settled detectors and package services

## OBS Public Integration

### Status

Not currently integrated. There is no plan to integrate openSUSE package
tracking at this time. This may be evaluated in the future if there is
demand for tracking security updates across openSUSE distributions. If
pursued, it would be addressed in a separate specification.

The public OBS API at `api.opensuse.org` is compatible with IBS but uses
separate authentication. A dedicated `OBSClient`
(`backend/app/services/obs_client.py`) with its own credentials and
configuration (`OBS_API_URL`, `OBS_USERNAME`, `OBS_PASSWORD`) would be
needed. See `docs/data-sources.md` for details on OBS and its RabbitMQ
event bus.

## Security

- IBS and OBS credentials are managed via environment variables
- API calls are made server-side only; credentials are never exposed to
  the frontend
- Product repository downloads are anonymous and never attach or forward IBS
  API credentials
- Operations that modify IBS/OBS state (future: rebuild triggers) require
  the Vulnerability Analyst or Admin role
- XML parsers disable DTDs, external entities, and parser network access;
  authenticated response bodies are never written to logs
