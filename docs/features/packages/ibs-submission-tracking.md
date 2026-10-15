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
work. Ticket convergence invokes the targeted catch-up defined below.

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
4. Acceptance of the RR alone is not delivery evidence;
   [Accepted RR Provenance](#accepted-rr-provenance) defines when an accepted
   RR proves the release.

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
| `source_project` | VARCHAR(255) | nullable | Exact normalized action source project; a project outside the `SUSE:` namespace is stored as the fixed token below. |
| `source_package` | VARCHAR(255) | nullable | Exact normalized physical source package. |
| `target_project` | VARCHAR(255) | nullable | Exact normalized target project. For an accepted SR this may be the incident project. |
| `target_package` | VARCHAR(255) | nullable | Exact normalized physical target package. |
| `target_release_project` | VARCHAR(255) | nullable | Exact SR target release project. |
| `logical_package` | VARCHAR(255) | NOT NULL | Validated Sentinel logical package name. |
| `codestream_name` | VARCHAR(255) | NOT NULL | Exact IBS track reference represented by this action. |
| `incident_number` | INTEGER | nullable, positive | Incident established from accepted-SR target or RR source provenance. Required for a retained RR action. |
| `accepted_revision` | VARCHAR(255) | nullable | Action `acceptinfo` target revision. |
| `accepted_srcmd5` | VARCHAR(32) | nullable, lowercase hexadecimal | Accepted target source checksum. |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Local row creation time. |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Local row update time. |

Type-specific structural checks require:

- `maintenance_incident`: non-null `source_project`, `source_package`, and
  `target_release_project`; `codestream_name` equals the validated target
  release project. `target_project`, `target_package`, incident, and
  acceptinfo fields may be absent until IBS exposes them.
- `maintenance_release`: non-null `source_project`, `source_package`,
  `target_project`, `target_package`, and `incident_number`;
  `codestream_name` equals the validated target project.

Every project column stores the value returned by IBS point detail, whose
parser replaces each project outside the `SUSE:` namespace by the fixed token
`_redacted_` (`../integrations/ibs-integration.md`, Request Point Detail). Such
a project, for example a personal `home:` project, is treated as a personal
identifier and is never persisted. Semantic identities, upserts, conflict
checks, correlation, and every comparison between retained and current
actions use this stored form.

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

A non-unique index on `(logical_package, codestream_name)` serves the
retained-root lookup of one logical package and codestream
([Required Roots](#required-roots)).

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
One action represents at most one logical package and codestream
([Package and Codestream Identity](#package-and-codestream-identity)). It can
correlate to the tracks of that package and codestream under multiple Tickets
when its diff names each of their CVEs. Because `Ticket.cve_id` is unique, one
CVE cannot produce occurrences in multiple Tickets. Multiple actions can
correlate to one track.

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

### Package and Codestream Identity

A request action represents at most one logical package and codestream.
Sentinel derives both from the action's own validated point-detail fields:

| Action | Physical package | Logical package | Codestream |
|---|---|---|---|
| `maintenance_incident` | `target/@package` when present (an accepted action), otherwise `source/@package` | The part of the physical package before its first `.SUSE_`, `.openSUSE_`, or `.RES_` that is followed by at least one character; otherwise the whole physical package | `target/@releaseproject` |
| `maintenance_release` | `target/@package` | The physical package without its exact final `.{n}`, where `source/@project` is exactly `SUSE:Maintenance:{n}` | `target/@project` |

IBS names a maintenance package `{logical package}.{origin}`, where `{origin}`
is a project name with every `:` replaced by `_`. The origin is normally the
release project (`curl.SUSE_SLE-15-SP6_Update`), but it names where the
submitted source was branched from when that source links elsewhere: an
incident (`.SUSE_Maintenance_{n}`), a GA project, `SUSE:Channels`, or an
openSUSE project, which can precede the release project
(`kguiaddons.openSUSE_Backports_SLE-15-SP4_Update.SUSE_SLE-15-SP4_Update`).
Origin projects start with `SUSE:`, `openSUSE:`, or `RES:` (the last follows
the SUSE maintenance toolkit and is not observed in IBS), so the first such
separator splits off the logical package even when the logical package
(`go1.27`) or an origin (`.SUSE_SLFO_1.1`) contains dots. SMELT splits
maintenance package names in the same way. A logical package name that itself
contains one of these separators is not supported. A name without a separator
is used whole: an SR submitted directly from a codestream or GA project, or from
a source outside the `SUSE:` namespace, can name the package without an
origin. A release request names its target package
`{logical package}.{n}`.

For one scope with logical package `L` and codestream `C`, comparisons are
exact and case-sensitive, and each supported action is exactly one of:

- **matching:** its logical package equals `L` and its codestream equals `C`;
- **unresolved:** a `maintenance_release` action whose target project is `C`
  and whose target package starts with `{L}.`, but whose source project is not
  exactly `SUSE:Maintenance:{n}` or whose target package does not end with that
  exact `.{n}`; an unresolved action makes the observation incomplete; or
- **non-matching:** every other action, including patchinfo release actions
  (`patchinfo.{n}`), actions targeting projects such as `SUSE:Updates:*` or
  `SUSE:Channels`, and actions whose physical package differs from `L` only in
  letter case.

`incident_number` is `n` of an exact `SUSE:Maintenance:{n}` (a positive decimal
number without leading zeros) in an accepted SR action's `target/@project` or a
release action's `source/@project`. A staging project such as
`SUSE:Maintenance:REQUEST:{n}` is never an incident.

### Required Roots

A complete observation of one scope (Ticket CVE `X`, logical package `L`,
codestream `C`) exhausts these roots, unless a proven release completes it
first (below):

1. **Retained roots.** The actions correlated to the scope's track, with their
   parent requests, and every retained `accepted` `maintenance_incident` action
   of `L` in `C` that is not correlated to the track and whose incident has no
   retained `accepted` release action of `L` in `C`: an incident in flight that
   Sentinel observed for another Ticket.
2. **Open submission requests.** The ID search for `maintenance_incident`
   actions in `new` or `review` whose source package starts with `{L}.`.
3. **Supersession.** The closure of every `superseded_by_request_number` of a
   request obtained from roots 1, 2, and 4.
4. **Open release requests.** The ID search for `maintenance_release` actions
   in `new` or `review` whose target package starts with `{L}.`.
5. **Current release evidence** of `L` in `C`
   ([Release Discovery](#release-discovery)).
6. **Release scan** of the codestream history of `L` in `C`, required only when
   the current release evidence has positive evidence for `X`
   ([Release Discovery](#release-discovery)).
7. **Incident histories.** The incident-package history of every matching
   accepted `maintenance_incident` action with positive evidence for `X`
   ([Effective SR](#effective-sr)).

The release proof of [Accepted RR Provenance](#accepted-rr-provenance) is
applied first: to every matching `accepted` release action correlated to the
track, then through roots 5 and 6. A proven release is the strongest delivery
state, so the observation is then complete positive without the remaining
roots; it persists the proving action with its request and correlation, and no
evidence from the remaining roots. For a track whose persisted delivery is
`RELEASED`, the proof is not applied and roots 5, 6, and 7 are not required,
because no observation can change that delivery; roots 1 to 4 refresh its
evidence.

An in-flight SR of root 1 that is not correlated to the track only shortens the
first limitation below. Its unavailable diff or incident history is therefore
not evidence and does not make the observation incomplete. Such an SR is
correlated to the track only when its diff has positive evidence for `X` and
its [Effective SR](#effective-sr) evaluation is complete, and it is not
examined for a track whose persisted delivery is `RELEASED`.

Each matching action also requires the diff evidence defined in
[Action-Scoped CVE Evidence](#action-scoped-cve-evidence). A scope whose track
reference does not start with `SUSE:` is incomplete before any IBS request.

Current patchinfo issue evidence, released binaries, and published advisories
are optional corroboration only. They never replace a required root, never
prove a negative, and never set `TicketPackageProduct.released_at`.

Discovery is bounded, with these accepted limitations:

- An accepted SR whose incident has no open or accepted release request yet is
  not discovered when Sentinel never observed it while it was open, or observed
  it only for another Ticket's track after its incident already had a retained
  release. It becomes visible once its release request is opened or accepted.
- An open SR whose source package does not start with `{L}.`, such as an SR
  submitted directly from a `SUSE:` codestream or GA project or from a source
  outside the `SUSE:` namespace, is not found by the search. A request wake-up
  can still select it.
- The diff of an open SR whose source is outside the `SUSE:` namespace is never
  available (`../integrations/ibs-integration.md`, Request Action Diff), so the
  scopes that require it stay incomplete while the SR is open.
- A release whose Ticket-CVE reference no longer appears in the current
  codestream sources is not discovered.
- A release recorded without acceptinfo cannot be proven
  ([Accepted RR Provenance](#accepted-rr-provenance)).

None of them produces a false `RELEASED`.

### Request Discovery and Detail

The reconciler uses narrowly bounded searches rooted in the finite local track
scope. It never depends on an unordered global `limit`/`offset` collection scan.

A narrow ID search is complete only when its response is complete under the
ID-search contract in `../integrations/ibs-integration.md` (Request ID Search).
Every returned ID is point-fetched, and each of its actions is classified under
[Package and Codestream Identity](#package-and-codestream-identity) and
validated against its semantic identity. Prefix matching proposes candidates;
it never proves package identity.

Every retained or candidate request is point-fetched, with one exception. IBS
permits no state change out of `accepted` and records acceptinfo once, at
acceptance, so for a retained `accepted` request the persisted state and the
provenance of its retained actions remain current. Such a request is
point-fetched again only when the scope needs an artifact that is not retained:
an action diff, or any action that Sentinel did not retain. Sentinel retains
only relevant actions, so the absence of a retained action never shows that IBS
has no such action; the release scan and every other classification of a
request's actions use point detail unless the action concerned is retained.
Current detail supplies the authoritative parent state and complete REST action
set available upstream. RabbitMQ action content is never used to fill or
replace detail. Supersession is closed by point-fetching each positive
`superseded_by_request_number`, with a visited set and a finite cycle check. A
cycle, missing required successor, or unknown successor state is incomplete
evidence.

Source history is read as the complete available history of a package in one
unpaged response, or by exact revision or checksum lookup
(`../integrations/ibs-integration.md`, Package Source History). A history that
is not complete under that contract is incomplete evidence. No wall-clock cutoff
is applied. Upstream retention can still make old evidence unavailable; that
condition is handled as incomplete evidence, not as absence. A history entry
without a request number is not by itself evidence of a direct source change:
IBS typically records one before an SR acceptance (the branch commit).
[Effective SR](#effective-sr) and [Release Discovery](#release-discovery)
define how each kind of entry is used.

Within one invocation, each artifact is obtained at most once per identity and
reused by every scope that needs it:

- the ID searches, per logical package;
- the current release evidence and the codestream history, per logical package
  and codestream;
- request detail, per request number;
- incident-package history, per incident package;
- an exact history lookup, per package and revision;
- an action diff, per action.

Reuse never merges scope outcomes. An incomplete or failed shared artifact makes
every scope that requires it incomplete or failed.

### Action-Scoped CVE Evidence

Each relevant action is diffed on its own through the request action diff
(`../integrations/ibs-integration.md`, Request Action Diff). For a release
action found by the release scan, that diff is its release diff
([Release Discovery](#release-discovery)). An issue is positive correlation
evidence only when all of these hold:

- it belongs to the exact action's own diff;
- `tracker = cve`;
- `state` is `added` or `changed`; and
- canonical `label` exactly equals the Ticket CVE ID.

The tracker-native `name` is not reinterpreted as a CVE ID. `deleted` is not
positive correlation evidence. `changed` is accepted because a later SR can
replace incident contents while retaining an existing CVE reference.

A matching action requires its diff when it is not yet correlated to the
scope's track and its request is `new`, `review`, or `accepted`, except that
the unavailable diff of an uncorrelated in-flight SR of root 1 is not evidence
([Required Roots](#required-roots)). A matching
action of a `declined`, `revoked`, `deleted`, or `superseded` request cannot
establish progress or release by itself (a superseded request acts only through
its successor), so its diff is not required and an unavailable diff of it never
makes the observation incomplete. A matching action that is already correlated
to the track is retained evidence: its correlation is not derived again, and
its diff is required only for the release proof
([Accepted RR Provenance](#accepted-rr-provenance)).

A completely parsed action diff with no qualifying issue is a successful
no-match for that action. A malformed, unavailable, truncated, or ambiguous diff
is incomplete; when correlation or effective contents depend on it, the
observation is incomplete, and it never deletes retained history or proves a
negative. The diff of an action that is not accepted can be unavailable,
temporarily or permanently, for the reasons listed in
`../integrations/ibs-integration.md` (Request Action Diff).

### Effective SR

An accepted matching `maintenance_incident` action with positive evidence for
the Ticket CVE establishes current progress only while it is effective for its
incident package. Its incident package is the action's `target/@package` in its
`target/@project`.

The action is effective when the unpaged history of that incident package has
both of these properties:

- it contains a revision carrying the action's request number whose `srcmd5`
  equals the action's acceptinfo `srcmd5`; and
- no later revision carries the number of another `maintenance_incident`
  request.

History `srcmd5` is the unexpanded commit checksum, so acceptinfo `xsrcmd5` is
never compared with it. Two kinds of revision neither select nor end an
effective SR:

- revisions without a request number, such as the branch commit that typically
  precedes an SR acceptance, or a direct change; and
- revisions carrying a release-request number.

Point detail of a later request number decides its kind; unavailable detail of
such a request makes the observation incomplete.

When a later SR replaced the incident contents, the later SR is the effective
one and its own diff decides whether progress for the CVE remains; the older SR
is historical. A release of the incident does not end its progress; the release
is proven separately ([Accepted RR Provenance](#accepted-rr-provenance)). An
unavailable or incomplete incident history, a missing acceptinfo `srcmd5`, or a
history that contains no revision for the action makes the observation
incomplete, except for an uncorrelated in-flight SR of root 1, whose
unavailable evidence is not evidence ([Required Roots](#required-roots)).

An SR in `new` or `review` can establish current progress directly after exact
action and CVE correlation. A `superseded` SR does not establish progress by
itself; its successor chain inherits the role only if traversal completes and a
successor action is relevant to the same track and CVE. `declined`, `revoked`,
and `deleted` requests do not establish current progress.

### Release Discovery

Release discovery finds an accepted release request that released contents
carrying the Ticket CVE to the codestream, without reading every historical
release:

1. **Current release evidence.** Read the current expanded source checksum of
   `L` in `C` through targeted source info, then the issue set of that state
   through the expanded source diff against the empty tree
   (`../integrations/ibs-integration.md`, Project Source Info and Source Diff
   with Issue Extraction). A failed package result from source info, or
   `IBSResponseDataError` from either operation, makes the current release
   evidence incomplete; a transport or HTTP error from either operation fails
   the scope. When the issue set has no positive evidence for the Ticket CVE
   (the conditions of
   [Action-Scoped CVE Evidence](#action-scoped-cve-evidence)), no release of
   the CVE is visible and the release scan is not required.
2. **Release scan.** Otherwise, read the unpaged history of `L` in `C` and
   examine its entries from the newest to the oldest:
   - Skip an entry without a request number.
   - Skip an entry whose request has no matching `maintenance_release` action.
   - A matching action of a request that is not `accepted` is contradictory
     evidence and makes the observation incomplete.
   - For a matching action without acceptinfo, stop: neither that release nor
     an older one can be proven.
   - Otherwise, obtain the action's release diff (the accepted form of the
     request action diff). Without positive evidence for the Ticket CVE,
     continue with the next older entry. With it, the action is relevant and
     the proof of [Accepted RR Provenance](#accepted-rr-provenance) decides:
     - a proven release ends the scan;
     - a failed proof makes the observation incomplete.

   A request detail, release diff, or exact lookup that is unavailable when the
   scan needs it makes the observation incomplete. When the scan exhausts the
   history, or stops at an action without acceptinfo, the observation is
   complete without a proven release.

The current release evidence is source evidence of the codestream only. It
never reads, writes, or depends on the track's affectedness status. A proven
release is irreversible, so a track is scanned again only while no release has
been proven.

### Accepted RR Provenance

RR acceptance alone is insufficient for `RELEASED`. A matching
`maintenance_release` action proves release of the Ticket CVE to the track
codestream only when this holds for that exact action:

```text
RR state is accepted
    -> acceptinfo rev and srcmd5 are present
    -> exact lookup of the action's own target/@package history at acceptinfo rev
       returns that revision with the same srcmd5 and the RR request number
    -> the action's release diff has positive evidence for the Ticket CVE
```

Every comparison is exact. The lookup uses only the action's own target package
(`{L}.{n}` in `C`). The history of the logical codestream package `L` also
carries the RR request number, but with the checksum of its link update; it is
a discovery root only and is never compared with release acceptinfo. No other
acceptinfo field is substituted for `rev` or `srcmd5`. The release diff is
required for the proof even when the action is already correlated to the track
through an earlier diff.

An accepted action without acceptinfo is not delivery evidence. IBS records
none in two cases: releases made before it stored acceptinfo, and packages that
it releases as a link to another package of the same release request. Such an
action proves nothing and does not make the observation incomplete. An action
with acceptinfo whose lookup is unavailable, or that returns another revision,
checksum, or request number, is incomplete evidence.

The proof binds release to the contents of that release request. An SR that
later reuses the incident is released, and proven, by its own release request.
The SR and incident chain is not part of the proof; it establishes
`IN_PROGRESS` only. A relevant RR in any state is correlated directly to the
track through `IBSRequestActionTrack`; only the proof establishes release.

## Observation Outcomes

Each track-scope reconciliation produces exactly one classification:

| Outcome | Meaning | Local effect |
|---|---|---|
| Complete positive | Every [required root](#required-roots) and artifact was validated, or a release was proven first, and relevant current SR/incident/RR evidence exists. | Atomically upsert relevant domain evidence and derive delivery. |
| Complete no-match | Every required root was exhausted successfully and no relevant current delivery evidence exists. | Retain history; a non-stale negative may derive `PENDING`. |
| Incomplete | Required evidence is absent, retention-limited, truncated, contradictory, unknown, malformed, cyclic, or ambiguous. | Preserve request/action/correlation and delivery state exactly. |
| Failed | A required external or local operation failed. | Roll back the scope and preserve prior state. |

Examples of incomplete evidence include:

- a required detail 404, or an unknown request or action type;
- a non-exhaustive search or unavailable source history;
- an unresolved action, or a track reference outside the `SUSE:` namespace;
- an unavailable required diff or a failed release proof;
- conflicting equal-time request detail;
- a value to be persisted that exceeds its column: a request, successor, or
  incident number above 2147483647, or an acceptinfo revision longer than 255
  characters.

None is translated into a negative result. An accepted release action without
acceptinfo and a history entry without a request number are not incomplete
evidence ([Accepted RR Provenance](#accepted-rr-provenance),
[Request Discovery and Detail](#request-discovery-and-detail)).

No upstream source guarantees indefinite retention. The feature converges while
enough request, diff, source-history, issue, binary, or advisory evidence remains
discoverable. If all required evidence has disappeared, preserving the last
established local delivery state is the intentional safe result.

## Delivery Derivation

This section maps IBS evidence to the delivery values whose meanings are
defined in `package-model.md`
([Axis 3](package-model.md#axis-3-delivery-and-release-observation)).

For a complete observation, derive the strongest proven state:

1. A release proven under [Accepted RR Provenance](#accepted-rr-provenance)
   yields `RELEASED`.
2. Otherwise, a relevant `new`/`review` SR, effective accepted SR, complete
   relevant supersession successor, or relevant `new`/`review` RR yields
   `IN_PROGRESS`.
3. Otherwise, a complete authoritative no-match yields `PENDING`.

A complete no-match is complete within the bounded discovery of
[Required Roots](#required-roots), whose accepted limitations apply; the
resulting `PENDING` carries the caveat stated in
[Axis 3](package-model.md#axis-3-delivery-and-release-observation). An
incomplete or failed observation never changes delivery.

The derived value is applied under the delivery state machine in
`package-model.md`
([Automatic Transitions](package-model.md#automatic-transitions)), including
irreversible `RELEASED` and the atomic `PENDING -> IN_PROGRESS -> RELEASED`
application of a release proven while the persisted value is `PENDING`. A
negative regression `IN_PROGRESS -> PENDING` also requires the stale-negative
guard of [Algorithm](#algorithm) step 8. When the delivery value reloaded under
the Ticket lock is `RELEASED`, a complete observation commits its evidence and
leaves delivery unchanged, whatever value it derives; it requests no
transition.

All effective changes use `package_service.set_track_delivery_status()` with
system attribution. Delivery changes create no Ticket audit event and do not
invoke affectedness or Product-release mutations.

Creating or updating `IBSRequest`, `IBSRequestAction`, or
`IBSRequestActionTrack` evidence likewise creates no `TicketAuditEvent` by
itself. Request discovery, observation classification, RabbitMQ wake-up, and
unchanged, stale, inapplicable, incomplete, or failed outcomes create no Ticket
event. When reconciliation delegates an independent audited domain mutation,
that mutation retains only its ordinary event contract. Audit history is never
request state, correlation provenance, delivery authority, or idempotency state.

## Shared Authoritative Reconciliation

The same track-scoped operation is used by the daily fetcher, package-add
acceleration, Ticket-convergence catch-up, and RabbitMQ request-number
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

A scope whose Ticket has no CVE is also selected. Positive evidence requires a
label equal to the Ticket CVE, so such a scope is a complete no-match without
any IBS request, whatever its package and codestream.

The scope's codestream is the track `reference`, which is the origin codestream
of the package (`package-model.md`, SMELT Query for Package Resolution). IBS
requests for a package that later codestreams inherit through a project link
name that origin codestream, so exact equality with an action's codestream
([Package and Codestream Identity](#package-and-codestream-identity))
identifies them.

### Algorithm

For each selected scope:

1. Without locking the Ticket, read the retained exact request/action roots
   and the scope's step-1 snapshot: the identity and row timestamps of every
   retained action of the scope's logical package and codestream, of their
   parent requests, and of the track's correlations, and the track's persisted
   `delivery_status`, retained as the pre-I/O delivery baseline. Step 1
   completes before the first IBS request whose result the scope can use, so
   evidence reused within one invocation is never older than the scope's
   snapshot.
2. Discover current request, supersession, incident, and RR candidates over the
   [Required Roots](#required-roots).
3. Point-fetch current request detail and required action-scoped diffs and source
   histories. Validate every consumed field, exhaust every required root
   unless a proven release completes the observation first, and classify the
   observation. No database mutation occurs for an incomplete or failed
   observation.
4. For a complete observation, begin one independent local transaction and lock
   the parent Ticket first.
5. Reload the exact Ticket, CVE, package, track, workflow type, codestream, and
   relevant retained request/action evidence. If the Ticket is no longer active,
   the track no longer exists, its workflow is no longer IBS, or the semantic
   scope no longer matches, return a successful stale/inapplicable no-op.
6. Conditionally lock or upsert each existing request/action identity that this
   scope will mutate. If a newer authoritative request observation has already
   committed, the observation is stale: the scope rolls back and fails with the
   category `stale_request_observation`, and a later run or catch-up observes
   the request again. For equal `upstream_updated_at`, identical normalized
   content is idempotent; conflicting content is incomplete and rolls back.
7. Upsert every validated relevant `IBSRequest` and `IBSRequestAction`, then
   upsert each exact `IBSRequestActionTrack` pair. Unknown and irrelevant
   actions are not persisted. Existing provenance omitted by IBS is retained;
   contradictory immutable provenance rolls back the scope.
8. Derive delivery from the complete observation, which includes the retained
   evidence read at step 1; the reloaded evidence serves only the
   stale-negative guard. Stale-negative guard: for a complete negative
   observation, do not regress `IN_PROGRESS` if the reloaded relevant request,
   action, and correlation rows differ from the step-1 snapshot (a row added,
   removed, or with a different row timestamp), or if the track's delivery
   value differs from the value observed before external I/O. Rows committed
   by another writer during the scan only block such a regression; they are
   never positive evidence for this scope.
9. Apply any effective delivery transition through
   `package_service.set_track_delivery_status()` with the complete Ticket,
   package, and track locator in the same transaction. Consume `changed` or
   `no_op` from locked-current state; delivery has no `rejected` outcome.
10. Flush and commit the request, action, correlation, and delivery outcome
    atomically. On any local failure, roll back all changes for this scope.

A definitely failed commit, which the database reports as rejected, is a local
failure of that scope. An ambiguous commit, whose outcome is unknown, such as a
connection failure during `COMMIT`, ends the invocation: that scope receives no
terminal outcome, and the remaining scopes are not attempted.

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
condition, not by replacing the winner. The stale-negative guard of step 8
prevents a stale negative result from overwriting positive event or polling
work committed after the scan began. Audit history is never queried
for current state, idempotency, or provenance.

### Structured Logs

The shared reconciliation logs these events. Standard correlation fields are
added by the logging infrastructure and are not repeated here.

| Event | Level | Required fields | Optional fields |
|---|---|---|---|
| `ibs_request_scope_failed` | WARNING | `ticket_id`, `track_id`, `package_name`, `reason_category` | `codestream`, `request_number`, `http_status` |
| `ibs_request_scope_stale` | WARNING | `ticket_id`, `track_id`, `package_name`, `reason_category` | `codestream` |
| `ibs_request_issue_ignored` | WARNING | `package_name`, `reason_category="invalid_cve_label"` | `codestream`, `request_number` |

`ibs_request_scope_failed` is emitted once for every scope whose observation is
incomplete or failed or whose local transaction fails, including each scope
that depends on an incomplete or failed shared artifact. `request_number` names
the request whose evidence made the scope incomplete or failed, when there is
one; `http_status` accompanies `reason_category="http_status"`.
`ibs_request_scope_stale` is emitted once for a scope that becomes stale or
inapplicable under the locked revalidation of [Algorithm](#algorithm) step 5,
which is a successful no-op: `reason_category` is `ticket_not_operable` when
the Ticket became `Ignored` or `Duplicated`, and `scope_changed` otherwise.
`ibs_request_issue_ignored` is emitted at most once per request action diff or
current release evidence diff that contains a `cve` issue in state `added` or
`changed` whose `label` is missing or is not a canonical CVE ID; such an issue
is not positive evidence (`../integrations/ibs-integration.md`, Request Action
Diff). `request_number` accompanies a request action diff. `codestream` is
logged only when it is a `SUSE:` project.

`reason_category` is a bounded internal classification, never upstream text.
It distinguishes at least:

- IBS operation failures: IBS API credentials not configured
  (`credentials_not_configured`), each `IBSAuthenticationError` reason
  (`unsupported_challenge`, `signature_rejected`), `transport`, and
  `http_status`;
- unusable current release evidence: each `IBSResponseDataError` reason and
  each source-info package failure (`missing`, `duplicate`, `upstream_error`,
  `invalid_srcmd5`);
- each bounded incomplete-evidence reason of the request operations
  (`../integrations/ibs-integration.md`, Service Layer › IBSClient);
- observation outcomes: an invalid scope identity (`invalid_identity`), a track
  reference outside the `SUSE:` namespace (`outside_suse_namespace`), an
  unresolved action (`unresolved_action`), a supersession cycle
  (`supersession_cycle`), missing accepted provenance (`missing_provenance`), a
  failed release proof (`release_proof_failed`), a matching release action of a
  request that is not accepted in the release scan (`contradictory_evidence`),
  and a value that exceeds its column (`value_out_of_range`);
- local outcomes: a stale request observation (`stale_request_observation`),
  conflicting equal-time request content (`conflicting_observation`),
  conflicting immutable action identity or acceptinfo
  (`conflicting_provenance`), a rejected delivery transition
  (`invalid_delivery_transition`), and a database failure (`database`).

Logs never carry upstream response text, actors, free text, credentials, or a
project outside the `SUSE:` namespace.

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

### Ticket Convergence

`SyncIbsRequests.participates_in_catch_up = True`. The established Ticket convergence
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
   scope, with independent transactions. The detail of step 3 only selects
   scopes; the reconciliation obtains its own evidence after its step 1
   ([Algorithm](#algorithm)).

The event handler does not publish a Celery correlation or discovery task.
Duplicate and out-of-order deliveries converge through current detail and
idempotent reconciliation. If point lookup or reconciliation fails after the
shared bounded HTTP transport retries, the consumer rolls back incomplete local
work, records the sanitized failure, acknowledges according to the RabbitMQ
integration contract, and continues. The next complete fetcher run owns
recovery while required evidence remains upstream.

Step 4 selects scopes by the
[Package and Codestream Identity](#package-and-codestream-identity) of validated
current actions and of retained actions. An action that matches no represented
active-Ticket IBS track selects no scope, and an unresolved action selects none
in the event path. Such a delivery is an irrelevant acceleration no-op; the
next complete `sync_ibs_requests` scan starts from each known logical package
and owns discovery. Event fields never supply a fallback mapping.

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
| Auth | IBS API SSH-signature authentication through the shared IBS client (`../integrations/ibs-integration.md`, Origins and Authentication) |
| `participates_in_catch_up` | `True` |
| Custom settings | No |
| Cursor | None; `FetcherRun.cursor` remains NULL |
| `default_request_delay` | 0 s — no IBS API rate limit is documented (`../../data-sources.md`, Fetcher Registry); see [Request Delay](#request-delay) |

The fetcher has no temporal lookback setting or fixed historical window.
It declares no inner `Settings` model, accepts no custom setting, and leaves
`FetcherConfig.custom_settings = {}`. It does not read `previous_cursor` or set
a cursor during execution.
`FetcherConfig` continues to provide only the generic enabled, schedule,
timeout, and request-delay controls. The first run, a run after re-enable, and a
run after a long gap use the same complete state-based algorithm.

### Request Delay

The fetcher spaces every IBS request under the generic request-delay contract
([fetcher-infrastructure.md, Request
Delay](../platform/fetcher-infrastructure.md#request-delay)). Catch-up also
applies the delay, with the class `default_request_delay`. One IBS operation,
including its unsigned and signed attempts
([ibs-integration.md, Request
Authentication](../integrations/ibs-integration.md#request-authentication)), is
one request. No IBS request occurs while a Ticket lock is held
([Algorithm](#algorithm)), so the fetcher never waits while holding one.
Request wake-ups ([RabbitMQ Request Wake-Ups](#rabbitmq-request-wake-ups)) are
not fetcher work and apply no delay.

### Algorithm

1. Select the distinct finite track scopes belonging to active Tickets where
   `workflow_type = ibs`. Include every affectedness and delivery status and all
   exclusion/actionability states.
2. Process each selected track with the shared authoritative reconciliation.
3. Commit each complete local scope independently. Roll back and continue after
   an incomplete or failed scope.
4. Let `SoftTimeLimitExceeded`, `MemoryError`, and an ambiguous scope commit
   escape as whole-run signals; they are never converted into per-scope
   failures.
5. Return normally after all scopes have been attempted. `BaseFetcher` derives
   success, partial, or failure from the non-overlapping metrics below.

A complete valid no-match and an idempotent no-op are successful scope outcomes.
The algorithm needs no special first-run branch, durable cursor, per-track
progress row, or global request-history scan. Source retention can still limit
what a long-gap run can prove; incomplete scopes preserve prior delivery.

### Error Handling

| Failure | Behavior |
|---|---|
| One track has a credentials-not-configured, authentication, transport, timeout, rate-limit, HTTP, parse, validation, search-completeness, retention, ambiguity, or local transaction failure | Roll back that scope, increment `record_failed` once, log the track/Ticket/request identities and sanitized category, and continue. Raw response bodies, URLs, credentials, and personal identifiers are not logged. |
| A newer authoritative request observation has already committed when the scope locks the request ([Algorithm](#algorithm) step 6) | Roll back that scope, increment `record_failed` once with the category `stale_request_observation`, and continue; a later run or catch-up observes the request again. |
| A definitely failed scope commit, which the database reports as rejected | A local transaction failure of that scope: it is rolled back, `record_failed` is incremented once with the category `database`, and processing continues. |
| An ambiguous scope commit, whose outcome is unknown, such as a connection failure during `COMMIT` | The invocation ends: that scope records no terminal outcome or effect metric, the exception reaches `BaseFetcher`, which finalizes the run as failure, and scopes committed earlier remain committed. |
| Scope enumeration or another whole-run database prerequisite fails | Raise so `BaseFetcher` finalizes the run as failure. Public `error_message` uses the infrastructure's sanitized generic category; restricted error fields retain diagnostics. |
| Every selected scope fails | Return normally after counting failures; `BaseFetcher` records run failure because no selected scope succeeded. |
| Some scopes complete and some fail | Return normally; `BaseFetcher` records a partial run from the mixed terminal outcomes, including when every successful scope was a no-op. |
| Soft or hard run time limit | `SoftTimeLimitExceeded` reaches `BaseFetcher`; it records the sanitized timeout failure. The worker enforces the hard limit. No cursor advances. Scopes committed before the limit remain committed; scopes not yet attempted keep their state until a later run reconciles them. |

**Run time (accepted limitation).** A first run, a run after a long gap, or a
large backlog of releases can exceed the default `run_timeout`, because release
scans read codestream histories. Later runs need less time: each scope commits
independently, and a track whose release is proven is never scanned again. A
track whose CVE appears in the current codestream sources without a provable
release, for example a fix that predates the codestream's maintenance releases,
is scanned in every run. An operator can raise `FetcherConfig.run_timeout`
through the fetcher configuration operations
(`../platform/fetcher-operations.md`) for such runs, or keep it higher when
regular runs approach the limit. The fetcher persists no progress between runs
and does not rotate scopes; their order within a run is not specified.

The generic `run_fetcher` task has no top-level retry. The next daily execution,
or the existing generic manual fetcher trigger, repeats the complete idempotent
scan. No SR/RR-specific retry, discovery, correlation, or operator endpoint is
introduced.

When the fetcher is disabled, successful RabbitMQ events can still reduce
latency, but lost events, terminal event-processing failures, and request
reopens have no automatic recovery. Re-enabling the fetcher restores recovery;
its next complete run processes all still-discoverable evidence.

### Metrics

The work unit is one distinct selected track scope with the complete semantic
identity defined in [Scope Identity](#scope-identity). Shared request evidence
is reused under [Request Discovery and Detail](#request-discovery-and-detail),
but it does not merge track scopes for outcome or effect accounting.

| Mapping | Exact behavior |
|---|---|
| Selected | Each distinct IBS track scope belonging to an active Ticket, once. |
| Succeeded | `record_succeeded()` once for a complete positive or complete no-match scope whose local transaction commits, including an unchanged/idempotent no-op. A scope that becomes stale or inapplicable under the locked revalidation in step 5 is also a successful no-op. |
| Failed | `record_failed()` once when a selected scope is incomplete or failed, regardless of the number of failed external calls or validation findings in that scope. Its local effects roll back. |
| Created | `record_created()` once when a succeeded scope transaction creates at least one relevant `IBSRequest`, `IBSRequestAction`, or `IBSRequestActionTrack`, even if the same transaction also updates existing evidence or delivery. |
| Updated | `record_updated()` once when a succeeded scope transaction creates no domain row but changes existing request state, provenance, or correlation, or effectively changes delivery. |
| Excluded before selection | Non-IBS tracks and tracks below inactive Tickets do not enter the recurring work scope. Package or track exclusion, actionability, affectedness, eligibility, delivery status, and Product lifecycle do not exclude an otherwise selected IBS track. |

Created and updated remain mutually exclusive effects for one scope. A
succeeded complete no-match, unchanged scope, or stale/inapplicable no-op has no
created or updated effect. Each selected terminal scope records exactly one of
succeeded or failed, so run status derives from outcomes rather than domain
mutation counts. Mixed succeeded and failed scopes produce `partial`, all
failed scopes produce `failure`, and no failed scopes produce `success`,
including an empty run.

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

These endpoints are also the read surface for correlated IBS evidence that a
consumer may inspect alongside a maintainer workbench row. They expose distinct
current request actions and their exact states; the workbench does not select or
label one effective SR, proving RR, or authoritative historical submission
chain from them.

Both endpoints inherit the ticket accessibility check. Anonymous callers can
read non-confidential Tickets; confidential Ticket existence and data remain
hidden according to the shared visibility contract.

The service query for each endpoint selects distinct actions through the parent
Ticket constrained by the canonical visibility predicate from
`docs/features/identity/rbac.md`. This constraint is part of the same database
result or view used for action deduplication, counting, pagination, and item
projection. A preliminary router or dependency check may provide the shared
HTTP denial response, but it cannot authorize a later unconstrained action
query. Missing and inaccessible parents both return `404 TICKET_NOT_FOUND`.
Model-aware ORM construction remains in the Service layer; endpoint handlers do
not build or pass visibility expressions.

### Common Query Rules

Both endpoints support standard `page` (default 1) and `per_page` (default 20,
maximum 100) pagination. Filters combine with AND semantics.

Action deduplication occurs within the caller-visible candidate set. The page
items and `meta.total` count the same distinct visible
`IBSRequestAction.id` values after all mandatory Ticket/path constraints and
client filters; invisible joins neither contribute to the count nor move
visible actions between pages.

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
| `incident_number` | positive integer | No | Exact incident number. At most 2147483647, the PostgreSQL `INTEGER` maximum; a larger value returns `422 VALIDATION_ERROR`. |

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
  or RabbitMQ `action_id`, the eight IBS action types (two supported, six
  ignored, any other incomplete), and the replacement of projects outside the
  `SUSE:` namespace, including actions whose identities collide through it;
- action-scoped `added`/`changed` CVE correlation through the accepted and
  not-accepted request action diff forms; valid no-match; malformed, HTTP 400,
  HTTP 404, and unrequested diffs (a missing form input or a project outside the
  `SUSE:` namespace); and unknown action/state handling;
- package and codestream identity:
  - match, non-match, and unresolved actions;
  - dotted logical packages (`go1.27`), dotted and branch-origin suffixes
    (`.SUSE_SLFO_1.1`, `.SUSE_Maintenance_{n}`, `.SUSE_Channels`, a GA
    project), an openSUSE origin before the release project, and a name
    without a separator;
  - release targets with and without the exact incident suffix, patchinfo and
    non-codestream targets, and letter-case differences;
  - incident numbers from exact incident projects only;
  - the origin codestream of an inherited package, and a track reference
    outside the `SUSE:` namespace;
- every required root:
  - retained roots, including an in-flight accepted SR correlated only to
    another Ticket's track of the same package and codestream, its exclusion
    once a retained accepted release action of its incident exists, and its
    unavailable diff or incident history, which does not make the observation
    incomplete;
  - a retained `accepted` request reused without new point detail, and point
    detail for an action of it that was not retained;
  - matching actions of `declined`, `revoked`, `deleted`, and `superseded`
    requests, whose unavailable diff does not make the observation incomplete;
  - a proven release that makes the observation complete without the remaining
    roots, including when another root is incomplete;
  - the open-SR and open-RR searches and supersession;
  - current release evidence with and without the Ticket CVE, including an
    incomplete source info or source diff;
  - a `RELEASED` track without the release proof and roots 5, 6, and 7;
  - an accepted SR never observed while open and without a release request,
    which is not discovered and yields a complete no-match;
- the release scan:
  - a release proven at the newest and at an older entry;
  - skipped entries without a request number or without a matching action;
  - a stop at an action without acceptinfo, and an exhausted history;
  - incomplete outcomes for an unavailable entry, a failed proof, and a
    matching action of a request that is not accepted;
- the release proof:
  - success, and failure of each comparison;
  - missing acceptinfo `rev` or `srcmd5`, and an unavailable lookup;
  - the history of the logical codestream package never accepted as the proof
    target;
  - an accepted action without acceptinfo as no delivery evidence;
  - a release proven although its SR's expanded checksum differs from the
    release request's source revision;
- effective-SR selection:
  - by request number and unexpanded `srcmd5`;
  - branch-commit and release-request revisions;
  - a later SR replacing the incident contents, with and without the CVE;
  - unavailable or incomplete incident history;
  - an accepted submission action without acceptinfo (incomplete);
- values to be persisted that exceed their columns;
- a CVE-less scope without any IBS request, and a stale request observation;
- an uncorrelated in-flight SR correlated only when its diff is positive and
  its effective-SR evaluation is complete;
- unpaged history completeness (not starting at revision 1 or not contiguous),
  revision and checksum lookups, and retention-limited outcomes;
- evidence reuse within one invocation without merging scope outcomes, and
  correlated actions whose diff is not requested again outside the release
  proof;
- release discovery that reads no affectedness, derives the same delivery for
  every affectedness status, and never changes affectedness, eligibility,
  `released_at`, or a `TrackReleaseCheckpoint`;
- the request delay:
  - no wait before the first IBS request of an invocation;
  - the run's `request_delay` before every later request of a periodic run, and
    the class `default_request_delay` in catch-up;
  - no wait for a zero delay, none while a Ticket lock is held, and none for
    request wake-ups;
- every delivery transition, irreversible `RELEASED` (including a track that a
  concurrent writer moved to `RELEASED` before the locked reload),
  complete-negative regression, and stale-negative concurrency with independent
  sessions;
- atomic request/action/join/delivery commit and rollback, including successful
  sibling scopes when another fails, a definitely failed commit, and an
  ambiguous commit;
- the structured logs and their bounded categories;
- zero Ticket-event assertions for effective and unchanged request, action,
  correlation, delivery, stale/inapplicable, incomplete, failed, and wake-up
  outcomes except where another delegated domain mutation requires its ordinary
  event;
- first run, long gap, re-enable, package-add and Ticket-convergence catch-up,
  duplicate/out-of-order event acceleration, and fetcher metric precedence;
- created, updated, complete-positive no-op, complete no-match,
  stale/inapplicable, incomplete, failed, mixed, all-failed, and empty-run
  outcomes with exact succeeded, failed, created, and updated counters;
- API authentication, confidential-Ticket visibility, action deduplication,
  exact filters, pagination, deterministic sorting, and response schemas,
  including missing/inaccessible 404 equivalence and one visibility-constrained
  distinct candidate set for items and totals; and
- log, API, and persistence assertions proving that authors, actors, comments,
  descriptions, raw payloads, credentials, raw response bodies, and project
  names outside the `SUSE:` namespace are absent, including from request URLs.

## Security and Privacy

- The public read endpoints process optional authentication, and their service
  queries select actions through an accessible parent Ticket in the same
  database result used for deduplication, counts, pages, and projection.
- IBS HTTP requests use existing configured credentials and the shared TLS and
  HTTP-client contracts. Credentials never enter persisted request evidence,
  API output, metrics, or logs.
- Personal identifiers and free text from IBS are neither persisted nor
  returned. Logs never include raw event payloads, raw response bodies, actors,
  comments, descriptions, credentials, or credential-bearing URLs. A project
  outside the `SUSE:` namespace, such as a personal `home:` project, is treated
  as a personal identifier: request evidence stores the fixed token
  `_redacted_` instead, and no request operation places such a project in a
  request URL, so it never reaches `httpx` request logs
  (`../integrations/ibs-integration.md`, Request Point Detail and Request Action
  Diff). Request action diffs carry issue references only, never file diff
  text.
- RabbitMQ event action arrays and personal fields are ignored. Only the public
  positive request number is consumed as the request wake-up identity.

## Recovery Guarantees

The complete daily state-based scan is the permanent recovery owner for active
Ticket IBS tracks. While sufficient upstream evidence remains, it covers first
enablement, long disablement, missed or duplicate events, transient queue loss,
failed package-add acceleration, tracks added after older releases or open
requests, request reopens, supersession, and partial prior runs without a cursor
or temporal window. The bounded discovery limitations of
[Required Roots](#required-roots) apply: an accepted SR that was never observed
while open is recovered once its release request is opened or accepted.

Package-add catch-up, Ticket-convergence catch-up, manual generic fetcher runs,
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
- `docs/features/packages/package-model.md` - orthogonal dimensions, delivery
  value meanings and the delivery state machine, strict IBS applicability,
  active-Ticket scope, and Ticket convergence ordering.
- `docs/features/packages/package-service.md` - centralized delivery mutation
  and Ticket locking.
- `docs/features/packages/maintainer.md` - current-state workbench projection;
  correlated request actions remain a separate evidence surface.
- `docs/features/packages/ibs-track-release-detection.md` - independent
  affectedness release detection.
- `docs/features/packages/ibs-product-release-detection.md` - independent
  Product publication detection.
- `docs/features/platform/fetcher-infrastructure.md` - `BaseFetcher`, generic
  trigger, metrics, catch-up, transaction, and error-sanitization contracts.
- `docs/features/platform/networking.md` - shared HTTP transport retries and
  retry classification.
