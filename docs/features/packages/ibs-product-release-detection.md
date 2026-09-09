# IBS Product Release Detection

## Purpose

Detect when a security fix for an existing Ticket package occurrence is
published in an IBS Product repository. The detector validates RPM repository
metadata and stable security advisories, then records the advisory-issued UTC
time in `TicketPackageProduct.released_at`.

This is Product-level factual reconciliation. It does not discover CVEs,
Tickets, packages, tracks, or Products, and it does not infer affectedness or
eligibility. Track-level source reconciliation is defined in
`ibs-track-release-detection.md`.

## Scope

The reconciliation unit is one existing `TicketPackageProduct` occurrence. An
occurrence is selected when all of the following are true:

- `released_at IS NULL`;
- its parent `TicketPackageTrack.workflow_type` is `ibs`;
- its parent Ticket is active (`New`, `Analysis`, or `Analyzed`); and
- the Ticket has a CVE.

VA exclusion, Product lifecycle, EOL, eligibility, track affectedness, and
delivery status do not narrow this factual-observation scope. A catalog Product
below both IBS and Git tracks produces distinct occurrences; only the occurrence
below the IBS track is eligible. Tickets without a CVE cannot be matched and are
not selected.

Completion is per occurrence, not per Product, repository, package name, or
Ticket. A match for one occurrence never suppresses processing of another
unreleased occurrence, including a sibling package below the same Product.

## Source Authority

The detector uses the `ProductRepository` associations retained by the Product
catalog and the RPM `repomd.xml` and `updateinfo.xml.gz` resources they identify.
It does not query the SMELT maintained-package endpoint during release
detection. That endpoint describes current package topology and could exclude a
historical repository that still contains the authoritative advisory.

A Product release candidate is authoritative only when all of these conditions
hold:

1. the repository and metadata snapshot pass every path, HTTP, integrity,
   resource, gzip, and XML validation in this specification;
2. the advisory has exact, case-sensitive `type="security"` and
   `status="stable"` values;
3. it has a valid advisory ID and issued time;
4. it contains a structurally valid `reference` with exact
   `type="cve"` and an `id` equal to the existing Ticket CVE;
5. it has a non-empty package collection; and
6. it contains an exact validated source-package entry matching the occurrence's
   `TicketPackage.package_name`.

The presence of a CVE reference alone is insufficient. Recommended, optional,
feature, and other non-security advisories do not establish release. Retracted
or otherwise non-stable advisories do not establish a new release.

## Download Origin and Repository Paths

### `IBS_DOWNLOAD_BASE_URL`

`IBS_DOWNLOAD_BASE_URL` is the configurable Product-repository front door. Its
default is `https://download.suse.de/ibs`. At application startup, Sentinel
parses and validates the value and refuses to start with an error naming the
setting unless all of the following hold:

- it is an absolute HTTPS URL with a non-empty hostname;
- it contains no user information, query, or fragment;
- its path is absolute, contains no empty, `.` or `..` segment, percent-encoded
  value, backslash, or control character, and may have at most one trailing
  slash; and
- every path segment is non-empty after removing that optional trailing slash.

A non-default port is permitted for an explicitly configured deployment. The
validated base is canonicalized by removing its trailing slash, if present.
Repository requests use the combined TLS trust store from `networking.md`.

Product-repository downloads are anonymous. The detector never sends
`IBS_USERNAME`, `IBS_PASSWORD`, an API token, an `Authorization` header, or
another credential to the configured base or to a redirect target.

### Repository qualification and URL construction

The detector derives a repository root from an exact retained `repo_name` only
when all of the following hold:

- the name starts with `SUSE:Updates:`;
- every colon-separated segment is non-empty and matches
  `[A-Za-z0-9._+-]+`;
- the terminal segment is not `debug` or `src`; and
- no segment identifies a Debian or Ubuntu target: exact `Debian` or `Ubuntu`,
  or a segment beginning with `Debian-` or `Ubuntu-`.

This exclusion is target-specific. A mixed family such as
`MultiLinuxManagerTools` is not excluded wholesale when its target is an RPM
SLE family. `SUSE:Products:*`, terminal debug/source companions, and known
Debian/Ubuntu targets are not candidates. An excluded or invalid repository
name is not requested.

For a qualified name, replace each colon separator with `/`, append the result
and `/update` to the validated base, and append
`/repodata/repomd.xml` for the metadata request. Construction is from validated
segments; it never interpolates a raw URL, absolute path, query, or fragment.

### Artifact location

The `repomd.xml` updateinfo `location/@href` must be a relative path with these
properties:

- it begins with `repodata/` and contains at least one following segment;
- every segment is non-empty, is neither `.` nor `..`, and matches
  `[A-Za-z0-9._+-]+`;
- it contains no scheme, authority, leading slash, backslash, percent escape,
  query, fragment, control character, or duplicate separator; and
- resolving it against the repository root remains below that exact root.

Absolute URLs and normalized alternatives are rejected rather than repaired.

## Repository Traversal

For each occurrence, traverse eligible repositories in two tiers:

1. associations whose `catalog_last_seen_at` belongs to the latest complete
   Product catalog snapshot; then
2. retained historical associations, only if the occurrence remains unresolved
   after every current association completes without a match.

SMELT repository-array order is not authoritative. Within each tier, order
candidates deterministically:

1. names without a recognized terminal architecture, in lexical repository-name
   order;
2. terminal `x86_64` repositories, in lexical repository-name order; then
3. other recognized terminal architectures in lexical architecture order,
   using repository name as the final tiebreaker.

Recognized architecture segments are `aarch64`, `i586`, `i686`, `ia64`,
`ppc64`, `ppc64le`, `s390x`, and `x86_64`. A name without one of these suffixes
is tried first as a traffic optimization; Sentinel does not claim that it is
multi-architecture merely because it lacks a recognized suffix.

One valid repository match is sufficient because release is tracked at
Product/package-occurrence grain, not per architecture. Stop traversal only for
that occurrence. In the first repository that matches it, inspect every valid
authoritative advisory before selecting the timestamp.

Repository outcomes affect traversal as follows:

| Outcome | Occurrence behavior |
|---|---|
| HTTP 404 for `repomd.xml` | Repository is a successful non-match; continue |
| Valid `repomd.xml` with no updateinfo entry | Repository is a successful non-match; continue |
| Valid updateinfo snapshot with no matching authoritative advisory | Continue |
| Valid match | Complete this occurrence and stop its traversal |
| Transport failure, timeout, 403, other non-success response, unsafe redirect/path, malformed metadata, integrity failure, resource-limit failure, gzip failure, or XML failure | Mark the occurrence incomplete; do not treat a lower-priority repository as definitive |

An absent repository or updateinfo entry is not interpreted as Product
lifecycle, deprecation, or access-policy evidence.

An incomplete repository stops traversal for that occurrence in the current
invocation; neither later repositories in the same tier nor the historical tier
may produce a mutation. A persistently failing higher-priority repository can
therefore defer the occurrence indefinitely until that repository produces a
complete outcome. This conservative availability trade-off is accepted because
`released_at` is irreversible. It is observable through occurrence failures and
`FetcherRun` history; there is no timeout-based downgrade, operator override,
or persisted failure counter.

## HTTP and Redirect Contract

Requests use `Accept-Encoding: identity` so HTTP content coding cannot hide the
bounded repository representation. A `repomd.xml` response must have base media
type `application/xml` or `text/xml`. An updateinfo artifact must have base media
type `application/gzip` or `application/x-gzip` and gzip magic bytes. Media-type
parameters are permitted and ignored after syntactic validation. A compatible
media type never substitutes for structural, checksum, or size validation.

The shared no-redirect default remains in force. The detector may manually
accept at most one redirect for a metadata artifact only when all of these
conditions hold:

- the original request was constructed from the validated configured HTTPS
  base;
- the response has exact status 302 with a valid absolute `Location`;
- the target scheme is HTTPS and the exact hostname is `dist.suse.de`;
- the target has no explicit port;
- the target has no user information, query, or fragment;
- the complete target path is byte-for-byte identical to the expected source
  request path; and
- the target path independently passes the path-safety rules above.

Any other 3xx status or target, a second redirect, an HTTP downgrade, a
port or path change, a malformed location, or path traversal fails the
repository. Generic automatic redirect following is not compliant with this
contract. No credential is sent or forwarded on either request.

## Repomd Contract

`repomd.xml` must be a complete XML document with root local name `repomd` in
the exact namespace `http://linux.duke.edu/metadata/repo`. Sentinel consumes
only `data` children in that namespace whose exact `type` is `updateinfo`.

- Zero updateinfo entries is a valid repository non-match.
- Exactly one entry supplies the artifact.
- More than one updateinfo entry is ambiguous and fails the repository.

The selected entry must contain exactly one each of `location`, `checksum`,
`open-checksum`, `size`, `open-size`, and `timestamp` in the repomd namespace.
The checksum elements each require one supported `type` and a lowercase or
uppercase hexadecimal value of the exact algorithm length. Size and timestamp
values are canonical unsigned decimal integers with no sign, fraction, or
whitespace. Sizes must satisfy the resource limits below, and the location must
satisfy the artifact-location contract. Missing, duplicate, empty, malformed,
unknown, or conflicting consumed fields fail the repository. Unknown
non-consumed elements or attributes do not change the result.

### Checksums

The accepted checksum names are:

| Repomd name | Algorithm | Use |
|---|---|---|
| `sha256` | SHA-256 | Normal current repositories |
| `sha` | SHA-1 | Verified reachable legacy repositories only |

MD5, missing or unknown algorithm names, malformed hexadecimal values, and
conflicting duplicates are rejected. Both compressed and open checksums are
required and must match the complete actual compressed and decompressed bytes.
SHA-1 here is a transfer/snapshot consistency check under authenticated TLS; it
is not treated as collision-resistant artifact authenticity.

## Resource and XML Safety

The following limits are fixed engineering constants, not environment variables
or fetcher settings:

| Resource | Limit |
|---|---:|
| `repomd.xml` transfer | 64 KiB |
| `repomd.xml` XML depth | 16 |
| `repomd.xml` total elements | 10,000 |
| Compressed updateinfo | 32 MiB |
| Open updateinfo | 256 MiB |
| Compression ratio | 100:1 |
| Updateinfo XML depth | 32 |
| Updateinfo total elements | 1,000,000 |
| Updateinfo `update` elements | 50,000 |
| Updateinfo `package` elements | 500,000 |

For either response, one non-negative decimal `Content-Length` is accepted when
present. Duplicate, signed, non-decimal, or conflicting values fail the
repository. Reject before body consumption if the value exceeds the applicable
transfer limit or, for updateinfo, disagrees with the repomd compressed size.
When it is absent, stream the body and abort on the first byte over the limit.
After reading, actual bytes must equal `Content-Length` when present. The
updateinfo compressed and open byte counts must also equal the respective
repomd declarations.

Before decompression, reject a declared open size over 256 MiB, a compressed
size over 32 MiB, or a declared open-to-compressed ratio over 100:1. Enforce the
same absolute and ratio limits incrementally while decompressing. A zero-byte
compressed artifact is invalid.

The updateinfo representation must contain exactly one complete gzip member
with a valid header, trailer, CRC, and ISIZE. Decompression must reach end of
stream and consume all compressed bytes. Concatenated members and any trailing
data, including zero padding, fail the repository. Truncation or an interrupted
stream never yields candidates.

Both XML documents are parsed incrementally. DTDs and entity declarations are
rejected; only predefined XML character entities are accepted. No external
entity, schema, XInclude, XSLT, file, or network resolver is installed. Depth
and element counts are enforced while parsing, and the parser must finalize the
complete document. An overflow, malformed document, unsupported construct, or
partial parse is a repository data failure, never a successful non-match.

## Snapshot Consistency

One repository examination uses this bounded consistency protocol:

1. Fetch and validate `repomd.xml` as R1.
2. Fetch, decompress, checksum, and completely parse the exact updateinfo
   artifact declared by R1.
3. Fetch and validate `repomd.xml` again as R2 before applying any mutation.
4. Accept candidates only when R1 and R2 have the same updateinfo identity
   tuple: location, compressed checksum name/value, open checksum name/value,
   compressed size, open size, and timestamp.
5. If the tuple changed or disappeared, discard all candidates and restart the
   repository once using R2 as the new first metadata snapshot.
6. If the tuple changes or disappears again, mark the repository incomplete for
   this invocation.

Changes to unrelated repodata entries do not invalidate the updateinfo
snapshot. A consistency restart is the only permitted second artifact
download for that repository in one invocation.

## Updateinfo and Advisory Validation

The decompressed document must have root local name `updates` and no namespace.
An `update` element is an advisory. Sentinel permits unknown non-consumed
elements and attributes but applies the following contract to every advisory
considered for a mutation:

- `status` and `type` attributes are required non-empty strings;
- exactly one non-empty `id` child is required. The ID must be 1-255 ASCII
  characters, start with an alphanumeric character, contain only
  alphanumerics, `.`, `_`, `:`, `+`, or `-`, and contain no whitespace or
  control character;
- exactly one `issued` child with one non-empty `date` attribute is required;
- exactly one `references` child and one `pkglist` child are required;
- `references` must contain at least one `reference`, and every `reference`
  requires non-empty `type` and `id` attributes;
- `pkglist` must contain at least one `collection`, and the combined collection
  must contain at least one `package`; and
- source entries follow the exact contract below.

A malformed advisory is ignored as a whole without invalidating structurally
valid sibling advisories. A malformed XML document or a document-level resource
violation still fails the complete repository.

Exact duplicate references and package entries collapse before matching. An
advisory ID repeated with identical consumed content collapses to one advisory.
If variants with one ID disagree in any consumed status, type, issued,
reference, or package content, every variant under that ID is invalid. Duplicate
evidence never multiplies mutations or metrics.

### Issued time

`issued/@date` is canonical unsigned decimal Unix seconds: ASCII digits only,
with no sign, fraction, whitespace, timezone text, or fixed digit-count
assumption. It must be non-negative, representable as a UTC datetime, and no
later than the updateinfo `timestamp` from the accepted repomd snapshot.
Malformed or out-of-range issued time invalidates that advisory only.

For one occurrence in the first successfully matching repository, select the
earliest issued time among all matching authoritative advisories. If more than
one advisory has that time, use the lexically smallest advisory ID as the audit
context. The selected value is deterministic within the accepted repository
snapshot. It is not claimed to be the globally earliest publication across
repositories not scanned after the occurrence matched.

## Exact Source-Package Match

Only advisory `package` entries whose exact `arch` is `src` or `nosrc` can
establish source-package identity. Binary entries are not joined through
`primary.xml` and do not participate in matching.

Each source entry requires non-empty `name`, `epoch`, `version`, `release`,
`arch`, and `src` attributes. `epoch` must be canonical unsigned decimal. The
other identity values must be ASCII, contain no whitespace or control
characters, and contain no `/`, `\\`, `%`, `?`, or `#`. `name` must also match
`[A-Za-z0-9][A-Za-z0-9._+-]{0,254}` so it fits the persisted package identity.

After those checks, the exact `src` value must be:

```text
src/{name}-{version}-{release}.src.rpm
```

for `arch="src"`, or:

```text
nosrc/{name}-{version}-{release}.nosrc.rpm
```

for `arch="nosrc"`. No leading slash, extra segment, encoding, normalized
alternative, or filename parsing fallback is accepted. Cross-validating the
separate attributes with the conventional path avoids ambiguous parsing when
names, versions, or releases contain hyphens.

After validation, `package/@name` is the source package identity. Compare it by
exact, case-sensitive equality with the occurrence's
`TicketPackage.package_name`. Missing, malformed, path-unsafe, unsupported, or
ambiguous source metadata invalidates that advisory and produces no mutation.

One advisory may match multiple represented source-package occurrences, and
each is evaluated independently. Several NVRs for one source name collapse to
one source-name match. Title matching, binary-prefix matching, longest-name
selection, and `primary.xml` fallback are not used. The contract intentionally
prefers a visible, retryable false negative over an irreversible false-positive
release mutation.

## Reconciliation Boundary

Periodic execution and per-Ticket catch-up apply the same system-only,
idempotent reconciliation behavior to a collection of existing occurrence IDs.
Duplicate IDs are processed once; an empty collection returns without HTTP or
mutation work. The boundary returns one terminal outcome per selected
occurrence:

| Outcome | Meaning |
|---|---|
| `updated` | This invocation changed `released_at` from NULL to the selected issued time |
| `no_op` | The occurrence completed without mutation: no match, or concurrent work had already set it |
| `failed` | Repository reconciliation or the local transaction did not complete |

The result ordering is not significant and is not persisted or exposed by an
API. Repository results and parsed updateinfo documents are deduplicated by
exact repository identity within one invocation and reused for all dependent
occurrences. The required R1/R2 consistency fetches and one permitted restart
do not violate this rule. No response body, parsed document, validator, cursor,
or no-match result is retained across invocations in PostgreSQL, Redis, or the
local filesystem.

Candidate selection also retains the expected Ticket, package occurrence, and
track occurrence for each Product occurrence. Together these values form the
semantic locator passed to the package mutation boundary after I/O. Its concrete
in-memory representation is an implementation choice.

Known repository, advisory, scope-race, and per-occurrence database failures are
converted to per-occurrence outcomes so siblings continue. `SoftTimeLimitExceeded`,
`MemoryError`, failure to enumerate a trustworthy candidate set, and unexpected
failures that prevent trustworthy outcomes propagate to the workflow owner.

### Local mutation and concurrency

All repository I/O, decompression, parsing, and candidate selection complete
before any Ticket lock. Each matching occurrence is then an independent
caller-owned transaction:

1. reload the occurrence and lock its parent Ticket;
2. verify its Ticket, CVE, package, Product, and IBS workflow scope still match
   the selected evidence;
3. if `released_at` is already non-NULL, return a concurrent/idempotent no-op;
4. otherwise call `package_service.set_product_released_at()` with the complete
   semantic locator, selected UTC issued time, and advisory ID; and
5. commit once.

`package_service` is the only owner of the mutation, Ticket reconciliation, and
the atomic `product_released` event. A database, audit, or reconciliation
failure rolls back the complete occurrence transaction. If the Ticket moved to
`Ignored` or `Duplicated`, or the occurrence/CVE/workflow identity changed, the
occurrence fails without mutation. An in-flight occurrence selected while
active may complete after the Ticket becomes `Resolved`, consistent with the
operable-Ticket factual-update contract.

Concurrent periodic, catch-up, or retry invocations serialize on the Ticket
lock. Only the first effective NULL-to-timestamp change mutates or emits an
event; later invocations receive the package service's `no_op` result and
preserve the first committed timestamp. Irreversibility means that contemporaneous
snapshots cannot replace the committed value.

## Irreversibility, Audit, and Observability

`released_at` irreversibility is defined by
`package_service.set_product_released_at()`. The detector never attempts to
clear or replace a committed value. Current non-stable advisories are ignored
for new mutations.

An effective mutation emits exactly one system-attributed `product_released`
event through `package_service`, with the selected issued time and advisory ID
defined in `ticket-audit-log.md`. No-match, malformed or retracted advisory,
repository failure, duplicate evidence, and idempotent/concurrent no-op outcomes
create no Ticket audit event and no durable state. Audit history is never used
as current release state.

Operational logging is structured and bounded:

| Event | Level | Frequency and fields |
|---|---|---|
| `ibs_product_release_repository_failed` | WARNING | Once per failed repository validation per invocation; `repository`, `affected_occurrence_count`, `reason_category`, optional `http_status` |
| `ibs_product_release_advisories_ignored` | WARNING | At most once per repository and reason category per invocation; `repository`, `reason_category`, `advisory_count` |
| `ibs_product_release_occurrence_failed` | WARNING | At most once per selected failed occurrence per invocation; `ticket_package_product_id`, `repository`, `reason_category` |
| `ibs_product_release_run_completed` | INFO | Once per periodic or catch-up invocation; selected, updated, no-match/no-op, and failed occurrence counts |

`reason_category` is a bounded internal value. It distinguishes at least
transport, timeout, HTTP status, redirect, unsafe path, content type, size,
checksum, gzip, XML structure, resource limit, snapshot changed, malformed
advisory, scope changed, Ticket not operable, and database/audit failure. Logs
never include raw response bodies, XML text, advisory titles, unsafe source
values, URLs containing configuration, credentials, or personal identifiers.
Advisory IDs are included only in the service-owned audit event after full
validation.

## Fetcher: `detect_ibs_product_releases`

| Property | Value |
|---|---|
| Fetcher name | `detect_ibs_product_releases` |
| Class name | `DetectIbsProductReleases` |
| Base class | `BaseFetcher` |
| Description | Reconcile unreleased active-Ticket IBS Product occurrences against validated updateinfo advisories |
| Schedule | Daily at 04:00 UTC (`0 4 * * *`) |
| Source | Anonymous IBS Product download infrastructure (`IBS_DOWNLOAD_BASE_URL`) |
| Scope | Unreleased Product occurrences below IBS tracks of active Tickets with a CVE; exclusion, eligibility, affectedness, delivery, EOL, and actionability do not narrow scope |
| Auth | None |
| `participates_in_catch_up` | `True` — custom per-Ticket catch-up |
| Custom settings | None |
| HTTP read timeout | 120 seconds per request |

### Algorithm

`DetectIbsProductReleases.execute()`:

1. Select and snapshot the occurrence IDs and source identities in [Scope](#scope).
2. Build current and historical repository tiers and deterministic order for
   every occurrence.
3. Reconcile occurrences under the shared repository, metadata, advisory,
   source-match, and per-occurrence transaction contracts above, reusing each
   validated repository result within the invocation.
4. Commit or roll back each matching occurrence independently. Continue after
   known per-occurrence failures; never mutate from a partial repository parse.
5. Record the metrics below from terminal occurrence outcomes and return
   normally after mixed outcomes. A whole-run failure that prevents trustworthy
   candidate enumeration or outcomes escapes to `BaseFetcher`.

This state-based complete scan is also first-run, re-enable, and long-gap
recovery. It has no distinct backfill mode, cursor, temporal window, or
persistent cache.

### Catch-Up

`DetectIbsProductReleases.catch_up(ticket_id, session)` is a custom non-CVE
catch-up under `fetcher-infrastructure.md`. The supplied session is used only to
verify the Ticket and enumerate its unreleased Product occurrence IDs after
package-tree re-resolution. A missing Ticket, a Ticket without a CVE, or no
relevant occurrence returns silently.

Catch-up applies the same current/historical repository tiers, complete
validation, timestamp selection, per-invocation deduplication, and independent
per-occurrence transactions as periodic execution. Advisories that predate the
Ticket or reactivation remain discoverable and retain their original issued
time. Per-occurrence failures are logged and siblings continue. Partial success
returns normally; when every selected occurrence fails, catch-up propagates
according to the shared non-CVE `run_catch_up` contract. Concurrent catch-up and
periodic execution are idempotent under the local mutation rules.

The daily fetcher retries every still-unreleased failed occurrence. An
administrator can accelerate a complete retry with the existing generic manual
fetcher trigger. No detector-specific endpoint or durable catch-up progress
state is introduced.

### Error Handling

Shared transport retries apply before the detector classifies a request. Known
repository and local failures produce the terminal occurrence behavior defined
above. A failure in one shared repository is logged once at repository level
and counts each dependent selected occurrence at most once, regardless of HTTP
retry count, validation stage, or how many of its repositories were attempted.

If candidate enumeration fails, the fetcher raises `FetcherError` with the
sanitized public message `"Failed to enumerate IBS Product release candidates"`.
Unexpected escaping exceptions use the shared `BaseFetcher` sanitization. Raw
upstream data and internal URLs never enter the public `FetcherRun.error_message`.

### Metrics and Run Status

- `record_created()` is never called; the detector creates no domain record.
- `record_updated()` is called once per occurrence effectively changed from
  `released_at = NULL` to the selected issued time by this invocation.
- `record_failed()` is called at most once per selected occurrence whose
  reconciliation did not complete.
- Successful no-match, already-released race, duplicate evidence, and repeated
  idempotent outcomes do not increment created or updated.

Fetcher status follows the shared `BaseFetcher` precedence. A normal return
with failures and no effective updates is `failure` under the all-items-failed
rule, even when some occurrences completed as successful no-ops. Failures plus
at least one effective update produce `partial`; no failures produce `success`.

## Testing Requirements

Future implementation tests must cover:

- exact active-Ticket, Ticket-CVE, unreleased, and IBS-workflow selection,
  including excluded, EOL, ineligible, and final-track occurrences;
- current-first and historical-fallback traversal, deterministic suffixless and
  architecture ordering, lexical tiebreakers, and per-occurrence stop behavior;
- one advisory matching multiple represented source packages without sibling
  suppression;
- 404, no-updateinfo, no-match, 403, transport, timeout, and lower-priority
  suppression after an incomplete higher-priority repository;
- base URL, repository name, artifact path, and the exact one-redirect policy,
  including credential absence on every request;
- repomd namespace/cardinality, checksum algorithms, declared and actual sizes,
  R1/R2 equality, one restart, and repeated snapshot change;
- every resource ceiling, `Content-Length` shape, media type, magic, gzip CRC,
  truncation, concatenated members, trailing bytes, ratio overflow, DTD/entity,
  depth/count overflow, parser finalization, and interrupted body;
- stable security, non-security with CVE, retracted, malformed, empty-package,
  duplicate-ID, conflicting-ID, duplicate-reference, and duplicate-package
  advisories;
- canonical issued seconds, epoch boundary, out-of-range and post-metadata
  values, multiple matching advisories, equal-time ID tiebreaking, and UTC
  persistence;
- exact `src` and `nosrc` entry paths with hyphenated names, multiple NVRs,
  binary-entry exclusion, malformed attributes, path traversal, and exact
  case-sensitive package matching;
- one independent transaction per occurrence, mutation/audit/reconciliation
  atomicity, rollback, active-to-inactive races, and concurrent first-write
  idempotency;
- per-invocation repository reuse without cross-run cache, cursor, Redis, or
  filesystem state;
- periodic and catch-up partial/all-failed outcomes, exact metrics and inherited
  run statuses; and
- bounded logs, sanitized public errors, exactly one service-owned positive
  audit event, and no event for every non-mutating outcome.

Implementation-time contract tests must use freshly verified, sanitized
representative fixtures for current, historical, suffixless, architecture-
specific, LTSS, ESPOS, source/debug, non-RPM, absent, and no-updateinfo
repositories. An observed anonymous 403 and hostile malformed upstream payloads
are not prerequisites for implementation; synthetic fixtures exercise their
specified behavior.

## External Contract Verification Status

Sanitized read-only verification on 2026-09-03 covered current, historical,
suffixless, architecture-specific, module, LTSS, ESPOS, extended-security,
debug/source, Debian/Ubuntu, missing, and no-updateinfo repository families.
Across representative updateinfo documents, verification observed stable and
retracted security advisories, non-security advisories containing CVEs,
duplicate CVEs across advisories, `src` and `nosrc` source entries, multiple
source packages in one advisory, unsigned Unix issued seconds, and both current
SHA-256 and reachable legacy SHA-1 repomd checksums.

Representative live HTTP responses established anonymous access, direct
`repomd.xml` retrieval as `application/xml`, `updateinfo.xml.gz` as
`application/x-gzip`, and a single same-path HTTP 302 from
`download.suse.de` to `dist.suse.de`. Downloaded compressed/open bytes matched
repomd sizes and checksums. Measured samples remained within the fixed limits
above; the largest measured updateinfo was 4,817,145 compressed bytes,
37,369,379 open bytes, depth 6, 221,719 total elements, 2,697 advisories, and
75,558 package entries.

No anonymous 403 or hostile upstream document was observed. Those are defined
failure shapes, not claims about current repository policy. Implementation must
freshly verify representative live responses and retain sanitized fixtures as
required by `docs/conventions.md` (External Integration Contract Verification).
Any contradiction in a consumed field blocks parser implementation and must be
resolved in the specification; it does not authorize fallback behavior.

## Cross-references

- `docs/features/packages/package-model.md` — release dimension, IBS scope, and
  active-Ticket convergence
- `docs/features/packages/product-catalog.md` — ProductRepository current and
  historical associations
- `docs/features/packages/package-service.md` — sole release mutation and audit
  owner
- `docs/features/integrations/ibs-integration.md` — anonymous Product repository
  download boundary
- `docs/features/platform/networking.md` — shared HTTP/TLS defaults and narrow
  redirect exception
- `docs/features/platform/fetcher-infrastructure.md` — BaseFetcher lifecycle,
  metrics, status, and catch-up
- `docs/features/tickets/ticket-audit-log.md` — `product_released` event payload
- `docs/data-model.md` — `TicketPackageProduct.released_at`
- `docs/data-sources.md` — IBS source and fetcher registry
- `docs/configuration.md` — `IBS_DOWNLOAD_BASE_URL` operator reference
