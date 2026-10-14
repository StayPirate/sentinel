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

- The IBS API at `IBS_API_URL` authenticates every operation Sentinel uses
  with the SSH-signature scheme defined in
  [Request Authentication](#request-authentication). Sentinel uses no other IBS
  API authentication scheme. It never sends HTTP Basic credentials, and it does
  not use OBS API tokens, which authorize only OBS trigger operations and none
  of the read operations below. The account name and private key are
  environment variables (`IBS_USERNAME`, `IBS_SSH_PRIVATE_KEY`), never code.
  Credentials that are not configured do not block application startup;
  credentialed IBS API operations fail at runtime.
- `IBS_API_URL` is the IBS API prefix (default: `https://api.suse.de`); API
  paths such as `source/{project}` are appended to it after removing any
  trailing slash. It must use HTTPS, name a host, and contain no user
  information, query, or fragment; a non-default port is permitted. Because
  request signatures and session cookies are sent to it, an invalid value
  fails application startup with an error naming only the variable.
- `IBS_DOWNLOAD_BASE_URL` is a separate anonymous HTTPS Product-repository
  front door (default: `https://download.suse.de/ibs`). Product release
  detection does not send IBS API credentials, an `Authorization` header, or
  another credential to the download front door or its permitted redirect
  target. Its complete validation, path, and redirect contract is defined in
  `docs/features/packages/ibs-product-release-detection.md`.

#### IBS API Credentials

| Setting | Contract |
|---|---|
| `IBS_USERNAME` | Name of the IBS account, sent as the `keyId` of every signature. Not a secret. A non-empty value consists only of printable ASCII characters other than space, `"`, and `\` (U+0021 to U+007E except U+0022 and U+005C). |
| `IBS_SSH_PRIVATE_KEY` | Secret. The standard padded base64 encoding, on one line without whitespace, of the complete OpenSSH private-key file of one unencrypted Ed25519 key registered for that account. The decoded file starts with its `-----BEGIN OPENSSH PRIVATE KEY-----` line and ends with its `-----END OPENSSH PRIVATE KEY-----` line, optionally followed by one line break; its lines are separated by LF. |

The IBS API credentials are **configured** only when both settings are
non-empty. When either is empty or unset, the application starts and logs a
warning naming the empty settings, and every credentialed IBS API operation
fails as specified in [Request Authentication](#request-authentication).

A non-empty value that violates its contract fails application startup with an
error naming only the variable. The value is never trimmed or otherwise
altered. For `IBS_SSH_PRIVATE_KEY`, a violation includes invalid base64, a
decoded value that is not exactly one OpenSSH-format private key file, a key
encrypted with a passphrase, and every key type other than Ed25519. The error
never includes the value, part of it, or a parser detail derived from it.
Ed25519 is the only supported key type: the key is generated for this account
alone, and a single signature algorithm leaves no algorithm or hash selection to
negotiate. The single-line encoding lets every environment mechanism, including
an environment file, carry the key unchanged.

Sentinel never writes the private key to a file, sends it, logs it, includes it
in an error, or gives it to a subprocess or an SSH agent as an argument, input,
or file. Like every setting supplied through the environment, the encoded value
is present in the environment that subprocesses inherit. Signatures are computed
in process; Sentinel does not run `ssh-keygen`, `ssh-agent`, `osc`, or another
external program to sign. Only the per-request signature derived from the key
is sent.

#### Request Authentication

`IBSClient` authenticates each credentialed operation reactively:

1. When the IBS API credentials are not configured, the operation raises
   `IBSCredentialsNotConfiguredError` without an HTTP request. Method input
   validation precedes this check.
2. The request is sent without an `Authorization` header. It carries the
   client instance's session cookie when one is held (see
   [Session Reuse](#session-reuse)).
3. A response other than HTTP 401 is that operation's response; authentication
   is not involved. In particular, an HTTP 403 authorization failure follows
   the operation's escaping outcomes and is never answered with a signature.
4. On HTTP 401, the client discards every session cookie it holds and examines
   every `WWW-Authenticate` value of the response. Challenges and their
   parameters are parsed as defined by RFC 9110 (section 11.6.1, including
   several challenges in one value); parameter names are case-insensitive, and
   a quoted value is unescaped before validation and use. It continues only when
   exactly one challenge uses the scheme `Signature` (case-insensitive), that
   challenge's `realm` is non-empty and consists only of printable ASCII
   characters (U+0020 to U+007E), and its `headers` parameter is absent or
   exactly `(created)`. Other parameters of that challenge, and challenges of
   other schemes such as `Basic`, are ignored and never answered. In every
   other case, the operation raises `IBSAuthenticationError` with reason
   `unsupported_challenge` and makes no further request.
5. The client computes one signature:
   - `created` is the current Unix time in whole seconds, from the system
     clock;
   - the signed message is the ASCII string `(created): ` followed by `created`
     in decimal, without a line break;
   - the signature is an OpenSSH SSHSIG version 1 signature
     (`PROTOCOL.sshsig`) over that message, with the challenge `realm` as its
     namespace, hash algorithm `sha512`, and signature algorithm
     `ssh-ed25519`; and
   - its header value is the standard padded base64 encoding of the complete
     binary SSHSIG blob, without the armor lines or line breaks.
6. The client resends the same method, URL, and body exactly once with this
   header, using the parameter names, order, and quoting shown; `created` is an
   unquoted decimal integer:

   ```text
   Authorization: Signature keyId="{IBS_USERNAME}",algorithm="ssh",headers="(created)",created={created},signature="{signature}"
   ```

7. An HTTP 401 response to the signed attempt raises `IBSAuthenticationError`
   with reason `signature_rejected`; the client does not sign again for that
   operation. Any other response is the operation's response.

Each attempt keeps the shared transport retry policy
(`docs/features/platform/networking.md`, Transport-Level Retry). A transport
retry of the signed attempt resends the same signature. One operation
therefore makes at most one unsigned and one signed attempt. Redirects are
never followed, so neither the signature nor a session cookie reaches another
destination.

The realm is taken from the challenge rather than compared with a fixed value.
It is the SSHSIG namespace, but only the TLS-validated `IBS_API_URL` origin can
supply it, and the signed message always has the fixed form above, so a
signature only authenticates the account to that origin. A changed realm text
therefore does not interrupt operation. IBS rejects a signature whose
`created` differs too far from its own clock; the accepted window is
unverified. The clocks of hosts running Sentinel must therefore be synchronized
(`docs/deployment.md`, Clock Synchronization).

`IBSAuthenticationError` carries exactly one bounded reason,
`unsupported_challenge` or `signature_rejected`, which consuming workflows may
use as their reason category. It never carries challenge content, the realm,
the account name, or response data.

`IBSCredentialsNotConfiguredError` and `IBSAuthenticationError` are not `httpx`
exceptions. They are therefore neither infrastructure failures nor retryable
conditions under `docs/features/platform/networking.md` (Infrastructure Failure
Classification, Celery Retry Classification). A prompt retry is not expected to
succeed: recovery requires correcting the account, key, key registration, or
host clock, or supporting a changed challenge.

#### Session Reuse

A successful signed response can set a session cookie. `IBSClient` keeps
cookies set by IBS API responses only in memory, for the lifetime of one client
instance, and sends them only to the `IBS_API_URL` origin. It never persists
them, shares them between client instances or processes, or depends on a cookie
name or lifetime. Correctness never depends on a session: a request whose
session IBS no longer accepts receives HTTP 401 and continues at step 4 of
[Request Authentication](#request-authentication).

#### Authentication Contract Verification Status

Sanitized read-only verification against the IBS API on 2026-10-12, and source
inspection of OBS, osc, and osc-tiny, established:

- `GET /about` is public. Without authentication, every operation family tested
  (targeted source info, source diff, request ID search, request point detail,
  request diff, and source history) returns HTTP 401 with an HTML
  body from the IBS front end, no cookie, and exactly one challenge:
  `WWW-Authenticate: Signature realm="Use your developer account",headers="(created)"`.
  No `Basic` challenge is offered;
- a signature for an unknown account by an unregistered Ed25519 key, and an
  unknown session cookie, each receive the same HTTP 401 challenge;
- a client signing with a registered Ed25519 key and the header form above
  succeeds for every operation family, and each successful signed login sets a
  session cookie with a 24-hour expiry; and
- the OBS API itself authenticates through a front-end proxy, a web session,
  or HTTP Basic, while the IBS front end enforces the signature scheme. OBS API
  tokens are accepted only by trigger operations.

Documentation-only verification is not sufficient for the signer, so
`IBSClient` itself was verified live and read-only on 2026-10-12 under
External Integration Contract Verification (`docs/conventions.md`), with a
registered Ed25519 key:

- its unsigned targeted source-info request received the HTTP 401 challenge,
  and the one signed attempt succeeded and set a session cookie;
- the following source-diff requests of the same client instance were
  accepted with that cookie and without a signature: none received HTTP 401,
  and the one naming a deliberately unavailable `orev` received its ordinary
  HTTP 400;
- the identical signed request, resent about two seconds later without a
  session cookie, succeeded; and
- a signature whose `created` was one hour before or after the current time
  received HTTP 401 to the signed attempt.

Not verified: the exact window within which IBS accepts `created`.

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
using their expanded source trees. `orev=0` represents an empty source tree. It
is used for a track's first observation and unavailable-history fallback, and
by submission tracking to read the issue set of a codestream package's current
state (`docs/features/packages/ibs-submission-tracking.md`, Release Discovery).

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

Both source-info and source-diff XML are processed incrementally with DTDs,
external entities, and parser network access disabled. Sentinel does not impose
an arbitrary response-byte or issue-count cap, but never accepts a truncated or
partially parsed document. The shared request and fetcher-run timeouts remain
the execution bounds.

##### Unavailable Old Revision

IBS no longer serves a source checksum whose stored source tree is absent, for
example after retention cleanup. A source diff naming such a checksum fails with
HTTP 400 and a backend status document. Example, with a fictional package and
checksum:

```xml
<status code="400" origin="backend">
  <summary>SUSE:SLE-15-SP6:Update/fictional-package/0123456789abcdef0123456789abcdef: not in repository. Either not existing or misconfigured server setting for '$nosharedtrees' setting in BSConfig.pm</summary>
</status>
```

This classification applies only to the track-release source diff
(`get_diff_issues()`); the [Request Action Diff](#request-action-diff) treats
every HTTP 400 as an incomplete result. A source-diff response identifies the
requested `orev` as unavailable only when all of the following hold:

1. the request's `orev` is a 32-character hexadecimal checksum, not `0`, and
   differs from its `rev`;
2. the HTTP status is 400;
3. the complete body is a well-formed XML document, parsed under the safety
   boundary above, whose root is a no-namespace `status` element with exactly
   one `summary` child element; and
4. the text of that `summary` starts with exactly
   `{project}/{package}/{orev}: not in repository`, where the three values are
   the project, package, and `orev` of the request. The comparison is
   case-sensitive and applies no trimming or other normalization.

The `code` and `origin` attributes, the text after that prefix, and other child
elements are not consumed. The summary names the checksum IBS failed to
resolve. IBS resolves `rev` before `orev`, so a summary naming `orev` also
establishes that the current `rev` was available, while an unavailable `rev`
produces the same shape naming `rev`. A summary naming `rev`, a link target, or
another project or package does not satisfy condition 4.

Every other response keeps its ordinary outcome and is never treated as
unavailable history. This includes:

- a 400 that names another checksum;
- a 404, such as `no such revision` for an unknown numeric revision, or the
  response for an unknown package or project;
- a 401, handled by [Request Authentication](#request-authentication);
- a 403; and
- every other 4xx.

A response that satisfies only some conditions is ambiguous and keeps its
ordinary outcome. Examples are a 400 whose body is empty, malformed, or
differently shaped, and a matching summary with another status. A 400 body
that fails to parse for this classification keeps the HTTP error outcome and
never becomes a response-data error. An interrupted body remains a transport
failure.

If IBS changes the summary text, the classification stops matching.
Unavailable history then becomes an ordinary diff failure that retains the old
checkpoint; a changed text never produces a false fallback. The response body,
including its summary, is never logged.

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
- unknown or unavailable revision references produce 400 or 404, depending on
  the reference form.

OBS source inspection established that `added`, `changed`, and `deleted`
describe changes to issue references extracted from package changes files.

The sanitized source-info and source-diff contract fixtures captured on
2026-10-12 also established that:

- a requested package that does not exist in the project is not omitted from
  source info: its entry carries an `error` child and no `srcmd5`, so it is an
  error-bearing entry rather than a missing one; and
- a source diff without issue references, observed between identical
  revisions, has no `issues` element. A source diff without an `issues`
  element, or with an empty one, is therefore a valid empty issue set.

Sanitized read-only verification on 2026-10-11 and 2026-10-12, using fictional
checksums, established the unavailable-revision shapes in
[Unavailable Old Revision](#unavailable-old-revision):

- an `orev` checksum without a stored tree returns HTTP 400 with the backend
  status document shown there, naming the requested project, package, and
  `orev`. The shape is the same with `expand=1` for linked packages, packages
  without a link, and packages inherited through a project link;
- an unavailable `rev` returns the same shape naming `rev`, also when `orev` is
  `0` or is unavailable as well; and
- a numeric `orev` without a matching revision returns HTTP 404 with the
  summary `no such revision`, and an unknown package or project returns HTTP 404
  with its own summary.

OBS source inspection established that the summary is produced when the stored
tree of a checksum is missing. A checksum that was never stored and one whose
tree was removed by retention cleanup take the same backend path. Inspection
also established that the source diff resolves `rev` before `orev` and that the
summary text has been unchanged since at least 2016.

A historical expanded checksum whose tree was actually removed was not verified
live: obtaining an old expanded checksum requires an expanding request, which
can recreate its tree. Contract fixtures therefore use the fabricated-checksum
responses, whose backend path is the same.

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
| `source_package_prefix` | No | Non-empty prefix of `source/@package`; only with `maintenance_incident`. Proposes SR candidates. |
| `target_package_prefix` | No | Non-empty prefix of `target/@package`; only with `maintenance_release`. Proposes RR candidates. |

Exactly one package prefix is required. The two approved searches are:

- open SR discovery: `maintenance_incident`, states `new` and `review`, and the
  source-package prefix `{logical_package}.`; and
- open RR discovery: `maintenance_release`, states `new` and `review`, and the
  target-package prefix `{logical_package}.`.

The action type and the package prefix belong to the same action
(`action[@type=… and starts-with(…)]`), and the supplied states are combined
with that action predicate, so only the requested action/state/package shape
can match.

The response is an XML collection with a required non-negative `matches` count
and zero or more positive request IDs. The result is complete only when every
entry is structurally valid, IDs are distinct, and the returned count equals
`matches`. A count mismatch, malformed successful response, or ambiguous
candidate set is incomplete evidence, never a negative result. This ID-only
search applies no upstream result limit; the configured result limit of IBS
applies only to the full request search, which Sentinel does not use. After
shared rate-limit handling, any 4xx from this read-only search except `401` or
`403`, such as a rejected predicate, is an incomplete `RequestEvidenceResult`. An
authentication failure raises `IBSAuthenticationError` (see
[Request Authentication](#request-authentication)), and a `403` authorization
failure propagates as an HTTP error. The endpoint has no offset-pagination
contract.

IBS matches package names case-insensitively, so a returned request can name a
package that differs from the predicate only in letter case; the exact package
is validated from point detail. Returned IDs are not ordered by number, and the
result carries no order.

Every returned ID is point-fetched. A package prefix proposes candidates but
does not establish logical package identity. Point detail decides the exact
action, logical package, and codestream under
`docs/features/packages/ibs-submission-tracking.md` (Package and Codestream
Identity). In particular, Sentinel does not include `target/@releaseproject` in
the search predicate because the deployed search engine rejects that predicate;
it validates the field from point detail instead.

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

`source/@rev`, when present, is a positive decimal revision number or a
lowercase 32-character hexadecimal checksum. It is an input of the
not-accepted [Request Action Diff](#request-action-diff) form only.

When `<acceptinfo>` is present, Sentinel consumes these optional attributes:

| Attribute | Contract | Use |
|---|---|---|
| `rev` | Positive decimal revision number of the accepted target package | Provenance |
| `srcmd5` | Lowercase 32-character hexadecimal checksum | Provenance and diff input |
| `xsrcmd5` | Lowercase 32-character hexadecimal checksum | Diff input only |
| `osrcmd5` | Lowercase 32-character hexadecimal checksum | Diff input only |
| `oxsrcmd5` | Lowercase 32-character hexadecimal checksum | Diff input only |
| `oproject` | IBS name | Diff input only |
| `opackage` | IBS name | Diff input only |

Diff inputs build the [Request Action Diff](#request-action-diff). A diff input
that is not also a provenance field is never compared, persisted, or substituted
for a provenance field. Other acceptinfo attributes are not consumed. Missing
optional elements or attributes are represented as absent typed values, not
empty strings. Omission can make provenance incomplete, but it is not by itself
malformed response data. A present `source/@rev` or consumed acceptinfo
attribute that is empty or violates its contract makes the request observation
incomplete.

Every consumed project and package value (`source/@project`, `source/@package`,
`target/@project`, `target/@package`, `target/@releaseproject`, and acceptinfo
`oproject` and `opackage`) is an **IBS name**: 1 to 255 characters, each an
ASCII letter or digit, `_`, `.`, `:`, `+`, or `-`, and neither `.` nor `..`.
OBS restricts project and package names to these characters. None of them ends
a path segment, a query parameter, or a quoted XPath string literal; path
segments and query values are still percent-encoded, so a `+` in a query value
is sent as `%2B`. A supported action whose consumed project or package value is
not an IBS name makes the request observation incomplete.

IBS request actions have exactly eight types: `submit`, `delete`, `add_role`,
`set_bugowner`, `change_devel`, `release`, `maintenance_incident`, and
`maintenance_release`. Sentinel supports `maintenance_incident` and
`maintenance_release`. Actions of the other six types are ignored and never
become Sentinel request actions; for example, a submission request pairs its
`maintenance_incident` action with a `delete` action for its staging project,
and kernel release requests contain `submit` actions for channel packages. An
action of any other type makes the request observation incomplete. Patchinfo is
not an action type: a release request carries the incident's `patchinfo`
package as the source package of `maintenance_release` actions, which are
parsed like every other supported action. Unknown elements and attributes are
ignored. A supported action with a missing or malformed required field also
makes the observation incomplete.

**Projects outside the `SUSE:` namespace.** A request action can name a project
outside the `SUSE:` namespace, such as a personal `home:` project whose name
identifies a person. After validation, the parser replaces every consumed
project value that does not start with exactly `SUSE:` by the fixed token
`_redacted_`. The token does not start with `SUSE:` and is not a valid OBS
project name, because OBS project names cannot start with `_`, so it never
equals a real project. No project name outside the `SUSE:` namespace leaves the
parser: typed values,
semantic identities, and every comparison and persisted value derived from
point detail use the replaced value. Two supported actions of one request whose
semantic identities become equal through the replacement make the request
observation incomplete.

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

#### Request Action Diff

```text
POST /source/{project}/{package}?cmd=diff&view=xml&withissues=1&onlyissues=1&{form}
```

This POST is semantically read-only. It returns the issue references of one
supported request action, computed by the source diff of that action's own
packages. Sentinel does not use the request diff
(`POST /request/{request_number}?cmd=diff`): when the source link of any one
action of a request cannot be expanded, it fails for the whole request, and its
response always carries complete file diffs, including changes-file text that
contains personal data. With `onlyissues=1`, the response carries issue
references without file names or diff text.

The form follows how IBS builds the diff of a request action. An action is
**accepted** when its point detail has `<acceptinfo>`; every other action is
**not accepted**, whatever its request state. In the table, `xsrcmd5`,
`srcmd5`, `oxsrcmd5`, `osrcmd5`, `oproject`, and `opackage` are the acceptinfo
attributes:

| Form | `{project}/{package}` | `{form}` parameters |
|---|---|---|
| Accepted | `target/@project` / `target/@package` | `rev` = `xsrcmd5`, or `srcmd5` when `xsrcmd5` is absent; `orev` = `oxsrcmd5`, or `osrcmd5` when `oxsrcmd5` is absent, or `0` when both are absent; `oproject` and `opackage`, each only when present |
| Not accepted | `source/@project` / `source/@package` | `expand=1`; `rev` = `source/@rev`; `oproject` = the codestream, which is `target/@releaseproject` of a `maintenance_incident` action and `target/@project` of a `maintenance_release` action; `opackage` = the caller-supplied logical package of that codestream |

These fallbacks select diff inputs only.

The accepted form is the diff IBS shows for an accepted action: it compares the
stored source states before and after acceptance. The not-accepted form
compares the request source with the current codestream package, as IBS shows
an open request. The old package resolves through its own link and through
project links, and `expand=1` expands both sides; the logical codestream
package gives the same result as the previous incident package that IBS
selects. Without `expand=1`, a linked source would be compared unexpanded and
report its entire changelog as added, so a not-accepted action is never diffed
without it. The not-accepted form deliberately differs from IBS in these cases:

- IBS omits `expand=1`, and diffs against the link target's package, for an
  action whose source package is a local link to a package carried by another
  action of the same request, and for an action that updates its link.
  Sentinel always expands against the codestream package, so such an action's
  diff includes the changes of its link target.
- IBS diffs a package that does not yet exist in the codestream against an
  empty tree. Sentinel's diff names the missing old package, receives HTTP 404,
  and is incomplete.
- IBS diffs the current source of an action without `source/@rev`. Sentinel
  requests no diff for it, and the result is incomplete.

The diff is not requested, and the result is incomplete, when a required form
input is absent (accepted form: `target/@project`, `target/@package`, or both
`xsrcmd5` and `srcmd5`; not-accepted form: `source/@rev`), or when the path
project or `oproject` is not a `SUSE:` project. The last rule keeps every
project outside the `SUSE:` namespace out of request URLs; point detail has
already replaced such a project by `_redacted_`. A not-accepted action from such
a project therefore has no available diff.

Example response, with fictional values:

```xml
<sourcediff key="0123456789abcdef0123456789abcdef">
  <old project="SUSE:SLE-15-SP6:Update" package="fictional-package" rev="3"
       srcmd5="fedcba9876543210fedcba9876543210"/>
  <new project="SUSE:Maintenance:40001" package="fictional-package.SUSE_SLE-15-SP6_Update"
       rev="0123456789abcdef0123456789abcdef" srcmd5="0123456789abcdef0123456789abcdef"/>
  <files/>
  <issues>
    <issue state="changed" tracker="cve" name="2026-1234" label="CVE-2026-1234"/>
    <issue state="added" tracker="bnc" name="1234567" label="bsc#1234567"/>
  </issues>
</sourcediff>
```

The response must be one completely parsed `<sourcediff>` document. Only
`issues/issue` is consumed; `old`, `new`, `files`, and issue attributes other
than `tracker`, `state`, `name`, and `label` are not. A diff without an
`issues` element, or with an empty one, is a valid empty issue set.

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
no-match for that action. An HTTP 400 or 404 response makes the action's diff
incomplete, and its body is not consumed. Observed causes are a source link
that no longer expands against the current codestream (400 with a backend
status document), a removed request staging project, and a codestream without
the old package (404). A malformed, interrupted, or partially parsed diff is
also incomplete. The consuming reconciliation decides whether an action's diff
is required; an incomplete diff never proves a negative and never deletes or
invalidates retained request/action history. The diff of a not-accepted action
can become permanently unavailable once its link conflicts with the current
codestream or its staging project is removed.

#### Package Source History

```text
GET /source/{project}/{package}/_history
GET /source/{project}/{package}/_history?rev={revision}
```

Source history supplies request provenance for incident and codestream package
contents. `project` is a `SUSE:` project and `package` is an IBS name (see
[Request Point Detail](#request-point-detail)). Without `rev`, the response is
the complete available history of the package. With `rev`, it is an exact
lookup: `revision` is either a positive decimal revision number or a lowercase
32-character hexadecimal source checksum. Sentinel never sends `limit` or
`startbefore`: the IBS API does not forward `startbefore`, so history cannot be
paged, and `limit` returns only the newest revisions.

The response is a completely consumed `<revisionlist>` of `<revision>` entries
in ascending revision order. Each consumed entry requires:

| Field | Form | Contract |
|---|---|---|
| `rev` | Attribute | Positive decimal revision number. |
| `srcmd5` | Child element | Lowercase 32-character hexadecimal source checksum. |
| `time` | Child element | Non-negative Unix seconds, converted to an aware UTC datetime. |
| `requestid` | Optional child element | Positive public request number; omission is preserved as absence. |

Other attributes, such as `vrev`, and other child elements are not consumed.
The `user` and `comment` children carry personal data and free text and are
never consumed, persisted, returned, or logged.

IBS numbers the revisions of a package from 1 without gaps. An unpaged history
is complete only when it is non-empty, its first entry is revision 1, and each
following entry is exactly one revision greater than the one before it. Any
other list is incomplete. This detects an upstream limit, which would silently
return only the newest revisions.

An exact lookup by revision number is complete when it returns exactly that
revision. A lookup by checksum returns every revision whose `srcmd5` equals the
checksum, so it can return several entries; it is complete when it returns at
least one entry, every returned entry carries that checksum, and the revisions
are distinct and ascending. A lookup that returns no entry answers HTTP 200 with
an empty `<revisionlist>`.

For a package that the project inherits through a project link, IBS returns the
history of the package in the linked project that provides it. The response does
not identify that project.

A 404 for an unknown project or package, an exact lookup that returns no entry,
and an unpaged history that is not complete are unavailable-history outcomes,
not empty successful matches. Malformed, duplicate, or conflicting entries, and
a lookup entry that does not match the requested revision or checksum, make the
observation incomplete.

Submission delivery compares history with point-detail provenance exactly;
the comparisons and their outcomes are defined in
`docs/features/packages/ibs-submission-tracking.md` (Effective SR, Release
Discovery, and Accepted RR Provenance). History `srcmd5` is the unexpanded
commit checksum, so an expanded checksum such as acceptinfo `xsrcmd5` never
matches it. An entry without `requestid` is not by itself evidence of a direct
source change: IBS typically records one before a submission acceptance (the
branch commit). After a release, the logical codestream package's new revision
carries the release request number with the checksum of its link update, while
the release action's own target package carries the released contents.

#### Request Contract Verification Status

Sanitized read-only verification against the IBS API on 2026-09-08,
2026-10-13, and 2026-10-14, and inspection of the OBS source, established the
request operations above. Request numbers, checksums, and personal fields were
never recorded.

Verified live:

- **ID search:** a `<collection>` whose `matches` equals its number of
  `request/@id` children, including `matches="0"` with HTTP 200; same-action
  predicates, the bracket form, and `starts-with` predicates on
  `source/@package` and `target/@package`; HTTP 400 `illegal_xpath_error` for a
  `target/@releaseproject` predicate; case-insensitive package matching; IDs
  not ordered by number. Every action of open submission requests came from a
  `SUSE:Maintenance:REQUEST:{n}` staging project, with a source package ending
  exactly in its release project with `:` replaced by `_`.
- **Point detail:**
  - The root `id` equals the requested number, and there is exactly one
    `state` with `name`, `created`, and `when`. The timestamps are offset-less
    UTC. `superseded_by` appears only for `superseded`. All seven state names
    were observed.
  - Requests are multi-action parents with no stable action ID or
    action-order identity, and RabbitMQ event action arrays are not complete.
  - Modern submission requests pair their `maintenance_incident` action with a
    `delete` action for the staging project. Kernel and live-patching release
    requests contain `submit` actions. Patchinfo is the source package of
    `maintenance_release` actions, and not-accepted patchinfo actions have no
    `source/@rev`.
  - Accepted `maintenance_incident` actions carry acceptinfo `rev`, `srcmd5`,
    `xsrcmd5`, `osrcmd5`, and `oxsrcmd5`, with one exception observed: among
    about 30 actions of an accepted submission request from a personal
    project, one had neither acceptinfo nor `target/@package`. Accepted
    `maintenance_release` actions of a package other than patchinfo carry
    `rev`, `srcmd5`, `osrcmd5`, `oxsrcmd5`, `oproject`, and `opackage`,
    without `xsrcmd5`; patchinfo actions carry only `rev`, `srcmd5`, and
    `osrcmd5`. Every observed `source/@rev` of a supported action and every
    acceptinfo checksum is lowercase 32-character hexadecimal, and every
    acceptinfo `rev` a decimal number; `submit` actions, which are ignored,
    carry a decimal or a checksum `source/@rev`. Omitted values are never
    rendered empty.
  - Accepted `maintenance_release` actions have no acceptinfo when IBS
    released the package as a link to another package of the same release
    request (for example the kernel flavors, which link to `kernel-source`)
    and in releases from before IBS recorded acceptinfo (observed in 2015).
  - Release actions name an exact `SUSE:Maintenance:{n}` source project and a
    `{logical package}.{n}` target package. Incident packages are named
    `{logical package}.{origin}`, the origin being the release project or,
    when the submitted source links elsewhere, the branch origin, such as an
    incident or an openSUSE project preceding the release project.
  - HTTP 404 `not_found` answers an unknown, zero, or non-numeric request
    number.
- **Request action diff:**
  - For accepted and not-accepted actions of submission and release requests,
    including open, superseded, revoked, and declined requests, the issue set
    equals the one in the request diff for the same action. The responses
    were 0.6 to 91 kB, against 10 kB to 1.4 MB for the request diff.
  - Using the logical codestream package as `opackage` gives the same result
    as the previous incident package that IBS derives. An old package
    inherited through a project link resolves.
  - An unexpandable link fails only that action (HTTP 400 with a backend
    status document), where the request diff fails the whole request with
    HTTP 404. A removed staging project and a missing old package return
    HTTP 404.
  - Without `expand=1`, a not-accepted action reports its entire changelog as
    added.
  - Issues carry `state`, `tracker`, `name`, `label`, and `url`, including the
    `changed` state.
- **Source history:**
  - The unpaged history is complete; the largest observed history has 86
    revisions in 26 kB. `startbefore` is ignored and `limit` returns the
    newest revisions.
  - Every checked history (14) was numbered from 1 without gaps, with the
    field forms above.
  - A numeric `rev` returns that revision, and a checksum `rev` returns every
    revision with that checksum. An unknown revision or checksum returns HTTP
    200 with an empty list, and an unknown project or package returns HTTP
    404.
  - An inherited package returns the linked project's history. Some entries
    have no `requestid`.
  - In sampled codestream histories, 5,524 of 5,563 revisions carry a
    `requestid`, and every sampled one names an accepted release request with
    a release action for that package and codestream. In incident histories,
    a revision without `requestid` (the branch commit) typically precedes a
    submission revision.
  - The acceptinfo `srcmd5` of an accepted submission action equals the
    `srcmd5` of its incident-history revision. The acceptinfo `rev` and
    `srcmd5` of an accepted release action equal the exact lookup of its own
    target package, whose revision carries the release request number. The
    acceptinfo `xsrcmd5` of a submission equals the `source/@rev` of its
    release action in every sampled release since 2024 and in most of 2023,
    but rarely before: earlier release requests recorded a differently
    expanded checksum.

Established only by OBS source inspection:

- the ID-only search has no result limit, which applies only to the full
  request search;
- the closed set of eight action types;
- a declined request can return to `new` or `review`;
- revision numbering from 1 without gaps survives package deletion,
  undeletion, and history-preserving project copies, and the API forwards no
  `startbefore` and applies no default `limit`;
- how IBS builds the diff of a request action, including the cases in which
  the not-accepted form deliberately differs;
- an `accepted` request cannot change state again, and acceptinfo is recorded
  once, at acceptance;
- the derivation of incident package names from the branch origin, and the
  release of local-link packages as links without acceptinfo.

Documentation-only, not verified: HTTP 403 outcomes; `deleted` on a maintenance
request; an action of an unknown type; a supported action missing a required
field; malformed or interrupted bodies and U+0000 (synthetic test data only);
an accepted action with neither `oxsrcmd5` nor `osrcmd5`; a not-accepted action
whose source is a local link carried by another action of the same request, or
that updates its link; and a not-accepted action for a package that does not yet
exist in the codestream.

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
  fields sufficient for its consumers to evaluate `tracker`, `state`, and
  `label`. It does not reinterpret `bnc` names as CVE IDs. A response that
  identifies `old_md5` as unavailable under
  [Unavailable Old Revision](#unavailable-old-revision) raises
  `IBSHistoricalRevisionUnavailable`, which the detector's fallback consumes.
  Every other HTTP or response-data failure, including an unavailable
  `new_md5`, remains distinct from successful empty results.
- `search_request_ids(action_type: IBSRequestActionType, *, states:
  Collection[IBSRequestState] | None = None, source_package_prefix: str | None
  = None, target_package_prefix: str | None = None) ->
  RequestEvidenceResult[RequestIdSearchResult]`: calls the ID-only search with
  an internally constructed narrow predicate. Before HTTP I/O it rejects:
  - unsupported action types and an empty state collection;
  - calls supplying neither or both prefixes;
  - a source-package prefix with `maintenance_release`, or a target-package
    prefix with `maintenance_incident`.

  Each prefix must be an IBS name (see
  [Request Point Detail](#request-point-detail)). A complete result contains
  distinct positive request numbers and the reported match count.
- `get_request(request_number: int) ->
  RequestEvidenceResult[IBSRequestDetail]`: point-fetches one positive request
  number. A complete result contains the typed parent plus every supported
  typed action (`IBSRequestActionDetail`) exposed by the complete REST detail.
  It validates the exact seven-state value, UTC timestamp interpretation,
  state/supersession relationship, action types, action-required fields, the
  consumed acceptinfo attributes, IBS names, and semantic action identities. It
  replaces every project outside the `SUSE:` namespace as specified in
  [Request Point Detail](#request-point-detail). A detail 404 is an incomplete
  result rather than a synthetic deleted state.
- `get_request_action_diff(action: IBSRequestActionDetail, *,
  codestream_package: str) -> RequestEvidenceResult[RequestActionDiff]`: diffs
  one supported action of a complete `IBSRequestDetail` with the semantically
  read-only [Request Action Diff](#request-action-diff). It selects the accepted
  form when the action has acceptinfo, and the not-accepted form otherwise.
  `codestream_package` is the logical package of the action's codestream,
  supplied by the caller from its package identity; it must be an IBS name and
  is used only by the not-accepted form. A missing form input or a project
  outside the `SUSE:` namespace is an incomplete result without a request. A complete result contains the action's typed issues with `tracker`,
  `state`, `name`, and `label` preserved for the owning reconciliation to
  evaluate; `changed` evidence is not filtered out.
- `get_source_history(project: str, package: str, *, revision: str | None =
  None) -> RequestEvidenceResult[SourceHistory]`: without `revision`, reads the
  complete unpaged history; with `revision`, performs the exact lookup by
  revision number or checksum specified in
  [Package Source History](#package-source-history). It rejects names that are
  not IBS names, a project that does not start with `SUSE:`, and a `revision`
  that is neither a positive decimal number nor a lowercase 32-character
  hexadecimal checksum before HTTP I/O. A complete result contains the typed
  revision number, checksum, UTC time, and optional request number of each
  returned entry, in ascending revision order.

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
| Invalid or empty method input, including an unbounded request search, a name input that is not an IBS name, a request-operation project input outside the `SUSE:` namespace, or an invalid source-history revision | `ValueError` before HTTP I/O |
| IBS API credentials not configured: `IBS_USERNAME` or `IBS_SSH_PRIVATE_KEY` is empty or unset | `IBSCredentialsNotConfiguredError` before HTTP I/O, after method input validation |
| Authentication rejected: HTTP 401 to the signed attempt, or an HTTP 401 without exactly one supported `Signature` challenge | `IBSAuthenticationError` with reason `signature_rejected` or `unsupported_challenge`; no further request for that operation |
| Transport failure, timeout, rate limit, or HTTP error other than an authentication failure, an identified unavailable source-diff old revision, or an operation-specific incomplete-evidence response, after shared retry handling. This includes an HTTP 403 authorization failure and every other `get_diff_issues()` 400 or 404 | The corresponding `httpx` exception propagates with the response body excluded from application logs |
| Malformed/interrupted successful `get_source_info()` or `get_diff_issues()` XML, or its document-level schema failure | `IBSResponseDataError` |
| One requested source-info package missing, duplicated, error-bearing, or carrying an invalid `srcmd5` | A per-package failed result in the returned mapping; valid sibling package results remain usable |
| `get_diff_issues()` response identifies `old_md5` as unavailable under [Unavailable Old Revision](#unavailable-old-revision) | `IBSHistoricalRevisionUnavailable` |
| `get_diff_issues()` response contains an issue with an unusable structural shape | `IBSResponseDataError` |
| `get_diff_issues()` response is valid and contains no qualifying issue | Empty list |
| Request ID search reports inconsistent successful-response completeness or leaves candidate identity ambiguous | Incomplete `RequestEvidenceResult` |
| Request ID search receives a 4xx other than 401 or 403 after shared rate-limit handling, including a predicate rejection | Incomplete `RequestEvidenceResult`; it never proves a negative |
| Request detail is 404, has an unknown state or an action type outside the eight IBS types, has an invalid supersession relationship, omits a required supported-action field, has an invalid consumed field or IBS name, or has two supported actions with one semantic identity, including through project replacement | Incomplete `RequestEvidenceResult` |
| Request detail contains only actions of the six ignored types | Complete typed parent with an empty supported-action collection |
| Request action diff cannot be requested (missing form input, or a project outside the `SUSE:` namespace), returns HTTP 400 or 404, or is malformed, interrupted, or partial, including an issue without a non-empty `tracker` or `state` | Incomplete `RequestEvidenceResult`; retained correlation and delivery evidence is not invalidated |
| Source history is 404, an exact lookup returns no entry, an unpaged history is not complete under [Package Source History](#package-source-history), or an entry is malformed, duplicated, conflicting, or does not match the lookup | Incomplete `RequestEvidenceResult` |
| Request action diff is complete and has no positive `added` or `changed` canonical CVE issue for an action | A valid typed action diff with no qualifying issue; the owning reconciler treats it as that action's successful no-match |

`IBSResponseDataError` and `IBSHistoricalRevisionUnavailable` are internal
integration exceptions caught by the Track detector; submission reconciliation,
which reads current release evidence through `get_source_info()` and
`get_diff_issues()` against the empty tree, catches `IBSResponseDataError`.
They never reach an API handler.
`IBSCredentialsNotConfiguredError` and `IBSAuthenticationError` are
internal integration exceptions that every method can raise. Each consuming
workflow handles them as a failure of the scope that depended on the operation,
with its own bounded reason category; they never reach an API handler and never
represent a negative observation. Submission reconciliation consumes incomplete
`RequestEvidenceResult` values and preserves prior request, action,
correlation, and delivery state for that scope. It does not convert unavailable
evidence into a no-match. `IBSHistoricalRevisionUnavailable` is raised only
when every condition of [Unavailable Old Revision](#unavailable-old-revision)
holds, and it carries no response content.

All request-search, point-detail, request-action-diff, and source-history XML
uses the same incremental parsing safety boundary as source release data: DTDs,
external entities, and parser network access are disabled, and no result is
accepted until the complete document has parsed. Raw XML, response bodies,
actor data, free text, and project names outside the `SUSE:` namespace never
enter logs. A parser or interrupted-body failure produces
the error or incomplete result assigned to that operation above. A document
containing U+0000, raw or as a character reference, is not well-formed XML and
produces that parser failure, which satisfies External String Admissibility
(`docs/conventions.md`).

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
`IBS_USERNAME`, `IBS_SSH_PRIVATE_KEY`).

**HTTP client infrastructure**: `IBSClient` uses the standalone HTTP
client factory (`backend/app/services/http_client.py`) directly, with
the following overrides:

- `Accept: application/xml` (IBS API returns XML, not JSON)
- SSH-signature authentication and in-memory session cookies as specified in
  [Request Authentication](#request-authentication) and
  [Session Reuse](#session-reuse); redirects are not followed
- TLS validated against the SUSE Trust Root CA via the combined trust
  store (see `networking.md`, TLS Trust Store
  Configuration)
- Transport-level retry active (4 attempts for 5xx/timeout/connection
  errors)
- Client lifetime: one client instance per workflow invocation, reused for
  every request of that invocation and closed before it ends. In a Celery
  role, each task invocation runs its own event loop, so its workflow creates
  the client on that loop and closes it before returning; the IBS RabbitMQ
  consumer runs one event loop and uses one client for its process. A client
  never crosses an event loop and is never held at module level. Its session
  cookies therefore last at most one invocation or consumer process (see
  [Session Reuse](#session-reuse))

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

**Retry safety for POST operations**: IBSClient's source-diff `cmd=diff` POST
operations (`get_diff_issues()` and `get_request_action_diff()`) are
semantically read-only; they compute a response
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

1. The application warns at startup when the IBS API account name or SSH
   private key is empty or unset, and credentialed IBS API operations then fail
   without an HTTP request; anonymous Product repository downloads never
   consume those credentials
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
- In staging and production, the IBS API account is a dedicated, non-personal
  account whose Ed25519 key is generated for it and used for no other purpose
- The IBS SSH private key is never sent; only per-request signatures derived
  from it are sent, and only to the `IBS_API_URL` origin
- Sentinel's log statements and errors never include key material,
  `Authorization` header values, signatures, session cookies, or
  `WWW-Authenticate` challenge content
- Product repository downloads are anonymous and never attach or forward IBS
  API credentials, signatures, or session cookies
- Request evidence treats every project name outside the `SUSE:` namespace,
  such as a personal `home:` project, as a personal identifier: point detail
  replaces it by a fixed token, and no request operation places it in a request
  URL, so it reaches neither persisted evidence nor `httpx` request logs (see
  [Request Point Detail](#request-point-detail) and
  [Request Action Diff](#request-action-diff)). Request action diffs request
  issue references only, never file diffs
- Operations that modify IBS/OBS state (future: rebuild triggers) require
  the Vulnerability Analyst or Admin role
- XML parsers disable DTDs, external entities, and parser network access;
  authenticated response bodies are never written to logs
