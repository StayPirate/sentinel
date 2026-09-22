# Ticket References

## Purpose

Ticket references are curated external links that help Vulnerability Analysts
research a Ticket. They may point to advisories, patches, commits, pull
requests, issue trackers, mailing-list posts, or other relevant web resources.

References have one of two ownership classes:

- **Automatic references** are created and updated by CVE fetchers. Their
  `source` is the stable `BaseFetcher.name` of the owning fetcher. Users cannot
  edit or delete them.
- **Manual references** are created through the Ticket reference API. Their
  `source` is exactly `manual`; any user with the `manage_references`
  capability and access to the parent Ticket may edit or delete them.

Both classes use the same URL validation, normalization, identity, storage,
classification, and projection contracts. All references are stored in the
single `TicketReference` table. This specification does not introduce a
history or per-source table, outbound URL validation, a record cap, pagination
state, or a generic ingestion framework.

## Data Model

`docs/data-model.md` owns the schema. The relevant entities are
`TicketReference` and the `ReferenceType` classification enum.

### ReferenceType

| Value | Meaning |
|---|---|
| `advisory` | Security advisory, vulnerability database entry, or vendor notice |
| `patch` | Patch, commit, pull request, or merge request |
| `issue` | Bug or issue tracker entry |
| `article` | Write-up, mailing-list post, or other technical article |

`NULL` means uncategorized. It is a valid persisted and API value, not another
enum member.

### TicketReference

| Column | Type | Contract |
|---|---|---|
| `id` | UUID | Public identifier for the nested reference resource |
| `ticket_id` | UUID | Parent Ticket foreign key; part of URL identity |
| `url` | VARCHAR(2048) | Validated and normalized URL; unique with `ticket_id` |
| `title` | VARCHAR(500), nullable | Human-readable label |
| `description` | VARCHAR(2000), nullable | Editorial context; automatic inputs leave it `NULL` |
| `type` | VARCHAR(20), nullable | `ReferenceType`, or `NULL` when uncategorized |
| `source` | VARCHAR(100) | Stable fetcher name, or exactly `manual` |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | Last effective update timestamp |

The unique constraint `(ticket_id, url)` is evaluated on the normalized URL.
It is the final database backstop for all concurrent writers.

`manual` is reserved for rows created and managed by the manual consumer
functions. An automatic caller must pass its stable
`BaseFetcher.name`, which must be non-empty, no longer than 100 characters, and
must not equal `manual`. Renaming a fetcher requires a data migration for its
existing `TicketReference.source` values; otherwise its old rows would become
different-source rows under the merge rules below.

## Semantic Types

These are service-boundary contracts. They describe typed meaning rather than
mandating dataclasses, `TypedDict`, Pydantic models, or another concrete Python
representation.

### AutomaticReferenceInput

```python
AutomaticReferenceInput(
    url: object,
    title: str | None = None,
    upstream_tags: Sequence[str] | None = None,
    explicit_type: ReferenceType | None = None,
)
```

- `url` is typed as `object` at this untrusted ingestion boundary so the
  service can apply the documented skip behavior to `None`, non-string, and
  malformed upstream values rather than relying on a false string guarantee.
- `title` is optional upstream or source-provided text.
- `upstream_tags` are optional source labels used only for classification.
  They are not persisted.
- `explicit_type` is an optional explicit `ReferenceType` hint and has the highest
  classification priority. `None` means no explicit hint.

This input is an in-memory transfer contract only. It is not a persisted
entity, API resource, or additional state. A fetcher's own human-readable CVE
page is supplied as a separate `AutomaticReferenceInput` with an explicit
title and `explicit_type = advisory`. Structured upstream inputs may likewise
provide their known title and type. For example, an OSV reference may carry
its mapped type and a Red Hat Bugzilla reference may carry its description as
the title and `explicit_type = issue`; `reference_service` does not branch on
fetcher names.

### ManualReferenceCreateInput

```python
ManualReferenceCreateInput(
    url: str,
    title: str | None = None,
    description: str | None = None,
    type: ReferenceType | None | Unset = UNSET,
)
```

`url` is required. Omitted `title` and `description` persist as `NULL`.
Omitted `type` requests URL-pattern classification; an explicit `null` stores
`NULL` and suppresses automatic classification.

### ManualReferenceUpdateInput

```python
ManualReferenceUpdateInput(
    url: str | Unset = UNSET,
    title: str | None | Unset = UNSET,
    description: str | None | Unset = UNSET,
    type: ReferenceType | None | Unset = UNSET,
)
```

The semantic input preserves supplied-field information. Omission preserves
the current value; `null` clears nullable `title`, `description`, or `type`;
`url` cannot be `null`. At least one field must be supplied. Changing `url`
without supplying `type` preserves the existing type rather than reclassifying
it.

### TicketReferenceProjection

All service responses and API `TicketReferenceResponse` objects use this
shape:

```python
TicketReferenceProjection(
    id: UUID,
    ticket_id: str,
    url: str,
    title: str | None,
    description: str | None,
    type: ReferenceType | None,
    source: str,
    created_at: datetime,
    updated_at: datetime,
)
```

`ticket_id` is the canonical `SNTL-{n}` identity, never the internal Ticket
UUID. `url` is always the persisted normalized value. Timestamps are UTC and
serialize with a `Z` suffix at the API boundary.

## URL Boundary

### URL Normalization

Automatic and manual references use exactly one service-enforced algorithm.
For each URL, in this order:

1. Require a string with at least one character. Do not trim or otherwise
   repair the input.
2. Reject a pre-parse value longer than 2048 characters or containing any
   control character U+0000 through U+001F or U+007F.
3. Parse the complete value as an absolute URL. Accept only `http` or `https`,
   case-insensitively. Require a syntactically valid, non-empty host. Reject
   any user-information component, including a username or password, whether
   or not a password is present.
4. Lowercase the scheme and host and replace `http` with `https`.
5. Remove the path slash only when it is the slash representing an otherwise
   empty root path. Preserve an explicit port, every non-root path, query, and
   fragment literally except for canonicalization required by the selected URL
   parser to produce a valid parsed URL. Do not remove a non-root trailing
   slash, a query, or a fragment.
6. Reject a normalized value longer than 2048 characters and recheck the
   scheme, host, user-information, and control-character invariants.

The resulting string is the stored URL, the input to URL-pattern
classification, and the `(ticket_id, url)` identity. For example,
`HTTP://Example.COM/` normalizes to `https://example.com`, while
`https://example.com/path/`, `https://example.com?view=full`, and
`https://example.com#analysis` retain their non-host components.

The algorithm is deliberately lexical. The service performs no DNS lookup,
address resolution, `HEAD`, `GET`, TLS handshake, redirect follow, reachability
test, or other outbound operation. It does not determine whether the resource
exists or is safe to visit.

Pydantic request schemas enforce transport shape, nullability, enum membership,
and declared string lengths. The service independently reruns all domain and
data-integrity checks for every caller. Manual service callers that violate a
typed input contract receive `ValueError`; API requests are rejected by the
corresponding Pydantic rule as `422 VALIDATION_ERROR` before service mutation.

Titles, when non-NULL, must be strings of 1 through 500 characters and must not
be whitespace-only. Descriptions, when non-NULL, must be strings of 1 through
2000 characters and must not be whitespace-only. These values are not trimmed.

### Automatic Rejection Logging

An invalid automatic candidate is skipped and processing continues. One
WARNING records only the canonical CVE ID, automatic source, and one of the
closed reason categories `url_not_string`, `url_empty`, `url_too_long`,
`invalid_url`, `invalid_scheme`, `invalid_host`, `userinfo_forbidden`,
`control_character`, or `invalid_metadata`. It never records the raw URL,
title, description, query, fragment, user information, credential material, or
an exception string that could contain those values.

Manual invalid input is rejected; it is never converted into an automatic
skip-and-continue outcome.

## Type Auto-Classification

Automatic references use the first applicable source in this order:

1. `AutomaticReferenceInput.explicit_type`.
2. A recognized `upstream_tags` mapping.
3. Pattern matching against the normalized URL.
4. `NULL`.

Manual POST uses its explicit `type`, including explicit `NULL`; only an
omitted type uses normalized-URL pattern matching and then `NULL`. PATCH never
implicitly reclassifies an existing reference.

### CVE Source Tag Mapping

NVD Title Case and MITRE kebab-case equivalents map as follows. Unknown tags
do not fail the candidate. When multiple recognized tags map to different
types, priority is `patch`, `advisory`, `issue`, then `article`.

| NVD tag | MITRE tag | Type |
|---|---|---|
| `Patch` | `patch` | `patch` |
| `Vendor Advisory` | `vendor-advisory` | `advisory` |
| `Third Party Advisory` | `third-party-advisory` | `advisory` |
| `US Government Resource` | `government-resource` | `advisory` |
| `VDB Entry` | `vdb-entry` | `advisory` |
| `Issue Tracking` | `issue-tracking` | `issue` |
| `Exploit` | `exploit` | `article` |
| `Mailing List` | `mailing-list` | `article` |
| `Release Notes` | `release-notes` | `article` |
| `Technical Description` | `technical-description` | `article` |
| `Mitigation` | `mitigation` | `article` |
| `Press/Media Coverage` | `media-coverage` | `article` |
| `Tool Signature` | `signature` | `article` |
| `Broken Link` | `broken-link` | `NULL` |
| `Not Applicable` | `not-applicable` | `NULL` |
| `Permissions Required` | `permissions-required` | `NULL` |
| `URL Repurposed` | - | `NULL` |
| `Product` | `product` | `NULL` |
| - | `customer-entitlement` | `NULL` |
| - | `related` | `NULL` |

A tag mapped to `NULL` does not prevent later recognized tags or URL-pattern
classification from supplying a type.

### URL Pattern Mapping

Patterns match host and path case-insensitively. Case-insensitive path matching
is an intentional classification heuristic; it does not alter the stored path.

| Pattern | Type |
|---|---|
| `github.com/*/commit/*`, `github.com/*/pull/*` | `patch` |
| `gitlab.com/*/commit/*`, `gitlab.com/*/-/merge_requests/*` | `patch` |
| `git.kernel.org/*/commit/*` | `patch` |
| `github.com/advisories/GHSA-*` | `advisory` |
| `github.com/*/security/advisories/*` | `advisory` |
| `nvd.nist.gov/vuln/detail/*`, `cve.org/CVERecord*` | `advisory` |
| `access.redhat.com/security/cve/*`, `access.redhat.com/errata/*` | `advisory` |
| `ubuntu.com/security/CVE-*`, `www.debian.org/security/*` | `advisory` |
| `security.gentoo.org/*`, `www.oracle.com/security-alerts/*` | `advisory` |
| `security.netapp.com/advisory/*` | `advisory` |
| `www.zerodayinitiative.com/advisories/*` | `advisory` |
| `msrc.microsoft.com/*`, `support.apple.com/*` | `advisory` |
| `www.mozilla.org/*/security/advisories/*` | `advisory` |
| `errata.almalinux.org/*` | `advisory` |
| `bugzilla.suse.com/*`, `bugzilla.redhat.com/*` | `issue` |
| `bugs.launchpad.net/*`, `savannah.gnu.org/bugs/*` | `issue` |
| `sourceware.org/bugzilla/*` | `issue` |
| `lists.fedoraproject.org/*`, `www.openwall.com/lists/*` | `article` |
| `seclists.org/*`, `www.exploit-db.com/*`, `lists.apache.org/*` | `article` |

An unmatched URL remains `NULL`. New patterns affect only references created
or effectively updated after the code change; no retroactive reclassification
is implied.

## Automatic Ingestion

### Source Reference

`BaseCVEFetcher.source_reference_url_pattern`, when non-NULL, formats a source
URL using the single `{cve_id}` placeholder. Fetchers whose page cannot be
derived from a CVE ID, such as a GHSA page, may construct the source candidate
directly. A fetcher with no human-readable page passes `source_reference=None`.

The caller supplies a source candidate with the source's explicit title and
`explicit_type = advisory`; `reference_service` does not derive labels from
the fetcher name. The source candidate remains independent from upstream
references, so callers invoke `upsert_references()` even when the upstream list
is empty.

### Deterministic Candidate Preparation

`upsert_references()` completes candidate preparation before comparing any
candidate with database state:

1. Form one ordered sequence: the optional source candidate first, followed by
   upstream candidates in their original order.
2. Validate and normalize every candidate with the shared URL and metadata
   boundary. Log and remove invalid candidates without changing the relative
   order of valid candidates.
3. Classify every valid candidate from explicit type, tags, normalized URL, and
   `NULL`, in that order.
4. Coalesce same-input candidates with the same normalized URL. The first
   candidate owns the position and every non-NULL field it supplied. Later
   duplicates only fill its missing `title` or `type` with non-NULL values.
   Because the source candidate is first and explicitly supplies its title and
   advisory type, an upstream duplicate cannot overwrite those fields.

Automatic inputs do not provide `description`; inserts use `description =
NULL`, and automatic upsert never changes an existing description.

### Database Merge Rules

Prepared candidates are applied in their deterministic order. The current
serialized database row for `(ticket_id, normalized_url)` controls each result:

- **No row**: insert the candidate with `source` equal to the automatic source.
- **Same automatic source**: update only candidate fields with a non-NULL
  prepared value. This is the merge meaning of explicitly provided: a title is
  provided only when the input carries a valid non-NULL title, and a type is
  provided only when explicit type, tags, or normalized-URL classification
  resolves to a non-NULL type. An absent title or a classification result of
  `NULL` does not clear persisted data. The source and description remain
  unchanged.
- **Different automatic source**: retain the source of the serialized first
  owner. Fill only currently `NULL` title or type fields from non-NULL candidate
  values. Never overwrite non-NULL fields or description.
- **Manual row**: leave every field untouched. This rule takes precedence over
  all fill-null behavior.

There is no stale deletion. A source removing a URL does not delete or clear
the accumulated reference.

The implementation may use any PostgreSQL/SQLAlchemy conflict mechanism that
preserves these outcomes, candidate order, and the caller's still-usable
transaction. It must not catch a unique `IntegrityError` and then query in the
same aborted transaction. A nested savepoint, conflict-aware statement,
locking, retry around an isolated candidate operation, or another equivalent
mechanism is acceptable; no particular SQL construct is mandated.

Concurrent automatic writers may serialize in either order. The transaction
that creates a new identity first owns `source`; the other observes that
current row and applies same-source or different-source rules. Concurrent
same-source writes apply explicitly supplied non-NULL fields in serialization
order. The final row must equal one valid serialized execution, and both
transactions remain usable after a handled uniqueness race.

Re-invocation with the same normalized candidates is idempotent once all
non-NULL fill opportunities are satisfied: it creates no duplicate and makes
no effective update. Reordering upstream candidates may change which duplicate
candidate supplies the first non-NULL value, so callers must preserve upstream
order.

## Mutability and Concurrency

### Manual-Zone Exception

Manual POST, PATCH, and DELETE are valid for every Ticket status, including
`Ignored` and `Duplicated`. They are explicit owning-contract exceptions to
`ensure_ticket_operable()` because they modify supplementary editorial
metadata, not Ticket workflow or package-gate state. They never assign a user,
reconcile gates, change status, or exit the manual zone, and they never return
`TICKET_NOT_MUTABLE`.

Automatic upsert likewise remains independent of Ticket status and consumer
scope. It is trusted ingestion within the owning per-CVE transaction and does
not acquire an HTTP caller's accessibility context.

### Manual Mutation Ordering

Service-level URL and field validation, including URL normalization, is
input-only work and may complete before any database access. Each manual
mutation then uses the parent Ticket as its serialization root. Its first
persistent read locks the Ticket row `FOR UPDATE`. Under that lock it performs,
in order:

1. Resolve the canonical SNTL locator and evaluate Ticket accessibility from
   locked-current Ticket and visibility-relationship state. Missing, malformed,
   and inaccessible parents raise `TicketNotFoundError`.
2. For PATCH or DELETE, resolve the reference by
   `(ticket_internal_id, reference_id)`. A missing reference or a UUID belonging
   to another Ticket raises `ReferenceNotFoundError`.
3. For PATCH or DELETE, require `source = manual`; otherwise raise
   `ReferenceNotEditableError`.
4. Evaluate any conflict for the already-normalized supplied URL. A conflicting
   different reference raises `ReferenceConflictError`.
5. Compare supplied values with locked-current persisted values. An
   equivalent-only PATCH is a true no-op.
6. Apply the effective mutation and its exact audit event or events, then flush
   all pending reference and audit writes before returning.

Capability checking occurs at the API boundary before the service performs its
first resource lookup. Accessibility denial therefore precedes nested missing,
editability, conflict, and no-op outcomes. Every audit value and URL locator is
derived from serialized current state, never stale pre-lock state.

### Race Outcomes

Manual operations on one Ticket serialize through the Ticket lock:

- **create/create, same normalized URL**: the first committed creator returns
  success with one `reference_added` event. The waiter returns
  `ReferenceConflictError` with no event. If the first transaction rolls back,
  the waiter may create normally.
- **update/update, same reference**: each committed effective update applies in
  lock order and audits its true serialized old and new values. A waiter whose
  requested state is already current is a no-op with no event.
- **update/update, different references competing for one normalized URL**: the
  first committed update claims the identity and records its true change. The
  waiter observes the locked-current conflict, raises `ReferenceConflictError`,
  and creates no event. If the first transaction rolls back, the waiter may
  update normally.
- **update/delete**: update first yields its change events, after which delete
  may remove that current row and emit `reference_deleted`. Delete first causes
  the waiting update to receive `ReferenceNotFoundError` with no event.
- **delete/delete**: the first committed delete returns 204 and emits one
  `reference_deleted`; the waiter receives `ReferenceNotFoundError` with no
  event.

Automatic upsert does not independently acquire the Ticket lock. Its calling
per-CVE transaction may already hold that lock because `upsert_cve()` acquired
it while applying Ticket-associated CVSS or lifecycle consequences; when so,
manual mutations serialize on that existing lock. Otherwise the unique key and
chosen transaction-safe merge mechanism serialize automatic/manual identity
races. Both paths have the same observable outcomes:

- If automatic insertion owns the normalized URL before manual create or a
  manual URL change, the manual operation returns `ReferenceConflictError` and
  creates no event.
- If the manual row owns the normalized URL first, automatic upsert observes a
  manual winner and leaves every field untouched.
- Automatic upsert that observes an existing manual row while a PATCH keeps
  that identity has no effect. A manual PATCH that changes identity and a
  concurrent automatic insertion produce the serialized conflict-or-manual-
  winner outcomes above.
- If manual DELETE commits before automatic processing of that URL, automatic
  upsert may create an automatic row. If automatic processing serializes
  against the existing manual row first, it leaves that row untouched and the
  later delete removes it. Either final state must correspond to the actual
  database serialization.
- If a manual PATCH moves a reference away from an identity before automatic
  processing reaches that identity, automatic upsert may create an automatic
  row at the old URL. If automatic processing observes the manual row first, it
  leaves that row untouched and the later PATCH moves it, leaving no row at the
  old URL. For a PATCH moving to the automatic candidate's identity, automatic
  first causes the manual conflict; manual first owns that identity and causes
  automatic fill behavior to skip the manual winner.
- A manual PATCH or DELETE that targets an already automatic row always reaches
  `ReferenceNotEditableError` after locked-current accessibility and scoped
  lookup. Concurrent automatic changes do not make that row consumer-editable
  and create no Ticket event.

No rejected operation, race loser, or rolled-back transaction creates an audit
event. Database, audit, or flush failure rolls back the complete caller-owned
transaction.

## Service Layer

`reference_service` owns all reference queries, mutations, URL processing,
classification, accessibility-constrained selection, and conflict handling.
API handlers and fetchers are thin callers and do not issue reference business
queries.

All functions accept a caller-supplied `AsyncSession`. They flush when needed
to expose generated IDs, persisted projections, audit rows, or constraint
failures, but never commit or roll back. The API transaction dependency or
fetcher's complete per-CVE workflow owns commit on success and rollback on any
escaping pre-finalization exception. A definitely failed commit publishes
nothing; an ambiguous commit terminates the owner without claiming rollback.
Post-commit finalization exceptions cannot roll back reference rows that already
committed. No function performs network I/O.

Request-resolved `CallerContext` below means the authenticated user ID and
effective scope for an authenticated caller, or the explicit anonymous caller.
Its concrete in-memory representation is an implementation choice. Every manual
mutation requires an authenticated caller and uses that caller's User UUID as
the audit actor. An anonymous caller at this boundary is a programming error
that raises `ValueError` before database access; an API handler must always
satisfy this precondition after its `manage_references` check.

### Service Exceptions

`ReferenceServiceError` inherits from `ServiceError`. Every module-owned
exception inherits from `ReferenceServiceError`. `TicketNotFoundError` is
shared and inherits directly from `ServiceError`, so handlers catch it
separately. Database, transaction, audit, parser-programming, and other
unexpected infrastructure exceptions are not translated into domain conflicts;
they propagate unchanged.

| Exception | HTTP | Code | Raised when |
|---|---:|---|---|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | Ticket locator is malformed, missing, or inaccessible to the caller |
| `ReferenceNotFoundError` | 404 | `RESOURCE_NOT_FOUND` | Nested reference does not exist under the accessible parent Ticket |
| `ReferenceNotEditableError` | 409 | `RESOURCE_NOT_EDITABLE` | A consumer attempts to update or delete an automatic reference |
| `ReferenceConflictError` | 409 | `RESOURCE_CONFLICT` | Another reference already owns the requested normalized URL on the Ticket |

† Shared exception; not a subclass of `ReferenceServiceError`.

API handlers catch each documented exception explicitly and map it to the
listed status and code. An optional `ServiceError` defense-in-depth fallback
does not replace those catches.

System-internal validation and infrastructure failures are distinct from API
domain conflicts:

| Exception | Raised when | Handling |
|---|---|---|
| `ValueError` | A non-API caller violates a semantic input contract, including the automatic source/CVE context or a manual field invariant | Propagate; the workflow owner rolls back |
| Database, transaction, audit, cancellation, or programming exception | The service cannot complete its documented operation for a reason other than the exact normalized-URL uniqueness conflict | Propagate unchanged; the workflow owner rolls back |

### `upsert_references()`

Category A signature:

```python
async def upsert_references(
    session: AsyncSession,
    ticket_id: UUID,
    cve_id: str,
    source: str,
    source_reference: AutomaticReferenceInput | None,
    upstream_references: Sequence[AutomaticReferenceInput],
) -> None
```

The internal `ticket_id` identifies the Ticket already established by the CVE
ingestion workflow. `cve_id` is the canonical CVE ID used only for bounded
rejection logging and must satisfy the canonical CVE identifier contract in
`docs/api-spec.md` (CVE Identifier Resolution). `source` must be the calling
fetcher's stable `BaseFetcher.name`, not `manual`.

In the authoritative ingestion order, this call follows CVE merge, unique
Ticket creation or selection, the complete trusted-external CVSS batch,
rejection or republication handling, source-success status, and the service
flush. It precedes the sole commit. The caller still owns the CVE and Ticket
locks; this service does not release them or publish an effect.

The function validates the automatic source contract, prepares every candidate
before database comparison, and applies the deterministic merge rules above.
An invalid candidate is logged, skipped, and does not prevent later candidates
from processing. An invalid automatic `source` or malformed `cve_id` raises
`ValueError` before persistent work and is not a candidate rejection. The
function does not perform a redundant parent lookup: if a write is attempted
for an absent internal Ticket, the database integrity exception propagates; if
there is no valid candidate to write, the empty operation returns `None`.

The result is always `None`. The function creates no Ticket audit event for an
insert, update, no-op, rejected candidate, or handled race. Re-invocation and
concurrency follow Automatic Ingestion. It flushes effective writes and handled
collision outcomes as needed before returning so generated state and constraint
failures are resolved inside its boundary. Unexpected database, transaction,
audit-independent infrastructure, parser-programming, cancellation, and other
errors propagate unchanged. The caller then rolls back the complete per-CVE
transaction, including CVE/source status, Ticket creation or lifecycle, CVSS,
Product eligibility, reconciliation, every audit event, and every reference
candidate; the function never converts such failures into skip-and-continue.

### `create_reference()`

Category A signature:

```python
async def create_reference(
    session: AsyncSession,
    ticket_id: str,
    caller: CallerContext,
    input: ManualReferenceCreateInput,
) -> TicketReferenceProjection
```

After the shared manual mutation ordering, normalize the URL, determine type
from explicit supplied state or URL classification, and insert a row with
`source = manual`. Return the flushed persisted projection. Create exactly one
`reference_added` event with acting `user_id`, `old_value = NULL`, `new_value`
equal to the normalized URL, and `comment = detail = NULL`.

A pre-existing normalized identity, including an automatic row, raises
`ReferenceConflictError`. Re-invocation after a successful commit is therefore
not idempotent: it conflicts and creates no second event. Before commit, caller
rollback removes both row and event. The function propagates the service
exceptions above, `ValueError` for a non-transport caller's invalid semantic
input, audit validation errors, and unexpected database/transaction errors.

### `update_reference()`

Category A signature:

```python
async def update_reference(
    session: AsyncSession,
    ticket_id: str,
    reference_id: UUID,
    caller: CallerContext,
    input: ManualReferenceUpdateInput,
) -> TicketReferenceProjection
```

Apply partial-update semantics after locked accessibility, nested ownership,
editability, and conflict checks. Normalize a supplied URL before comparison
and response projection. Omitted fields preserve current values; explicit
`NULL` clears nullable fields. A supplied URL without a supplied type preserves
the current type.

Create one event for each field whose persisted value changes, in fixed order:

1. `reference_url_changed`: old and new normalized URLs; `detail = NULL`.
2. `reference_type_changed`: old and new enum values or `NULL`;
   `detail = {"url": <post-update normalized URL>}`.
3. `reference_title_changed`: old and new title or `NULL`; same URL detail.
4. `reference_description_changed`: old and new description or `NULL`; same URL
   detail.

Every event uses the acting user and `comment = NULL`. A multi-field PATCH and
all events are one transaction. If every supplied value is equivalent to the
serialized current value, return that current projection without writing the
row, changing `updated_at`, or creating an event. Repeating an effective PATCH
with the same input is therefore a no-op after the first commit.

The function propagates the service exceptions above, `ValueError` for invalid
non-transport semantic input, audit validation errors, and unexpected
database/transaction errors. Failure or caller rollback leaves all fields,
`updated_at`, and events unchanged.

### `delete_reference()`

Category A signature:

```python
async def delete_reference(
    session: AsyncSession,
    ticket_id: str,
    reference_id: UUID,
    caller: CallerContext,
) -> None
```

After locked accessibility, scoped nested lookup, and editability checks,
delete the manual row and create exactly one `reference_deleted` event with the
acting user, `old_value` equal to its normalized URL, `new_value = NULL`, and
`comment = detail = NULL`. Flush both before returning `None`.

Re-invocation after commit raises `ReferenceNotFoundError` and creates no event.
The function propagates the service exceptions above, audit validation errors,
and unexpected database/transaction errors. Failure or caller rollback retains
the row and removes the pending event.

### `list_references()`

Category B signature:

```python
async def list_references(
    session: AsyncSession,
    ticket_id: str,
    caller: CallerContext,
    source: str | None,
    type: ReferenceType | None,
    type_was_supplied: bool,
) -> list[TicketReferenceProjection]
```

Resolve the canonical SNTL locator and select references through the canonical
Ticket visibility predicate in one database operation or equivalent coherent
PostgreSQL view. Malformed, missing, and inaccessible Tickets raise the shared
`TicketNotFoundError` before filters are evaluated. `source`, when supplied, is
an exact case-sensitive match. A valid `type` is an exact enum match. Filters
combine with AND. `type_was_supplied = True` with `type = None` represents a
supplied invalid enum value removed at the API boundary and returns an empty
list, but only after parent accessibility succeeds.

Order by fixed type priority `advisory`, `patch`, `issue`, `article`, `NULL`,
then `created_at ASC`, then `id ASC`. Return the complete unpaginated list of
projections. There is no count, cursor, page metadata, client-controlled sort,
or mutation lock. The function creates no event and does not flush. It
propagates `TicketNotFoundError` and database/transaction exceptions unchanged.

## API Schemas

Pydantic owns transport parsing and OpenAPI shape; service inputs preserve the
semantic supplied/omitted distinctions.

### TicketReferenceCreate

| Field | Type | Required | Rules |
|---|---|---:|---|
| `url` | string | yes | Shared URL boundary; maximum 2048 before and after normalization |
| `title` | string or null | no | 1-500 characters when non-NULL; not whitespace-only |
| `description` | string or null | no | 1-2000 characters when non-NULL; not whitespace-only |
| `type` | `ReferenceType` or null | no | Omitted classifies by URL; explicit null stores uncategorized |

### TicketReferenceUpdate

| Field | Type | Required | Rules |
|---|---|---:|---|
| `url` | string | no | Same URL rules; explicit null is invalid |
| `title` | string or null | no | Null clears; omitted preserves |
| `description` | string or null | no | Null clears; omitted preserves |
| `type` | `ReferenceType` or null | no | Null clears; omitted preserves |

An empty object is rejected with `422 VALIDATION_ERROR` and message `At least
one field must be provided.` `{"url": null}` is also `422 VALIDATION_ERROR`.
Pydantic distinguishes omission from explicit null.

### TicketReferenceResponse

| Field | Type | Nullability |
|---|---|---|
| `id` | UUID | non-null |
| `ticket_id` | string (`SNTL-{n}`) | non-null |
| `url` | string | non-null, normalized persisted value |
| `title` | string | nullable |
| `description` | string | nullable |
| `type` | `ReferenceType` | nullable |
| `source` | string | non-null |
| `created_at` | UTC datetime | non-null |
| `updated_at` | UTC datetime | non-null |

POST and PATCH always serialize the service's flushed persisted projection, so
their response URL is normalized even when the request used another equivalent
form.

## API Endpoints

Every `{ticket_id}` is the canonical `SNTL-{n}` locator. Each
`{reference_id}` is a TicketReference UUID and is always resolved under its
path parent. Responses use the standard `{"data": ...}` envelope except the
204 response. Global and Ticket-scoped errors derive from `docs/api-spec.md`;
endpoint tables below contain only endpoint-specific service errors.

### List References

```text
GET /api/v1/tickets/{ticket_id}/references
```

**`Access: Public`**

**`Authentication: Optional`**

Returns every automatic and manual reference visible through the parent
Ticket. The endpoint is intentionally unpaginated because references are a
small Ticket-scoped editorial collection. It makes no cursor or future
pagination compatibility promise.

| Query parameter | Type | Behavior |
|---|---|---|
| `source` | string | Exact, case-sensitive source match |
| `type` | single `ReferenceType` | Exact match; invalid values follow global enum-filter semantics |

Both filters combine with AND. A non-matching source or invalid supplied type
returns `{"data": []}` only for an accessible Ticket. Client-controlled sort
parameters are not supported; undeclared parameters are ignored. Ordering is
fixed at type priority (`advisory`, `patch`, `issue`, `article`, uncategorized),
then `created_at ASC`, then `id ASC`.

**Response: 200 OK**

```json
{
  "data": [
    {
      "id": "019b3b4e-4a00-7000-8000-000000000001",
      "ticket_id": "SNTL-42",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-3317",
      "title": "NVD",
      "description": null,
      "type": "advisory",
      "source": "sync_nvd_cves",
      "created_at": "2026-04-21T10:20:00Z",
      "updated_at": "2026-04-21T10:20:00Z"
    }
  ]
}
```

Parent accessibility has precedence over filter emptiness. A malformed,
missing, or inaccessible parent returns the scoped `TICKET_NOT_FOUND`, never an
empty collection.

### Add Reference

```text
POST /api/v1/tickets/{ticket_id}/references
```

**`Capability: manage_references`**

Creates one manual reference from `TicketReferenceCreate` and returns the
persisted `TicketReferenceResponse`.

```json
{
  "url": "http://issues.example.test/tickets/12345",
  "title": "Fictional packaging issue",
  "description": "Tracks the downstream packaging review",
  "type": "issue"
}
```

**Response: 201 Created**

```json
{
  "data": {
    "id": "019b3b4e-4a00-7000-8000-000000000002",
    "ticket_id": "SNTL-42",
    "url": "https://issues.example.test/tickets/12345",
    "title": "Fictional packaging issue",
    "description": "Tracks the downstream packaging review",
    "type": "issue",
    "source": "manual",
    "created_at": "2026-04-21T14:30:00Z",
    "updated_at": "2026-04-21T14:30:00Z"
  }
}
```

Capability denial precedes Ticket lookup. The service then locks the Ticket and
checks locked-current accessibility before conflict and creation. The endpoint
is an explicit manual-zone exception: it does not call
`ensure_ticket_operable()`, performs no assignment or reconciliation, and does
not produce `TICKET_NOT_MUTABLE` for `Ignored` or `Duplicated` Tickets.

| Status | Code | Condition |
|---:|---|---|
| 409 | `RESOURCE_CONFLICT` | Another reference owns the normalized URL on this Ticket |

### Update Reference

```text
PATCH /api/v1/tickets/{ticket_id}/references/{reference_id}
```

**`Capability: manage_references`**

Applies `TicketReferenceUpdate` partial-update semantics to a manual reference
and returns its persisted `TicketReferenceResponse`. The UUID lookup is scoped
by `(ticket_id, reference_id)`; a reference belonging to another Ticket is not
found. URL normalization occurs before conflict and equality comparison.

```json
{
  "title": "Updated fictional issue title",
  "description": null
}
```

**Response: 200 OK**

The response uses the same envelope and fields as POST. An equivalent-only
PATCH returns 200 with the current projection, creates no event, and does not
change `updated_at`.

Error precedence after capability is locked-current `TICKET_NOT_FOUND`, nested
`RESOURCE_NOT_FOUND`, `RESOURCE_NOT_EDITABLE`, normalized URL
`RESOURCE_CONFLICT`, then no-op or effective update. This endpoint is an
explicit manual-zone exception and never produces `TICKET_NOT_MUTABLE`.

| Status | Code | Condition |
|---:|---|---|
| 404 | `RESOURCE_NOT_FOUND` | Reference does not exist under this Ticket |
| 409 | `RESOURCE_NOT_EDITABLE` | Reference is automatic |
| 409 | `RESOURCE_CONFLICT` | Another reference owns the requested normalized URL |

### Delete Reference

```text
DELETE /api/v1/tickets/{ticket_id}/references/{reference_id}
```

**`Capability: manage_references`**

Deletes a manual reference selected by `(ticket_id, reference_id)`.

**Response: 204 No Content**

The response has no body. Error precedence after capability is locked-current
`TICKET_NOT_FOUND`, nested `RESOURCE_NOT_FOUND`, then
`RESOURCE_NOT_EDITABLE`. This endpoint is an explicit manual-zone exception
and never produces `TICKET_NOT_MUTABLE`.

| Status | Code | Condition |
|---:|---|---|
| 404 | `RESOURCE_NOT_FOUND` | Reference does not exist under this Ticket |
| 409 | `RESOURCE_NOT_EDITABLE` | Reference is automatic |

## Ticket Audit Events

Manual mutations use the six existing reference event types. Automatic
upsert, including effective insert and update, creates no Ticket audit event.

| Outcome | Event | `old_value` | `new_value` | `detail` |
|---|---|---|---|---|
| Manual create | `reference_added` | `NULL` | Normalized URL | `NULL` |
| Manual delete | `reference_deleted` | Normalized URL | `NULL` | `NULL` |
| URL changed | `reference_url_changed` | Previous normalized URL | New normalized URL | `NULL` |
| Type changed | `reference_type_changed` | Previous type or `NULL` | New type or `NULL` | `{"url": <post-update URL>}` |
| Title changed | `reference_title_changed` | Previous title or `NULL` | New title or `NULL` | `{"url": <post-update URL>}` |
| Description changed | `reference_description_changed` | Previous description or `NULL` | New description or `NULL` | `{"url": <post-update URL>}` |

All six use the acting user's UUID and `comment = NULL`. A multi-field PATCH
inserts events in URL, type, title, description order. Values and detail come
from serialized persisted state under the Ticket lock. The mutation and every
required event are flushed in the same caller-owned transaction.

Invalid automatic candidates, all automatic inserts/updates/no-ops, manual
validation rejection, inaccessible or missing resources, noneditable targets,
conflicts, equivalent PATCHes, concurrent losers, and rolled-back operations
create zero events. Audit history is never an input to reference state,
ownership, authorization, conflict handling, classification, or idempotency.

## Security and Privacy

- Public listing uses optional authentication and the canonical Ticket
  visibility predicate. Anonymous callers see references only for
  non-confidential Tickets.
- Manual writes require `manage_references` before resource lookup and
  locked-current Ticket accessibility before nested state is disclosed.
- Only `source = manual` rows are consumer-editable.
- The shared URL boundary rejects non-HTTP(S), hostless, credential-bearing,
  control-character, and overlength values without dereferencing them.
- Automatic validation logs contain only CVE ID, source, and a bounded reason;
  they do not expose submitted reference content.
- Service and API layers perform no DNS, HTTP, TLS, or other outbound URL
  validation, so URL submission cannot be used as an SSRF primitive in this
  feature.

## Testing Requirements

`docs/features/platform/testing-strategy.md` (Ticket References) owns the
complete URL, schema, service, API, accessibility, audit, rollback, concurrency,
transaction-usability, and zero-outbound-call matrix for this feature. Every
behavior and no-event boundary in this specification must have coverage there;
tests use independent database sessions for lock and uniqueness races rather
than simulating concurrency inside one transaction.

## Boundary with CVEExternalIdentifier

`TicketReference` is a Ticket-scoped research link. `CVEExternalIdentifier` is
a CVE-scoped identity mapping used for identifier search. A GHSA may therefore
appear in both: its identifier and canonical URL support CVE identity lookup,
while its TicketReference URL supports the analyst's research workflow. The two
records have independent ownership and lifecycle contracts.

## Dependencies and Cross-References

- `docs/api-spec.md` - envelopes, errors, authorization order, identifiers,
  filtering, and partial updates
- `docs/data-model.md` - `TicketReference`, `ReferenceType`, and uniqueness
- `docs/features/identity/rbac.md` - `manage_references`, endpoint permission
  map, and canonical Ticket visibility
- `docs/features/platform/audit-trail-infrastructure.md` - audit atomicity and
  operational-state separation
- `docs/features/platform/cve-fetcher-infrastructure.md` - CVE fetcher contract
- `docs/features/platform/fetcher-infrastructure.md` - stable fetcher identity
- `docs/features/platform/logging.md` - secrets and PII discipline
- `docs/features/platform/testing-strategy.md` - service, concurrency,
  accessibility, API, and audit testing
- `docs/features/tickets/cve-service.md` - per-CVE transaction composition
- `docs/features/tickets/ticket-audit-log.md` - exact reference event contracts
- `docs/features/tickets/tickets.md` - Ticket status and manual-zone guard
