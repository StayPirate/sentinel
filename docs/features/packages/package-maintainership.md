# Package Maintainership

## Purpose

Associate existing active Sentinel users with the individual
`TicketPackage` occurrences they maintain. These durable associations provide:

1. package-provenance visibility for confidential Tickets;
2. package-wide maintainer workbench filtering; and
3. a user-facing `maintainer` filter on the Ticket list.

Sentinel uses **maintainership** as its only package-ownership concept. It does
not preserve the IBS distinction between `bugowner` and `maintainer`. SMELT
`GET /api/experimental/v2/packages/{package_name}/maintainership` is the sole
external boundary for discovering both IBS and Git/SLFO maintainers. Sentinel
does not call IBS owner, person, or group endpoints for this feature.

Maintainership is package-associated authorization and work-routing metadata.
It is not a fourth package dimension and does not affect affectedness,
eligibility, or delivery. Those three dimensions remain independent as defined
in `docs/features/packages/package-model.md`.

## Domain Semantics

### Package-wide scope

A `TicketPackageMaintainer` applies to one `TicketPackage` occurrence. The
associated user maintains every track below that occurrence, regardless of
`TicketPackageTrack.workflow_type` or reference. The association does not apply
to a same-named package on another Ticket unless that other occurrence is
acquired separately.

SMELT's maintained-package and maintainership endpoints expose different
codestream namespaces. Maintained-package entries describe delivery/update or
compose targets; maintainership entries can identify the project where the
assignment originated. Sentinel MUST NOT compare, join, persist, or infer a
mapping between these codestream sets. `data[].codestream` from maintainership
is contract context only and never scopes an association to a track.

### Add-only acquisition

Associations are immutable and additive:

- a later SMELT omission, empty response, malformed response, or request
  failure never removes an existing association;
- package, track, or Product exclusion never deletes an association;
- Ticket status and confidentiality changes never delete an association; and
- user deactivation does not delete an existing association.

Only a later successful package-resolution invocation can add newly available
associations. There is no unresolved-email table, maintainership history,
identity-provisioning hook, periodic fetcher, freshness marker, cleanup, or
revocation synchronization.

## Data Model

### TicketPackageMaintainer

`TicketPackageMaintainer` is the immutable junction between one package
occurrence and one existing Sentinel user. See `docs/data-model.md` for the
authoritative schema.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PK | Standard UUIDv7 identifier |
| `ticket_package_id` | UUID | FK(ticket_package.id) ON DELETE RESTRICT, NOT NULL | Maintained package occurrence |
| `user_id` | UUID | FK(user.id) ON DELETE RESTRICT, NOT NULL | Existing Sentinel user acquired as maintainer |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Acquisition time |

**Unique constraint**: `(ticket_package_id, user_id)`.

The model has no `updated_at`: rows are write-once and are never updated or
deleted by application workflows. `TicketPackage.maintainers` and
`User.maintained_packages` use explicit `back_populates`. A non-unique index on
`user_id` supports caller-first confidential-visibility and workbench queries;
the unique constraint supports package-first acquisition and duplicate
prevention. No other index is required by current queries.

Both foreign keys use `ON DELETE RESTRICT`. Users are deactivated rather than
deleted, Tickets are never deleted, and package removal is a soft deletion of
`TicketPackage`; hard deletion therefore is not an application operation.

## SMELT Contract

### Endpoint

```text
GET /api/experimental/v2/packages/{url_encode(package_name)}/maintainership
```

The request uses the same configured SMELT API origin, shared async HTTP client,
TLS trust, timeout, and transport retry policy as other SMELT requests. It is an
unauthenticated, non-paginated GET. The package path segment is URL-encoded.
Sentinel sends no codestream filter.

The response shape below is source-inspected from merged SMELT MR
`tools/smelt!1992` (merge commit
`4448a860c1581c8031a70edba39239cbb61241f7`, successful pipeline). The
production endpoint still returned its legacy string arrays during sanitized
verification on 2026-09-03. Deployed-contract
verification MUST be completed before implementation begins: deployed OpenAPI
and representative live responses must verify every consumed field and
behavior. The merged source contract is sufficient to specify Sentinel
behavior, but it is not yet a deployed-and-verified implementation contract.

SMELT issue `tools/smelt#1461` concerns population of the collective group
email only. Sentinel neither consumes nor persists that field, so that issue is
informational and does not block specification or implementation.

### Successful response

HTTP 200 uses a JSend success envelope:

```json
{
  "status": "success",
  "data": [
    {
      "codestream": {
        "name": "Fictional:Product:Origin",
        "url": "https://example.com/fictional-origin"
      },
      "users": [
        {"username": "jdoe", "email": "maintainer.one@example.com"}
      ],
      "groups": [
        {
          "name": "fictional-maintainers",
          "email": null,
          "members": [
            {"username": "asmith", "email": "maintainer.two@example.com"}
          ]
        }
      ]
    }
  ]
}
```

Source-inspected field shape:

| Field | Shape and nullability | Sentinel use |
|---|---|---|
| `status` | required string; successful value is `success` | Envelope validation |
| `data` | required array; may be empty | Iteration; empty means no maintainers |
| `data[]` | object | Structural validation |
| `data[].codestream` | required object; source defines link fields including `name` and `url` | Validate object type only; never consume, persist, or join inner values |
| `data[].users` | required array | Direct-user traversal |
| `data[].users[]` | object with required string `username`; optional nullable string `email` | Consume only non-null `email` |
| `data[].groups` | required array | Group traversal |
| `data[].groups[]` | object with required string `name`, optional nullable string `email`, and `members` defaulting to an empty array | Traverse only `members` |
| `data[].groups[].members[]` | object with required string `username`; optional nullable string `email` | Consume only non-null `email` |

Sentinel validates the complete envelope, `data`/`users`/`groups` collection
types, element object types, the codestream object, and every consumed `email`
value's string-or-null type. An omitted optional `email` is equivalent to null;
an omitted `members` field is equivalent to its source-defined empty-array
default. A malformed consumed structure rejects the **entire** maintainership
response; Sentinel never grants from a partially valid response.

The parser does not require or semantically validate unconsumed values beyond
the enclosing source shape needed to identify the response: usernames, group
names, collective group emails, codestream names/URLs, and unknown additional
fields cannot create an association. This deliberately avoids making
authorization availability depend on collective metadata that Sentinel does
not trust or store. The deployed-contract verification must correct this
specification before implementation if requiredness or nullability differs.

### Missing and invalid responses

- HTTP 404 uses a JSend error envelope with string `status = "error"` and a
  string `data` message; after the maintained-package request has already found
  the package, this is a non-blocking upstream inconsistency, not
  package-not-found for the main operation. The message is never logged.
- HTTP 200 success with `data = []`, entries whose user/member emails are all
  null, and groups with empty members are valid no-maintainer outcomes.
- Any transport failure after shared retries, any other HTTP status/envelope
  combination, invalid JSON, unrecognized JSend status, or schema failure is an
  invalid maintainership result.

Every missing or invalid result becomes an empty normalized email set for that
invocation. The package-tree operation continues and existing associations are
untouched. Emit one WARNING-level
`package_maintainership_acquisition_unavailable` structured event with
`ticket_id`, `package_name`, and a bounded reason category such as `transport`,
`http_status`, `package_missing`, `envelope`, or `schema`. It MAY include the
HTTP status and exception class name, but MUST NOT include response bodies,
email addresses, usernames, group names, URLs, raw exception messages, or other
personal/infrastructure data.

## Email Extraction

For a valid response, Sentinel:

1. collects only non-null `data[].users[].email` and
   `data[].groups[].members[].email` values across every entry;
2. ignores direct/group usernames, group names, collective group email, and
   codestream values for persistence and identity resolution;
3. lowercases each collected email without deriving aliases or applying fuzzy
   matching; and
4. deduplicates the normalized values globally across the complete package
   response.

The resulting `set[str]` is an ephemeral mutation input. Email addresses are
never stored in maintainership rows or emitted in operational logs. Identity
matching is exact equality against lowercase `User.email`.

## Acquisition Workflow

### Invocation boundary

Every invocation of `add_package_to_ticket()` attempts maintainership
acquisition, including:

- manual and CVE-ingestion package additions;
- package-tree invocations that become a complete database no-op;
- IBS and Git/SLFO package results;
- Product catalog backfill; and
- Ticket convergence, including persisted soft-deleted package markers.

The ordered external phase is:

1. call and fully validate the maintained-package endpoint, resolve supported
   targets against the current Product catalog, and preserve all existing
   blocking package-target errors;
2. after target resolution succeeds, call and validate the maintainership
   endpoint, converting any maintainership-only failure to an empty email set;
3. pass resolved tracks and the normalized email set into
   `add_package_records()`; and
4. only then acquire the Ticket `FOR UPDATE` lock.

No maintainership request is made when maintained-package or Product-catalog
validation has already failed. Neither SMELT request occurs while a Ticket lock
is held.

### Locked mutation

Under the Ticket lock, `add_package_records()`:

1. applies its existing `active_ticket_only` skip before mutation; a skipped
   inactive Ticket creates neither package records nor maintainer associations;
2. creates or finds the `TicketPackage` and normal package tree;
3. queries users whose lowercase `User.email` exactly matches the supplied set
   and whose `active` value is true at this mutation time;
4. inserts one missing `TicketPackageMaintainer` per matching user, relying on
   the unique constraint as a concurrency backstop; and
5. creates the required audit event for every inserted association in the same
   caller-owned transaction.

Emails with no user match and inactive-user matches are ignored. Re-running the
operation after a user is created or reactivated can add that user. Re-running
with unchanged inputs creates no duplicate association or audit event.
Concurrent invocations for one Ticket serialize on the Ticket lock; the unique
constraint protects against any residual duplicate insert.

If maintainers are the only new records, the function MUST NOT call
`auto_assign_actor()` and MUST NOT call `reconcile_ticket_status()`.
Maintainership is system-derived authorization/workbench metadata, not
gate-relevant package state. If the package tree also changes, preserve the
existing auto-assignment, `package_added` audit, and reconciliation behavior.
Maintainer audit events remain system-attributed even when the invocation came
from a human-facing package-add request.

`AddPackageResult` and the public package-add response retain their existing
track/Product counts. They do not expose maintainer identities or add a public
maintainer count.

### Audit event

Each newly inserted association creates exactly one atomic
`package_maintainer_added` `TicketAuditEvent`. The exact field and `detail`
contract is owned by `docs/features/tickets/ticket-audit-log.md`.

The event and association use the same session and transaction. Audit failure
rolls back the association and all package-tree changes in that invocation.
Audit history is append-only evidence and MUST NOT drive authorization,
workbench filtering, restoration, or acquisition idempotency.

Existing `package_excluded` and `package_restored` events document dynamic loss
and return of access. There is no association-removal event because no normal
workflow removes an association.

## Confidential Ticket Visibility

For an authenticated caller with `caller_user_id`, a confidential Ticket is
visible when any ordinary visibility rule succeeds, including:

```text
EXISTS TicketPackageMaintainer
JOIN TicketPackage
WHERE TicketPackageMaintainer.user_id = caller_user_id
  AND TicketPackage.ticket_id = ticket_id
  AND TicketPackage.deleted_at IS NULL
```

The complete predicate is therefore: Ticket is non-confidential, caller scope
is `all`, an explicit `TicketAccessGrant` exists, **or** the included-package
maintainer predicate above succeeds. `confidential_ticket_filter()` needs no
caller email parameter. Authentication already guarantees that the caller's
current User is active.

Package exclusion disables every association below that package immediately.
Access remains if another included package qualifies. Package restore
reactivates retained associations without SMELT I/O. Track or Product exclusion
does not affect access because maintainership is package-wide. A later SMELT
omission, Ticket resolution, or user/profile email change does not revoke the
persisted user-ID association. Removing confidentiality makes all
maintainer-based restriction inert because the Ticket is public.

Maintainership grants visibility only. Capability checks remain orthogonal:
"full access" means normal Ticket visibility plus whatever operations the
caller's existing capabilities permit. Sentinel MUST NOT create an automatic
`TicketAccessGrant` for maintainership.

Associations are acquired whether or not a Ticket is confidential at the time,
so a later confidentiality change uses already persisted provenance.

## API Privacy and Filtering

Normal Ticket and package detail responses do not expose maintainer identities,
emails, groups, or association counts. `PackageDetail` contains only package
tree fields. The maintainership source response is never proxied to clients.

The existing Ticket-list ownership filter is named `maintainer`:

```text
GET /api/v1/tickets?maintainer={user}
```

`maintainer` is an optional string that accepts a User UUID or exact username
under `docs/api-spec.md` (User Identifier Resolution). Because it is a list
filter, an unknown UUID/username produces an empty result rather than 404. A
Ticket matches when the resolved `User.id` has a
`TicketPackageMaintainer` association through at least one
`TicketPackage.deleted_at IS NULL` on that Ticket. The normal confidentiality
filter, all other filters, pagination, and sorting apply independently. The API
does not accept email for this filter and returns no maintainer identity field.
The target User's current active state does not alter filtering; activity was
required at association creation and later deactivation does not delete the
historical package association.

## Workbench Dependency

The maintainer workbench identifies the authenticated caller by
`TicketPackageMaintainer.user_id`, not by email or group membership. One
association selects all actionable tracks under the included package occurrence.
The workbench's endpoint, queue, response, Ticket-status, and actionability
contracts remain owned by `docs/features/packages/maintainer.md`.

## Recovery and Accepted Limitations

Package resolution is the only acquisition trigger. There is no guaranteed
acquisition until a later trigger after:

- a transient or malformed maintainership response;
- creation or reactivation of a matching Sentinel user; or
- a new upstream maintainer assignment.

An operator can idempotently repeat the existing
`POST /api/v1/tickets/{ticket_id}/packages` for an included package. A directly
soft-deleted package returns `409 PACKAGE_ALREADY_EXCLUDED` on that public
endpoint. Package restore only reactivates retained associations and performs
no I/O. A later internal Ticket convergence workflow does resolve soft-deleted
package markers and may add associations, but they cannot grant effective
access until the package is restored. Sentinel deliberately introduces no new
operator endpoint, task, fetcher, configuration, progress state, or identity
hook for this limitation.

## Security and Privacy

- SMELT-provided individual emails are personal data used only transiently for
  exact identity matching. They are not persisted as maintainership data,
  exposed through normal APIs, or included in logs.
- Usernames, group names, collective group emails, and codestream provenance
  are not trusted identity keys and are not persisted by this feature.
- Only an existing active User can be newly associated. Authentication enforces
  active status before a retained association can be exercised by that user.
- Invalid or partial source data fails closed for **new** access while preserving
  existing durable associations. Package-tree creation remains available.
- PostgreSQL associations, not SMELT responses or audit events, are the source
  of current maintainership visibility and workbench provenance.

## Implementation Gate

Implementation MUST NOT begin until SMELT MR `tools/smelt!1992` is confirmed
deployed and deployed OpenAPI plus sanitized live responses verify field paths,
requiredness, nullability, empty/missing cases, cardinality, deduplication
behavior, 404 behavior, authentication, pagination, freshness metadata, and the
non-joinable codestream namespaces. A mismatch is a specification gap and must
be resolved in documentation before parser work. The GitHub work item tracking
this external verification remains coordination evidence, not behavioral
authority.

## Testing Requirements

Implementation coverage must include:

- success responses with direct users, groups/members, coexistence, duplicates
  across entries, null/omitted emails, omitted/empty members, and empty data;
- whole-response rejection for every malformed consumed envelope, array,
  object, and email type, plus transport, HTTP, JSON, and 404 inconsistency
  handling without package-tree failure;
- lowercase/global email deduplication, exact active-User matching, unmatched
  and inactive skips, and acquisition after later User creation/reactivation;
- additive no-removal behavior after omission/failure and package-tree no-op
  acquisition for IBS, Git/SLFO, Ticket convergence, and `active_ticket_only` race
  skip;
- concurrent invocations proving Ticket-lock serialization and the unique
  constraint backstop;
- sequential re-invocation with unchanged input producing no duplicate
  association or audit event;
- one exact atomic `package_maintainer_added` event per new association and no
  event for skipped associations, including rollback on audit failure;
- no auto-assignment or Ticket reconciliation for association-only mutation,
  with unchanged package-tree behavior when both kinds of mutation occur;
- Product catalog backfill attempting acquisition on package-tree no-ops while
  preserving its locked inactive-Ticket skip;
- confidential visibility for each scope/grant/maintainer branch, package
  exclusion/later restore, another qualifying package, track/Product exclusion,
  Resolved Tickets, non-confidential Tickets, and unauthenticated callers;
- a maintainer without the required capability remaining unable to invoke a
  capability-protected Ticket mutation despite having visibility;
- Ticket `maintainer` filtering by UUID and username, unknown-filter empty
  results, included-package semantics, confidentiality composition, and no
  email/maintainer projection in normal responses; and
- maintainer-only acquisition leaving `AddPackageResult` fields and counts
  unchanged and adding no maintainer identity or count to the public response;
- PII-free structured warnings and absence of source emails, usernames, group
  data, response bodies, and raw exceptions from logs.

## Cross-references

- `docs/features/packages/package-model.md` - package-resolution triggers,
  three dimensions, and package API
- `docs/features/packages/package-service.md` - I/O-then-lock orchestration and
  atomic mutation boundary
- `docs/features/packages/maintainer.md` - workbench consumer
- `docs/features/tickets/tickets.md` - confidential visibility and Ticket list
- `docs/features/tickets/ticket-audit-log.md` - exact audit payload contract
- `docs/features/identity/rbac.md` - scope/capability independence
- `docs/features/platform/networking.md` - shared HTTP/TLS/retry behavior
- `docs/features/platform/logging.md` - PII-free operational logs
- `docs/api-spec.md` - API and User Identifier Resolution conventions
- `docs/data-model.md` - authoritative relational schema
- `docs/data-sources.md` - SMELT source status and evidence
