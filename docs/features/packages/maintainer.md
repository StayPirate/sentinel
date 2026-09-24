# Maintainer Operations

## Purpose

Provide an authenticated package maintainer with four bounded workbench views:
pending fixes, in-progress delivery, completed delivery, and all three
classifications for one Ticket. The workbench is package-centric and lets a
Vulnerability Analyst share one Ticket URL without exposing work owned by
other maintainers.

The workbench is a current-state PostgreSQL projection. It does not reconstruct
historical workflow chronology or make audit or external request history the
authority for current classification.

## User Identification and Ownership

The authenticated caller is identified by `User.id`. Workbench ownership for
one row requires that same ID to have a persisted
`TicketPackageMaintainer.user_id` association through the row's parent
`TicketPackage`, with `TicketPackage.deleted_at IS NULL`. Runtime email or
group matching, newly fetched SMELT data, and audit history are not ownership
inputs.

One association is package-wide and applies to every track under its included
`TicketPackage`, regardless of `workflow_type`, reference, or which person
performed a delivery action. Track and Product exclusion do not change the
association, but they affect current actionability and therefore workbench
participation. An excluded parent package does not qualify for ownership or
visibility until restored.

Every workbench candidate independently satisfies both:

1. the canonical Ticket visibility predicate in
   `docs/features/identity/rbac.md`; and
2. the caller-owned included-package predicate above.

Neither predicate substitutes for the other. Maintainership grants no
capability, and another visibility branch does not make an unmaintained package
the caller's work. A caller with no qualifying package association receives
empty results after any required Ticket accessibility check succeeds.

## Workbench Row and Privacy Contract

One workbench item represents one exact `TicketPackageTrack`. Multiple tracks
under one package occurrence are distinct rows. Product and maintainer joins
must not fan out or duplicate that row. `TicketPackageTrack.id` is an internal
ordering tie-breaker; it is not exposed as another workbench identifier.

All workbench sections use this item schema:

| Field | Type | Contract |
|---|---|---|
| `package_name` | string | Persisted `TicketPackage.package_name` |
| `ticket_id` | string | Canonical consumer-facing Ticket identity (`SNTL-{n}`) |
| `cve_id` | string or null | Associated CVE identifier; null for a CVE-less Ticket |
| `severity` | string or null | Resolved Ticket severity: `critical`, `high`, `medium`, `low`, `none`, or null when unresolved |
| `workflow_type` | string | Persisted track workflow: `ibs` or `git` |
| `reference` | string | Persisted IBS codestream project or Git branch reference |
| `status` | string | Persisted affectedness: `analysis`, `affected`, `not_affected`, `fixed`, or `wont_fix` |
| `delivery_status` | string | Persisted delivery: `pending`, `in_progress`, or `released` |
| `submission_due_at` | string (datetime) or null | Due date of the maintainer submission milestone for this track; null when no SLA applies. See `docs/features/tickets/ticket-deadlines.md` |
| `submission_milestone` | string or null | The track's `submission` milestone status: `done`, `pending`, `overdue`, `not_applicable`, or null. Unrelated to `delivery_status = pending` |

Example:

```json
{
  "package_name": "fictional-kernel",
  "ticket_id": "SNTL-42",
  "cve_id": "CVE-2026-1234",
  "severity": "high",
  "workflow_type": "ibs",
  "reference": "SUSE:SLE-15-SP6:Update",
  "status": "affected",
  "delivery_status": "pending",
  "submission_due_at": "2026-10-12T09:15:00Z",
  "submission_milestone": "pending"
}
```

The response does not expose maintainer identity, username, email, group,
association count, source payload, or SMELT provenance. It also does not expose
or derive a submission chain, an effective SR, a proving RR, `analyzed_at`,
`first_sr_created_at`, an authoritative completion timestamp, waiting duration,
or any chronology synthesized from generic row timestamps or audit history.
The submission deadline fields are not such a chronology: they are the
remediation SLA projection defined by
`docs/features/tickets/ticket-deadlines.md`, derived from the Ticket's
immutable `created_at` and resolved severity, and they record no completion
time. The deadline is projected only on rows that satisfy a workbench
classification; a submission milestone that is overdue on a track outside every
classification (for example `FIXED` with delivery `pending`, or a track still in
`ANALYSIS`) remains visible through the track's `milestones` in the Ticket
package tree and the `overdue` filter of `GET /api/v1/tickets`.
Correlated IBS request actions and their exact current states remain available
through the Ticket
[submission-request](ibs-submission-tracking.md#list-submission-requests) and
[release-request](ibs-submission-tracking.md#list-release-requests) endpoints;
those actions are evidence associated with the track, not a uniquely
reconstructible historical chain for this projection.

## Classification

All classifications use one UTC `evaluation_date` for the complete result,
derived from one evaluation instant that also evaluates the submission
milestone, and apply the canonical actionability predicates in
`package-model.md`. Combining
affectedness, eligibility, actionability, and delivery here is an allowed
presentation gate only. It does not derive or mutate one package dimension from
another.

### Pending

A track is pending exactly when all of these conditions hold:

1. the parent Ticket status is `Analysis` or `Analyzed`;
2. the exact track is actionable;
3. `TicketPackageTrack.status = AFFECTED`;
4. `TicketPackageTrack.delivery_status = PENDING`; and
5. at least one Product below the exact track is actionable and has persisted
   `eligible = true`.

`PENDING` means relevant current delivery progress has not been established. It
does not prove that no submission exists or that synchronization succeeded.

### In Progress

A track is in progress exactly when all of these conditions hold:

1. the parent Ticket status is `Analysis` or `Analyzed`;
2. the exact track is actionable;
3. `TicketPackageTrack.status` is `AFFECTED` or `FIXED`;
4. `TicketPackageTrack.delivery_status = IN_PROGRESS`; and
5. at least one Product below the exact track is actionable and has persisted
   `eligible = true`.

### Completed

A track is completed exactly when all of these conditions hold:

1. the parent Ticket status is `Analysis`, `Analyzed`, or `Resolved`;
2. the exact track is actionable; and
3. `TicketPackageTrack.delivery_status = RELEASED`.

Completed classification does not require an eligible Product. The persisted
irreversible delivery fact remains useful completion history even when current
eligibility no longer requires work.

### Ticket Status and Workflow Boundaries

`Analysis` participates because one track can have a decided affectedness while
another track remains under analysis. `New` is excluded because no track-level
analysis decision is admitted to active workbench presentation. `Ignored` and
`Duplicated` are excluded because they are isolated in the manual zone.
`Resolved` contributes only completed rows; pending and in-progress rows require
an active gate-zone Ticket.

The classification is workflow-agnostic and applies equally to persisted `ibs`
and `git` tracks. The persisted `workflow_type` is authoritative. The workbench
does not send a Git reference to IBS, correlate it to an IBS request, create a
Git delivery fact, or define Git submission and release mechanisms. A Git row
is classified only from the package facts already persisted by their owning
workflows.

## Shared Global-List Query Contract

The pending, in-progress, and completed endpoints share these query parameters:

| Parameter | Type | Default | Contract |
|---|---|---|---|
| `package` | string | — | Case-sensitive exact match against `TicketPackage.package_name`; no trimming, aliasing, substring matching, or case normalization; max 500 characters |
| `page` | integer | 1 | Standard page number, minimum 1 |
| `per_page` | integer | 20 | Standard page size, minimum 1 and maximum 100 |
| `sort_by` | string | `severity` | `severity` (semantic ordering; see `docs/api-spec.md`, Sorting), `package`, or `submission_due_at` (`NULL` last) |
| `sort_order` | string | `desc` | `asc` or `desc` |

Different supplied filters compose with AND semantics. Invalid pagination or
sort values return the global `422 VALIDATION_ERROR`. A page beyond the last
returns an empty `data` array with the correct `meta.total`.

`severity` follows `docs/api-spec.md` (Semantic Sort Fields and Nullable Sort
Field Ordering). `package` orders `package_name` by Unicode code point,
independent of database collation. The internal deterministic pagination
tie-breaker required by `docs/api-spec.md` (Deterministic Pagination Ordering)
is `TicketPackageTrack.id`. `submission_due_at` uses timestamp order with
`NULL` last under Nullable Sort Field Ordering. Apart from that SLA deadline,
the lists expose no temporal filter or sort: `days`, `waiting`, `since`, and
`released` are not declared query parameters.

Each global list returns the standard paginated envelope:

```json
{
  "data": [],
  "meta": {
    "total": 0,
    "page": 1,
    "per_page": 20
  }
}
```

Rows, `meta.total`, ordering, and page slicing derive from the same
caller-visible, caller-owned candidate set and the same `evaluation_date`.
Visibility and Product-eligibility checks occur in PostgreSQL before counting
and pagination; no Python post-filter may remove rows from a broad page.

## API Endpoints

All four endpoints use mandatory authentication, receive the authenticated User
ID and request-resolved effective scope, capture one UTC evaluation instant and
its `evaluation_date`, and
delegate model-aware query construction to `package_service`. Handlers do not
construct ORM predicates or perform response fan-out queries.

### Pending Packages

```http
GET /api/v1/my/packages/pending
```

**`Access: Authenticated`**

Returns tracks satisfying [Pending](#pending). It accepts the shared global-list
query parameters and returns workbench items in the paginated envelope.

Delegates to `package_service.list_maintainer_pending_work()`.

### In-Progress Packages

```http
GET /api/v1/my/packages/in-progress
```

**`Access: Authenticated`**

Returns tracks satisfying [In Progress](#in-progress). It accepts the shared
global-list query parameters and returns workbench items in the paginated
envelope.

Delegates to `package_service.list_maintainer_in_progress_work()`.

### Completed Packages

```http
GET /api/v1/my/packages/completed
```

**`Access: Authenticated`**

Returns tracks satisfying [Completed](#completed). It accepts the shared
global-list query parameters and returns workbench items in the paginated
envelope.

Delegates to `package_service.list_maintainer_completed_work()`.

### Package Details for Ticket

```http
GET /api/v1/my/packages/tickets/{ticket_id}
```

**`Access: Authenticated`**

`{ticket_id}` accepts only canonical `SNTL-{n}`. The endpoint returns every
qualifying caller-owned track for that Ticket, partitioned by the same three
classifications from one coherent PostgreSQL observation:

```json
{
  "data": {
    "pending": [],
    "in_progress": [],
    "completed": []
  }
}
```

Each array contains the shared workbench item schema. An item can satisfy only
one classification because its persisted delivery status has one value.
Arrays use fixed ascending Unicode code-point order by `package_name`, then
`reference`, with `TicketPackageTrack.id ASC` as the final internal tie-breaker.
Client-controlled sorting is not supported because one Ticket has a bounded
track set and the endpoint provides one canonical sharing order.

The endpoint is unpaginated and therefore has no `meta`: a Ticket's persisted
track set is bounded by its package tree. It delegates to
`package_service.get_maintainer_ticket_work()`.

The service first resolves the locator and selects the Ticket through the
canonical visibility predicate as part of the coherent view that supplies the
response. A malformed locator, Ticket UUID, well-formed missing Ticket, and
inaccessible Ticket all return the derived scoped `404 TICKET_NOT_FOUND`.
Only after accessibility succeeds does the service evaluate caller ownership
and classification. An accessible Ticket with no qualifying caller work —
including `New`, `Ignored`, `Duplicated`, or a Ticket with no caller-maintained
included package — returns 200 with all three arrays empty. The endpoint has no
status-specific response union, `error_state`, or `no_packages` outcome.

## Consistency, Side Effects, and Performance

Each list or per-Ticket result is assembled from one coherent PostgreSQL
observation. A concurrent confidentiality change, grant revocation, package
exclusion, or removal of another qualifying visibility path may be observed
entirely before or after that observation, but cannot produce rows, totals, or
arrays assembled across incompatible visibility states.

These are read-only operations. They acquire no mutation lock, write no row,
create no audit event, enqueue no task, perform no external or Redis I/O, and do
not commit or roll back the caller-owned transaction. Query work is bounded by
the page or one Ticket; Product eligibility uses existence semantics rather
than row fan-out, and response projection must avoid per-item/N+1 database
queries.

## Security and Privacy

- Mandatory authentication identifies the workbench owner; no capability is
  required.
- Canonical Ticket visibility and persisted maintainership ownership are
  independent mandatory predicates for every returned row.
- Missing and inaccessible per-Ticket locators are indistinguishable before
  status, ownership, or package data is projected.
- Responses expose no maintainer identity, personal identifier, group, source
  payload, SMELT provenance, or internal Ticket UUID.
- `SNTL-{n}` is the only Ticket identity in paths and response items.

## Dependencies

- `docs/features/packages/package-service.md` — service-owned query contracts
- `docs/features/packages/package-maintainership.md` — package-wide persisted
  ownership and privacy
- `docs/features/packages/package-model.md` — orthogonal dimensions,
  actionability, workflow discriminator, and presentation boundary
- `docs/features/tickets/tickets.md` — Ticket lifecycle and severity resolution
- `docs/features/identity/rbac.md` — canonical Ticket visibility predicate and
  authenticated endpoint map
- `docs/features/packages/ibs-submission-tracking.md` — separate correlated IBS
  request-action read surfaces
- `docs/features/tickets/ticket-deadlines.md` — submission deadline and
  milestone status

## Cross-References

- `docs/api-spec.md` — authentication, Ticket identity, envelopes, filtering,
  pagination, sorting, and derived responses
- `docs/features/platform/testing-strategy.md` — Maintainer Workbench and Ticket
  Accessibility test matrices
- `docs/data-model.md` — authoritative persisted schema
