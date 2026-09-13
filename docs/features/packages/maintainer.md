# Maintainer Operations

## Purpose

Provide package maintainers with API access to their pending
work, in-progress submissions, and completed releases across all packages
they maintain. This gives maintainers immediate visibility into what needs
fixing, what is already in the pipeline, and what has been recently
released — without requiring them to search through individual tickets.

Additionally, a per-ticket endpoint allows Vulnerability Analysts to share
a focused link with a maintainer showing exactly what needs to be done for
a specific ticket.

## Target Audience

This feature targets **package maintainers** associated with one or more
Ticket package occurrences. It complements the
VA-focused ticket workflow by providing a package-centric perspective on
security update work.

## User Identification

A user is identified as a maintainer through
`TicketPackageMaintainer.user_id` (see
`docs/features/packages/package-maintainership.md`). The authenticated User ID
must match the association; runtime email or group matching is not used. If a
user has no package association, all endpoints return empty results.

### Package-wide visibility

One association applies to every track under its `TicketPackage`. The data is
package-centric regardless of whether SMELT originally discovered the user
directly or through group membership and regardless of which individual
performed a specific action. Sentinel stores no group provenance.

## Filtering Criteria

All three sections include only actionable tracks according to
`package-model.md` (Exclusion and Actionability), evaluated with one UTC date
shared by the result and pagination count. A manually excluded scope or a track
with no actionable Products does not appear in the maintainer work queue.

Each pending, in-progress, and completed service query combines two distinct
predicates:

- the canonical Ticket visibility predicate from
  `docs/features/identity/rbac.md`, evaluated for the authenticated caller; and
- the workbench ownership predicate requiring that same caller's
  `TicketPackageMaintainer` association to the returned package occurrence.

Neither predicate substitutes for the other. The Service layer owns their
model-aware ORM construction; the endpoint supplies caller context and does not
build SQL expressions. Returned items, `meta.total`, and pagination all derive
from the same caller-visible, caller-maintained candidate set and the same
`evaluation_date`.

### Pending Fixes

Codestreams where:

1. The user is associated as a maintainer of the parent package occurrence
2. The `TicketPackageTrack.status` is `AFFECTED`
3. The parent ticket status is `Analyzed` (the VA has confirmed that
   fixes are needed)
4. `TicketPackageTrack.delivery_status` is `PENDING`

These represent actionable work for which Sentinel has not established current
delivery progress. `PENDING` is not proof that no SR exists or that the latest
synchronization completed; synchronization health remains separate from the
maintainer projection.

### In Progress

Codestreams where:

1. The user is associated as a maintainer of the parent package occurrence
2. `TicketPackageTrack.delivery_status` is `IN_PROGRESS`
3. The displayed chain is projected through exact `IBSRequestActionTrack`
   joins from authoritative request actions: a relevant SR in exact state
   `new` or `review`, or the effective accepted SR/incident chain, with any
   directly correlated RR action shown in its exact current state. An accepted
   RR is not treated as completed unless the source/target provenance proof
   established `RELEASED`

### Completed

Codestreams where:

1. The user is associated as a maintainer of the parent package occurrence
2. `TicketPackageTrack.delivery_status` is `RELEASED`
3. The displayed chain contains the effective SR and the directly correlated
   accepted `maintenance_release` action whose exact source/target provenance
   proved release to this track

These represent proven completed delivery work. A track with
`TicketPackageTrack.status = FIXED` alone does not appear here because
affectedness and delivery are orthogonal dimensions; an accepted RR without the
required provenance proof is likewise insufficient.

For both chain-bearing sections, the projection uses the same effective-SR and
accepted-RR provenance rules that produced the track's delivery status. It
joins actions to the exact track through `IBSRequestActionTrack`; request-level
incident equality is never a substitute for that join. Where an effective
accepted SR/incident exists, the chain uses that effective SR. Otherwise, an
in-progress chain uses the most recent relevant `new` or `review` SR by
`IBSRequest.upstream_created_at`, with `IBSRequestAction.id` as the deterministic
descending tiebreaker. An RR is shown only when its action is directly
correlated to the track and belongs to the selected SR/incident chain. A
completed chain uses the exact accepted RR that satisfied release provenance;
an in-progress chain uses the most recent such RR by
`IBSRequest.upstream_created_at` and the same action-ID tiebreaker. Every
displayed request state is the exact current `new`, `review`, `accepted`,
`declined`, `revoked`, `superseded`, or `deleted` value from its parent
`IBSRequest`.

## Per-Ticket View

The per-ticket endpoint returns all three sections (pending, in-progress,
completed) for a specific ticket, filtered to only the packages where the
requesting user is an associated maintainer. Packages in the ticket
that the user does not maintain are excluded.

### Evaluation Order

When the per-ticket endpoint cannot return the normal three-section
response, it returns an error state instead. Evaluation order (first match
wins):

1. Authentication completes.
2. The service selects the Ticket through the canonical visibility predicate;
   missing and inaccessible are indistinguishable and return 404
   `TICKET_NOT_FOUND`.
3. Project the accessible Ticket's status. A status other than `Analyzed`
   returns its status-specific 200 `error_state`.
4. Evaluate the caller's package-maintainer membership. No maintained package
   returns 200 `no_packages`.
5. All checks pass → 200 with normal data filtered to the caller's maintained
   packages.

The status and maintainer checks cannot run first or authorize a later
unconstrained query. No status-specific or `no_packages` response may reveal a
missing or inaccessible Ticket.

**Error state conditions:**

| Condition | HTTP | Error state type |
|-----------|------|------------------|
| Ticket does not exist or is inaccessible | 404 | — (standard `TICKET_NOT_FOUND` response) |
| Ticket status is `New` or `Analysis` | 200 | `not_analyzed` |
| Ticket status is `Resolved` | 200 | `resolved` |
| Ticket status is `Ignored` | 200 | `ignored` |
| Ticket status is `Duplicated` | 200 | `duplicated` (includes `duplicate_of`) |
| User is not a maintainer | 200 | `no_packages` |

**Duplicated link**: the `duplicate_of` value in the error-state
response is the `SNTL-{n}` identifier of the target ticket (always
non-Duplicated).

## API Endpoints

### Pending Packages

Returns pending fixes for the authenticated user.

**Query parameters:**

| Parameter  | Type    | Default | Description                         |
|------------|---------|---------|-------------------------------------|
| package    | string  | —       | Filter by package name              |
| page       | integer | 1       | Page number                         |
| per_page   | integer | 20      | Items per page                      |
| sort_by    | string  | severity| Sort field: severity (semantic ordering, see Sorting), waiting |
| sort_order | string  | desc    | Sort direction: asc, desc           |

**Response**: paginated list of pending fix items using the standard
`{"data": [...], "meta": {"total", "page", "per_page"}}` envelope.

**Response item schema:**

```json
{
  "package_name": "kernel-default",
  "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
  "ticket_sequence_id": 42,
  "cve_id": "CVE-2026-1234",
  "severity": "high",
  "reference": "SLE-15-SP6",
  "analyzed_at": "2026-04-15T10:30:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| package_name | string | Source package name |
| ticket_id | uuid | Ticket UUID |
| ticket_sequence_id | integer | Ticket sequence number (for `SNTL-{n}` display) |
| cve_id | string \| null | CVE identifier (null if ticket has no CVE) |
| severity | string \| null | Resolved severity: critical, high, medium, low, none (null if unresolved) |
| reference | string | Target codestream name |
| analyzed_at | datetime | When the ticket entered `Analyzed` status (consumers compute "Waiting" from this) |

### In-Progress Packages

Returns in-progress submissions for the authenticated user.

**Query parameters:**

| Parameter  | Type    | Default | Description                         |
|------------|---------|---------|-------------------------------------|
| package    | string  | —       | Filter by package name              |
| page       | integer | 1       | Page number                         |
| per_page   | integer | 20      | Items per page                      |
| sort_by    | string  | since   | Sort field: since, package          |
| sort_order | string  | desc    | Sort direction: asc, desc           |

**Response**: paginated list of in-progress items with submission chain
details, using the standard `{"data": [...], "meta": {"total", "page", "per_page"}}` envelope.

**Response item schema:**

```json
{
  "package_name": "kernel-default",
  "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
  "ticket_sequence_id": 42,
  "cve_id": "CVE-2026-1234",
  "reference": "SLE-15-SP6",
  "submission_chain": {
    "sr": {"number": 12345, "state": "accepted"},
    "incident": {"number": 67890},
    "rr": {"number": 11111, "state": "review"}
  },
  "first_sr_created_at": "2026-04-20T08:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| package_name | string | Source package name |
| ticket_id | uuid | Ticket UUID |
| ticket_sequence_id | integer | Ticket sequence number |
| cve_id | string \| null | CVE identifier |
| reference | string | Target codestream name |
| submission_chain | object | Authoritative in-progress action chain for this codestream, projected through exact action-track joins |
| submission_chain.sr | object | Relevant or effective maintenance-incident request: `number` (int), exact current `state` (string) |
| submission_chain.incident | object \| null | Maintenance incident: `number` (int) |
| submission_chain.rr | object \| null | Directly correlated maintenance-release request, if present: `number` (int), exact current `state` (string). Acceptance alone does not imply proven release |
| first_sr_created_at | datetime | Earliest `upstream_created_at` among maintenance-incident actions directly correlated to the track (consumers compute "Since") |

### Completed Packages

Returns completed releases for the authenticated user.

**Query parameters:**

| Parameter  | Type    | Default  | Description                        |
|------------|---------|----------|------------------------------------|
| package    | string  | —        | Filter by package name             |
| days       | integer | 30       | Number of days to look back        |
| page       | integer | 1        | Page number                        |
| per_page   | integer | 20       | Items per page                     |
| sort_by    | string  | released | Sort field: released, package      |
| sort_order | string  | desc     | Sort direction: asc, desc          |

**Response**: paginated list of completed items with full submission chain
and release date, using the standard `{"data": [...], "meta": {"total", "page", "per_page"}}` envelope.

**Response item schema:**

```json
{
  "package_name": "kernel-default",
  "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
  "ticket_sequence_id": 42,
  "cve_id": "CVE-2026-1234",
  "reference": "SLE-15-SP6",
  "submission_chain": {
    "sr": {"number": 12345, "state": "accepted"},
    "incident": {"number": 67890},
    "rr": {"number": 11111, "state": "accepted"}
  },
  "released_at": "2026-04-25T14:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| package_name | string | Source package name |
| ticket_id | uuid | Ticket UUID |
| ticket_sequence_id | integer | Ticket sequence number |
| cve_id | string \| null | CVE identifier |
| reference | string | Target codestream name |
| submission_chain | object | Proven chain containing the effective SR and accepted RR action correlated directly to this track |
| released_at | datetime | Proven accepted RR's `upstream_updated_at`, representing when IBS entered the accepted state; this is not `TicketPackageProduct.released_at` |

The `days` filter and `released` sorting use this projected `released_at`.

### Package Details for Ticket

Returns all three sections (pending, in-progress, completed) for a
specific ticket, filtered to the authenticated user's packages.

**Status codes:**

| Code | Error Code | Condition |
|------|------------|-----------|
| 200  | — | Ticket exists — response contains either normal data or an error state object |
| 404  | `TICKET_NOT_FOUND` | Ticket does not exist or is inaccessible |

**Response (normal view)**: returned when ticket status is `Analyzed` and
the user is a maintainer of at least one package. Object with three arrays
using a reduced item schema (ticket-level fields like `severity` and
`cve_id` are excluded since they are available from the ticket header):

```json
{
  "data": {
    "pending": [
      {
        "package_name": "kernel-default",
        "reference": "SLE-15-SP6",
        "status": "AFFECTED"
      }
    ],
    "in_progress": [
      {
        "package_name": "kernel-default",
        "reference": "SLE-15-SP6",
        "submission_chain": {
          "sr": {"number": 12345, "state": "accepted"},
          "incident": {"number": 67890},
          "rr": null
        },
        "first_sr_created_at": "2026-04-20T08:00:00Z"
      }
    ],
    "completed": [
      {
        "package_name": "kernel-default",
        "reference": "SLE-15-SP6",
        "submission_chain": {
          "sr": {"number": 12345, "state": "accepted"},
          "incident": {"number": 67890},
          "rr": {"number": 11111, "state": "accepted"}
        },
        "released_at": "2026-04-25T14:00:00Z"
      }
    ]
  }
}
```

No pagination (a single ticket has a bounded number of codestreams).

**Response (error state)**: returned when ticket status is not `Analyzed`
or the user is not a maintainer. Object with an `error_state` key:

```json
{
  "data": {
    "error_state": {
      "type": "not_analyzed",
      "duplicate_of": null
    }
  }
}
```

```json
{
  "data": {
    "error_state": {
      "type": "duplicated",
      "duplicate_of": "SNTL-42"
    }
  }
}
```

The `duplicate_of` field is populated only for the `duplicated` type,
containing the `SNTL-{n}` identifier of the target ticket.

## Security

- All endpoints require authentication
- No capability restriction — any authenticated user can access their own
  maintainer data
- Users can only see data for package occurrences associated to their User ID
- The per-ticket endpoint filters by the authenticated user's packages;
  users cannot see other maintainers' pending work through this endpoint
- **Confidentiality filtering**: all maintainer service queries apply the
  canonical Ticket visibility predicate independently from workbench ownership.
  Package association can satisfy the maintainership branch of visibility, but
  the complete predicate remains explicit in the same query so future
  workbench changes cannot bypass confidentiality

## Performance Considerations

The "Pending Fixes" query involves a multi-table join:

```
User.id
  → TicketPackageMaintainer → TicketPackage
    → TicketPackageTrack (status = AFFECTED, delivery_status = PENDING)
      → Ticket (status = Analyzed)
```

For users who maintain many packages (e.g., kernel team), this could
return a significant number of rows. Mitigation strategies:

- **Pagination**: all endpoints are paginated (default 20 items per page)
- **Indexes**: use `TicketPackageMaintainer.user_id`, the unique
  `(ticket_package_id, user_id)` key, and existing package/track/Ticket keys
- **Future**: if performance becomes an issue, consider a materialized
  view or periodic pre-computation of the maintainer work queue

## Future Considerations

- **Claim mechanism**: ability to claim a pending fix to signal that someone is
  working on it
- **Metrics**: aggregate statistics (average time to fix, submission
  success rate) per maintainer or team

## Dependencies

- `docs/features/packages/package-maintainership.md` — package-wide
  association acquisition and visibility
- `docs/features/identity/rbac.md` — canonical Ticket visibility predicate
- `docs/features/packages/package-model.md` — TicketPackageTrack status
  and delivery status model
- `docs/features/packages/ibs-submission-tracking.md` — normalized IBS request
  actions, exact states, action-track joins, and delivery provenance for
  pending/in-progress/completed views
- `docs/features/tickets/tickets.md` — ticket status lifecycle and
  confidentiality model

## Cross-references

- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
