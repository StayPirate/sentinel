# Ticket Deadlines

## Purpose

Define the internal **remediation SLA** of a Ticket and the cumulative
**milestones** that divide the SLA window among the actors who produce a
security update. Each actor starts from the previous actor's output, so without
per-actor milestones an early actor could consume the complete window and leave
later actors with little time.

This specification is the authoritative source for the SLA tiers, the phase
shares, the due-date formula, the per-track milestone completion,
applicability, and status rules, `current_phase`, the `overdue` list filter,
the due-date sort fields, and the pure functions and read-query ownership that
implement them. The Coordinated Release Date of a confidential Ticket is a
separate concept owned by
[tickets.md](tickets.md#coordinated-release-date); it is not an SLA input.

## Actors and Phases

| Phase | Actor | Work completed in the phase |
|---|---|---|
| `triage` | VA (Vulnerability Analyst) | Decides the affectedness of the track |
| `submission` | Maintainer | Prepares the fix and submits it to IBS (submission request, SR) |
| `um` | UM (the SUSE maintenance update team) | Prepares the maintenance update and creates the release request (RR) |
| `qa` | QA (quality assurance) | Tests the maintenance update; the update is then published to the Products |

The phase identifiers are exactly `triage`, `submission`, `um`, and `qa`, in
this order. The Pydantic response schemas MUST describe the phases and define
VA, maintainer, UM, and QA in `Field(description=...)`, because external API
consumers discover these values through the generated OpenAPI documentation.
Actors do not need to know the SLA itself: each consumes only the due date of
its own phase.

## Informational Only

Deadlines and milestones are **informational only**. They are never an input to
a Ticket status gate, `reconcile_ticket_status()`, Product eligibility, package
affectedness or delivery, assignment, auto-assignment eligibility, Ticket
accessibility, priority, or any fetcher scope. They are computed at read time,
are never persisted, create no audit event, and have no refresh point. No
existing behavior changes because a deadline passes.

## SLA Tier

The SLA tier is selected from the Ticket's resolved severity (the canonical
cascade in [tickets.md](tickets.md#resolution-rules): `CVE.severity` for a
Ticket with a CVE, otherwise `Ticket.severity_manual`):

| Resolved severity | SLA tier (days) |
|---|---|
| `Critical`, `High` | 30 |
| `Medium` | 90 |
| `Low` | 180 |
| `None` (resolved score exactly 0.0) | No SLA: every due date, milestone status, and `current_phase` is `null` |
| SQL `NULL` (unresolved) | 30 (worst case) |

A severity change moves every due date at the next read; the start never moves.
The tiers are specification constants, not settings: changing them requires a
new deployment. There is no manual deadline override.

Sentinel applies one SLA to every Product. The track and Ticket dates below are
defined through "the SLA applicable to the track" so that a stricter SLA for a
subset of Products could later be expressed without changing the API schema:
each track would use the strictest SLA among its actionable eligible Products,
and the Ticket would expose the earliest date among its tracks. No column,
table, or logic exists for that today.

## Phase Shares

Each phase receives a fixed integer percentage of the SLA window. The shares
are specification constants and apply to every tier:

| Phase | Share (%) | Cumulative milestone (%) |
|---|---|---|
| `triage` | 10 | 10 |
| `submission` | 50 | 60 |
| `um` | 10 | 70 |
| `qa` | 30 | 100 |

Invariants, asserted by a test: every share is an integer greater than or equal
to 1, and the shares sum to exactly 100. Tuning moves percentage points between
shares while preserving both invariants.

## Due Dates

### Formula

Every due date starts from `Ticket.created_at`, which is immutable. The start
does not change on reopen, manual-zone exit, CVE association, severity change,
or confidentiality change, and the Coordinated Release Date is never a start.

For a phase with cumulative milestone `c` (percent) and SLA tier `d` (days):

```text
due_at = created_at + d × 864 × c seconds
```

The product is always an exact integer number of seconds (`d` days × 86 400
seconds × `c` / 100), so no rounding occurs. Due dates are `datetime` values in
UTC that carry the time of day of `created_at`.

| Field | Cumulative milestone | 30-day tier | 90-day tier | 180-day tier |
|---|---|---|---|---|
| `triage_due_at` | 10 % | +3 days | +9 days | +18 days |
| `submission_due_at` | 60 % | +18 days | +54 days | +108 days |
| `um_due_at` | 70 % | +21 days | +63 days | +126 days |
| `qa_due_at` | 100 % | +30 days | +90 days | +180 days |
| `release_due_at` | Final SLA deadline | +30 days | +90 days | +180 days |

`release_due_at` is `created_at + d days`: the final deadline by which the
update must be released. Because the shares sum to 100, `qa_due_at` always
equals `release_due_at`; a test asserts this. `release_due_at` is exposed
separately so consumers do not need to know that the QA milestone is the final
deadline. Its OpenAPI description states that it is the final release deadline
and currently equals `qa_due_at`.

### Null Due Dates

All five due dates are `null` when either:

- the Ticket status is `Ignored` or `Duplicated` (manual zone); or
- the resolved severity is the `None` label (SQL `NULL` uses the 30-day tier).

After a manual-zone exit the dates reappear at the next read from the unchanged
`created_at`.

### Ticket and Track Dates

`TicketSummary`, `TicketDetail`, and `TrackDetail` expose the same five fields.
With one SLA for every Product, the dates of every track equal the dates of its
Ticket, including for non-actionable tracks.

## Evaluation Instant

A milestone status compares a due date with one UTC **evaluation instant**. Each
response that projects milestone statuses or applies the `overdue` filter
captures exactly one instant when its read or final projection begins (in
`list_tickets()` or `get_ticket_detail()`, or in the endpoint that supplies it
to `get_ticket_packages()` or a maintainer workbench query), and uses it for
every comparison in that response. A composed projection receives the instant from its caller and does
not capture another; serializers never recapture it.

A read-only request (one that does not receive an `evaluation_date` from a
mutation workflow) uses the UTC date of its instant as the response's
`evaluation_date` (see
[package-model.md](../packages/package-model.md#derived-actionability)). A
mutation that returns `TicketDetail` keeps its existing workflow
`evaluation_date` for actionability and reconciliation; its final projection
captures the instant at projection entry. Mutation workflows therefore carry no
additional time parameter. If such a projection crosses UTC midnight after the
workflow date was captured, actionability still uses the workflow date while
milestone comparisons use the later instant; both remain internally consistent
within their own contract.

A due date is **past** when `due_at < evaluation_instant`.

## Track Milestones

Every `TrackDetail` exposes `milestones`, an object with the members `triage`,
`submission`, `um`, and `qa`, and `current_phase`. Each member has one of these
values:

| Value | Meaning |
|---|---|
| `done` | The phase is completed |
| `pending` | The phase is not completed and its due date is not past |
| `overdue` | The phase is not completed and its due date is past |
| `not_applicable` | The phase does not apply to the track |
| `null` | No SLA applies, or Sentinel cannot observe the phase for this track |

`pending` here is a milestone status. It is unrelated to
`delivery_status = pending`; the OpenAPI descriptions MUST state the
distinction.

The statuses are produced by the first matching rule:

1. **No SLA**: if the Ticket is `Ignored` or `Duplicated`, or its resolved
   severity is the `None` label (not SQL `NULL`), every member is `null`.
2. **Non-actionable track**: if the track is not actionable under the canonical
   predicate in
   [package-model.md](../packages/package-model.md#derived-actionability), every
   member is `not_applicable`. This matches the gates, which ignore
   non-actionable tracks.
3. **Otherwise** each member is evaluated as follows.

### Triage

`triage` has completion evidence when the track status is not `ANALYSIS`.

### Observability of Later Phases

`submission`, `um`, and `qa` are `null` when the Ticket has no CVE or the track
`workflow_type` is `git`. Delivery and release evidence is established only for
CVE-associated IBS tracks; a `null` status therefore never reports a phase as
overdue when Sentinel cannot observe it. The rule keys on `workflow_type`
because Sentinel has no Git delivery or release detection; adding one changes
only this observability rule, not the persisted fields or the API schema.

### Applicability of Later Phases

For an observable track, `submission`, `um`, and `qa` are applicable when both:

- the track status is `ANALYSIS`, `AFFECTED`, or `FIXED`; and
- at least one actionable Product under the track has persisted
  `eligible = true` (an actionable eligible Product).

Otherwise they are `not_applicable`. A track in `ANALYSIS` is treated as
applicable because the pending VA decision may still require a fix: a late
triage therefore also makes later milestones overdue when their dates pass. When
the VA decides `NOT_AFFECTED` or `WONT_FIX`, the later phases become
`not_applicable`.

### Completion Evidence

| Phase | Completion evidence |
|---|---|
| `triage` | Track status is not `ANALYSIS` |
| `submission` | Track `delivery_status` is `IN_PROGRESS` or `RELEASED` |
| `um` | An `IBSRequestActionTrack` correlates the track to a `maintenance_release` action whose `IBSRequest.state` is `new`, `review`, or `accepted`, or the track `delivery_status` is `RELEASED` |
| `qa` | Every actionable eligible Product under the track has `released_at IS NOT NULL` |

Request states and correlation are owned by
[ibs-submission-tracking.md](../packages/ibs-submission-tracking.md). The
milestone observes the persisted evidence; it never writes or reconciles it.

### Monotonicity

A phase is completed when it has its own completion evidence or when any later
phase whose status is not `null` or `not_applicable` has completion evidence.
For example, when every actionable eligible Product is released, `submission`
and `um` are completed even without SR or RR evidence, and `triage` is
completed even if the track is still in `ANALYSIS`.

### Status

For each member not already fixed by the rules above: `done` when completed;
otherwise `overdue` when its due date is past; otherwise `pending`.

### Current Phase

`current_phase` is `null` when rule 1 applies. Otherwise, examine the phases in
order `triage`, `submission`, `um`, `qa`:

- skip a phase whose status is `done` or `not_applicable`;
- the first phase whose status is `pending` or `overdue` is the current phase;
- if a `null` status is reached first, `current_phase` is `null`;
- if every phase is skipped, `current_phase` is `done`.

The values are therefore `triage`, `submission`, `um`, `qa`, `done`, or `null`.
`overdue` and `pending` are never phases.

### Accepted Limitation

Because nothing is persisted, Sentinel reports only "completed now" or "not
completed and past due". It does not report a phase completed late, and it
provides no SLA compliance report or metric.

## Ticket-Level Overdue Filter

`GET /api/v1/tickets` accepts the repeatable `overdue` filter with the values
`triage`, `submission`, `um`, and `qa` (OR semantics; invalid values follow
Enum Filter Validation in `docs/api-spec.md`). There is no `release` value: it
would equal `qa`. A Ticket matches a value when:

| Value | Match |
|---|---|
| `triage` | Ticket status is `New` or `Analysis`, and `triage_due_at` is past |
| `submission`, `um`, `qa` | At least one track of the Ticket has that `milestones` member equal to `overdue` |

The `triage` value is Ticket-level so that a Ticket without packages is
covered: statuses `Analyzed` and `Resolved` count as triage completed. The
meaning is always "past due and not completed", never "completed late". For
example, `overdue=qa` returns Tickets past their final deadline that still have
an applicable CVE-associated IBS track with an actionable eligible Product
lacking `released_at`.

`Ignored` and `Duplicated` Tickets never match because their dates and
statuses are `null`. `Resolved` Tickets never match by construction: every
actionable track is resolution-complete, so each applicable `FIXED` track has
every actionable eligible Product released, `AFFECTED` tracks without an
actionable eligible Product and `NOT_AFFECTED`/`WONT_FIX` tracks have their
later phases `not_applicable`, and CVE-less Tickets have `null` later phases.

VAs sort the triage queue by priority when severity is still unresolved; no
further triage mechanism exists.

## Sorting

`GET /api/v1/tickets` accepts `sort_by` values `triage_due_at`,
`submission_due_at`, `um_due_at`, `qa_due_at`, and `release_due_at`, ordering by
the Ticket-level date. `null` dates sort last in both directions under Nullable
Sort Field Ordering in `docs/api-spec.md`. The maintainer workbench lists accept
`sort_by=submission_due_at` with the same rule (see
[maintainer.md](../packages/maintainer.md#shared-global-list-query-contract)).

## Dimension Governance

A milestone status combines affectedness, delivery (track `delivery_status`,
correlated RR state, and Product `released_at`), persisted Product eligibility,
and actionability. It is the read-only SLA milestone projection listed among the
permitted observation boundaries in
[package-model.md](../packages/package-model.md#design-rationale). It never
writes, derives, or suppresses any dimension.

## Pure Resolution Functions

Module: `backend/app/services/ticket_deadlines.py`. It defines the tier and
share constants and the functions below. It imports no other service module,
so both `ticket_service` and `package_service` may use it without creating a
dependency cycle. All functions are Category B: they perform no database
access, write, audit, lock, or external call.

### `resolve_sla_days()`

```python
def resolve_sla_days(severity: Severity | None) -> int | None:
```

`severity` is the resolved severity label; `None` means SQL `NULL`, distinct
from the `None` severity label. Returns the [SLA Tier](#sla-tier) in days, or
`None` for the `None` label. Infallible.

### `compute_due_dates()`

```python
def compute_due_dates(
    *,
    created_at: datetime,
    severity: Severity | None,
    ticket_status: TicketStatus,
) -> DueDates | None:
```

Returns `None` under [Null Due Dates](#null-due-dates); otherwise a value with
`triage`, `submission`, `um`, `qa`, and `release` instants computed by the
[Formula](#formula). `created_at` is the persisted `Ticket.created_at`, which is
timezone-aware UTC under `docs/conventions.md` (Timestamps & Timezones); a
naive value raises `ValueError`. `DueDates` is a service-internal typed value, not a Pydantic
schema.

### `resolve_track_milestones()`

```python
def resolve_track_milestones(
    *,
    due_dates: DueDates | None,
    ticket_has_cve: bool,
    workflow_type: WorkflowType,
    track_status: PackageStatus,
    track_actionable: bool,
    has_actionable_eligible_product: bool,
    all_actionable_eligible_released: bool,
    delivery_status: DeliveryStatus,
    has_active_release_request: bool,
    evaluation_instant: datetime,
) -> TrackMilestones:
```

`due_dates` is the result of `compute_due_dates()` (`None` selects rule 1).
`all_actionable_eligible_released` is meaningful only when
`has_actionable_eligible_product` is true. `has_active_release_request` states
whether the `um` RR evidence in [Completion Evidence](#completion-evidence)
exists. Returns the four member statuses and `current_phase` under
[Track Milestones](#track-milestones). `evaluation_instant` must be
timezone-aware; a naive value raises `ValueError`. `TrackMilestones` is a
service-internal typed value.

## Read Ownership and Query Integration

| Surface | Owner |
|---|---|
| Ticket-level due dates in `TicketSummary` and `TicketDetail`, the `overdue` filter, and due-date sorting | `ticket_service.list_tickets()` and `get_ticket_detail()` ([ticket-service.md](ticket-service.md#ticket-query-operations)) |
| `TrackDetail` due dates, `milestones`, and `current_phase` | The package-owned tree projection `package_service.get_ticket_packages()` ([package-service.md](../packages/package-service.md#get_ticket_packages)) |
| Workbench `submission_due_at`, `submission_milestone`, and sorting | `package_service` maintainer workbench queries ([package-service.md](../packages/package-service.md#maintainer-workbench-queries)) |

The service layer MUST expose reusable SQL/SQLAlchemy expressions for the
Ticket-level due dates and the per-track milestone statuses used by filtering,
sorting, and counting. For the same inputs and evaluation instant, the SQL
expressions and the pure functions MUST produce identical results; a test
asserts this. Filtering, sorting, and totals are evaluated in PostgreSQL before
pagination; no Python post-filter may remove rows from a page. Track and
Product existence checks use existence semantics, so they cannot duplicate a
Ticket or inflate `total`.

The overdue comparison depends on the current instant and therefore cannot be
served by an index even if due dates were persisted. Persisting due dates would
be a transparent optimization that does not change this API contract.

## API Surface

| Surface | Contract | Owner |
|---|---|---|
| `TicketSummary`, `TicketDetail`: `triage_due_at`, `submission_due_at`, `um_due_at`, `qa_due_at`, `release_due_at` | Ticket-level due dates | [tickets.md](tickets.md#response-schemas) |
| `TrackDetail`: the five due dates, `milestones`, `current_phase` | Per-track milestones | [tickets.md](tickets.md#shared-sub-schemas) |
| `GET /api/v1/tickets` `overdue` filter and five due-date `sort_by` values | Ticket-level overdue work and deadline ordering | [tickets.md](tickets.md#list-tickets) |
| Maintainer workbench `submission_due_at`, `submission_milestone`, `sort_by=submission_due_at` | Submission deadline of the maintainer's tracks | [maintainer.md](../packages/maintainer.md#workbench-row-and-privacy-contract) |

No endpoint mutates a deadline.

## Testing Requirements

Tests MUST cover:

1. The phase-share invariants (integers ≥ 1, sum exactly 100) and
   `qa_due_at == release_due_at` for every tier.
2. Every tier row, including `Critical` and `High` at 30 days, the `None`
   label producing all-`null` values, and SQL `NULL` severity using the 30-day
   tier for all phases; CVE-less Tickets using `severity_manual`.
3. The exact formula offsets for every tier, preservation of the `created_at`
   time of day, and immutability of the start across severity change, reopen,
   revert, CVE association, confidentiality change, and a set Coordinated
   Release Date.
4. `null` dates, milestones, and `current_phase` for `Ignored` and
   `Duplicated`, and their reappearance after manual-zone exit.
5. Every milestone rule: non-actionable tracks (excluded and all-EOL) with
   every member `not_applicable`; `null` later phases for Git tracks and
   CVE-less Tickets; applicability for `ANALYSIS`, `AFFECTED`, and `FIXED` with
   and without an actionable eligible Product; `not_applicable` for
   `NOT_AFFECTED` and `WONT_FIX`; each completion evidence, including every RR
   state (`new`, `review`, `accepted` versus `declined`, `revoked`,
   `superseded`, `deleted`), an uncorrelated RR, and SR-only evidence;
   monotonic completion including `triage` on an `ANALYSIS` track; the
   `due_at < evaluation_instant` boundary (equal instant is `pending`).
6. Every `current_phase` outcome, including `null` reached before a pending
   phase and `done` for an all-`not_applicable` track.
7. One evaluation instant per response: a response spanning the boundary uses
   one consistent result, and the read `evaluation_date` is the instant's UTC
   date.
8. The `overdue` filter for each value, OR combinations, AND composition with
   other filters, invalid values ignored, Ticket-level `triage` semantics for
   Tickets without packages and for `Analyzed`/`Resolved`, `overdue=qa`
   returning a Ticket with an unreleased actionable eligible Product, exclusion
   of `Ignored`, `Duplicated`, and `Resolved` Tickets, no row duplication, and
   correct `total`.
9. The five `sort_by` values with `null` last in both directions and
   deterministic tie-breaking.
10. SQL/pure-function equivalence for due dates and milestone statuses over a
    parametrized matrix of the inputs above. Both implementations are driven
    from one shared input matrix so that a new evidence case exercises both.
11. Proof that deadlines never alter status, gates, eligibility, affectedness,
    delivery, assignment, priority, or accessibility, and that no deadline
    computation writes a row or creates an audit event.
12. `TrackDetail` fields in `TicketDetail` and
    `GET /api/v1/tickets/{ticket_id}/packages`, and the workbench fields and
    sort in `docs/features/packages/maintainer.md`.

## Cross-references

- `docs/features/tickets/tickets.md` — severity resolution, Ticket schemas,
  list filters, and the Coordinated Release Date
- `docs/features/tickets/ticket-service.md` — Ticket list and detail assembly
- `docs/features/packages/package-model.md` — actionability, delivery, and the
  permitted observation boundaries
- `docs/features/packages/package-service.md` — package tree projection and
  maintainer workbench queries
- `docs/features/packages/ibs-submission-tracking.md` — SR/RR evidence and
  request states
- `docs/features/packages/maintainer.md` — maintainer workbench fields and
  sorting
- `docs/features/tickets/ticket-priority.md` — informational priority used to
  order the triage queue
- `docs/api-spec.md` — filtering, sorting, and nullable ordering
