# Tickets

## Purpose

Define the Ticket entity — the primary workflow unit of Sentinel. A ticket
tracks the triage, analysis, and resolution of a security issue across
maintained products. Tickets may or may not be associated with a CVE.

This specification is the authoritative source for ticket identification,
creation pathways, lifecycle, severity resolution, and status transition
rules. Other feature specifications reference this document for
ticket-related behavior.

## Ticket Identification

Every Ticket has one public identifier and one internal database identifier:

| Identifier | Format | Purpose |
|------------|--------|---------|
| `id` | UUIDv7 | Internal primary key used by foreign keys, services, tasks, locks, and internal ordering; never accepted or returned as Ticket identity by the API |
| `sequence_id` | Auto-increment integer, exposed as `SNTL-{n}` | Unique immutable consumer-facing Ticket identity for paths, responses, UI display, search, and communication |

### SNTL-{n} Format

- The `sequence_id` is an auto-increment integer assigned at ticket
  creation. It is unique and immutable.
- The human-readable form is `SNTL-{sequence_id}` (e.g., `SNTL-1`,
  `SNTL-42`, `SNTL-1337`). No zero-padding.
- The canonical grammar is `^SNTL-[1-9][0-9]*$`, with the numeric value within
  the positive PostgreSQL `INTEGER` range. It is uppercase and is not trimmed,
  case-normalized, sign-normalized, or padding-normalized.
- `SNTL-{n}` is the sole Ticket identity in the consumer-facing API. Internal
  service/task payloads and structured operational logs retain their owning
  UUID contracts.

### API Lookup

All `{ticket_id}` API path parameters accept only canonical `SNTL-{n}` values
and resolve them through `sequence_id`. Malformed values, Ticket UUIDs, missing
Tickets, and inaccessible Tickets all return `404 TICKET_NOT_FOUND` as defined
by `docs/api-spec.md` (Ticket Identifier Resolution). The API does not perform
format detection or provide a UUID compatibility alias.

### Search

The `search` query parameter on `GET /api/v1/tickets` searches across
the following fields. A ticket matches if any field matches.

- **SNTL-{n} identifier**: prefix-match on the numeric part of the
  sequence number. The `SNTL-` prefix is optional in the query — a
  purely numeric term is treated as a sequence number search (e.g.,
  `42` matches SNTL-42 and SNTL-420 but not SNTL-1042). A query of
  just `SNTL-` with no digits is ignored for this field.
- **CVE ID** (if the ticket has an associated CVE): prefix-match on
  the full CVE-ID string (e.g., `CVE-2024-12` matches `CVE-2024-1234`
  and `CVE-2024-1200`). The `CVE-` prefix is optional if the format is
  recognizable as year-number (e.g., `2024-1234`).
- **Package names**: case-insensitive substring match (ILIKE). Matches
  any directly included package (`TicketPackage.deleted_at IS NULL`) whose
  name contains the search term.
- **External identifiers** (if the ticket has an associated CVE with
  external identifiers): prefix-match on the identifier string (e.g.,
  `GHSA-xxxx` matches `GHSA-xxxx-yyyy-zzzz`). Case-insensitive.

The service trims leading and trailing whitespace from `search` once. If the
result is empty, no text search is applied. Percent, underscore, and backslash
are literal input characters rather than SQL wildcard or escape syntax. These
normalization rules do not change the field-specific case and prefix semantics
above.

## CVE Association

A ticket may optionally be associated with a CVE.

- `Ticket.cve_id`: UUID, FK to `cve.id`, **UNIQUE**, **NULLABLE**
- The UNIQUE constraint ensures that a CVE can be associated with at most
  one ticket (1:0..1 relationship)
- Tickets created from CVE ingestion have `cve_id` set at creation time
- Tickets created manually or from external sources (e.g., bug trackers)
  start without a CVE

### CVE Resolution Behavior

Whenever a CVE-ID is provided for association with a ticket (whether at
ticket creation or via explicit association), the following rules apply:

- **Conflict**: if the CVE exists in the database and is already
  associated with another ticket, the operation fails with 409 Conflict.
  The response body includes `existing_ticket_id` (`SNTL-{n}`) to identify
  the conflicting Ticket
- **On-demand freshness fetch**: if the CVE does not exist, create a minimal
  record through `ensure_cve_exists()`; otherwise use the existing locked row.
  In both cases, the owning Ticket service prepares and registers a broadcast
  freshness refresh inside the same transaction after association, CVSS
  handover, Product eligibility, reconciliation, audit, and dispatch validation
  succeed. The shared transaction dependency commits and releases locks before
  publication. Redis deduplication prevents redundant queued work. Publication
  failure preserves the ordinary committed Ticket response. Periodic sync or
  manual refetch recovers the accepted commit-to-publication crash gap; no
  durable job state is added.
- **Normal**: if the CVE exists and is not associated with any ticket,
  the association proceeds directly
- **Already rejected, manual operation**: when an authorized user deliberately
  creates a Ticket with, or associates an existing Ticket to, a CVE whose
  locked-current `cve_state` is already `REJECTED`, the manual operation retains
  its ordinary initial/current Ticket status and audit sequence. It does not
  invoke `ignore_new_for_rejected_cve()` or create the automatic `CVE rejected`
  status event. The user may move the Ticket to `Ignored` through the ordinary
  manual operation when appropriate. Automatic `New -> Ignored` remains limited
  to the source-neutral ingestion cases in the status matrix below

### Associating a CVE Later

An authorized acting user can associate a CVE with a ticket that does not yet
have one, via
`POST /api/v1/tickets/{ticket_id}/associate-cve`.

**Rules**:

- The ticket must not already have a CVE associated (`cve_id IS NULL`)
- The CVE-ID string must be provided (e.g., `CVE-2024-1234`)
- [CVE Resolution Behavior](#cve-resolution-behavior) applies
- When a CVE is associated:
  - `Ticket.cve_id` is set
  - The automatic severity from CVSS takes over (see
    [Severity Resolution](#severity-resolution)) — initially `null`
    (unresolved) if the CVE data has not been fetched yet; updated
    automatically once CVSS data arrives from the on-demand fetch
  - CVSS sync and release tracking begin applying to the ticket
  - Existing system-managed Product eligibility is recalculated immediately
    from current assessments, default version, Product thresholds, and
    lifecycle dates; manual overrides are preserved
  - The ticket may regress from Analyzed to Analysis if CVSS data has
    not arrived yet (gate #3 and #4 may fail)

See [ticket-service.md](ticket-service.md#associate_cve) for the full
service-layer contract (locking, audit events, status evaluation).

## Ticket Creation

### Automatic: CVE Ingestion

When a CVE is ingested from an external source (NVD, MITRE, or future
sources), a ticket is created automatically. See
`docs/features/tickets/cve-tracking.md` for the full ingestion flow.

- `cve_id`: set to the ingested CVE
- `status`: `New`
- `assignee_id`: `NULL`
- `TicketAuditEvent`: `event_type = ticket_created`, `user_id = NULL`,
  `comment = "CVE ingested from {source}"`, where `{source}` is the canonical
  human-readable `CVESourceType` label in `cve-service.md`

### Manual Creation

A user with the `create_ticket` capability can create a ticket manually
via `POST /api/v1/tickets` or through the UI.

- `cve_id`: optionally, the user may specify a CVE-ID string (e.g.,
  `"CVE-2024-1234"`) at creation time. If omitted, the ticket is
  created without a CVE (can be associated later)
- When a CVE-ID is provided:
  - [CVE Resolution Behavior](#cve-resolution-behavior) applies
- If the locked-current creating user is active and holds the
  `vulnerability_analyst` role:
  - `status`: `Analysis` (direct, bypasses `New` — the creating user is
    automatically assigned)
  - `assignee_id`: set to the creating user
- If the locked-current creating user is inactive or does NOT hold the
  `vulnerability_analyst` role (e.g., `restricted_analyst`):
  - `status`: `New` (auto-assignment is skipped — see
    [Auto-Assignment on Unassigned Tickets](#auto-assignment-on-unassigned-tickets))
  - `assignee_id`: `NULL`

See [ticket-service.md](ticket-service.md#create_ticket) for the full
service-layer contract (audit events, CVE uniqueness handling).

**`Capability: create_ticket`**

### Future: External Sources

The data model supports automatic ticket creation from external systems
(e.g., internal bug trackers). These tickets are created without a CVE
and follow the same rules as automatic creation:

- `cve_id`: `NULL`
- `status`: `New`
- `assignee_id`: `NULL`

Specific integrations will be defined in separate feature specifications.

## Severity Resolution

Ticket severity is resolved transparently — the API and UI expose a
single `severity` field. The resolution logic is internal to the service
layer.

### Resolution Rules

1. If the ticket has a CVE (`cve_id IS NOT NULL`): severity =
   `cve.severity` (derived from CVSS assessments via the resolution
   cascade — see `docs/features/tickets/cvss-scoring.md`). Note:
   `cve.severity` can be `null` if no CVSS data is available yet. It is
   CVE-owned state and remains current when the CVE is ticketless or associated
   with an inactive Ticket; Product eligibility propagation is separate
2. If the ticket does not have a CVE (`cve_id IS NULL`): severity =
   `ticket.severity_manual`
3. If neither is available: severity = `null` (unresolved)

### severity_manual Field

- `Ticket.severity_manual`: VARCHAR(20) (Critical, High, Medium, Low, None),
  nullable
- Set manually by an authorized acting user via the API or UI
- Only used when `cve_id IS NULL`
- Mutually exclusive with `cve_id` at the database level
  (`chk_ticket_severity_manual_cve_exclusive`): at most one can be
  non-NULL at any given time
- When a CVE is associated later (`associate_cve`), `severity_manual` is
  cleared to `NULL` in the same transaction. The automatic severity from
  CVSS takes over. The acting user's previous manual assessment is preserved in
  the audit trail (`severity_changed` events)

## Ticket Lifecycle

### Statuses

| Status     | Description |
|------------|-------------|
| New        | Initial pre-gate state. The Ticket has not yet been admitted to automatic gate evaluation. Assignment presence does not define the status. |
| Analysis   | Gate-zone floor. At least one Analyzed-gate condition is currently false, or the Ticket has just left `New` or the manual zone and has not qualified for a higher gate result. Assignment is irrelevant. |
| Analyzed   | Every Analyzed-gate condition is true and at least one actionable track is not resolution-complete. Assignment is irrelevant. |
| Resolved   | Every Analyzed-gate condition is true and every actionable track is resolution-complete under the CVE-aware formula below. Assignment is irrelevant; track `delivery_status` is not a gate input. |
| Ignored    | Manual-zone isolation for an issue that is not currently being worked. It can be entered manually only from `New` or `Analysis`, or automatically from `New` after CVE rejection. Gates and ordinary mutations do not operate in this status. |
| Duplicated | Manual-zone isolation for a Ticket represented by another non-Duplicated Ticket. The duplicate link is required and the status is reversible through its dedicated exit workflow. |

**Design note — why Analyzed → Ignored is intentionally excluded**: A ticket
in Analyzed status has had all its packages and tracks fully evaluated. If a VA
later determines the CVE does not require action, the natural workflow is to
exclude the remaining packages. Each exclusion calls
`reconcile_ticket_status()`; once no track remains manually included, the
"at least one package" gate condition fails and the Ticket automatically
regresses to Analysis. At that point the VA can use the existing Analysis →
Ignored transition. Adding a direct Analyzed → Ignored transition would bypass
the package exclusion step, leaving included affectedness data attached to an
Ignored Ticket. The regression path ensures a clean state.

### Status Transition Diagram

```
                         highest-valid gate result
New ──assignment──→ Analysis ⇄ Analyzed ⇄ Resolved
 │                     ╲_________________╱
 ├──manual/rejection──→ Ignored ──dedicated exit──→ evaluated gate status
 └──manual────────────→ Duplicated ─dedicated exit→ evaluated gate status

Analysis ──manual──→ Ignored
Analysis / Analyzed / Resolved ──manual──→ Duplicated
```

### Status Transitions

The following matrix is exhaustive. A transition not represented by one of its
rows is illegal. "Evaluated" means the owner prepares the `Analysis` floor and
then records one semantic transition from the preserved source status to the
highest valid gate-zone status (`Analysis`, `Analyzed`, or `Resolved`).

| From | To | Trigger | Mode and actor | Owning service/function |
|---|---|---|---|---|
| `New` | `Analysis` | First explicit assignment, or implicit assignment by a qualifying modifying operation | Explicit or implicit user action; status event is system-attributed | `ticket_service.assign_ticket()` or `ticket_mutations.auto_assign_actor()` |
| `New` | `Ignored` | User invokes Ignore | Manual; acting user | `ticket_service.ignore_ticket()` |
| `New` | `Ignored` | Associated CVE changes to `REJECTED`, or ingestion creates the Ticket for an already-`REJECTED` orphan CVE | Automatic; system | `cve_service.upsert_cve()` orchestrates `ticket_service.ignore_new_for_rejected_cve()` |
| `Analysis` | `Ignored` | User invokes Ignore | Manual; acting user | `ticket_service.ignore_ticket()` |
| `New`, `Analysis`, `Analyzed`, `Resolved` | `Duplicated` | User marks the Ticket as duplicate | Manual; acting user | `ticket_service.mark_as_duplicate()` |
| `Ignored` | evaluated `Analysis`, `Analyzed`, or `Resolved` | User invokes Reopen, or associated CVE changes from `REJECTED` to `PUBLISHED` | Manual or automatic; final status event is system-attributed | `ticket_service.reopen_from_ignored()` and `_complete_manual_zone_exit()` |
| `Duplicated` | evaluated `Analysis`, `Analyzed`, or `Resolved` | User invokes Revert Duplicate | Manual; final status event is system-attributed | `ticket_service.revert_duplicate()` and `_complete_manual_zone_exit()` |
| `Analysis` | `Analyzed` or `Resolved` | A gate-relevant mutation makes the corresponding status the highest valid result | Automatic; system | `ticket_mutations.reconcile_ticket_status()` |
| `Analyzed` | `Analysis` or `Resolved` | A gate-relevant mutation changes the highest valid result | Automatic; system | `ticket_mutations.reconcile_ticket_status()` |
| `Resolved` | `Analysis` or `Analyzed` | A gate-relevant mutation invalidates resolution | Automatic; system | `ticket_mutations.reconcile_ticket_status()` |

For a user action on a `New` Ticket, the existing auto-assignment rule still
applies. A VA actor records `New -> Analysis` before the requested Ignore or
Duplicate transition; a non-VA actor cannot be assigned and may record the
direct `New -> Ignored` or `New -> Duplicated` transition. These are the same
matrix paths, not additional legal targets.

**Note on CVE Rejections**: When a CVE's `cve_state` changes to `REJECTED`
(detectable from any discovery fetcher — NVD, MITRE, or kernel), only its unique
associated Ticket in `New` is automatically transitioned to `Ignored`. The same
consequence applies after ingestion creates a Ticket for an already-`REJECTED`
orphan CVE. Tickets in `Analysis` or later statuses are not automatically
transitioned — the VA must review the rejection manually. For the complete flow,
see `docs/features/tickets/cve-tracking.md` (Rejection handling and Rejection
revert handling).

### Gate: Analysis → Analyzed

For one shared UTC `evaluation_date`, define:

- `M` as every persisted track whose package and track `deleted_at` are both
  `NULL` (the manually included tracks). Product markers and lifecycle do not
  affect membership in `M`.
- `A` as every actionable track under the canonical package-model predicate.
  Therefore `A` is a subset of `M` and a track belongs to `A` only when it has
  at least one actionable Product.

The Analyzed predicate is exactly:

```text
|M| >= 1
AND every track in A has status != ANALYSIS
AND resolved Ticket severity IS NOT NULL
AND (
    Ticket.cve_id IS NULL
    OR at least one canonical SUSE assessment exists in an accepted version
)
```

In prose, all of the following conditions must be met:

1. **At least one manually included track**: at least one
   `TicketPackageTrack` must not be effectively manually excluded through its own or
   its package's `deleted_at`. Product lifecycle does not affect this
   structural completeness check.
2. **All actionable track affectedness decided**: no actionable
   `TicketPackageTrack` is in `ANALYSIS`. A manually included track whose
   Products are all EOL or otherwise non-actionable does not block analysis.
3. **Severity set**: the ticket must have a determined severity (not
   `NULL`). Severity `None` (CVSS score 0.0) IS a valid determined
   severity and satisfies this gate. For tickets with CVE, this is
   derived from CVSS. For tickets without CVE, `severity_manual`
   must be set by an authorized acting user
4. **SUSE CVSS provided** (only for tickets with CVE): at least one canonical
   `SUSE` assessment must exist in any CVSS version currently accepted by
   Sentinel. The current accepted set is v2.0, v3.0, v3.1, and v4.0; any one
   of them satisfies this gate. Assessments from other providers do not. A
   canonical SUSE assessment at the configured `default_cvss_version` does
   not need to be present: the setting controls severity preference and
   eligibility score selection, not this SUSE data-presence gate.

This evaluation is performed automatically by the centralized status
evaluation function (see "Centralized Status Evaluation" below) after
every operation that modifies gate-relevant data. There is no manual
"Mark as Analyzed" action — the transition happens as soon as all
conditions are satisfied.

Conversely, when an owning mutation workflow invokes centralized status
evaluation after any condition ceases to be met (for example, a package is
added with tracks in ANALYSIS, a committed SUSE CVSS deletion is consumed by
its Ticket-scoped propagation workflow, or severity becomes undetermined), the
ticket transitions back from Analyzed to Analysis.

### Gate: Analyzed → Resolved

The Resolved predicate is the Analyzed predicate above AND universal
resolution completeness over `A`. For each actionable track `t`, let `AP(t)`
be its actionable Products and `AEP(t)` the members of `AP(t)` whose persisted
`eligible` value is true. Track `t` is resolution-complete exactly when:

```text
t.status IN {NOT_AFFECTED, WONT_FIX}
OR (
    t.status = FIXED
    AND (
        Ticket.cve_id IS NULL
        OR every Product in AEP(t) has released_at IS NOT NULL
    )
)
OR (t.status = AFFECTED AND AEP(t) is empty)
```

Manual exclusion and lifecycle-derived participation are combined only by the
canonical predicates in `docs/features/packages/package-model.md` (Exclusion
and Actionability). The gate observes the resulting sets; it does not make
affectedness, eligibility, delivery, or actionability computations depend on
one another.

A track is **resolution-complete** when any of:

- **(a)** `status` is `NOT_AFFECTED` or `WONT_FIX`, OR
- **(b)** `status = FIXED` AND either the Ticket has no CVE, or every
  actionable eligible Product (`eligible = true`) under it has
  `released_at IS NOT NULL`, OR
- **(c)** `status = AFFECTED` AND it has no actionable eligible Products (all
  actionable Products have `eligible = false`, or no actionable Product
  exists).

A track in `ANALYSIS` is never resolution-complete.

The gate observes affectedness, derived actionability, Product eligibility, and
Product `released_at` exactly as listed above. Track `delivery_status` is not an
input to this gate or to the Analyzed gate. It records independent maintenance
pipeline evidence and may be projected alongside gate-relevant fields without
constraining them.

For a Ticket with a CVE, clause (b) uses universal quantification over
actionable eligible Products. If a `FIXED` track has no actionable eligible
Products, the publication condition is vacuously true. For a Ticket without a
CVE, `FIXED` itself is the available source-fix confirmation and the track is
resolution-complete regardless of Product `released_at`. This exception never
writes or fabricates publication evidence: every `released_at` remains `NULL`
until its owning detector establishes a real advisory. Associating a CVE later
immediately restores the ordinary publication condition and may regress the
Ticket until every then-actionable eligible Product is confirmed released.

Clause (c) enables auto-resolution for the legitimate scenario where a
track is genuinely affected (code vulnerable) but all products under it
are ineligible — there is nothing to wait for, and the "affected, no
fix" fact is preserved (the track stays `AFFECTED`). If a product later
becomes eligible and actionable through its owning mutation workflow (for
example, atomic CVSS propagation, an AIMAAS threshold
update, Product restore, or correction of an EOL lifecycle date), clause (c)
ceases to hold and centralized reconciliation reverts the Ticket to Analyzed.

This evaluation is performed by the centralized status evaluation
function after every operation that modifies track statuses, product
eligibility, or product release confirmation. The Resolved gate is only
reachable when the Analyzed gate is also met (which requires at least one
manually included track). The actionable-track set may be empty, in which case
the Resolved predicate is intentionally true because lifecycle leaves no
current work.
There is no manual "Mark as Resolved" action and no generic force-Resolved
operation. When policy-driven eligibility makes a previously resolved Ticket
actionable again, an authorized acting user records the actual domain decision
through existing
mutations: `WONT_FIX` when no fix will be produced for the complete track, a
Product-specific manual `eligible = false` override when that Product will not
receive a fix despite automatic policy, or exclusion only when the package,
track, or Product is outside Ticket scope. These mutations retain their
ordinary audit and reconciliation behavior.

Conversely, if any track ceases to be resolution-complete (for example,
atomic CVSS propagation changes Product eligibility, an authorized acting user
resets a track status from a final state to `AFFECTED`, or a Product is restored
under an `AFFECTED` track), the owning mutation workflow invokes centralized
reconciliation and the Ticket transitions back from Resolved to Analyzed (or to
Analysis, if the "Analyzed" gates are also no longer met).

#### Deterministic Gate Edge Cases

- No manually included track makes the Analyzed predicate false, even when the
  actionable-track set is empty.
- At least one manually included track with no actionable tracks (including an
  all-EOL tree) satisfies the structural condition. If severity and the
  CVE-specific SUSE condition are also satisfied, both gates are true and the
  Ticket is `Resolved` by empty-set universal quantification.
- A manually included track with no Product is non-actionable. It contributes
  to `M`, does not block on `ANALYSIS`, and does not participate in the Resolved
  quantification.
- Package or track exclusion removes a track from both `M` and `A`. Product
  exclusion or EOL removes only that Product from Product-level participation;
  the track remains actionable if another actionable Product exists.
- Missing lifecycle data means no lifecycle override and therefore does not
  make a Product non-actionable. Missing Products do not create implicit
  lifecycle or release facts.
- Eligibility overrides participate through the persisted effective
  `eligible` value. `eligible = false` removes an actionable Product from
  `AEP(t)`; clearing the override restores the automatic formula and may
  regress or advance the Ticket.
- An actionable `ANALYSIS` track always prevents Analyzed. A non-actionable
  `ANALYSIS` track does not.
- Later exclusion, restoration, lifecycle, affectedness, eligibility,
  severity, SUSE-assessment, Product-creation, release, or CVE-association
  changes are evaluated from current state and may move the Ticket in either
  direction. No prior gate result is sticky.

### Read-Only Gate Projection

The default-CVSS impact preview in `system-settings.md` evaluates the
Analyzed and Resolved predicates above read-only for a hypothetical proposed
default version. It reuses the exact same predicates, sets, and clause
semantics, substituting projected effective Product eligibility for the
persisted boolean without writing it: the projected automatic result where no
manual override applies, and the preserved persisted `eligible` value where
`is_eligible_override = true`.

- The projection invokes no mutation function. It does not call
  `reconcile_ticket_status()`, acquire the Ticket lock, change a status,
  create a `status_change` event, or register a transaction-local Ticket
  convergence effect.
- Only a currently `Resolved` Ticket whose projected highest valid gate
  result is `Analysis` or `Analyzed` contributes a regression count.
  Promotions, demotions of `Analysis` or `Analyzed` Tickets, and no-change
  evaluations are not separate response categories.
- `Ignored` and `Duplicated` Tickets remain outside gate projection, exactly
  as they remain outside `reconcile_ticket_status()` and ordinary gate
  evaluation.

### Automatic Status Evaluation

Forward and reverse transitions between Analysis, Analyzed, and
Resolved are governed by a single mechanism: the centralized status
evaluation function (`reconcile_ticket_status`) in the
`ticket_mutations` module. This function re-evaluates gate conditions
after every relevant data change and sets the ticket to the highest
valid status. It is the sole authority for gate-zone status.

- If all "Resolved" AND "Analyzed" gates are met → Resolved
- If all "Analyzed" gates are met → Analyzed
- Otherwise → Analysis (unconditional floor)

`New` is a pre-state outside the gate zone. `reconcile_ticket_status`
skips tickets in `New` status entirely (guard clause). The floor of
the gate zone is `Analysis` — this function never produces `New`.

The `New → Analysis` transition is not a gate evaluation. It is an
explicit one-way event triggered only by the first assignment action:
`auto_assign_actor()` (implicit assignment via any modifying operation
by a VA on an unassigned ticket) or `assign_ticket()` (explicit
assignment via the PATCH assignee endpoint). Once a ticket leaves
`New`, it never returns there under normal operation.

Reverse transitions between `Analysis`, `Analyzed`, and `Resolved`
are not special cases — they emerge naturally when gate conditions are
no longer met.

#### Gate Input and Reconciliation Ownership

Every change capable of changing a gate has exactly one mutation owner and one
final reconciliation boundary:

| Gate input or derived set | Change source | Reconciliation owner |
|---|---|---|
| Manual severity | `ticket_mutations.set_severity_manual()` | The same function after the effective mutation |
| CVE association and severity-source handover | `ticket_service.associate_cve()` | The composed association workflow after CVSS and Product propagation |
| CVE severity, canonical-SUSE presence, and CVSS-originated automatic eligibility | CVSS mutation/default-version chains in `ticket_mutations` | The owning chain, at most once after all effective Product changes |
| Track affectedness | `package_service.set_track_status()` | The same function after an effective change |
| Product eligibility override or automatic Product-originated recalculation | `package_service` | The owning package mutation after all Product changes |
| Product `released_at` | `package_service.set_product_released_at()` | The same function after the first effective release observation |
| Package, track, or Product direct exclusion/restoration | `package_service` | The same direct-marker mutation using its one evaluation date |
| Package-tree creation | `package_service.add_package_records()` | The same function when at least one package-tree record is created |
| Lifecycle-derived actionability or passage of the UTC date | `package_service.reconcile_lifecycle_actionability_for_ticket()` | One reconciliation for the selected gate-zone Ticket |
| Manual-zone exit | `ticket_service._complete_manual_zone_exit()` | Exactly one reconciliation after synchronous automatic-eligibility convergence |

No gate derives its own affectedness, eligibility, delivery, release, exclusion,
or lifecycle value. A true no-op does not reconcile unless an owning
date-driven lifecycle workflow explicitly evaluates derived actionability.
The read-only impact preview is not a reconciliation owner: it consumes the
same predicates without calling `reconcile_ticket_status()` and without
acquiring the Ticket lock.

An owning composed workflow establishes all of its current gate inputs before
the one final call to `reconcile_ticket_status()`. In particular, immediate
CVSS propagation, including propagation on `Resolved`, applies every applicable
automatic Product update from one UTC `evaluation_date`. An explicit
`Ignored` or `Duplicated` exit first performs its separate synchronous
eligibility convergence. The status evaluator never launches a second
eligibility chain.

All automatic transitions (status promotion and demotion within the
gate zone, the `New → Analysis` promotion) create a `TicketAuditEvent`
with `user_id = NULL` (system action), even when the underlying data
change was initiated by an authorized acting user.

See [ticket-mutations.md](ticket-mutations.md) for the full function
contract, assignment-eligibility sanitation, concurrency control rules,
actionability-aware gate evaluation, and architectural test requirements.

#### Architectural Invariant

> **Ticket status reflects work state, not staffing state.** The status
> of a ticket represents the progress of the analysis work, never the
> assignment state. Assignment is an orthogonal staffing concern.
> Consequently:
>
> - A ticket in `Analysis`, `Analyzed`, or `Resolved` status may have
>   `assignee_id = NULL` (an orphaned ticket awaiting reassignment).
>   This is a valid and expected state, visible in the unassigned queue
>   (`?assignee=none`).
> - `New` is the initial pre-gate state: the Ticket has not yet been admitted
>   to automatic gate evaluation. Once a ticket transitions from `New` to
>   `Analysis`, it never returns to `New` under normal operation.
> - `reconcile_ticket_status` never pushes a ticket below `Analysis`.
>   The floor of the gate zone is `Analysis`, not `New`.
> - Whenever a mutation clears a non-NULL `assignee_id`, the Ticket audit trail
>   contains the corresponding `assignment` event. A Ticket that has never been
>   assigned may validly remain unassigned in the gate zone without an
>   unassignment event.
>
> Tickets created directly by an active VA (`create_ticket()` with a
> locked-current active VA actor)
> start at `Analysis` and bypass `New` entirely — no `New → Analysis`
> transition occurs and no corresponding `status_change` audit event is
> expected on these tickets.

#### Concurrency Control

Every operation that modifies the `Ticket` row MUST acquire
`FOR UPDATE` on the Ticket row before any modification. See
[ticket-mutations.md](ticket-mutations.md#concurrency-control) for
the full locking rules and
[ticket-service.md](ticket-service.md#concurrency-control) for the
per-operation locking matrix.

### Reassignment

A ticket can be reassigned to a different VA at any time, as long as the
ticket is in a mutable status (not Ignored or Duplicated). For Ignored
tickets, the dedicated reopen flow (`POST .../reopen`) handles
assignment; for Duplicated tickets, the revert-duplicate flow
(`POST .../revert-duplicate`) handles it. Reassignment does not change
the ticket status. All reassignments are logged in the ticket event
history.

**Target constraint**: the assignment target MUST be an **active** user
holding the `vulnerability_analyst` role. Attempting to assign a ticket
to a user without this role fails with 400 Bad Request
(`TICKET_ASSIGNEE_NOT_VA`). Attempting to assign to an inactive user
fails with 409 Conflict (`TICKET_ASSIGNEE_INACTIVE`). This applies to
the explicit assignment endpoint (`PATCH .../assignee`).
Every assignment-capable path stabilizes the prospective assignee with a User
`FOR SHARE` lock before any CVE or Ticket lock and evaluates both conditions
from that locked state. Auto-assignment and embedded assignment are skipped if
the acting user is inactive or lacks the role; explicit assignment retains the
existing errors above.

**System-initiated unassignment**: tickets are automatically unassigned
in three scenarios:

1. **User deactivation**: bulk unassignment via `deactivate_user` when a
   user is deactivated (see
   [user-service.md](../identity/user-service.md#deactivate_user))
2. **VA role loss**: bulk unassignment via
   `_unassign_tickets_on_va_role_loss` when a user loses the
   `vulnerability_analyst` role entirely — no remaining `UserRole`
   records from any origin (see
   [user-service.md](../identity/user-service.md#private-helpers))
3. **Assignment-eligibility sanitation**: individual cleanup by
   `reconcile_ticket_status` when it encounters an inactive or non-VA assignee
   on a Ticket whose final result is `Analysis` or `Analyzed` (see
   [Assignment Eligibility Sanitization](ticket-mutations.md#assignment-eligibility-sanitization))

Scenario 1 and active manual-role uses of scenario 2 are proactive and serialize
with every assignment path on the User lock. Scenario 3 is defensive
current-state sanitation during gate evaluation, including when a preserved
inactive-status Ticket returns to `Analysis` or `Analyzed`; it is not the
primary repair for an assignment race. Deferred external-origin behavior is
owned by `identity-provisioning.md`.

### Auto-Assignment on Unassigned Tickets

When an active user with the `vulnerability_analyst` role performs any
modifying operation on a ticket with `assignee_id = NULL`, the ticket is
automatically assigned to the acting user. The User is locked and checked
before the Ticket lock. A `TicketAuditEvent` with
`event_type = assignment` is created atomically in the same transaction
as the modifying operation. If the acting user is inactive or does not hold the
`vulnerability_analyst` role (e.g., a `restricted_analyst`),
auto-assignment is skipped — the ticket remains unassigned for a
vulnerability analyst to claim.

If the ticket is in `New` status, `auto_assign_actor()` immediately
promotes it to `Analysis` as an explicit side effect of the assignment,
creating a `status_change` audit event (`New → Analysis`,
`user_id = NULL`). The caller then calls `reconcile_ticket_status`, which
evaluates from `Analysis` upward and may promote further if gate
conditions are already satisfied.

For operations that call `auto_assign_actor` and then immediately set an
explicit status (e.g., `ignore_ticket` → `Ignored`, `mark_as_duplicate`
→ `Duplicated`): `auto_assign_actor` sets `Analysis`, the caller then
sets the explicit status. The audit trail records two `status_change`
events — `New → Analysis` and `Analysis → Ignored` (or `Duplicated`).
This is correct and intentional: the VA claimed the ticket before
choosing to act on it explicitly.

This rule does not apply to system operations (background tasks,
automated ingestion) or to users without the `vulnerability_analyst`
role.

Manual reference create, update, and delete are also excluded. They modify only
supplementary editorial metadata and never call `auto_assign_actor()`, reconcile
gates, change Ticket status, or exit the manual zone.

A package-resolution invocation whose only mutation is creation of
system-derived `TicketPackageMaintainer` associations is also excluded. It does
not represent the acting user's package-tree decision and does not invoke
`auto_assign_actor`; if that invocation creates package, track, or Product
state as well, normal auto-assignment applies.

This rule is enforced via the shared helper
`ticket_mutations.auto_assign_actor()`, which is called by all
modules that modify tickets under a `FOR UPDATE` lock
(`ticket_mutations`, `package_service`, `ticket_service`). See
[ticket-mutations.md](ticket-mutations.md#auto_assign_actor) for
the helper's signature and behavior.

### Duplicate Handling

#### Terminology

- **Target**: the non-Duplicated ticket referenced by
  `duplicate_of_id`. The system guarantees this ticket is never in
  Duplicated status (see Invariant below).
- **Original ticket**: the user-facing synonym for "target." Used in
  UI copy (e.g., "See the original ticket: SNTL-42").

#### Mark-as-Duplicate Operation

A ticket can be marked as duplicate from any **operable** status (New,
Analysis, Analyzed, Resolved). Tickets in the manual zone (Ignored or
Duplicated) are blocked by `ensure_ticket_operable` at the service layer
(409 `TICKET_NOT_MUTABLE`) — an Ignored ticket must be reopened first,
and a Duplicated ticket must be reverted first.

Steps:

1. Lock source and target in the deterministic order defined by
   `ticket_service.mark_as_duplicate()` and require both locked-current Tickets
   to satisfy the canonical visibility predicate. A missing or inaccessible
   root returns 404 `TICKET_NOT_FOUND`.
2. Verify the source ticket is operable (`ensure_ticket_operable` in the
   service layer — rejects Ignored and Duplicated).
3. Verify the target ticket is not in Duplicated status (else 409
   `TICKET_DUPLICATE_TARGET_DUPLICATED`).
4. Verify the target is not the source ticket (else 400
   `TICKET_SELF_DUPLICATE`).
5. Set `duplicate_of_id = target_id` and `status = Duplicated`.
6. Atomically repoint all tickets whose `duplicate_of_id` points to
   the source ticket to point to the target instead. One
   `duplicate_target_changed` audit event is created per repointed
   ticket.
7. If a dependent ticket is locked by a concurrent operation, the
   entire transaction rolls back (409
   `TICKET_DUPLICATE_CONCURRENT_MODIFICATION`). The client should
   re-read source and target state before retrying.

See [ticket-service.md](ticket-service.md#mark_as_duplicate) for the
full service-layer contract (two-phase locking, auto-assignment, audit
events, atomicity guarantee).

#### Revert-Duplicate Operation

When reverting a ticket from Duplicated status
(`ticket_service.revert_duplicate()`):

- `duplicate_of_id` is cleared (set to NULL)
- If the locked-current acting user is active and holds the
  `vulnerability_analyst` role, the ticket
  is reassigned to them. If the acting user does not hold the VA role
  (e.g., a `restricted_analyst`), the reassignment step is skipped — the
  ticket retains its current assignee (or remains unassigned)
- The ticket re-enters the gate zone; `reconcile_ticket_status`
  determines the correct status based on current gate conditions only after
  existing automatic Product eligibility synchronously converges from current
  PostgreSQL inputs
- Creates `duplicate_removed`, plus any optional assignment and synchronous
  Product eligibility events, followed by one final system `status_change`

See [ticket-service.md](ticket-service.md#revert_duplicate) for the
full function contract.

The revert is non-retroactive: if other tickets were repointed away
from this ticket during a prior `mark_as_duplicate` operation, they are
not affected by this revert — they remain pointing to their current
target.

#### API Response Behavior

`duplicate_of_id` always points to a non-Duplicated Ticket. The API field
`duplicate_of_ticket_id` contains that target's `SNTL-{n}` identity. Projection
selects the referenced Ticket's `sequence_id` directly without following a
duplicate chain or applying a second protected-content lookup. The raw
`duplicate_of_id` UUID is not exposed in the API.

#### Invariant

`duplicate_of_id` always points to a non-Duplicated ticket. This is
enforced by `mark_as_duplicate`, which locks the target and verifies
its status before writing. The CHECK constraint
`chk_ticket_duplicate_status_coherence` enforces the bidirectional
implication between status and FK at the database level. Multiple
tickets may reference the same target.

### Status Categories

- **Active tickets**: status `New`, `Analysis`, or `Analyzed`. Actively
  monitored by ticket-scoped external background tasks.
- **Inactive tickets**: status `Resolved`, `Ignored`, or `Duplicated`.
  Excluded from ticket-scoped external monitoring. `Resolved` remains
  operable and may receive local derived reconciliation that causes a
  gate-driven return to an active status; `Ignored` and `Duplicated` remain in
  the manual zone.

## Inactive Statuses and Mutability

### Ignored

Ignored is a **manual-zone status** — `reconcile_ticket_status` never
operates on Ignored tickets. Two exit transitions are allowed:

1. **VA assigns themselves (manual):** the VA becomes the assignee.
2. **System reopens (automatic):** the current assignee is retained, including
   an inactive or non-VA assignee when the final gate result is `Resolved`.
   Final reconciliation clears an ineligible assignee only for `Analysis` or
   `Analyzed`. This handles cases like CVE rejection reverts (see
   `docs/features/tickets/cve-tracking.md`, "Rejection revert handling").

Both transitions go through `ticket_service.reopen_from_ignored()`:
1. For a manual caller, acquires `FOR SHARE` on the acting User; a system caller
   has no User root
2. Acquires `FOR UPDATE` on the Ticket
3. Verifies current status is Ignored
4. Sets assignee when the locked-current actor is eligible
5. Re-enters the gate zone at `Analysis` (the unconditional floor),
   synchronously converges existing automatic Product eligibility from current
   PostgreSQL inputs, then calls `reconcile_ticket_status` once; it may promote to
   `Analyzed` or `Resolved` if gate conditions are already satisfied

Every successful manual-zone exit registers one transaction-local Ticket
convergence effect, including an exit whose immediate gate result is `Resolved`.
If the final result is `Analysis` or `Analyzed`, reconciliation clears an
inactive or non-VA assignee; if it is `Resolved`, the existing assignee is
retained even when that user is ineligible. A broker operational error while
publishing this automatically registered effect is best-effort: it is logged
after commit with exactly one sanitized event and does not change the successful
manual-zone-exit response. Other publication exceptions follow the automatic
owner's failure boundary. An operator can recover an unconfirmed publication
through the complete rerun action below.

See [ticket-service.md](ticket-service.md#reopen_from_ignored) for
the full function contract.

Other consumer modifications on Ignored tickets are blocked — mutation
endpoints return 409 `TICKET_NOT_MUTABLE` (same guard as Duplicated) unless
their owning contract declares an explicit opt-out. The visibility-only
operations `set_confidentiality()`, `grant_access()`, and `revoke_access()` and
the supplementary editorial metadata operations `create_reference()`,
`update_reference()`, and `delete_reference()` are explicit exceptions
alongside the dedicated manual-zone exit operations. They may run while the
Ticket remains Ignored or Duplicated, but never assign, reconcile gates, change
status, or exit the manual zone. Blocking gate-relevant data prevents
unexpected status jumps on reopen without preventing an authorized user from
correcting access to embargoed content or curating reference links.
Trusted external CVSS ingestion remains the narrow source-owned exception
defined under Modifications in Inactive Statuses; it does not apply Ticket-
  scoped propagation before Ticket convergence.
See [Mutability Guard](#mutability-guard) for enforcement details.

### Modifications in Inactive Statuses

Tickets in inactive statuses (`Resolved`, `Ignored`, `Duplicated`) are not
included in ticket-scoped external monitoring. Global source synchronization
and local derived reconciliation may still update source-owned or derived data;
they do not poll an inactive Ticket's external package scope.

- **Resolved**: an authorized consumer mutation may apply its documented
  Ticket-scoped consequences immediately and trigger centralized status
  evaluation. Effective manual SUSE mutation, source-owned external CVSS
  ingestion, and default-version recalculation all maintain automatic Product
  eligibility immediately and run at most one final gate reconciliation. A
  resulting `Resolved → Analyzed` or `Resolved → Analysis` transition is an
  ordinary gate-zone regression. `Resolved` remains outside ticket-scoped
  external monitoring until such a regression places it in the active scope
- **Ignored and Duplicated** (manual zone): gate-relevant and ordinary Ticket
  mutation endpoints return 409 `TICKET_NOT_MUTABLE` via
  `ensure_ticket_operable()` in the service layer. The dedicated exit endpoints
  (`POST .../reopen` for Ignored, `POST .../revert-duplicate` for Duplicated)
  and the visibility-only confidentiality/grant mutations bypass this guard for
  their separately documented purposes. Manual reference create, update, and
  delete likewise bypass it because they change only supplementary editorial
  metadata. These reference operations do not assign, reconcile, change status,
  or exit the manual zone. Trusted source ingestion is not a consumer mutation
  endpoint: it may
  persist non-SUSE external CVSS assessments and refresh `CVE.severity`, while
  Product eligibility, assignment, gates, and status propagation remain
  deferred until Ticket convergence after manual-zone exit. See
  [Mutability Guard](#mutability-guard) for the consumer enforcement mechanism.

### Mutability Guard

Enforcement of the manual-zone mutability guard is
centralized in the service-layer function `ensure_ticket_operable()`
(defined in `ticket_mutations`). Mutation functions in `ticket_mutations`,
`ticket_service`, and `package_service` call it after acquiring `FOR UPDATE` on
the Ticket row unless their owning contract declares an explicit opt-out.

```python
def ensure_ticket_operable(ticket: Ticket) -> None:
    if ticket.status in (TicketStatus.Ignored, TicketStatus.Duplicated):
        raise TicketNotMutableError(ticket.id)
```

**Scope**:
- Applied to: service-layer mutations unless their owning contract declares an
  explicit opt-out
- NOT applied to: read operations; manual-zone exit functions
  (`reopen_from_ignored`, `revert_duplicate`); visibility-only
  `set_confidentiality`, `grant_access`, and `revoke_access`; supplementary
  editorial metadata functions `create_reference`, `update_reference`, and
  `delete_reference`; asynchronous convergence dispatch; CVE on-demand refetch
  preparation; or trusted source ingestion that modifies only source-owned
  external CVSS assessment and CVE-derived severity

This source-ingestion boundary does not weaken manual-zone immutability:
authenticated consumer APIs may mutate only the internal SUSE assessment and
remain subject to `TICKET_NOT_MUTABLE`; they cannot use the trusted external
caller category. Package eligibility behavior follows the CVSS mutation's
`immediate`, `deferred_until_reactivation`, `not_applicable`, or `none`
disposition and the narrow atomic boundary in `ticket-mutations.md`.

**Relationship with Ticket accessibility**: `docs/features/identity/rbac.md`
owns the canonical visibility predicate and `docs/api-spec.md` owns the request
flows. For a consumer mutation, the mutation service evaluates accessibility
from locked-current Ticket state before this operability guard. The checks are
independent: visibility determines whether the caller may observe the Ticket;
operability determines whether the already-accessible Ticket can accept the
mutation. A thin API dependency may perform a delegated preliminary check where
the request flow requires one, but that check never replaces locked-current
mutation accessibility.

## Tickets Without CVE: Behavioral Differences

When a ticket has no associated CVE (`cve_id IS NULL`), the following
features behave differently:

| Feature | Behavior |
|---------|----------|
| CVSS scoring | Not applicable — no CVE means no CVSS assessments |
| Product eligibility | Automatic calculation still applies using the conservative 10.0 eligibility fallback; this does not make CVSS itself applicable |
| CVSS sync (NVD, Red Hat) | Not applicable — ticket is skipped |
| Severity | Manual via `severity_manual` (editable by an authorized acting user) |
| Release tracking (track) | Not applicable — track-level detection relies on CVE-ID in IBS diffs |
| Release tracking (product) | Not applicable — product-level detection relies on CVE-ID in `updateinfo.xml` |
| CVE rejection handling | Not applicable — no CVE means no `cve_state` changes |
| CVE rejection revert handling | Not applicable |
| Gate: SUSE CVSS required | Not applicable — severity is set via `severity_manual` instead |

Packages, tracks, and products can still be added and managed
normally. An authorized acting user can set affectedness statuses and the ticket can
progress through the full lifecycle. A caller with `manage_packages` may set a
track to `FIXED` from any affectedness state while the locked-current Ticket is
CVE-less; `admin_ticket_ops` may do so for any Ticket. On a CVE-less Ticket,
an actionable `FIXED` track is resolution-complete without `released_at`.
Sentinel does not invent release evidence. Associating a CVE later restores the
ordinary CVE-backed publication gate and may regress the Ticket.

## Confidential Tickets

Sentinel supports "Confidential Tickets" to securely handle embargoed
vulnerabilities. Confidential tickets restrict read and write access to a
specific subset of authorized users, preventing data leaks prior to public
disclosure.

- **Confidentiality Flag**: A boolean state (`is_confidential`) on the
  Ticket entity that determines if the ticket is under embargo.
- **Visibility predicate**: `docs/features/identity/rbac.md` (Scope and
  Confidential Ticket Visibility) is the single normative definition. This
  specification applies it but does not restate or implement a second variant.
- **Confidentiality Filtering**: Confidential tickets are excluded at
  the database query level for unauthorized and unauthenticated users.
  They do not appear in list results, are not returned by detail
  endpoints, and produce no placeholder or redacted resource representation.
  The identifier-only exceptions under Identifier Disclosure Boundary do not
  expose protected content. Authorized users see confidential tickets normally
  alongside non-confidential ones.

Ticket response objects (both list and detail) MUST include the
`is_confidential: boolean` field. This field is always present — there
is no information leakage concern because a user only receives tickets
they are authorized to see (see [Confidentiality Filtering](#confidentiality-filtering)).

See `docs/data-model.md` for the `TicketAccessGrant` entity definition
and the `is_confidential` column on the Ticket table.

### Authorization Rules

Every consumer-facing Ticket-derived operation applies the canonical predicate
from `rbac.md`. Its branches are additive, visibility never grants capability,
and anonymous access is limited to non-confidential Tickets without grant or
maintainer lookup. Package exclusion disables only the maintainership branch
through that package and restore reactivates it. Track/Product exclusion,
lifecycle or EOL, affectedness, eligibility, delivery, and Ticket status have no
visibility effect.

Internal system workflows outside a consumer caller context, including Celery
fetchers and event consumers, do not use HTTP scope. Their selection and status
rules are defined by their owning background-workflow specifications.

### Confidentiality Filtering

Confidentiality is enforced by model-aware service queries, not by endpoint-
built SQL or a Core model utility. The API resolves authentication and
resource-independent capabilities, delegates caller information to services,
and maps inaccessible outcomes. Services own the database predicate and the
Ticket-, CVE-, package-, reference-, audit-, submission-, and maintainer-query
shapes that consume it.

#### Read Atomicity

A protected read MUST constrain the same database result it returns by the
canonical Ticket visibility predicate. A preliminary existence or visibility
lookup followed by an unconstrained resource query is insufficient.

- Single-resource and nested-resource reads select the Ticket and requested
  Ticket-derived data within one visibility-constrained service operation. A
  missing Ticket, an inaccessible Ticket, or a nested resource that cannot be
  returned under that Ticket's visibility contract produces the resource-
  appropriate not-found response.
- List, search, and count operations establish the visible candidate set before
  client filters, sorting, total calculation, and page slicing. `meta.total`,
  rows, and aggregates therefore describe only visible candidates.
- An assembled Ticket-derived response uses one coherent observation point for
  the Ticket and its components. No component may be selected from a later
  unconstrained Ticket state after an earlier visibility decision. The
  implementation may use one SQL statement, a database snapshot, or another
  mechanism that provides this guarantee; this specification does not prescribe
  the SQL or transaction shape.
- If a grant, maintainership path, or confidentiality state is revoked after a
  completed response's observation point, that response remains valid. A later
  request observes the later committed state and is denied when no visibility
  branch remains.

**Ticket List (`GET /api/v1/tickets`)**:
The list query includes only non-confidential tickets plus confidential
tickets satisfying the canonical predicate. For unauthenticated users, only
non-confidential tickets are returned. Every filter, search term, sort,
pagination operation, and total applies to that visible candidate set.

**Package Search (`GET /api/v1/packages`)**:
The cross-ticket package search endpoint applies the same
confidentiality filtering as the ticket list. Packages belonging to
confidential tickets are excluded for unauthorized callers. See
`docs/features/packages/package-model.md` (Search Packages Across
Tickets).

**Maintainer Workbench (`GET /api/v1/my/packages/*`)**:
The maintainer workbench service applies canonical Ticket visibility to the
same query results used for rows and totals. Ticket status determines workbench
participation only through the classification contract in
`docs/features/packages/maintainer.md`; this specification does not define a
second workbench predicate. For
`GET /api/v1/my/packages/tickets/{ticket_id}`, malformed, UUID-shaped, missing,
and inaccessible Tickets return `404 TICKET_NOT_FOUND` before Ticket status,
maintainer ownership, or package data is projected. An accessible Ticket with
no qualifying caller work returns the normal three empty collections.

**CVE Detail (`GET /api/v1/cves/{cve_id}/...`)**:
All endpoints under `/api/v1/cves/{cve_id}/` use the service-delegated CVE
accessibility role in `docs/api-spec.md`. Ticketless CVEs are public. An
associated CVE is selected only when its Ticket satisfies the canonical
predicate. Missing and inaccessible outcomes both return `404 CVE_NOT_FOUND`,
never a Ticket code.

**CVE List (`GET /api/v1/cves`)**:
The service-owned list query includes Ticketless CVEs and CVEs whose associated
Ticket satisfies the canonical predicate. Filtering, sorting, totals, and page
slicing apply to that set.

#### Mutation Atomicity

Consumer mutations authorize against the locked-current pre-mutation Ticket.
After authentication and any resource-independent capability check, the
mutation service acquires the applicable roots in its owning lock order,
including each protected Ticket, and applies the canonical predicate to each
protected Ticket before operability,
nested-resource ownership, state or transition guards, no-op classification,
writes, auto-assignment, audit, reconciliation, or post-commit-effect
registration. Multi-root operations retain the deterministic lock order in
their owning mutation contract.

If the Ticket is missing or inaccessible at that point, the operation returns
`TICKET_NOT_FOUND` and performs zero writes, assignment, audit events,
reconciliation, or post-commit effects. Caller identity, roles, and effective
scope resolved at request start are not reconstructed mid-request; Ticket-side
confidentiality, grants, and included-package maintainership are read from the
locked-current database state.

A permitted workflow that requires external I/O before locking follows the
fourth flow in `docs/api-spec.md`: preliminary service-owned accessibility,
external I/O without a lock, then authoritative locked-current accessibility.
An external failure before the lock retains its documented precedence even if
visibility was concurrently removed; no extra lookup replaces it with 404.

If a mutation was accessible in its locked pre-state and that mutation itself
removes the actor's final visibility path, the mutation and its ordinary success
response complete. For example, a restricted analyst who sees a confidential
Ticket only by maintaining its last included package may exclude that package.
The exclusion, audit, reconciliation, and response succeed normally; later
requests evaluate the committed post-state and return `TICKET_NOT_FOUND` unless
another visibility branch applies.

#### Identifier Disclosure Boundary

`SNTL-{n}` and CVE IDs are identifiers, not confidential Ticket content.
Confidentiality still hides protected Ticket-derived content and direct reads,
but it does not add identifier redaction, alternate states, or lookup
machinery. Ticket UUIDs are internal and are not an API representation.

**Accepted risk — `duplicate_of_ticket_id` and confidential targets**: A
Duplicated ticket that is non-confidential may have a
`duplicate_of_id` pointing to a confidential ticket. The target
identifier (`SNTL-{n}`) appears in public API responses. This
reveals the *existence* of the confidential target ticket but not
its content (the detail endpoint returns 404 for unauthorized
callers, indistinguishable from a non-existent ticket). This is an
accepted risk because: (a) only the identifier is exposed — no
title, CVE, severity, or package data leaks; (b) creating the
duplicate link requires `triage_ticket` capability — users with
this capability via the `vulnerability_analyst` role already have
scope `all`; `restricted_analyst` users have `non_confidential`
scope but initial duplicate targeting requires target accessibility; (c) the
principal exception is a target that becomes inaccessible after the link is
created; and (d) the leak is limited to an identifier. Following that identifier
may return `404 TICKET_NOT_FOUND`.

The existing `409 TICKET_CVE_CONFLICT` response likewise retains
`existing_ticket_id` even when that Ticket is not otherwise visible. The global
CVE-source listing may expose CVE IDs without joining through Ticket visibility.
These are bounded identifier-only exceptions; they do not permit protected
Ticket content or direct inaccessible-resource reads.

### Audit Trail

Four `TicketAuditEventType` values record confidentiality or its explicit and
automatic access provenance:

| `event_type` | Trigger | `user_id` | `old_value` | `new_value` | `comment` | `detail` |
|---|---|---|---|---|---|---|
| `confidentiality_changed` | `is_confidential` toggled | Acting user | `"true"` or `"false"` | `"true"` or `"false"` | `NULL` | `NULL` |
| `access_grant_added` | User manually added to access grants | Acting user | `NULL` | Target username | `NULL` | `NULL` |
| `access_grant_removed` | User manually removed from access grants | Acting user | Target username | `NULL` | `NULL` | `NULL` |
| `package_maintainer_added` | Package resolution associated an existing active User with a package occurrence | `NULL` | `NULL` | Target username | `NULL` | `{"package": "fictional-package"}` |

`package_maintainer_added` records acquisition even when the Ticket is not
currently confidential because the retained association can govern a later
confidentiality state. Package exclusion/restoration events record the dynamic
loss/return of effective access; no maintainer-removal event exists.

An effective `true` to `false` confidentiality transition deletes every manual
grant atomically but creates only the one `confidentiality_changed` event. The
automatic deletions are consequences of declassification, not manual revokes,
and therefore create no `access_grant_removed` events. User deactivation and
reactivation do not mutate grants and likewise create no grant event.

See `docs/features/tickets/ticket-audit-log.md` for the audit event
contract and detail JSONB schema.

## API Endpoints

For the service-layer contract (function signatures, locking, audit
event creation) of these operations, see
[ticket-service.md](ticket-service.md).

### Response Schemas

This section defines the response schemas for ticket endpoints. All
endpoints that return a ticket use one of two representations depending
on the context: a compact summary for list views, or a full detail
object for single-ticket views and mutation responses.

**Enum serialization**: all enum values (`status`, `severity`,
`workflow_type`, `delivery_status`, `PackageStatus`, and `cve_state`)
are serialized as **lowercase** strings in API responses (e.g., `"new"`, `"critical"`,
`"affected"`). Request bodies and query parameters also use lowercase.
The PascalCase forms used elsewhere in this spec (e.g., `New`,
`Analysis`, `Critical`) refer to the logical values; the wire format is
always lowercase.

**Nullable enum fields**: nullable enum fields (e.g., `severity`)
serialize as JSON `null` when unset. The enum value `"none"` is a
distinct valid value (CVSS score 0.0), not equivalent to JSON `null`.

**Exclusion and actionability visibility**: package, track, and Product
entities include a `deleted_at` field (`datetime | null`) that indicates only
direct manual exclusion at that level. They also include derived `actionable` and
`non_actionable_reason` fields. In single-ticket views (`TicketDetail`, `GET
/api/v1/tickets/{ticket_id}/packages`), all records are returned
including non-actionable ones. In cross-ticket search (`GET /api/v1/packages`),
non-actionable packages are excluded. See `docs/features/packages/package-model.md`
for the canonical predicates and reason precedence.

Ticket detail, package detail, and every mutation endpoint that returns
package-tree data or `TicketDetail` follow the canonical evaluation-date
capture and reuse contract in `docs/features/packages/package-model.md`
(Derived Actionability).

#### Shared Sub-Schemas

**UserSummary** — inline representation of a user reference. Fields:
`id` (UUID), `username` (string), `full_name` (string | null), `active`
(boolean). See `docs/api-spec.md`, "User References in Responses" for
the canonical definition.

**TicketAccessGrantResponse** — current projection of one explicit manual
grant:

| Field | Type | Description |
|---|---|---|
| `user` | UserSummary | Current target-user profile, including `active = false` when deactivated |
| `granted_at` | datetime | Original grant creation time in UTC |
| `granted_by` | UserSummary | Current profile of the user who created the grant |

Both user references are complete because users are never physically deleted.
Deactivation changes only the current `active` projection; it does not rewrite
or remove grant provenance.

**CVESummary** — compact CVE representation for list views:

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier (e.g., `CVE-2024-1234`) |
| `title` | string \| null | Brief summary from CNA (max 256 chars). Null if not provided by the CNA |
| `description` | string \| null | Vulnerability description |

**CVEDetail** — expanded CVE representation for detail views:

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier (e.g., `CVE-2024-1234`) |
| `title` | string \| null | Brief summary from CNA (max 256 chars). Null if not provided by the CNA |
| `description` | string \| null | Vulnerability description |
| `published_date` | datetime \| null | Date published (UTC) |
| `modified_date` | datetime \| null | Date last modified (UTC) |
| `cve_state` | string | CVE record state (`"published"` or `"rejected"`) |
| `date_rejected` | datetime \| null | When the CVE was rejected (UTC). `null` if `cve_state` is `"published"` |
| `external_identifiers` | CVEExternalIdentifierResponse[] | External identifiers from other naming authorities |

Source status is available via `GET /api/v1/cves/{cve_id}/sources` — see
`docs/features/tickets/cve-service.md`.

**CVEExternalIdentifierResponse** — external vulnerability identifier:

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Naming authority (e.g., `"ghsa"`). Serialized as lowercase |
| `identifier` | string | External ID (e.g., `"GHSA-xxxx-xxxx-xxxx"`) |
| `url` | string \| null | Direct link to the advisory page |

**ProductDetail** — product within a track:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | TicketPackageProduct primary key |
| `product_cpe` | string | Canonical public identity of the related catalog Product |
| `product_name` | string | Product display name (from `Product.display_name`) |
| `eligible` | boolean | Whether this product receives the fix |
| `is_eligible_override` | boolean | `true` if an authorized acting user manually set eligibility |
| `released_at` | datetime \| null | Authoritative issued time of the validated stable security advisory that established Product release, serialized in UTC; `null` until confirmed |
| `lifecycle_phase` | string \| null | Current Product lifecycle phase for the response's UTC evaluation date |
| `deleted_at` | datetime \| null | Direct manual-exclusion timestamp |
| `actionable` | boolean | Whether the Product currently participates in operational decisions |
| `non_actionable_reason` | string \| null | `package_excluded`, `track_excluded`, `product_excluded`, or `eol` according to canonical precedence; `null` when actionable |

**TrackDetail** — track (codestream) within a package:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | TicketPackageTrack primary key |
| `workflow_type` | string | `"ibs"` or `"git"` |
| `reference` | string | Codestream project name or branch reference |
| `status` | string | PackageStatus enum: `analysis`, `affected`, `not_affected`, `fixed`, `wont_fix` |
| `delivery_status` | string | DeliveryStatus enum: `pending`, `in_progress`, `released` |
| `delivery_relevant` | boolean | Computed field (see `docs/features/packages/package-model.md`) |
| `products` | ProductDetail[] | Products under this track |
| `deleted_at` | datetime \| null | Direct manual-exclusion timestamp |
| `actionable` | boolean | Whether the track has at least one actionable Product and is not manually excluded |
| `non_actionable_reason` | string \| null | `package_excluded`, `track_excluded`, or `no_actionable_products`; `null` when actionable |

**PackageDetail** — package within a ticket (detail view only):

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | TicketPackage primary key |
| `package_name` | string | Source package name |
| `tracks` | TrackDetail[] | Tracks (codestreams) for this package |
| `deleted_at` | datetime \| null | Direct manual-exclusion timestamp |
| `actionable` | boolean | Whether the package has at least one actionable track and is not manually excluded |
| `non_actionable_reason` | string \| null | `package_excluded` or `no_actionable_tracks`; `null` when actionable |

#### TicketSummary

Returned by the list endpoint. Provides enough information for table
views without the full package tree.

| Field | Type | Description |
|-------|------|-------------|
| `ticket_id` | string | Canonical Ticket identity (`SNTL-{n}`) |
| `status` | string | TicketStatus enum: `new`, `analysis`, `analyzed`, `resolved`, `ignored`, `duplicated` |
| `severity` | string \| null | Resolved severity (CVSS-derived → manual fallback). Values: `critical`, `high`, `medium`, `low`, `none`, or `null` if unresolved. `null` = no CVSS data and no manual severity set. `"none"` = CVSS score 0.0 (informational) |
| `assignee` | UserSummary \| null | Assigned VA, or `null` if unassigned |
| `cve` | CVESummary \| null | Associated CVE summary, or `null` if no CVE |
| `duplicate_of_ticket_id` | string \| null | Duplicate target Ticket identity (`SNTL-{n}`), or `null` |
| `is_confidential` | boolean | Whether the ticket is confidential |
| `package_names` | string[] | Exact-deduplicated package names whose `TicketPackage.deleted_at IS NULL`, ordered by ascending Unicode code point (e.g., `["curl", "openssl-3"]`). Product lifecycle actionability does not remove an included package name |
| `created_at` | datetime | Creation timestamp (UTC) |
| `updated_at` | datetime | Last modification timestamp (UTC) |

#### TicketDetail

Returned by the detail endpoint and all mutation endpoints. It repeats the
shared Ticket fields explicitly, replaces the compact `package_names`
projection with the full package tree, and uses expanded CVE data.

| Field | Type | Description |
|-------|------|-------------|
| `ticket_id` | string | Canonical Ticket identity (`SNTL-{n}`) |
| `status` | string | TicketStatus enum: `new`, `analysis`, `analyzed`, `resolved`, `ignored`, `duplicated` |
| `severity` | string \| null | Resolved severity (CVSS-derived → manual fallback). Values: `critical`, `high`, `medium`, `low`, `none`, or `null` if unresolved. `null` = no CVSS data and no manual severity set. `"none"` = CVSS score 0.0 (informational) |
| `assignee` | UserSummary \| null | Assigned VA, or `null` if unassigned |
| `cve` | CVEDetail \| null | Expanded CVE data with dates, or `null` if no CVE |
| `duplicate_of_ticket_id` | string \| null | Duplicate target Ticket identity (`SNTL-{n}`), or `null` |
| `is_confidential` | boolean | Whether the ticket is confidential |
| `packages` | PackageDetail[] | Full package/track/product tree; maintainer identities are not exposed |
| `created_at` | datetime | Creation timestamp (UTC) |
| `updated_at` | datetime | Last modification timestamp (UTC) |

`TicketDetail` does not include `package_names`; `packages[].package_name`
provides the full-tree equivalent. `duplicate_of_ticket_id` is selected from
the referenced target's `sequence_id`; no duplicate chain is followed and no
other target content is loaded or exposed.

#### TicketConvergenceDispatchResponse

Returned only by the asynchronous Ticket convergence rerun action.

| Field | Type | Description |
|---|---|---|
| `ticket_id` | string | Canonical external identity of the accessible Ticket (`SNTL-{n}`) |
| `task_id` | string | Transient Celery ID of the newly published root convergence task |

The `task_id` is correlation data only. It is not a durable run resource, has
no status or progress endpoint, and is not a `FetcherRun` identifier.

#### Endpoint → Schema Mapping

| Endpoint | Response Schema |
|----------|----------------|
| `GET /api/v1/tickets` | `TicketSummary[]` (paginated) |
| `GET /api/v1/tickets/{ticket_id}` | `TicketDetail` |
| `POST /api/v1/tickets` | `TicketDetail` (201 Created) |
| `POST .../associate-cve` | `TicketDetail` |
| `PATCH .../severity` | `TicketDetail` |
| `PATCH .../assignee` | `TicketDetail` |
| `POST .../ignore` | `TicketDetail` |
| `POST .../duplicate` | `TicketDetail` |
| `POST .../reopen` | `TicketDetail` |
| `POST .../revert-duplicate` | `TicketDetail` |
| `POST .../rerun-reactivation` | `TicketConvergenceDispatchResponse` (202 Accepted) |
| `PATCH .../confidentiality` | `TicketDetail` |
| `GET .../access` | `TicketAccessGrantResponse[]` (unpaginated) |
| `POST .../access` | `TicketAccessGrantResponse` (200 existing, 201 created) |
| `DELETE .../access/{user}` | No body (204 No Content) |

### List Tickets

```
GET /api/v1/tickets
```

**`Access: Public`**
**`Authentication: Optional`**
- **Response schema**: `TicketSummary[]` (paginated)

Lists tickets with filtering, search, pagination, and sorting.

Query parameters:

- `search` (string, optional): free-text search across `SNTL-{n}`
  identifier (prefix-match on numeric part), CVE ID (prefix-match),
  package names (case-insensitive substring), and external identifiers
  such as GHSA-IDs (prefix-match, case-insensitive). See
  [Search](#search) for detailed matching behavior per field.
- `status` (string, repeatable, optional): filter by ticket status.
  Accepts one or more values from: `new`, `analysis`, `analyzed`,
  `resolved`, `ignored`, `duplicated`. When multiple values are provided,
  tickets matching any of the specified statuses are returned.
- `assignee` (string, optional): filter by assignee. Accepts a user UUID,
  a username, or the special value `none` to return only unassigned
  tickets.
- `severity` (string, repeatable, optional): filter by severity level.
  Accepts one or more values from: `critical`, `high`, `medium`, `low`,
  `none`, `unresolved`. `none` matches tickets with severity `None`
  (CVSS score 0.0). `unresolved` matches tickets with `NULL` severity
   (no CVSS data and no manual severity set).
- `maintainer` (string, optional): User UUID or exact username per User
  Identifier Resolution. Matches Tickets with at least one included
  `TicketPackage` associated to that User through
  `TicketPackageMaintainer`. Unknown filter values return an empty result, not
  404. Email input is not accepted.
- `page` (integer, optional): page number for pagination (default: 1).
- `per_page` (integer, optional): items per page (default: 20).
- `sort_by` (string, optional): field to sort by (default: `created_at`).
  Valid values: `created_at`, `updated_at`, `severity` (semantic ordering, see Sorting),
  `status` (semantic ordering, see Sorting), `ticket_id` (sorts by numeric `sequence_id`).
- `sort_order` (string, optional): `asc` or `desc` (default: `desc`).

Response: paginated `TicketSummary` array in standard
`{"data": [...], "meta": {...}}` envelope (200 OK).

### Get Ticket

```
GET /api/v1/tickets/{ticket_id}
```

**`Access: Public`**
**`Authentication: Optional`**
- **Response schema**: `TicketDetail`

Returns a single Ticket by canonical `SNTL-{n}` through
`ticket_service.get_ticket_detail()`. The service owns SNTL resolution,
visibility-constrained selection, CVE and assignee projection, duplicate-target
identity, and composition of the package-owned full tree. Maintainer identities
and source maintainership data are not included. The endpoint validates
transport input, supplies caller information, maps service outcomes, and
performs no business ORM query or response assembly.

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

### Create Ticket

```
POST /api/v1/tickets
```

**`Capability: create_ticket`**
- **Response schema**: `TicketDetail` (201 Created)

Creates a ticket manually. The creating user is automatically assigned
if the locked-current user is active and holds the `vulnerability_analyst`
role — see
[Auto-Assignment on Unassigned Tickets](#auto-assignment-on-unassigned-tickets).

Request body:

```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "high",
  "is_confidential": false
}
```

- `cve_id` (string, optional): CVE identifier string to associate with
  the ticket. If provided, it must match the canonical CVE-ID format
  (`^CVE-[0-9]{4}-[0-9]{4,}$`, validated via
  `core.identifiers.is_valid_cve_id`); on mismatch → 422
  `CVE_INVALID_FORMAT`. Empty strings are rejected like any other
  non-matching value — clients that intend "no CVE" must omit the field
  or send `null`. If the CVE is not in the database, a minimal CVE record
  is created and on-demand freshness fetch is prepared regardless of whether
  the CVE was new or already present (see
  `docs/features/tickets/cve-service.md`, "On-Demand Fetch: fetch_single_cve")
- `severity` (string, optional): initial manual severity (critical,
  high, medium, low, none). If omitted, severity is `null` (unresolved)
  until set by the user. Must not be provided when `cve_id` is also
  provided — severity is derived from CVSS; providing both yields 409
  `TICKET_SEVERITY_DERIVED`
- `is_confidential` (boolean, optional): if `true`, the ticket is
  created as confidential. Requires the `manage_confidentiality`
  capability in addition to `create_ticket`. If the caller lacks
  `manage_confidentiality`, the endpoint returns 403
  `AUTH_INSUFFICIENT_PERMISSION`. Default: `false`

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(201 Created).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 422 | `CVE_INVALID_FORMAT` | `cve_id` provided but does not match `^CVE-[0-9]{4}-[0-9]{4,}$` or exceeds 20 characters |
| 409 | `TICKET_CVE_CONFLICT` | CVE is already associated with another Ticket. Response includes `existing_ticket_id` (`SNTL-{n}`) |
| 409 | `TICKET_SEVERITY_DERIVED` | Both `cve_id` and `severity` provided; severity is auto-derived from CVSS |

### Associate CVE

```
POST /api/v1/tickets/{ticket_id}/associate-cve
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Associates a CVE with a ticket that does not have one. A minimal CVE record is
created only when needed. The service always prepares on-demand freshness fetch,
including for an existing CVE (see `docs/features/tickets/cve-service.md`,
"On-Demand Fetch: fetch_single_cve").

Request body:

```json
{
  "cve_id": "CVE-2024-1234"
}
```

- `cve_id` (string, required): CVE identifier string. Must match the
  canonical CVE-ID format (`^CVE-[0-9]{4}-[0-9]{4,}$`, validated via
  `core.identifiers.is_valid_cve_id`); on mismatch → 422
  `CVE_INVALID_FORMAT`

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 422 | `CVE_INVALID_FORMAT` | `cve_id` does not match `^CVE-[0-9]{4}-[0-9]{4,}$` or exceeds 20 characters |
| 400 | `TICKET_CVE_ALREADY_SET` | Ticket already has a CVE associated |
| 409 | `TICKET_CVE_CONFLICT` | CVE is already associated with another Ticket. Response includes `existing_ticket_id` (`SNTL-{n}`) |

### Set Severity Manual

```
PATCH /api/v1/tickets/{ticket_id}/severity
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Sets or clears the manual severity for a ticket without a CVE.

Request body:

```json
{
  "severity": "high"
}
```

To clear the manual severity (revert to unresolved):

```json
{
  "severity": null
}
```

- `severity` (string | null, required): a string value (critical, high,
  medium, low, none) sets the manual severity; JSON `null` clears it
  (sets `severity_manual` to SQL NULL = unresolved)

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `TICKET_SEVERITY_DERIVED` | Ticket has an associated CVE (severity is derived from CVSS) |

### Assign Ticket

```
PATCH /api/v1/tickets/{ticket_id}/assignee
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Assigns or reassigns a ticket. See
[Reassignment](#reassignment) for reassignment rules and
[Auto-Assignment on Unassigned Tickets](#auto-assignment-on-unassigned-tickets)
for auto-assignment behavior.

Request body:

```json
{
  "user_id": "jdoe"
}
```

- `user_id` (string, required): UUID or username of the target user. The
  target must be active and hold the `vulnerability_analyst` role.

> **No unassignment by design**: the `user_id` field is required and
> cannot be null. Via the API, a ticket can only be **reassigned** to
> another active VA — never unassigned. This enforces explicit handover.
> System-initiated unassignment may occur as a side effect of user
> deactivation or VA role loss (see
> [user-service.md](../identity/user-service.md#deactivate_user)); the
> unassignment clears `assignee_id` but does **not** change the ticket
> status — the ticket remains in its current gate-zone status and appears
> in the unassigned ticket queue (`?assignee=none`) awaiting
> reassignment (see
> [ticket-mutations.md](ticket-mutations.md#assignment-eligibility-sanitization)
> and the [Architectural Invariant](#architectural-invariant)).

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `TICKET_ASSIGNEE_NOT_VA` | Target user does not hold the Vulnerability Analyst role |
| 404 | `USER_NOT_FOUND` | Target user not found |
| 409 | `TICKET_ASSIGNEE_INACTIVE` | Target user is inactive |

### Ignore Ticket

```
POST /api/v1/tickets/{ticket_id}/ignore
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Marks a ticket as Ignored. Allowed transitions: New → Ignored,
Analysis → Ignored (see [Status Transitions](#status-transitions)). If
the ticket has no assignee, auto-assignment applies (see
[Auto-Assignment on Unassigned Tickets](#auto-assignment-on-unassigned-tickets)).

No request body is required.

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `TICKET_INVALID_TRANSITION` | Current status does not allow transition to Ignored |

### Mark Ticket as Duplicate

```
POST /api/v1/tickets/{ticket_id}/duplicate
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Marks a ticket as a duplicate of another non-Duplicated ticket. If other
tickets currently point to the source, they are atomically repointed
to the target. See [Duplicate Handling](#duplicate-handling) for the
invariant and error conditions.

Request body:

```json
{
  "duplicate_of_ticket_id": "SNTL-42"
}
```

- `duplicate_of_ticket_id` (string, required): canonical `SNTL-{n}` identity of
  the target Ticket. Malformed syntax is a Pydantic `422 VALIDATION_ERROR`

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `TICKET_SELF_DUPLICATE` | Source and target are the same ticket |
| 404 | `TICKET_NOT_FOUND` | The well-formed target `duplicate_of_ticket_id` is missing or inaccessible |
| 409 | `TICKET_DUPLICATE_TARGET_DUPLICATED` | Target ticket is itself Duplicated (use its target instead) |
| 409 | `TICKET_DUPLICATE_CONCURRENT_MODIFICATION` | A dependent is locked by a concurrent operation; retry |

### Reopen Ticket

```
POST /api/v1/tickets/{ticket_id}/reopen
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Reopens an Ignored ticket. If the calling user holds the
`vulnerability_analyst` role, they become the new assignee; otherwise,
the ticket retains its current assignee (or remains unassigned). After
assignment (if applicable), the workflow enters the gate zone at the
unconditional `Analysis` floor, then
`ticket_service._complete_manual_zone_exit()` synchronously converges existing
automatic Product eligibility and evaluates upward exactly once. The
result is Analysis, Analyzed, or Resolved based on current gate conditions,
independent of assignee presence. See [Ignored](#ignored)
for the full reopen behavior and audit trail.

No request body is required.

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `TICKET_INVALID_TRANSITION` | Ticket is not in Ignored status |

This endpoint is **not** subject to `ensure_ticket_operable`
(it is the dedicated exit from the Ignored manual-zone status).

### Revert Duplicate Status

```
POST /api/v1/tickets/{ticket_id}/revert-duplicate
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Reverts a Duplicated ticket into the gate zone. If the locked-current user who
performed the revert is active and holds the `vulnerability_analyst` role, the ticket
is reassigned to them; otherwise, the ticket retains its current
assignee. After clearing the duplicate link, the service enters the
`Analysis` floor, synchronously converges existing automatic Product
eligibility, and evaluates upward exactly once. The result is `Analysis`,
`Analyzed`, or `Resolved` from current gate conditions.
See [Duplicate Handling](#duplicate-handling) for revert behavior and
status reconciliation.

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `TICKET_INVALID_TRANSITION` | Ticket is not in Duplicated status |

This endpoint is **not** subject to `ensure_ticket_operable` (it is the
dedicated exit from the Duplicated manual-zone status).

### Rerun Ticket Convergence

```text
POST /api/v1/tickets/{ticket_id}/rerun-reactivation
```

Reruns the complete Ticket convergence workflow from its beginning. This is an
asynchronous recovery action for a terminal convergence-wrapper failure, an
individual catch-up failure, or a lost or unconfirmed initial publication; it
does not directly change Ticket status.

**`Capability: triage_ticket OR manage_fetchers`**

The capabilities are alternatives. The authorization dependency accepts the
request when the authenticated caller holds either capability and returns the
same generic `403 AUTH_INSUFFICIENT_PERMISSION` when neither is present.

**Request body**: none.

**Response** (`202 Accepted`):

```json
{
  "data": {
    "ticket_id": "SNTL-42",
    "task_id": "01994c20-7c00-7000-8000-000000000002"
  }
}
```

The response uses `TicketConvergenceDispatchResponse`; see
[Response Schemas](#response-schemas).

**Behavior and ordering**:

1. Authenticate the caller.
2. Require at least one of `triage_ticket` or `manage_fetchers`, without loading
   the Ticket. A caller lacking both receives the generic 403 before Ticket
   accessibility, regardless of Ticket existence.
3. Under `FOR UPDATE` in one short service-owned transaction, resolve the
   locked-current Ticket and its accessibility.
   A missing or invisible Ticket returns `404 TICKET_NOT_FOUND`; either
   capability alone never grants visibility.
4. From that same locked state, require status
   `Analysis`, `Analyzed`, or `Resolved`. `New`, `Ignored`, and `Duplicated`
   raise `InvalidTransitionError` and return
   `409 TICKET_INVALID_TRANSITION`. The operation commits and closes that
   transaction, releasing the lock, before any broker I/O.
5. Perform one initial publication attempt for the root Ticket convergence task
   and return its ID with 202. A publication attempt that raises the broker
   operational error returns `503 CELERY_UNAVAILABLE` before the response is
   transmitted, with fixed detail
   `"Ticket convergence could not be dispatched to the task broker"` and no
   durable run or progress record. The response never includes broker exception
   text, host, port, URL, credentials, or traceback. An ambiguous broker
   acknowledgement may still have accepted the task; a later request may
   therefore duplicate work.

The operation registers no post-commit callback and does not depend on an
exception raised during the API transaction dependency's teardown or callback
loop; its failure mapping comes from the requested dispatch itself. Publication
terms follow `ticket-service.md` (Ticket Convergence, Publication vocabulary).

This endpoint does not call `ensure_ticket_operable()` and never returns
`TICKET_NOT_MUTABLE`. Repeated and concurrent accepted requests are allowed;
they never return a conflict and each may publish a complete workflow. The
workflow's current-state, idempotent mutation boundaries make duplicate work
safe.

The action creates no dedicated `TicketAuditEvent`. The request and workflow
outcomes are operational evidence in structured logs; effective delegated
package, eligibility, release, affectedness, and status mutations create only
their existing domain events. Request-side logs use the existing `request_id`
correlation and do not add a separate requesting-user field. A generic
`POST /api/v1/fetchers/{fetcher_name}/trigger` runs one complete fetcher over
its normal scope and is not equivalent: it neither enumerates this Ticket's
persisted package markers nor preserves the ordered complete convergence
workflow. No package/phase/fetcher selector, progress API, or CLI wrapper is
defined.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 409 | `TICKET_INVALID_TRANSITION` | Locked-current status is `New`, `Ignored`, or `Duplicated` |
| 503 | `CELERY_UNAVAILABLE` | Initial publication raised the broker operational error; the response uses fixed sanitized detail |

### Set Confidentiality

```
PATCH /api/v1/tickets/{ticket_id}/confidentiality
```

**`Capability: manage_confidentiality`**
- **Response schema**: `TicketDetail`
- **Request body**: `{ "is_confidential": boolean }`
- **Idempotency**: If the ticket already has the requested value, the
  operation returns 200 OK without side effects.

Sets the confidentiality status of a ticket. See
[ticket-service.md](ticket-service.md#set_confidentiality) for the
service-layer contract (locking, audit events).

An effective transition to non-confidential deletes all explicit manual grants
atomically. A later transition back to confidential does not recreate them.
Persisted package-maintainer associations are not grants and remain unchanged.
The grant deletion is an intrinsic confidentiality-state consequence, so the
client-facing operation remains a field-setting PATCH under the mutation
conventions in `docs/api-spec.md`. Although the grant rows are separate
entities, they have no valid retained lifecycle after the parent becomes
non-confidential; their deletion is therefore a mandatory cascade of setting
the parent field, not a separately requested destruction command.
This endpoint is a genuine exception to the mutation-path derivation of
`TICKET_NOT_MUTABLE`: it does not call `ensure_ticket_operable()` and is valid
while the Ticket remains Ignored or Duplicated because it changes visibility,
not workflow or gate state.

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

### Access Grant Management

Endpoints to manage `TicketAccessGrant` records. Requires the
`manage_confidentiality` capability.

#### List Access Grants

```
GET /api/v1/tickets/{ticket_id}/access
```

List all users with explicit access grants for a confidential ticket.

**`Capability: manage_confidentiality`**
- **Response** (200 OK, unpaginated):
  ```json
  {
    "data": [
      {
        "user": {
          "id": "uuid",
          "username": "jdoe",
          "full_name": "John Doe",
          "active": true
        },
        "granted_at": "2025-03-15T10:30:00Z",
        "granted_by": {
          "id": "uuid",
          "username": "asmith",
          "full_name": "Alice Smith",
          "active": true
        }
      }
    ]
  }
  ```
  *Note: Unpaginated because explicit access grants per ticket are a
  bounded dataset (typically a handful of users).*

The response uses `TicketAccessGrantResponse` and is ordered by
`granted_at ASC, user.id ASC`. Inactive target or granting users remain fully
projected from current User state with `active = false`. This fixed order is not
client-configurable; `sort_by` and `sort_order` are not accepted because the
unpaginated dataset is bounded and has one canonical provenance order.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `TICKET_NOT_CONFIDENTIAL` | Ticket is not confidential |

#### Grant Access

```
POST /api/v1/tickets/{ticket_id}/access
```

Grant explicit access to a user on a confidential ticket.

**`Capability: manage_confidentiality`**
- **Request body**: `{ "user": str }` (Accepts UUID or username per User
  Identifier Resolution convention; the service stabilizes the target under
  the User-then-Ticket lock contract in `ticket-service.md`).
- **Idempotency**: If the grant already exists, returns 200 OK with the
  existing grant data (reflecting the original `granted_by` and
  `granted_at`), without creating an audit event. This existing-grant result
  applies even when the target is currently inactive and returns that target
  with `active = false`. Otherwise, creation requires an active target, creates
  the grant, and returns 201 Created.
- **Response** (200 OK or 201 Created): The grant object wrapped in the
  standard `{"data": <grant>}` envelope. The grant object has the same
  shape as items in the list response.
- **Audit**: A newly created grant creates `TicketAuditEvent` with
  `event_type = access_grant_added`; an existing grant creates no event.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | Target user not found |
| 409 | `TICKET_NOT_CONFIDENTIAL` | Ticket is not confidential |
| 409 | `USER_INACTIVE` | Target user is inactive and no grant currently exists |

This endpoint is a genuine exception to the mutation-path derivation of
`TICKET_NOT_MUTABLE`: it does not call `ensure_ticket_operable()`, is valid
while the confidential Ticket remains Ignored or Duplicated, and does not
assign, reconcile, or change Ticket status.

#### Revoke Access

```
DELETE /api/v1/tickets/{ticket_id}/access/{user}
```

Revoke explicit access from a user on a confidential ticket. The
`{user}` path parameter is of type `str` and accepts either a UUID or
username. Revocation remains valid when that user is inactive.

**`Capability: manage_confidentiality`**
- **Idempotency**: If the grant does not exist, returns 204 No Content
  without creating an audit event.
- **Response**: 204 No Content.
- **Audit**: An effective deletion creates `TicketAuditEvent` with
  `event_type = access_grant_removed`; an absent-grant no-op creates no event.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | Target user not found |
| 409 | `TICKET_NOT_CONFIDENTIAL` | Ticket is not confidential |

This endpoint is a genuine exception to the mutation-path derivation of
`TICKET_NOT_MUTABLE`: it does not call `ensure_ticket_operable()`, is valid
while the confidential Ticket remains Ignored or Duplicated, and does not
assign, reconcile, or change Ticket status.

## Data Model

See `docs/data-model.md` for the full schema. Key fields on the Ticket
table:

| Column            | Type        | Constraints                  | Description |
|-------------------|-------------|------------------------------|-------------|
| id                | UUID        | PK                           | Internal identifier |
| sequence_id       | INTEGER     | UNIQUE, NOT NULL, auto-increment | Human-readable ID, exposed as `SNTL-{n}` |
| cve_id            | UUID        | FK(cve.id), UNIQUE, nullable | Associated CVE (optional) |
| status            | VARCHAR(20) | NOT NULL, DEFAULT New        | Ticket status |
| assignee_id       | UUID        | FK(user.id), nullable        | Assigned VA |
| severity_manual | VARCHAR(20) | nullable                     | Manual severity (Critical, High, Medium, Low, None). NULL = not set (unresolved). `None` = an authorized acting user explicitly set informational severity (CVSS score 0.0). Used when `cve_id IS NULL`. Cleared to NULL by `associate_cve` when a CVE is linked. Mutually exclusive with `cve_id` (`chk_ticket_severity_manual_cve_exclusive`) |
| duplicate_of_id   | UUID        | FK(ticket.id), nullable      | Original ticket when Duplicated |
| created_at        | TIMESTAMPTZ   | NOT NULL, DEFAULT            | Record creation timestamp |
| updated_at        | TIMESTAMPTZ   | NOT NULL, DEFAULT            | Record update timestamp |
| is_confidential   | BOOLEAN       | NOT NULL, DEFAULT FALSE      | Confidentiality flag. See [Confidential Tickets](#confidential-tickets) |

## Security

- Viewing ticket lists and details: publicly accessible (no
  authentication required). Exceptions: (1) the ticket audit log
  sub-resource (`/audit-log`) requires authentication — see
  `docs/features/tickets/ticket-audit-log.md`; (2) confidential tickets
  are invisible to users whose effective scope is not `all` (unless they
  have an explicit `TicketAccessGrant` or included-package maintainer
  association) — see
  [Confidential Tickets](#confidential-tickets)
- Creating tickets: `create_ticket` capability
- Assigning, changing status, associating CVE, setting manual severity:
  `triage_ticket` capability
- Refetching an accessible CVE: `triage_ticket` capability
- Rerunning complete Ticket convergence: `triage_ticket` OR
  `manage_fetchers`, plus ordinary Ticket visibility
- Managing packages: `manage_packages` capability
- Setting confidentiality, managing access grants: `manage_confidentiality`
  capability
- See `docs/features/identity/rbac.md` for the full permission model

## Cross-references

- `docs/features/tickets/ticket-service.md` — service-layer contract for Ticket
  lifecycle operations, cross-domain compositions, and confidentiality
  management
- `docs/features/tickets/ticket-mutations.md` — CVSS/severity mutations,
  `reconcile_ticket_status()`, `auto_assign_actor()`, concurrency rules,
  and architectural test requirements
- `docs/features/packages/package-service.md` — package-centric mutations,
  orchestration, and query operations (populates `TicketDetail.packages`)
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
- `docs/features/tickets/ticket-audit-log.md` — audit event contract, detail
  JSONB schema
- `docs/features/identity/rbac.md` — Endpoint Permission Map
- `docs/features/packages/package-maintainership.md` — package-wide maintainer
  acquisition and dynamic visibility
- `docs/features/packages/maintainer.md` — authoritative maintainer workbench
  classification and per-Ticket response
