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

Every ticket has two identifiers:

| Identifier | Format | Purpose |
|------------|--------|---------|
| `id` | UUID | Internal primary key, used in all foreign key relationships and API paths |
| `sequence_id` | Auto-increment integer, exposed as `SNTL-{n}` | Human-readable identifier for UI display, search, communication, and API lookup |

### SNTL-{n} Format

- The `sequence_id` is an auto-increment integer assigned at ticket
  creation. It is unique and immutable.
- The human-readable form is `SNTL-{sequence_id}` (e.g., `SNTL-1`,
  `SNTL-42`, `SNTL-1337`). No zero-padding.
- `SNTL-{n}` is the primary label shown in logs, events, and external
  communications.

### API Dual Lookup

All API endpoints that accept a `{ticket_id}` path parameter support
dual lookup:

- **UUID**: `GET /api/v1/tickets/a1b2c3d4-...` — standard UUID lookup
- **SNTL-{n}**: `GET /api/v1/tickets/SNTL-42` — resolved via
  `sequence_id` lookup

The backend detects the format automatically (UUIDs contain hyphens and
hex characters; `SNTL-{n}` starts with the literal prefix `SNTL-`).

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
  any package associated with the ticket whose name contains the search
  term.
- **External identifiers** (if the ticket has an associated CVE with
  external identifiers): prefix-match on the identifier string (e.g.,
  `GHSA-xxxx` matches `GHSA-xxxx-yyyy-zzzz`). Case-insensitive.

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
  The response body includes `existing_ticket_id` (UUID) to identify
  the conflicting ticket
- **On-demand fetch**: if the CVE does not exist in the Sentinel
  database, a minimal CVE record (only `cve_id` set) is created via
  `ensure_cve_exists()` (see `docs/features/tickets/cve-service.md`).
  The operation proceeds immediately with the minimal record. After the
  transaction commits, the endpoint handler calls
  `trigger_on_demand_fetch()` to dispatch background fetch tasks. This
  dispatch occurs unconditionally (regardless of whether the CVE was
  newly created or already existed), with Redis deduplication preventing
  redundant work.
- **Normal**: if the CVE exists and is not associated with any ticket,
  the association proceeds directly

### Associating a CVE Later

An VA can associate a CVE with a ticket that does not yet have one, via
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
  `comment` = fetcher source description (e.g., `"CVE ingested from NVD"`)

### Manual Creation

A user with the `create_ticket` capability can create a ticket manually
via `POST /api/v1/tickets` or through the UI.

- `cve_id`: optionally, the user may specify a CVE-ID string (e.g.,
  `"CVE-2024-1234"`) at creation time. If omitted, the ticket is
  created without a CVE (can be associated later)
- When a CVE-ID is provided:
  - [CVE Resolution Behavior](#cve-resolution-behavior) applies
- If the creating user holds the `vulnerability_analyst` role:
  - `status`: `Analysis` (direct, bypasses `New` — the creating user is
    automatically assigned)
  - `assignee_id`: set to the creating user
- If the creating user does NOT hold the `vulnerability_analyst` role
  (e.g., `restricted_analyst`):
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
   `cve.severity` can be `null` if no CVSS data is available yet
2. If the ticket does not have a CVE (`cve_id IS NULL`): severity =
   `ticket.severity_manual`
3. If neither is available: severity = `null` (unresolved)

### severity_manual Field

- `Ticket.severity_manual`: VARCHAR(20) (Critical, High, Medium, Low, None),
  nullable
- Set manually by the VA via the API or UI
- Only used when `cve_id IS NULL`
- Mutually exclusive with `cve_id` at the database level
  (`chk_ticket_severity_manual_cve_exclusive`): at most one can be
  non-NULL at any given time
- When a CVE is associated later (`associate_cve`), `severity_manual` is
  cleared to `NULL` in the same transaction. The automatic severity from
  CVSS takes over. The VA's previous manual assessment is preserved in
  the audit trail (`severity_changed` events)

## Ticket Lifecycle

### Statuses

| Status     | Description |
|------------|-------------|
| New        | Created automatically (CVE ingestion or external source). Not yet assigned to any VA. |
| Analysis   | Assigned to an VA who is actively analyzing — filling in affectedness data. |
| Analyzed   | All required data has been filled in. Ready for updates to be prepared. |
| Resolved   | Every actionable track is resolution-complete: either in a conclusive affectedness status, publication-confirmed (`FIXED` + all actionable eligible Products released), or factually affected with no actionable eligible Products remaining. Track `delivery_status` is not a gate input. |
| Ignored    | The issue does not require action. Can only be set from New or Analysis. See design note below. |
| Duplicated | Duplicate of another ticket. Links to the original. Reversible. |

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
                     automatic         automatic
New ──→ Analysis ──────────→ Analyzed ──────────→ Resolved
 │         │    ◄────────────    │    ◄────────────
 │         │     automatic       │     automatic
 ├──→ Ignored (from New or Analysis only)
 │         ◄── Ignored → Analysis (VA assigns or system reopen)
 │
 └──→ Duplicated (from any operable status, reversible)
      (New, Analysis, Analyzed, Resolved → Duplicated)
```

### Status Transitions

| From       | To         | Trigger                                                | Mode               | Who                                    |
|------------|------------|--------------------------------------------------------|--------------------|----------------------------------------|
| New        | Analysis   | First assignment of a VA (explicit or implicit via any modifying operation); one-way irreversible | Manual (explicit) or Manual (implicit) | `assign_ticket`, `auto_assign_actor` |
| New        | Ignored    | User clicks "Ignore" action                            | Manual             | `triage_ticket`                        |
| New        | Ignored    | CVE is rejected (`cve_state` → `REJECTED`)             | Automatic          | System                                 |
| Analysis   | Analyzed   | All "Analyzed" gate conditions met                     | Automatic          | System                                 |
| Analysis   | Ignored    | User determines issue is not relevant                  | Manual             | `triage_ticket`                        |
| Analyzed   | Resolved   | All "Resolved" gate conditions met                     | Automatic          | System                                 |
| Analyzed   | Analysis   | "Analyzed" gate conditions no longer met               | Automatic          | System (triggered by user or system action) |
| Resolved   | Analyzed   | "Resolved" gate conditions no longer met, but "Analyzed" gates still met | Automatic | System (triggered by user or system action) |
| Resolved   | Analysis   | Both "Resolved" and "Analyzed" gate conditions no longer met | Automatic    | System (triggered by user or system action) |
| New, Analysis, Analyzed, Resolved | Duplicated | User marks ticket as duplicate | Manual | `triage_ticket` |
| Duplicated | (evaluated) | User reverts duplicate status; `_reenter_gate_zone` determines target | Manual | `triage_ticket` (assignment only if actor holds VA role) |
| Ignored    | (evaluated) | User reopens or system reopens (e.g., CVE rejection revert); `_reenter_gate_zone` determines target | Manual / Automatic | `triage_ticket` or System (assignment only if actor holds VA role) |

**Note on CVE Rejections**: When a CVE's `cve_state` changes to `REJECTED` (detectable from any discovery fetcher — NVD, MITRE, or kernel), only tickets in `New` status are automatically transitioned to `Ignored`. Tickets in `Analysis` or later statuses are NOT automatically transitioned — the VA must review the rejection manually. For the complete flow regarding CVE rejections and rejection reverts, see `docs/features/tickets/cve-tracking.md` ("Rejection handling" and "Rejection revert handling").

### Gate: Analysis → Analyzed

The system automatically transitions a ticket from Analysis to Analyzed
when ALL of the following conditions are met:

1. **At least one manually included track**: at least one
   `TicketPackageTrack` must not be effectively VA-excluded through its own or
   its package's `deleted_at`. Product lifecycle does not affect this
   structural completeness check.
2. **All actionable track affectedness decided**: no actionable
   `TicketPackageTrack` is in `ANALYSIS`. A manually included track whose
   Products are all EOL or otherwise non-actionable does not block analysis.
3. **Severity set**: the ticket must have a determined severity (not
   `NULL`). Severity `None` (CVSS score 0.0) IS a valid determined
   severity and satisfies this gate. For tickets with CVE, this is
   derived from CVSS. For tickets without CVE, `severity_manual`
   must be set by the VA
4. **SUSE CVSS provided** (only for tickets with CVE): the VA must have
   provided BOTH SUSE CVSS v3.1 AND v4.0 assessments (see
   `docs/features/tickets/cvss-scoring.md`). Note: this is a data
   completeness requirement — both versions are always required regardless
   of the system-wide `default_cvss_version` setting. That setting (see
   `cvss-scoring.md`) controls which version is used for operational
   decisions (severity resolution, eligibility threshold comparison) but
   does not affect this gate, which ensures complete CVSS data coverage

This evaluation is performed automatically by the centralized status
evaluation function (see "Centralized Status Evaluation" below) after
every operation that modifies gate-relevant data. There is no manual
"Mark as Analyzed" action — the transition happens as soon as all
conditions are satisfied.

Conversely, if any of these conditions ceases to be met (e.g., a package
is added with tracks in ANALYSIS, a SUSE CVSS assessment is deleted, or
severity becomes undetermined), the ticket automatically transitions back
from Analyzed to Analysis.

### Gate: Analyzed → Resolved

The system automatically transitions a ticket from Analyzed to Resolved
when **every actionable `TicketPackageTrack` is resolution-complete**. Manual
exclusion and lifecycle-derived participation are combined by the canonical
predicates in `docs/features/packages/package-model.md` (Exclusion and
Actionability). For each track, only actionable Products are considered when
evaluating Product-level conditions.

A track is **resolution-complete** when any of:

- **(a)** `status` is `NOT_AFFECTED` or `WONT_FIX`, OR
- **(b)** `status = FIXED` AND every actionable eligible Product
  (`eligible = true`) under it has `released_at IS NOT NULL`, OR
- **(c)** `status = AFFECTED` AND it has no actionable eligible Products (all
  actionable Products have `eligible = false`, or no actionable Product
  exists).

A track in `ANALYSIS` is never resolution-complete.

The gate observes affectedness, derived actionability, Product eligibility, and
Product `released_at` exactly as listed above. Track `delivery_status` is not an
input to this gate or to the Analyzed gate. It records independent maintenance
pipeline evidence and may be projected alongside gate-relevant fields without
constraining them.

Note: clause (b) uses universal quantification over actionable eligible
Products. If a `FIXED` track has no actionable eligible Products, the
condition is vacuously satisfied
and the track is resolution-complete. This is the intended behavior — the
source fix was confirmed and no eligible Product is pending publication
confirmation.

Clause (c) enables auto-resolution for the legitimate scenario where a
track is genuinely affected (code vulnerable) but all products under it
are ineligible — there is nothing to wait for, and the "affected, no
fix" fact is preserved (the track stays `AFFECTED`). If a product later
becomes eligible and actionable (CVSS recalculation, AIMAAS threshold update,
Product restore, or correction of an EOL lifecycle date), clause (c) ceases to
hold and the Ticket automatically reverts to Analyzed.

This evaluation is performed by the centralized status evaluation
function after every operation that modifies track statuses, product
eligibility, or product release confirmation. The Resolved gate is only
reachable when the Analyzed gate is also met (which requires at least one
manually included track). The actionable-track set may be empty, in which case
the Resolved predicate is intentionally true because lifecycle leaves no
current work.
There is no manual "Mark as Resolved" action.

Conversely, if any track ceases to be resolution-complete (e.g., CVSS
recalculation changes product eligibility, a VA resets a track status
from a final state to `AFFECTED`, or a product is restored under an
`AFFECTED` track), the ticket automatically transitions back from
Resolved to Analyzed (or to Analysis, if the "Analyzed" gates are also
no longer met).

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

All automatic transitions (status promotion and demotion within the
gate zone, the `New → Analysis` promotion) create a `TicketAuditEvent`
with `user_id = NULL` (system action), even when the underlying data
change was initiated by a VA.

See [ticket-mutations.md](ticket-mutations.md) for the full function
contract, inactive assignee sanitization, concurrency control rules,
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
> - `New` is a pre-state: it means the ticket has never been claimed by
>   a VA. Once a ticket transitions from `New` to `Analysis`, it never
>   returns to `New` under normal operation.
> - `reconcile_ticket_status` never pushes a ticket below `Analysis`.
>   The floor of the gate zone is `Analysis`, not `New`.
> - When `assignee_id` is `NULL` on a ticket in `Analysis` or later,
>   the ticket's audit trail MUST contain an `assignment` event
>   documenting the unassignment. An orphaned ticket without a
>   corresponding unassignment audit event indicates a bug in the
>   mutation path that cleared `assignee_id`.
>
> Tickets created directly by a VA (`create_ticket()` with a VA actor)
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
Auto-assignment checks internally whether the acting user holds the
`vulnerability_analyst` role — if not (e.g., a `restricted_analyst`),
auto-assignment is skipped and the ticket remains unassigned.

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
3. **Inactive assignee sanitization**: individual cleanup by
   `reconcile_ticket_status` when it encounters an inactive assignee on
   an active ticket (see
   [Inactive Assignee Sanitization](ticket-mutations.md#inactive-assignee-sanitization))

Scenarios 1 and 2 are proactive (triggered at the point of mutation).
Scenario 3 is reactive (catch-up mechanism that runs during gate
evaluation, ensuring that even if a ticket enters the gate zone after
the triggering event, the stale assignee is cleared).

### Auto-Assignment on Unassigned Tickets

When a user with the `vulnerability_analyst` role performs any modifying
operation on a ticket with `assignee_id = NULL`, the ticket is
automatically assigned to the acting user. A `TicketAuditEvent` with
`event_type = assignment` is created atomically in the same transaction
as the modifying operation. If the acting user does not hold the
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

1. Verify the ticket is operable (`ensure_ticket_operable` in the
   service layer — rejects Ignored and Duplicated).
2. Verify the target ticket is not in Duplicated status (else 409
   `TICKET_DUPLICATE_TARGET_DUPLICATED`).
3. Verify the target is not the source ticket (else 400
   `TICKET_SELF_DUPLICATE`).
4. Set `duplicate_of_id = target_id` and `status = Duplicated`.
5. Atomically repoint all tickets whose `duplicate_of_id` points to
   the source ticket to point to the target instead. One
   `duplicate_target_changed` audit event is created per repointed
   ticket.
6. If a dependent ticket is locked by a concurrent operation, the
   entire transaction rolls back (409
   `TICKET_DUPLICATE_CONCURRENT_MODIFICATION`). The client should
   re-read source and target state before retrying.

See [ticket-service.md](ticket-service.md#mark_as_duplicate) for the
full service-layer contract (two-phase locking, auto-assignment, audit
events, atomicity guarantee).

#### Revert-Duplicate Operation

When reverting a ticket from Duplicated status
(`ticket_mutations.revert_duplicate()`):

- `duplicate_of_id` is cleared (set to NULL)
- If the acting user holds the `vulnerability_analyst` role, the ticket
  is reassigned to them. If the acting user does not hold the VA role
  (e.g., a `restricted_analyst`), the reassignment step is skipped — the
  ticket retains its current assignee (or remains unassigned)
- The ticket re-enters the gate zone; `reconcile_ticket_status`
  determines the correct status based on current gate conditions
- Creates two `TicketAuditEvent` records: `duplicate_removed` (user
  action) + `status_change` (system action)

See [ticket-mutations.md](ticket-mutations.md#revert_duplicate) for the
full function contract.

The revert is non-retroactive: if other tickets were repointed away
from this ticket during a prior `mark_as_duplicate` operation, they are
not affected by this revert — they remain pointing to their current
target.

#### API Response Behavior

`duplicate_of_id` always points to a non-Duplicated ticket. The
API field `duplicate_of` is the `SNTL-{n}` format of the stored
UUID — a direct conversion with no resolution step. The raw
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
2. **System reopens (automatic):** the last active assignee is restored,
   or no assignee is set if none exists or the previous one is
   deactivated. This handles cases like CVE rejection reverts (see
   `docs/features/tickets/cve-tracking.md`, "Rejection revert handling").

Both transitions go through `ticket_mutations.reopen_from_ignored()`:
1. Acquires `FOR UPDATE` on the ticket
2. Verifies current status is Ignored
3. Sets assignee (if applicable)
4. Re-enters the gate zone at `Analysis` (the unconditional floor);
   `reconcile_ticket_status` evaluates upward and may promote to
   `Analyzed` or `Resolved` if gate conditions are already satisfied

See [ticket-mutations.md](ticket-mutations.md#reopen_from_ignored) for
the full function contract.

All other modifications on Ignored tickets are blocked — mutation
endpoints return 409 `TICKET_NOT_MUTABLE` (same guard as Duplicated).
This prevents gate-relevant data from accumulating while the ticket is
in the manual zone, which would cause unexpected status jumps on reopen.
See [Mutability Guard](#mutability-guard) for enforcement details.

### Modifications in Inactive Statuses

Tickets in inactive statuses (`Resolved`, `Ignored`, `Duplicated`) are not
included in ticket-scoped external monitoring. Global source synchronization
and local derived reconciliation may still update source-owned or derived data;
they do not poll an inactive Ticket's external package scope.

- **Resolved**: modifying gate-relevant data triggers centralized status
  evaluation, which may regress the ticket to Analyzed or Analysis
- **Ignored and Duplicated** (manual zone): mutation endpoints return
  409 `TICKET_NOT_MUTABLE` via `ensure_ticket_operable()` in the service
  layer. Only the dedicated exit endpoints (`POST .../reopen` for
  Ignored, `POST .../revert-duplicate` for Duplicated) bypass this
  guard. See [Mutability Guard](#mutability-guard) for the enforcement
  mechanism.

### Mutability Guard

Enforcement of the manual-zone mutability guard is
centralized in the service-layer function `ensure_ticket_operable()`
(defined in `ticket_mutations`). This function is called by all mutation
functions in `ticket_mutations`, `ticket_service`, and `package_service`
after acquiring `FOR UPDATE` on the ticket row.

```python
def ensure_ticket_operable(ticket: Ticket) -> None:
    if ticket.status in (TicketStatus.Ignored, TicketStatus.Duplicated):
        raise TicketNotMutableError(ticket.id)
```

**Scope**:
- Applied to: all service-layer functions that modify ticket data
- NOT applied to: read operations, manual-zone exit functions
  (`reopen_from_ignored`, `revert_duplicate`)

**Relationship with `require_accessible_ticket`**: the accessibility
check is a router-level API dependency (applies to all operations on a
single ticket, including reads — see `docs/api-spec.md`, Ticket
Accessibility Check). `ensure_ticket_operable` is a service-layer guard
(applied by all mutation functions). The two guards are independent
checks: accessibility is verified at the API layer before the request
reaches the service; operability is verified at the service layer under
the `FOR UPDATE` lock (the authoritative check).

## Tickets Without CVE: Behavioral Differences

When a ticket has no associated CVE (`cve_id IS NULL`), the following
features behave differently:

| Feature | Behavior |
|---------|----------|
| CVSS scoring | Not applicable — no CVE means no CVSS assessments |
| CVSS sync (NVD, Red Hat) | Not applicable — ticket is skipped |
| Severity | Manual via `severity_manual` (editable by VA) |
| Release tracking (track) | Not applicable — track-level detection relies on CVE-ID in IBS diffs |
| Release tracking (product) | Not applicable — product-level detection relies on CVE-ID in `updateinfo.xml` |
| CVE rejection handling | Not applicable — no CVE means no `cve_state` changes |
| CVE rejection revert handling | Not applicable |
| Gate: SUSE CVSS required | Not applicable — severity is set via `severity_manual` instead |

Packages, tracks, and products can still be added and managed
normally. The VA can set affectedness statuses and the ticket can
progress through the full lifecycle.

## Confidential Tickets

Sentinel supports "Confidential Tickets" to securely handle embargoed
vulnerabilities. Confidential tickets restrict read and write access to a
specific subset of authorized users, preventing data leaks prior to public
disclosure.

- **Confidentiality Flag**: A boolean state (`is_confidential`) on the
  Ticket entity that determines if the ticket is under embargo.
- **Visibility mechanisms**: confidential visibility follows scope, explicit
  manual grants, and additive package-maintainer associations.
- **Confidentiality Filtering**: Confidential tickets are excluded at
  the database query level for unauthorized and unauthenticated users.
  They do not appear in list results, are not returned by detail
  endpoints, and leave no visible trace (no placeholders, no redacted
  entries). Authorized users see confidential tickets normally alongside
  non-confidential ones.

Ticket response objects (both list and detail) MUST include the
`is_confidential: boolean` field. This field is always present — there
is no information leakage concern because a user only receives tickets
they are authorized to see (see [Confidentiality Filtering](#confidentiality-filtering)).

See `docs/data-model.md` for the `TicketAccessGrant` entity definition
and the `is_confidential` column on the Ticket table.

### Authorization Rules

When a ticket is `is_confidential=True`, any read/write HTTP request
MUST be evaluated against these rules. Access is **GRANTED** if the user
meets at least one condition:

1. **Scope-based**: The user's effective scope is `all` (see
   `docs/features/identity/rbac.md`, Scope).
2. **Explicit Grant**: The user's `id` exists in the `TicketAccessGrant`
   table for the requested `ticket_id`.
3. **Package maintainer**: The user's `id` matches a
   `TicketPackageMaintainer.user_id` whose parent `TicketPackage` belongs to
   the Ticket and has `deleted_at IS NULL`.

The "full access" conferred by rules 2 or 3 means visibility plus only the
operations permitted by the user's existing capabilities. Neither mechanism
grants capabilities.

*Dynamic Access Note:* A maintainer gains access when a package occurrence is
associated with their User ID and loses access the moment the last qualifying
package is excluded. Restoring the package reactivates the retained association
without external I/O. Track and Product exclusion, lifecycle actionability,
Ticket resolution, and later SMELT omission do not revoke package-wide access.
A package whose Products are all EOL remains qualifying until excluded.

If no condition is met, or if the user is unauthenticated, the
confidential ticket is **invisible**: it is excluded from list queries
and detail endpoints return `404 Not Found`. Unauthenticated users never
see confidential tickets.

*Note: System background tasks (Celery fetchers, event consumers) bypass
these rules and process confidential tickets normally.*

### Confidentiality Filtering

Confidential tickets are filtered at the database query level.
Unauthorized and unauthenticated users never see them — no placeholders,
no redacted entries, no trace of their existence.

**Ticket List (`GET /api/v1/tickets`)**:
The list query includes only non-confidential tickets plus confidential
tickets for which the current user satisfies at least one authorization
rule from [Authorization Rules](#authorization-rules). For
unauthenticated users, only non-confidential tickets are returned.
Pagination counts reflect only the tickets visible to the caller.

**Package Search (`GET /api/v1/packages`)**:
The cross-ticket package search endpoint applies the same
confidentiality filtering as the ticket list. Packages belonging to
confidential tickets are excluded for unauthorized callers. See
`docs/features/packages/package-model.md` (Search Packages Across
Tickets).

**Maintainer Dashboard (`GET /api/v1/my/packages/*`)**:
The maintainer dashboard endpoints MUST apply the same confidentiality
filtering as the ticket list. Although the package-maintainer association used
by the dashboard already coincides with authorization rule 3
([Authorization Rules](#authorization-rules)), the confidentiality filter
MUST be applied explicitly as defense in depth — protecting against
future changes to the dashboard query logic that might inadvertently
bypass the authorization check.

**CVE Detail (`GET /api/v1/cves/{cve_id}/...`)**:
All endpoints under `/api/v1/cves/{cve_id}/` are subject to the
`require_accessible_cve` router-level dependency (see `docs/api-spec.md`,
CVE Accessibility Check). If the CVE is linked to a confidential ticket
that the caller is not authorized to access, the endpoint returns
`404 CVE_NOT_FOUND` — indistinguishable from a non-existent CVE. CVEs
without an associated ticket are freely accessible.

**CVE List (`GET /api/v1/cves`)**:
The list query applies confidentiality filtering via LEFT JOIN to the
Ticket table using `confidential_ticket_filter()`. CVEs associated with
confidential tickets are silently excluded for unauthorized callers,
consistent with the `GET /api/v1/tickets` pattern. CVEs
without an associated ticket are always included. Pagination counts
reflect only the CVEs visible to the caller.

#### Shared Utility: `confidential_ticket_filter()`

The confidentiality filtering logic is implemented as a shared stateless
function in `backend/app/core/filters.py`. It returns a SQLAlchemy
`ColumnElement` (a WHERE clause fragment) that any query can apply. The
endpoint handler constructs the filter; the service function receives it
as a parameter.

```python
# backend/app/core/filters.py

def confidential_ticket_filter(
    ticket_id_col: Column,          # e.g., Ticket.id or TicketPackage.ticket_id
    is_confidential_col: Column,    # e.g., Ticket.is_confidential
    caller_scope: Scope | None,     # None for unauthenticated
    caller_user_id: UUID | None,    # grants and maintainership lookup
) -> ColumnElement:
    """Build a SQL filter expression for confidential ticket visibility.

    Returns a boolean SQL expression that evaluates to TRUE for rows
    the caller is authorized to see. Apply with query.where(...).

    Visibility rules (from rbac.md, Scope and Confidential Ticket
    Visibility):
    - Scope 'all': see everything (returns TRUE)
    - Unauthenticated (scope is None): only non-confidential
    - Scope 'non_confidential': non-confidential OR any of:
        - TicketAccessGrant exists for (ticket_id, user_id)
        - TicketPackageMaintainer exists for caller_user_id through an
          included TicketPackage
    """
```

**Behavior**:

```
IF caller_scope is None:
    return is_confidential_col == False  # unauthenticated

IF caller_scope == Scope.ALL:
    return literal(True)  # no filter -- scope 'all' sees everything

return OR(
    is_confidential_col == False,
    EXISTS(TicketAccessGrant for caller_user_id),
    EXISTS(TicketPackageMaintainer for caller_user_id through an included package),
)
```

**Design properties**:

- **Stateless**: pure function, no side effects, no database calls
- **Decoupled**: accepts column references, not model instances — works
  with any query shape (ticket list, package list, CVE details, etc.)
- **Testable**: can be tested in isolation by inspecting the generated
  SQL expression
- **Single responsibility**: the handler knows the user; the service
  knows the query; the filter knows the rules

**Consumers**:

| Consumer | `ticket_id_col` | Notes |
|----------|-----------------|-------|
| `GET /api/v1/tickets` | `Ticket.id` | Ticket list endpoint |
| `GET /api/v1/cves` | `Ticket.id` (via JOIN from CVE) | CVE list endpoint |
| `GET /api/v1/packages` | `Ticket.id` (via JOIN) | Cross-ticket package search |
| `GET /api/v1/my/packages/*` | `Ticket.id` (via JOIN) | Maintainer operations |
| `require_accessible_ticket` | `Ticket.id` | Single-ticket access guard |
| `require_accessible_cve` | `Ticket.id` (via JOIN from CVE) | Single-CVE access guard |

**Accepted risk — `duplicate_of_id` and confidential targets**: A
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
scope but only reach this code path for non-confidential source
tickets; (c) the reverse scenario (target becomes confidential
after the link is created) is rare and the leak is limited to
existence inference; (d) implementing bidirectional cascading
confidentiality adds significant complexity (reverse traversal,
audit events, revert semantics) disproportionate to the severity
of the information leak.

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

See `docs/features/tickets/ticket-audit-log.md` for the audit event
contract and detail JSONB schema.

### Stale Access Grant Cleanup

When a ticket's `is_confidential` flag is set to `FALSE` (embargo
lifted), the explicit `TicketAccessGrant`
records remain in the database inertly.

To prevent infinite database growth, a Celery Beat background task
(`cleanup_stale_ticket_access_grants`) will be implemented:

- **Type**: Plain Celery Beat task (NOT a `BaseFetcher`, as it does not
  fetch external data). Registered as a static `beat_schedule` entry;
  the Beat registration mechanism is fully specified in
  `docs/features/platform/fetcher-infrastructure.md` ("Non-Fetcher
  Periodic Tasks").
- **Schedule**: Weekly, Sunday at 04:00 UTC.
- **Logic**: Deletes all `TicketAccessGrant` records belonging to
  tickets where `is_confidential = FALSE` AND `updated_at` is older
  than 14 days.

This single condition covers all cases:

- Embargo lifted (ticket made non-confidential) → grants cleaned after
  14 days

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
direct VA exclusion at that level. They also include derived `actionable` and
`non_actionable_reason` fields. In single-ticket views (`TicketDetail`, `GET
/api/v1/tickets/{ticket_id}/packages`), all records are returned
including non-actionable ones. In cross-ticket search (`GET /api/v1/packages`),
non-actionable packages are excluded. See `docs/features/packages/package-model.md`
for the canonical predicates and reason precedence.

Every response that contains `PackageDetail` captures one UTC evaluation date
after its mutations have completed and uses it for the complete package tree.
This applies to Ticket detail, package detail, and every mutation endpoint that
returns `TicketDetail`; one response never mixes lifecycle dates across rows.

#### Shared Sub-Schemas

**UserSummary** — inline representation of a user reference. Fields:
`id` (UUID), `username` (string), `full_name` (string | null), `active`
(boolean). See `docs/api-spec.md`, "User References in Responses" for
the canonical definition.

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
| `is_eligible_override` | boolean | `true` if VA manually set eligibility |
| `released_at` | datetime \| null | Authoritative issued time of the validated stable security advisory that established Product release, serialized in UTC; `null` until confirmed |
| `lifecycle_phase` | string \| null | Current Product lifecycle phase for the response's UTC evaluation date |
| `deleted_at` | datetime \| null | Direct VA-exclusion timestamp |
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
| `deleted_at` | datetime \| null | Direct VA-exclusion timestamp |
| `actionable` | boolean | Whether the track has at least one actionable Product and is not VA-excluded |
| `non_actionable_reason` | string \| null | `package_excluded`, `track_excluded`, or `no_actionable_products`; `null` when actionable |

**PackageDetail** — package within a ticket (detail view only):

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | TicketPackage primary key |
| `package_name` | string | Source package name |
| `tracks` | TrackDetail[] | Tracks (codestreams) for this package |
| `deleted_at` | datetime \| null | Direct VA-exclusion timestamp |
| `actionable` | boolean | Whether the package has at least one actionable track and is not VA-excluded |
| `non_actionable_reason` | string \| null | `package_excluded` or `no_actionable_tracks`; `null` when actionable |

#### TicketSummary

Returned by the list endpoint. Provides enough information for table
views without the full package tree.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Ticket primary key |
| `identifier` | string | Human-readable identifier (`SNTL-{n}`) |
| `status` | string | TicketStatus enum: `new`, `analysis`, `analyzed`, `resolved`, `ignored`, `duplicated` |
| `severity` | string \| null | Resolved severity (CVSS-derived → manual fallback). Values: `critical`, `high`, `medium`, `low`, `none`, or `null` if unresolved. `null` = no CVSS data and no manual severity set. `"none"` = CVSS score 0.0 (informational) |
| `assignee` | UserSummary \| null | Assigned VA, or `null` if unassigned |
| `cve` | CVESummary \| null | Associated CVE summary, or `null` if no CVE |
| `duplicate_of` | string \| null | Duplicate target identifier (`SNTL-{n}`), or `null` |
| `is_confidential` | boolean | Whether the ticket is confidential |
| `package_names` | string[] | Flat list of package names whose `TicketPackage.deleted_at IS NULL` (e.g., `["curl", "openssl-3"]`). Product lifecycle actionability does not remove an associated package name |
| `created_at` | datetime | Creation timestamp (UTC) |
| `updated_at` | datetime | Last modification timestamp (UTC) |

#### TicketDetail

Returned by the detail endpoint and all mutation endpoints. Extends
TicketSummary with the full package tree and expanded CVE data.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Ticket primary key |
| `identifier` | string | Human-readable identifier (`SNTL-{n}`) |
| `status` | string | TicketStatus enum: `new`, `analysis`, `analyzed`, `resolved`, `ignored`, `duplicated` |
| `severity` | string \| null | Resolved severity (CVSS-derived → manual fallback). Values: `critical`, `high`, `medium`, `low`, `none`, or `null` if unresolved. `null` = no CVSS data and no manual severity set. `"none"` = CVSS score 0.0 (informational) |
| `assignee` | UserSummary \| null | Assigned VA, or `null` if unassigned |
| `cve` | CVEDetail \| null | Expanded CVE data with dates, or `null` if no CVE |
| `duplicate_of` | string \| null | Duplicate target identifier (`SNTL-{n}`), or `null` |
| `is_confidential` | boolean | Whether the ticket is confidential |
| `packages` | PackageDetail[] | Full package/track/product tree; maintainer identities are not exposed |
| `created_at` | datetime | Creation timestamp (UTC) |
| `updated_at` | datetime | Last modification timestamp (UTC) |

Note: TicketDetail does not include `package_names` — the same
information is available from `packages[].package_name`.

Note: the API field `duplicate_of` is the `SNTL-{n}` format of
the database column `duplicate_of_id` (UUID FK). No resolution is
needed — the stored UUID always references a non-Duplicated
ticket.

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
| `PATCH .../confidentiality` | `TicketDetail` |

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
  `status` (semantic ordering, see Sorting), `identifier` (sorts by numeric `sequence_id`).
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

Returns a single ticket by UUID or `SNTL-{n}`. The `packages` field
in the response is populated via
`package_service.get_ticket_packages()` — the same function used by
`GET /api/v1/tickets/{ticket_id}/packages`. The response includes
the full package/track/product tree. Maintainer identities and source
maintainership data are not included.

The endpoint captures one UTC evaluation date and passes it to
`get_ticket_packages()` so every lifecycle phase, actionability value, and
reason in the tree uses the same temporal input.

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

### Create Ticket

```
POST /api/v1/tickets
```

**`Capability: create_ticket`**
- **Response schema**: `TicketDetail` (201 Created)

Creates a ticket manually. The creating user is automatically assigned
(if the user holds the `vulnerability_analyst` role — see
[Auto-Assignment on Unassigned Tickets](#auto-assignment-on-unassigned-tickets)).

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
  is created and on-demand fetch is triggered (see
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
| 409 | `TICKET_CVE_CONFLICT` | CVE is already associated with another ticket. Response includes `existing_ticket_id` (UUID) |
| 409 | `TICKET_SEVERITY_DERIVED` | Both `cve_id` and `severity` provided; severity is auto-derived from CVSS |

### Associate CVE

```
POST /api/v1/tickets/{ticket_id}/associate-cve
```

**`Capability: triage_ticket`**
- **Response schema**: `TicketDetail`

Associates a CVE with a ticket that does not have one. If the CVE is not
yet in the Sentinel database, a minimal CVE record is created and on-demand
fetch is triggered automatically (see `docs/features/tickets/cve-service.md`,
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
| 409 | `TICKET_CVE_CONFLICT` | CVE is already associated with another ticket. Response includes `existing_ticket_id` (UUID) |

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
  target must hold the `vulnerability_analyst` role.

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
> [ticket-mutations.md](ticket-mutations.md#inactive-assignee-sanitization)
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
  "duplicate_of_id": "SNTL-42"
}
```

- `duplicate_of_id` (string, required): UUID or `SNTL-{n}` of the
  target ticket

Response: `TicketDetail` object in standard `{"data": ...}` envelope
(200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `TICKET_SELF_DUPLICATE` | Source and target are the same ticket |
| 404 | `TICKET_NOT_FOUND` | Target ticket (`duplicate_of_id`) does not exist |
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
assignment (if applicable), `_reenter_gate_zone()` re-enters the gate
zone at the unconditional `Analysis` floor and evaluates upward — the
result is Analysis, Analyzed, or Resolved based on current gate
conditions, independent of assignee presence. See [Ignored](#ignored)
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

Reverts a Duplicated ticket to its previous status. If the user who
performed the revert holds the `vulnerability_analyst` role, the ticket
is reassigned to them; otherwise, the ticket retains its current
assignee. After restoring the status, `reconcile_ticket_status`
reconciles with current gate conditions.
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
  Identifier Resolution convention; backend resolves via
  `resolve_user_identifier`).
- **Idempotency**: If the grant already exists, returns 200 OK with the
  existing grant data (reflecting the original `granted_by` and
  `granted_at`), without creating an audit event. Otherwise, creates the
  grant and returns 201 Created.
- **Response** (200 OK or 201 Created): The grant object wrapped in the
  standard `{"data": <grant>}` envelope. The grant object has the same
  shape as items in the list response.
- **Audit**: Creates `TicketAuditEvent` with
  `event_type = access_grant_added`.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | Target user not found |
| 409 | `TICKET_NOT_CONFIDENTIAL` | Ticket is not confidential |

#### Revoke Access

```
DELETE /api/v1/tickets/{ticket_id}/access/{user}
```

Revoke explicit access from a user on a confidential ticket. The
`{user}` path parameter is of type `str` and accepts either a UUID or
username.

**`Capability: manage_confidentiality`**
- **Idempotency**: If the grant does not exist, returns 204 No Content
  without creating an audit event.
- **Response**: 204 No Content.
- **Audit**: Creates `TicketAuditEvent` with
  `event_type = access_grant_removed`.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | Target user not found |
| 409 | `TICKET_NOT_CONFIDENTIAL` | Ticket is not confidential |

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
| severity_manual | VARCHAR(20) | nullable                     | Manual severity (Critical, High, Medium, Low, None). NULL = not set (unresolved). `None` = VA explicitly set informational severity (CVSS score 0.0). Used when `cve_id IS NULL`. Cleared to NULL by `associate_cve` when a CVE is linked. Mutually exclusive with `cve_id` (`chk_ticket_severity_manual_cve_exclusive`) |
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
- Managing packages: `manage_packages` capability
- Setting confidentiality, managing access grants: `manage_confidentiality`
  capability
- See `docs/features/identity/rbac.md` for the full permission model

## Cross-references

- `docs/features/tickets/ticket-service.md` — service-layer contract for
  non-gate ticket lifecycle operations and confidentiality management
- `docs/features/tickets/ticket-mutations.md` — ticket-centric mutations,
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
