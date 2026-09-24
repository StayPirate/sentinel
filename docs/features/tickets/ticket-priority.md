# Ticket Priority

## Purpose

Define Ticket **priority**: the urgency of remediating the security issue a
Ticket tracks. Sentinel derives priority automatically from the Ticket's
resolved severity and the exploitation evidence already ingested for its CVE
(CISA KEV, CISA SSVC, FIRST EPSS). An authorized user may override the derived
value.

This specification is the authoritative source for priority semantics, the
exploitation classification, the decision table, persistence of the automatic
and manual values, the automatic refresh points, the manual override, the
`priority_changed` audit contract, and the priority-related API surface.

## Priority and Severity

Severity and priority answer different questions:

| Concept | Question | Source | Owner |
|---|---|---|---|
| Severity | How large is the intrinsic impact? | CVSS resolution (`CVE.severity`) or `Ticket.severity_manual` | [tickets.md](tickets.md#severity-resolution), [cvss-scoring.md](cvss-scoring.md) |
| Priority | How urgently should the issue be remediated? | Resolved severity combined with exploitation evidence, or a manual override | This specification |

Priority is **informational only**. It is never an input to a Ticket status
gate, `reconcile_ticket_status()`, Product eligibility, package affectedness or
delivery, assignment, auto-assignment eligibility, Ticket accessibility, or any
fetcher scope. No existing behavior changes because a priority value changes.

Priority belongs to the Ticket only. A CVE has no priority; CVE resources expose
the exploitation evidence (see [cve-tracking.md](cve-tracking.md#get-cve)) but
never a derived priority.

## Priority Levels

| Level | Meaning |
|---|---|
| `P1` | Remediate immediately |
| `P2` | Remediate with high urgency |
| `P3` | Remediate in the normal flow |
| `P4` | Remediate when convenient |
| `NULL` | Not yet prioritizable: neither the severity nor strong exploitation evidence is known |

`NULL` is never replaced by `P4` or any other level. The logical values are
`P1`–`P4`; the API wire format is lowercase (`p1`–`p4`) under the Ticket enum
serialization rule in [tickets.md](tickets.md#response-schemas). The
`TicketPriority` enum is defined in `docs/data-model.md`.

## Exploitation Level

The exploitation level is an internal, non-persisted classification of the
evidence attached to the Ticket's associated CVE. The first matching row wins:

| Level | Condition |
|---|---|
| `kev` | A `CVEKEVEntry` exists for the CVE |
| `active` | The CVE's `CVESSVCAssessment.exploitation` is `active` |
| `likely` | The CVE's `CVESSVCAssessment.exploitation` is `poc`, or its `CVEEPSSScore.percentile` is greater than or equal to `0.95` |
| `unknown` | Every other case, including SSVC `exploitation = none`, absent SSVC/EPSS/KEV rows, and a Ticket without a CVE |

Classification uses the persisted evidence as is. Evidence freshness follows
each source's own refresh scope; for example, EPSS is refreshed only while the
Ticket is active ([cve-sync-epss.md](cve-sync-epss.md)), so an inactive
Ticket's priority may reflect its last persisted percentile.

The EPSS threshold `0.95` is a specification constant, not a setting. It
compares the persisted percentile, never the EPSS probability score. SSVC
`automatable`, SSVC `technical_impact`, the EPSS score, CWE classifications,
and every other CVE field are not inputs.

## Decision Table

The automatic priority is a pure function of the Ticket's resolved severity
(canonical cascade in [tickets.md](tickets.md#resolution-rules)) and the
exploitation level:

| Exploitation | Critical | High | Medium | Low or None | Severity `NULL` |
|---|---|---|---|---|---|
| `kev` | P1 | P1 | P1 | P1 | P1 |
| `active` | P1 | P1 | P2 | P3 | P2 |
| `likely` | P2 | P2 | P3 | P4 | P3 |
| `unknown` | P2 | P3 | P4 | P4 | `NULL` |

A Ticket without a CVE always uses the `unknown` row with its
`severity_manual`; if that value is `NULL`, its automatic priority is `NULL`.

## Pure Resolution Functions

Module: `backend/app/services/ticket_priority.py`. Both functions are
Category B: they perform no database access, write, audit, lock, or external
call, and they raise no exception for any value of their declared input types.

### `classify_exploitation()`

```python
def classify_exploitation(
    *,
    kev_listed: bool,
    ssvc_exploitation: str | None,
    epss_percentile: float | None,
) -> ExploitationLevel:
```

`kev_listed` states whether a `CVEKEVEntry` exists. `ssvc_exploitation` is the
persisted SSVC `exploitation` value or `None` when no assessment exists.
`epss_percentile` is the persisted EPSS percentile or `None` when no score
exists. The function applies the [Exploitation Level](#exploitation-level)
table in order. An SSVC value other than `active` or `poc` contributes no
evidence.

`ExploitationLevel` is a service-internal enum with the values `kev`,
`active`, `likely`, and `unknown`; it is neither persisted nor serialized.

### `resolve_priority()`

```python
def resolve_priority(
    severity: Severity | None,
    exploitation: ExploitationLevel,
) -> TicketPriority | None:
```

Returns the [Decision Table](#decision-table) cell for the resolved severity
label (`None` meaning SQL `NULL`, distinct from the `None` severity label) and
the exploitation level.

## Persistence and Effective Priority

`Ticket` persists two nullable columns (see `docs/data-model.md`, Ticket):

- `priority_auto` — system-managed. Only
  [`refresh_priority_auto()`](#refresh_priority_auto) writes it.
- `priority_override` — the sticky manual value. Only
  [`set_priority_override()`](#set_priority_override) writes it. Automatic
  processing never modifies or clears it.

The **effective priority** is `COALESCE(priority_override, priority_auto)`. It
is the value exposed as `priority` in API responses, filtered, sorted, and
recorded in audit events. It is derived at read time and is not stored in a
third column. No override reason or comment is stored.

The columns are introduced without a data backfill because no live or
production database exists; every Ticket receives its automatic value at its
next refresh point.

## Automatic Refresh

### `refresh_priority_auto()`

Category A primitive in `ticket_mutations`:

```python
async def refresh_priority_auto(
    db: AsyncSession,
    *,
    ticket: Ticket,
) -> bool:
```

`ticket` is the caller's locked Ticket instance. The return value is `True`
exactly when this call changed the persisted `priority_auto`.

**Preconditions (trusted, not rediscovered)**: the caller holds the Ticket
`FOR UPDATE` or inserted it in the current transaction and, when the Ticket has an associated CVE, holds that CVE root
lock acquired before the Ticket under the cross-domain root order. The function
acquires no lock, performs no consumer accessibility check, and does not call
`ensure_ticket_operable()`: automatic priority is maintained in every Ticket
status, like `CVE.severity`.

**Behavior**:

1. Read the resolved severity from locked-current state: `CVE.severity` when
   `ticket.cve_id` is set, otherwise `ticket.severity_manual`. Every read
   observes the writes already made by the enclosing transaction.
2. When the Ticket has a CVE, read whether its `CVEKEVEntry` exists, its SSVC
   `exploitation`, and its EPSS `percentile`; otherwise use no evidence.
3. Compute `resolve_priority(severity, classify_exploitation(...))`.
4. If the result equals `ticket.priority_auto`, return `False` with no write or
   event.
5. Otherwise capture the old effective priority, persist the new
   `priority_auto`, and compute the new effective priority.
6. If the effective priority changed, create one system-attributed
   `priority_changed` event (see [Audit](#audit)). If an override masks the
   change, create no event.
7. Flush and return `True`.

It never assigns, reconciles, changes status, registers Ticket convergence, or
performs network, Redis, or Celery I/O. Re-invocation with unchanged inputs is
a no-op. Database, audit, and flush exceptions propagate unchanged and roll
back the caller's complete transaction.

### Refresh Points

Every workflow that can change a priority input calls
`refresh_priority_auto()` under the locks it already holds. No refresh point
introduces a new root or lock order.

| Priority input change | Workflow and refresh position |
|---|---|
| External CVSS assessments change `CVE.severity` | `upsert_external_cvss_batch()`, after at least one created or updated candidate and its severity and Product steps, before its optional final reconciliation, in every Ticket status ([ticket-mutations.md](ticket-mutations.md#upsert_external_cvss_batch)) |
| KEV, SSVC, or EPSS evidence changes, including enrichment-only payloads and Ticket creation during ingestion | `cve_service.upsert_cve()`, once after the CVSS batch and before the lifecycle decision ([cve-service.md](cve-service.md#complete-upsert_cve-composition)) |
| Manual SUSE assessment create, update, or delete | `upsert_cvss_assessment()` and `delete_cvss_assessment()`, after an effective mutation's severity and Product steps and before the optional final reconciliation, when a Ticket exists |
| Manual severity | `set_severity_manual()`, after its `severity_changed` event and before reconciliation |
| CVE association (severity-source handover and new evidence) | `recalculate_cvss_chain()` in association mode, after the handover and Product events; `associate_cve()` then performs its one final reconciliation |
| Default CVSS version change | `recalculate_cvss_chain()` in default-version mode, after the severity and Product steps and before the optional final reconciliation, in every Ticket status |
| Manual Ticket creation | `create_ticket()` with `source = manual`, after its last creation event. The `cve_ingestion` source does not refresh; its caller `upsert_cve()` owns the refresh |

The refresh in `upsert_cve()` is a no-op when the batch already refreshed from
the same inputs, because KEV, SSVC, and EPSS writes precede the batch.

Status transitions, assignment, reconciliation, manual-zone entry and exit,
package-tree, Product, confidentiality, grant, reference, and priority-override
mutations do not change a priority input and do not refresh. Priority inputs
are never changed by reconciliation or by the CVE rejection lifecycle step.

The default-CVSS impact preview does not project priority: priority is not part
of its result, and no preview count reflects it.

## Manual Override

### `set_priority_override()`

Category A operation in `ticket_service`:

```python
async def set_priority_override(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    priority: TicketPriority | None,
    acting_user_id: UUID,
    evaluation_date: date | None = None,
) -> Ticket:
```

`priority` is the requested override; `None` clears it. `acting_user_id` is the
authorized user; system callers do not exist for this operation.
`evaluation_date` follows the `TicketDetail` workflow-date contract in
[ticket-service.md](ticket-service.md#get_ticket_detail); when omitted, the
function captures one UTC date at entry.

**Behavior**:

1. Acquire `FOR SHARE` on the acting User and stabilize its active and
   `vulnerability_analyst` eligibility, then acquire `FOR UPDATE` on the
   Ticket.
2. Revalidate consumer accessibility from the locked-current Ticket. Missing or
   inaccessible raises `TicketNotFoundError` with no effect.
3. Call `ensure_ticket_operable(ticket)`. `Ignored` and `Duplicated` raise
   `TicketNotMutableError` with no effect.
4. If `priority` equals the current `priority_override` (including `None` when
   no override exists), return the Ticket unchanged: no assignment, write,
   event, or reconciliation.
5. Call `auto_assign_actor()` with the stabilized User.
6. Classify the action from the locked pre-state: `set` (no override to a
   value), `changed` (one value to another), or `cleared` (a value to none).
   Capture the old effective priority, persist `priority_override`, and compute
   the new effective priority.
7. Create one `priority_changed` event attributed to the acting user, with the
   old and new effective priorities and the action in `detail`, even when the effective priority is unchanged (for
   example, an override equal to `priority_auto`).
8. Call `reconcile_ticket_status()` exactly once with the one
   `evaluation_date`. Priority is not a gate input; reconciliation is required
   by the [auto-assignment rule](ticket-mutations.md#auto-assignment-rule) and
   performs assignment-eligibility sanitation and gate evaluation after a
   possible `New -> Analysis` promotion.
9. Return the updated Ticket.

`priority_auto` is not modified. Re-invocation with the same value is the
step-4 no-op. The operation propagates `TicketNotFoundError`,
`TicketNotMutableError`, and exceptions from `auto_assign_actor()` and
`reconcile_ticket_status()`; any failure rolls back the override, assignment,
status, and every event together.

The consumer endpoint is `PATCH /api/v1/tickets/{ticket_id}/priority` with
`Capability: triage_ticket`, defined in
[tickets.md](tickets.md#set-priority-override).

## Audit

`priority_changed` records a change of priority. The field contract is owned by
[ticket-audit-log.md](ticket-audit-log.md#event-type-contract):

| Trigger | `user_id` | `old_value` / `new_value` | `comment` | `detail` |
|---|---|---|---|---|
| Automatic refresh changes the effective priority | `NULL` | Old and new effective priority (`P1`–`P4` or `NULL`) | `NULL` | `NULL` |
| Override set, changed, or cleared | Acting user | Old and new effective priority; may be equal | `NULL` | `{"override_action": "set" \| "changed" \| "cleared"}` |

An automatic `priority_auto` change masked by an override, an unchanged
refresh, an override no-op, and every rejected or rolled-back operation create
no event. Audit history is never an input to priority resolution.

## API Surface

| Surface | Contract | Owner |
|---|---|---|
| `TicketSummary.priority`, `TicketDetail.priority` | Effective priority | [tickets.md](tickets.md#response-schemas) |
| `TicketDetail.priority_automatic`, `TicketDetail.priority_override` | Persisted automatic and manual values | [tickets.md](tickets.md#ticketdetail) |
| `GET /api/v1/tickets` `priority` filter and `sort_by=priority` | Repeatable filter over effective priority, including `unresolved`; semantic ordering | [tickets.md](tickets.md#list-tickets), [api-spec.md](../../api-spec.md#semantic-sort-fields) |
| `PATCH /api/v1/tickets/{ticket_id}/priority` | Set or clear the override | [tickets.md](tickets.md#set-priority-override) |
| `CVEDetail` exploitation and weakness data; `GET /api/v1/cves/{cve_id}` | Evidence inputs, never a CVE priority | [tickets.md](tickets.md#shared-sub-schemas), [cve-tracking.md](cve-tracking.md#get-cve) |

The derived exploitation level is not exposed; its inputs are visible in
`CVEDetail`.

## Testing Requirements

Tests MUST cover:

1. Every decision-table cell, including severity `None` versus `NULL`, and each
   exploitation precedence order (KEV over SSVC, SSVC `active` over `poc`, EPSS
   percentile exactly `0.95` versus just below, EPSS score ignored, SSVC
   `none`, `automatable`, and `technical_impact` ignored).
2. CVE-less Tickets using `severity_manual` with the `unknown` row, and `NULL`
   priority when it is unset.
3. Every refresh point: the persisted `priority_auto`, the exact system event
   and its position (after severity and Product events, before assignment-
   eligibility sanitation and the final gate `status_change`), refresh in every
   Ticket status, the single refresh for ingestion-created Tickets, and
   enrichment-only KEV/SSVC/EPSS payloads.
4. An override masking an automatic change (persisted `priority_auto` change,
   no event) and a later clear exposing the automatic value.
5. Override set, changed, and cleared with exact `override_action`, equal
   old/new values when the effective priority does not change, the no-op,
   auto-assignment with `New -> Analysis` followed by one reconciliation,
   `TICKET_NOT_FOUND` for missing and inaccessible Tickets, `TICKET_NOT_MUTABLE`
   in `Ignored` and `Duplicated`, `403` without `triage_ticket`, and rollback.
6. Proof that the automatic refresh never alters status, gates, Product
   eligibility, assignment, or accessibility, that the override's assignment
   and status consequences arise only from the auto-assignment rule (item 5),
   and that no refresh consults audit history.
7. Independent-session races between the override and an automatic refresh on
   the same Ticket, proving serialized pre-state and no stale event values.
8. The default-version runner classifying a unit `changed` when only
   `priority_auto` changes.
9. API filter (`p1`–`p4`, `unresolved`, invalid values ignored), semantic
   sort with NULL last, and response fields.

Audit assertions follow `docs/features/platform/testing-strategy.md` (Audit
Trail Testing).

## Cross-references

- `docs/features/tickets/tickets.md` — severity resolution, Ticket schemas,
  list filters, and the override endpoint
- `docs/features/tickets/ticket-mutations.md` — CVSS chains, manual severity,
  auto-assignment, and reconciliation
- `docs/features/tickets/ticket-service.md` — Ticket creation, CVE
  association, and `TicketDetail` assembly
- `docs/features/tickets/cve-service.md` — `upsert_cve()` composition and CVE
  reads
- `docs/features/tickets/cve-tracking.md` — CVE detail endpoint
- `docs/features/tickets/cve-sync-kev.md`, `cve-sync-epss.md`,
  `cve-sync-mitre.md` — exploitation evidence sources
- `docs/features/tickets/ticket-audit-log.md` — `priority_changed` contract
- `docs/features/platform/default-cvss-version-operations.md` — all-CVE
  runner and impact preview
- `docs/data-model.md` — `Ticket` priority columns and `TicketPriority`
- `docs/api-spec.md` — semantic sorting, filtering, and error derivation
- `docs/features/identity/rbac.md` — `triage_ticket` and the Endpoint
  Permission Map
