# Ticket Audit Log

## Purpose

Provide a complete, searchable audit trail for every ticket in Sentinel. Each
effective Ticket-related mutation creates exactly the event or events required
by its owning domain contract, or follows an explicit no-event contract in the
canonical matrix below. A mutation covered by neither is an undefined audit
boundary and must not be implemented. Audit events record semantic domain
changes, not mutation attempts, operational workflow progress, or every factual
write associated with a Ticket.
Users can browse, filter, and search the history through the audit-log API
endpoint.

The `TicketAuditLog` subclass of `BaseAuditLog` provides the event creation
helper and registers this audit trail in the global registry. See
`docs/features/platform/audit-trail-infrastructure.md` for the base class
contract.

## Data Model

The `TicketAuditEvent` table and `TicketAuditEventType` enum are defined in
`docs/data-model.md`. This specification defines the **contract** for how
each event type must be populated.

### Event Type Contract

When the canonical mutation matrix requires an event, the owning service
populates it according to this table. The enum remains a closed inventory of 30
event types; an explicit no-event boundary is not represented by an additional
event type.

| `event_type` | Trigger | `user_id` | `old_value` | `new_value` | `comment` | `detail` |
|---|---|---|---|---|---|---|
| `status_change` | Ticket status transitions (manual or system-initiated) | Authorized acting user for direct manual transitions; `NULL` for derived or automatic transitions | Previous status (e.g., `New`) | New status (e.g., `Analysis`) | Exactly `CVE rejected` for CVE rejection; otherwise `NULL` | `NULL` |
| `assignment` | Ticket assigned, reassigned, or system-unassigned | Authorized acting user for direct assignment and auto-assignment; `NULL` for system unassignment | Previous assignee username or `NULL` | New assignee username or `NULL` (unassigned) | `NULL` for assignment/reassignment; system unassignment uses `Unassigned from {username}: {reason}` with a closed reason below | `NULL` |
| `duplicate_set` | Ticket marked as duplicate | Authorized acting user | `NULL` | `SNTL-{n}` identifier of the original ticket | `NULL` | `NULL` |
| `duplicate_removed` | Duplicate mark reverted | Authorized acting user | `SNTL-{n}` identifier of the original ticket | `NULL` | `NULL` | `NULL` |
| `duplicate_target_changed` | Atomic repoint: the ticket's `duplicate_of_id` was updated within the same transaction as the triggering mark-as-duplicate operation, because the ticket's previous target was itself marked as duplicate | `NULL` | `SNTL-{n}` identifier of the previous target | `SNTL-{n}` identifier of the new target | `NULL` | `{"triggered_by_ticket": "SNTL-{n}"}` — the identifier of the ticket whose mark-as-duplicate operation triggered this repoint |
| `package_added` | Package tree created or incrementally completed (manual or automatic). One event per invocation that creates at least one package, track, or Product record; child records do not generate separate events. A completely no-op invocation creates no `package_added` event. | Acting user for manual, `NULL` for automatic | `NULL` | Package name | User-facing API: `NULL`; automatic workflow: exactly `CVE package resolution`, `Product catalog backfill`, or `Ticket convergence` | `NULL` |
| `package_maintainer_added` | Package resolution creates one `TicketPackageMaintainer` association | `NULL` | `NULL` | Event-time target username | `NULL` | `{"package": "fictional-package"}` |
| `package_excluded` | Package directly soft-deleted by an authorized acting user. Child tracks and Products are not modified and do not generate events; they become effectively excluded through the hierarchy | Acting user | Package name | `NULL` | `NULL` | `NULL` |
| `package_restored` | Directly excluded package restored to ticket. Only the package record is restored — child records are not modified | Acting user | `NULL` | Package name | `NULL` | `NULL` |
| `track_status_changed` | Track status changed (authorized user action, including CVE-less `manage_packages` or unrestricted `admin_ticket_ops` FIXED, or release detection) | Acting user for user-attributed changes, `NULL` for automatic transitions (e.g., release detected sets FIXED) | Old status | New status | `NULL` | `{"track": "...", "package": "..."}` (see detail contract) |
| `product_released` | Product release detected via updateinfo.xml | `NULL` | `NULL` | Advisory-issued `released_at` timestamp in UTC ISO 8601 format | `NULL` | Product subject plus `advisory_id` (see detail contract) |
| `ticket_created` | Ticket created (CVE ingestion or manual creation) | `NULL` for automatic creation, creating user for manual creation | `NULL` | `NULL` | Exactly `Ticket created manually`, or `CVE ingested from {source}` using the canonical source label in `cve-service.md` | `NULL` |
| `cve_associated` | CVE associated with a ticket that previously had no CVE | Acting user for explicit association; creating user or `NULL` when included in Ticket creation | `NULL` | CVE-ID string (e.g., `"CVE-2024-1234"`) | `NULL` | `NULL` |
| `severity_changed` | CVSS resolution changes `CVE.severity`, an authorized user sets/clears manual severity, or CVE association hands over from manual to CVSS-derived severity | `NULL` for every CVSS-derived value, including association handover; acting user only for direct `set_severity_manual()` | Old severity (e.g., `High`) or `NULL` | New severity (e.g., `Critical`) or `NULL` | `NULL` | `NULL` |
| `priority_changed` | An automatic refresh changes the Ticket's effective priority, or an authorized user sets, changes, or clears the priority override (see `ticket-priority.md`) | `NULL` for automatic changes; acting user for override changes | Previous effective priority (`P1`–`P4`) or `NULL` | New effective priority (`P1`–`P4`) or `NULL`; may equal the old value for an override change | `NULL` | `NULL` for automatic changes; `{"override_action": "..."}` for override changes (see detail contract) |
| `cvss_assessment_changed` | CVSS assessment added, modified, or removed | Acting user for manual SUSE changes, `NULL` for trusted external ingestion | Previous canonical `"provider_name vX.Y vector_string (score)"` or `NULL` if new | Current canonical `"provider_name vX.Y vector_string (score)"` or `NULL` if removed | `NULL` | `NULL` |
| `product_eligibility_changed` | Product eligibility or its manual-override ownership changed due to CVSS/default-version recalculation, reactivation, lifecycle phase transition (Reactive Support), threshold change, or authorized-user override | Authorized acting user for direct overrides, `NULL` for system-triggered changes | Old eligibility (`true` or `false`) | New eligibility (`true` or `false`); may equal old value for a metadata-only override set/clear | `NULL` | Product subject plus `reason` and conditional `override_action` (see detail contract) |
| `track_excluded` | Track directly soft-deleted by an authorized acting user. Child Products are not modified and do not generate events; they become effectively excluded through the hierarchy | Acting user | Track name | `NULL` | `NULL` | `{"track": "...", "package": "..."}` (see detail contract) |
| `track_restored` | Directly excluded track restored to ticket. Only the track record is restored — child products are not modified | Acting user | `NULL` | Track name | `NULL` | `{"track": "...", "package": "..."}` (see detail contract) |
| `product_excluded` | Product directly soft-deleted by an authorized acting user | Acting user | Product display name | `NULL` | `NULL` | Product subject (see detail contract) |
| `product_restored` | Directly excluded product restored to ticket | Acting user | `NULL` | Product display name | `NULL` | Product subject (see detail contract) |
| `confidentiality_changed` | Ticket `is_confidential` flag toggled; when changing `true` to `false`, all explicit grants are deleted in the same transaction | Acting user | `"true"` or `"false"` | `"true"` or `"false"` | `NULL` | `NULL` |
| `access_grant_added` | User manually granted explicit access to a confidential ticket | Acting user | `NULL` | Target username | `NULL` | `NULL` |
| `access_grant_removed` | User manually revoked explicit access to a confidential ticket | Acting user | Target username | `NULL` | `NULL` | `NULL` |
| `reference_added` | Manual reference added to ticket | Acting user | `NULL` | Reference URL | `NULL` | `NULL` |
| `reference_deleted` | Manual reference deleted from ticket | Acting user | Reference URL | `NULL` | `NULL` | `NULL` |
| `reference_url_changed` | Manual reference URL changed via PATCH | Acting user | Previous URL | New URL | `NULL` | `NULL` |
| `reference_type_changed` | Manual reference type changed via PATCH | Acting user | Previous type (e.g., `advisory`) or `NULL` | New type (e.g., `patch`) or `NULL` | `NULL` | `{"url": "..."}` (see detail contract) |
| `reference_title_changed` | Manual reference title changed via PATCH | Acting user | Previous title or `NULL` | New title or `NULL` | `NULL` | `{"url": "..."}` (see detail contract) |
| `reference_description_changed` | Manual reference description changed via PATCH | Acting user | Previous description or `NULL` | New description or `NULL` | `NULL` | `{"url": "..."}` (see detail contract) |

> **Severity value note**: `old_value` and `new_value` can be `NULL` for
> `severity_changed`. A transition from unresolved to resolved uses
> `old_value = NULL`; deleting the last winning assessment may produce
> `new_value = NULL`. For the manual-to-derived handover triggered by
> `associate_cve()`, the old value is the previous `severity_manual` and the
> new value is the CVSS-derived severity or `NULL`. `recalculate_cvss_chain()`
> emits this event from the previous value supplied by `associate_cve()`, with
> `user_id = NULL`, because Sentinel derives the result even though a user
> initiated the association.

**Rules**:

- `user_id` identifies the actor of the semantic event represented, not
  necessarily the initiator of a larger composed workflow. A direct authorized
  user action uses that acting user's UUID. A derived consequence uses `NULL`
  even when a user initiated the containing workflow. Derived system events
  include CVSS-derived severity, automatic Product eligibility, gate-derived
  status, assignment-eligibility sanitation, duplicate-dependent repointing, and
  package maintainership acquisition. The `vulnerability_analyst` role is named
  only where role membership itself controls assignment eligibility or
  auto-assignment.
- `product_released` is created only for an effective NULL-to-timestamp
  Product release mutation. No-match, malformed or retracted advisory,
  repository failure, duplicate evidence, and idempotent or concurrent no-op
  outcomes create no Ticket audit event.
- `delivery_status` changes create no `TicketAuditEvent`. Request/action
  provenance and the persisted track value are their domain evidence; no
  `delivery_status_changed` event exists.
- `old_value` and `new_value` store human-readable strings. For enum values,
  store the enum name (e.g., `AFFECTED`, `NOT_AFFECTED`). For user
  references, store the username.
- A canonical CVSS assessment value has the exact form
  `"{provider_name} v{cvss_version} {vector_string} ({score:.1f})"`. The
  provider is the persisted canonical provider, the version and vector are the
  parser's canonical values, and score is the decimal base score. Created
  events use `old_value = NULL`; deleted events use `new_value = NULL`.
- An effective assessment mutation creates `cvss_assessment_changed` whenever
  the CVE has an associated Ticket, in every Ticket status. If the resulting
  unified `CVE.severity` changes, `severity_changed` follows it in the same
  transaction. Deferred-until-reactivation package propagation never defers
  these direct records.
- A ticketless CVE has no `TicketAuditEvent` target and creates no Ticket audit
  record. Unchanged, rejected, not-found, concurrent-loser no-op, and rolled-
  back assessment outcomes likewise create none.
- Event insertion order is deterministic. Ticket creation records
  `ticket_created` first, then optional assignment, optional manual severity,
  optional CVE association, and, for manual creation, optional automatic
  `priority_changed` events. CVE association
  records `cve_associated` before its derived severity handover. An effective
  manual SUSE chain records optional `assignment`, optional system
  `New → Analysis`, `cvss_assessment_changed`, optional derived
  `severity_changed`, automatic Product eligibility events, optional automatic
  `priority_changed`, and optional final gate `status_change`, in that order.
  Every automatic `priority_changed` follows the severity and Product events of
  its workflow and precedes assignment-eligibility sanitation and the final
  gate event. A direct override records optional `assignment` and system
  `New → Analysis`, then `priority_changed`, then the optional final gate
  event. An external chain begins with
  `cvss_assessment_changed` because it never assigns. Product events are ordered
  by `TicketPackageProduct.id` ascending; multiple maintainer events are ordered
  by `User.id` ascending; duplicate-dependent events follow the locked dependent
  Ticket UUID order; and a multi-field reference PATCH emits URL, type, title,
  then description events. These UUIDs are ordering inputs and are not added to
  event `detail`. Assignment-eligibility sanitation follows all gate-input events and
  precedes the final gate-derived `status_change`, which is always last.
- One trusted-external ingestion batch orders its effective assessment events by
  version `4.0`, `3.1`, `3.0`, `2.0`, then canonical provider ascending by Unicode code
  point. It then emits at most one `severity_changed`, all changed Product
  events, at most one automatic `priority_changed`, and at most one final
  reconciliation event. If the transaction also
  creates a Ticket, `ticket_created` and `cve_associated` precede that batch.
  When the batch is empty or all-unchanged, the ingestion's own priority refresh
  emits the optional `priority_changed` after the batch. If
  it then applies CVE rejection, the exact `New -> Ignored` event follows the
  complete CVSS batch and priority refresh. Republication's manual-zone-exit events likewise follow
  the assessment writes and direct CVSS events; an `Ignored` Ticket's deferred
  Product events occur during that exit from the batch's final assessment set.
- Automatic Product recalculation creates exactly one event for each occurrence
  whose persisted boolean changes. Override-skipped, unchanged, manual-zone-
  deferred or skipped, rejected, not-found, and rolled-back Product outcomes
  create none. `Resolved` is not a deferred state. An authorized-user override
  set or clear remains an effective metadata mutation when
  `is_eligible_override` changes even if the boolean does not; that one event
  truthfully carries equal old/new booleans and the applicable
  `override_action`.
- `priority_changed` records the effective priority
  (`COALESCE(priority_override, priority_auto)`). An automatic refresh creates
  it only when the effective value changes; a `priority_auto` change masked by
  an override is an effective mutation with an explicit no-event contract. A
  direct override set, change, or clear always creates one event, even when the
  effective value is unchanged, carrying the applicable `override_action`.
- `comment` is system-generated human-readable text and is never user input or
  structured machine-readable data. Event types use `comment = NULL` unless the
  event table or the canonical vocabulary below specifies an exact value. A
  future user-note feature requires its own contract rather than ad-hoc audit
  comments.
- `detail` is used for structured machine-readable context (JSONB). Keys are
  validated per event type — see the detail JSONB Schema Contract below.
  Event types not listed in the contract MUST set `detail` to `NULL`.
- Product subject fields are event-time snapshots. Services populate them from
  the locked mutation context before changing the row. Audit reads and search
  never join current Product data to reconstruct historical meaning.
- Every effective direct exclusion or restoration creates exactly one event of
  its corresponding type for the selected marker, even when effective
  actionability was already false or remains false because of an ancestor or
  EOL. Assignment and Ticket status changes, when applicable, are separate
  events. Repeated-call losers, path/operability rejection, rollback, and
  lifecycle-only actionability changes create no exclusion/restoration event.
- An effective confidentiality `true` to `false` transition creates exactly one
  `confidentiality_changed` event. Its automatic deletion of every
  `TicketAccessGrant` creates no `access_grant_removed` event; that type is
  reserved for an effective manual revoke. User deactivation and reactivation
  retain grants and create no grant event. A later `false` to `true` transition
  does not recreate deleted grants and creates only its own
  `confidentiality_changed` event.
- All events include an implicit `created_at` timestamp set by the database
  default.
- Dispatching or executing the Ticket convergence workflow, including an
  operator rerun, creates no event of its own. Effective delegated domain
  mutations retain their existing event contracts. Operational request,
  retry, partial-failure, and terminal-failure evidence belongs in structured
  logs; audit history is never used as workflow provenance or current-state
  input.
- Publishing or executing post-ingest package resolution creates no event for
  the workflow outcome. Empty resolution, candidate no-match, excluded skip,
  inactive-Ticket termination, isolated package failure, partial completion,
  and terminal failure are operational log outcomes only. Effective delegated
  mutations retain their atomic `package_added` and
  `package_maintainer_added` events per independently committed package.

### Canonical Automatic Comment Vocabulary

The following values are exact and testable. No caller may substitute an
illustrative phrase or pass arbitrary text into a Ticket audit comment.

| Event and context | Exact `comment` |
|---|---|
| Manual Ticket creation | `Ticket created manually` |
| CVE-ingestion Ticket creation | `CVE ingested from {source}` |
| User-facing package addition | `NULL` |
| Post-ingest CVE package resolution | `CVE package resolution` |
| Product catalog backfill | `Product catalog backfill` |
| Ticket convergence package resolution | `Ticket convergence` |
| Assignment, reassignment, assignment promotion, ordinary gate reconciliation, manual-zone entry or exit, and other normal status transitions | `NULL` |
| CVE rejection `New → Ignored` | `CVE rejected` |
| System unassignment | `Unassigned from {username}: {reason}` |

System unassignment selects `{reason}` from this closed vocabulary:

- `user deactivated`;
- `vulnerability_analyst role removed`;
- `vulnerability_analyst role removed by external sync`;
- `vulnerability_analyst role removed after role mapping deletion`; or
- `inactive assignee`.

The two sanitation reasons have deterministic precedence: when the current
assignee is both inactive and without any VA origin, use `inactive assignee`.
`vulnerability_analyst role removed` is used when the User is still active but
has no VA origin. Identity-owned deactivation and final-role-loss batches use
their applicable lifecycle reason from the same closed vocabulary; external
workflows use the more specific external variant. In the
sanitation path, `vulnerability_analyst role removed` describes the observed
absence of a current origin under this closed vocabulary; it does not assert
that audit history proves the User previously held one.

The username and source label are event-time snapshots. Audit reads never join
current operational data to reconstruct them.

### Canonical Mutation and No-Event Matrix

This matrix classifies the complete Ticket-related mutation boundary. The event
table above owns exact fields; the referenced domain service owns guards,
idempotency, lock order, and transaction composition. A row that says “none” is
an intentional no-event contract, not missing audit coverage.

| Domain outcome | Required Ticket event or explicit no-event contract | Semantic actor | Owner and serialization root |
|---|---|---|---|
| Ticket creation | `ticket_created` first, then optional `assignment`, optional `severity_changed`, and optional `cve_associated` | Direct creation events use the acting user; ingestion uses system | `ticket_service`; manual path locks User, then optional CVE before insert; system path locks optional CVE before insert |
| Direct assignment or reassignment | One `assignment`; optional system `New → Analysis`; optional final gate event | Acting user for assignment, system for derived status | `ticket_service`; target User then Ticket |
| Auto-assignment during an effective mutation | One `assignment`; system `New → Analysis` when applicable | Acting user for assignment, system for promotion | Owning mutation service; stabilized acting User then optional CVE then Ticket |
| User deactivation, final VA-role loss, or assignment-eligibility sanitation | One `assignment` per effectively cleared non-NULL assignee | System | `user_service`: User `FOR NO KEY UPDATE` then ordered Ticket locks; reconciliation sanitation: existing Ticket lock plus a fresh unlocked User/role observation |
| Ignore, mark duplicate, reopen, or revert duplicate | Direct `status_change`, `duplicate_set`, or `duplicate_removed` as applicable; one `duplicate_target_changed` per repointed dependent; derived Product, sanitation, and final status events retain their normal contracts | Acting user for the direct ignore, duplicate-set, or duplicate-remove decision; reopen's resulting gate status and all other derived consequences use system | `ticket_service`; Ticket, ordered multi-Ticket, or locked dependent roots as specified there |
| CVE association and rejection/revert | `cve_associated`; applicable derived severity/Product/status events; rejection uses one `status_change`. A rejected orphan records creation/association, then CVSS events, then `New -> Ignored` | Acting user for association; system for derived changes and rejection/revert status | manual `ticket_service`: User then CVE then Ticket; system `cve_service`: CVE then Ticket |
| Manual severity | One `severity_changed`, plus ordinary assignment/status consequences | Acting user for severity; system for derived status | `ticket_mutations`; acting User then Ticket |
| Effective CVSS assessment mutation or ingestion batch | One `cvss_assessment_changed` per effective assessment; optional single `severity_changed`, Product-event sequence, and final status per chain/batch | Direct SUSE event uses acting user; all derived events and external ingestion use system | `ticket_mutations`; manual path User then CVE then optional Ticket; system path CVE then optional Ticket |
| Default-version severity/eligibility chain | No assessment event; optional `severity_changed`, Product events, `priority_changed`, and final status | System | `ticket_mutations`; CVE then optional Ticket |
| Automatic priority refresh within any workflow listed in `ticket-priority.md` (Refresh Points) | One `priority_changed` when the effective priority changes; none when `priority_auto` changes behind an override or does not change | System | `ticket_mutations.refresh_priority_auto()` under the calling workflow's existing CVE-then-Ticket or Ticket roots |
| Priority override set, change, or clear | One `priority_changed` with `override_action`; ordinary assignment/final status events when applicable | Acting user for the override; system for derived status | `ticket_service`; acting User then Ticket |
| Ticketless CVE, CVSS, or enrichment mutation | None because no Ticket audit target exists | N/A | CVE-domain owner; CVE root where required |
| Other CVE-owned metadata or enrichment mutation | None by itself; resulting CVSS, automatic priority, or rejection effects retain the events above | N/A | `cve_service`; CVE root |
| Package-tree creation or completion | One invocation-level `package_added`; one `package_maintainer_added` per inserted association | Acting user for direct addition; system for automatic additions and maintainership | `package_service`; User then Ticket after external I/O for direct addition; Ticket only for system work |
| Track affectedness change | One `track_status_changed`; ordinary assignment/final status events when applicable | Acting user for direct change; system for release detection | `package_service`; User then Ticket for direct change, Ticket for system work |
| Product release confirmation | One `product_released`; optional final status | System | `package_service`; Ticket lock after external I/O |
| Product eligibility or override ownership change | One `product_eligibility_changed` per changed occurrence; optional final status | Acting user for direct override; system for automatic changes | direct override uses acting User then Ticket; system `package_service` uses Ticket; the narrow CVSS-chain exception uses User then CVE then Ticket for manual work or CVE then Ticket for system work |
| Direct package, track, or Product exclusion/restoration | Exactly one corresponding direct event; ordinary assignment/status events remain separate | Acting user | `package_service`; acting User then Ticket |
| Confidentiality toggle or manual access grant/revoke | One `confidentiality_changed`, `access_grant_added`, or `access_grant_removed`. Effective `true` to `false` deletes all grants atomically but produces only `confidentiality_changed` | Acting user | `ticket_service`; target User then Ticket for grant/revoke, Ticket for confidentiality |
| User deactivation or reactivation with retained Ticket grants | None for grants; ordinary identity and Ticket-unassignment events remain unchanged | N/A for grant state | `user_service`; User root and its documented side effects |
| Manual reference create/update/delete | One direct event, or one event per changed PATCH field | Acting user | `reference_service`; parent Ticket lock |
| Automatic reference upsert | None; fetcher execution and current rows are the evidence | N/A | `reference_service`; owning ingestion transaction |
| Effective or unchanged `delivery_status` processing | None; no assignment or Ticket reconciliation | N/A | `package_service`; Ticket lock |
| IBS request/action/correlation observation | None unless it delegates another audited domain mutation | N/A | IBS reconciliation; Ticket lock plus conditional evidence writes |
| `TrackReleaseCheckpoint` create/advance/no-op | None; an accompanying affectedness mutation retains `track_status_changed` | N/A | Track release workflow; Ticket lock and expected-predecessor validation |
| EOL entry/exit or derived actionability change | None for the derived change; an actual Ticket status change retains `status_change` | System for resulting status | Product/lifecycle owner; Ticket lock only for reconciliation |
| Post-ingest package-resolution publication, empty/no-match/excluded/inactive outcome, partial or terminal failure, or task completion | None for the workflow outcome; each independently committed delegated package or maintainer mutation retains its normal events | N/A for workflow outcomes; system for delegated mutations | `package_service`; one Ticket-locked transaction per attempted package after external I/O |
| Ticket convergence registration, dispatch, execution, retry, partial/terminal failure, or operator rerun | None for the workflow outcome; effective delegated mutations retain their normal events | N/A | Ticket convergence owner; per-domain locks |
| CVE refetch preparation, publication, deduplication, retry, or terminal task outcome | None for dispatch workflow outcomes; effective fetched CVE/CVSS/Ticket mutations retain their existing contracts | N/A | `cve_service` preparation and `fetch_single_cve`; CVE then optional Ticket for preparation |
| Product catalog source mutation or workflow-only dispatch/checkpoint outcome | None; later per-Ticket delegated mutations retain their normal events | N/A | Owning catalog/workflow service |

For every row, a rejected, not-found, unchanged, stale/inapplicable,
concurrent-loser, or rolled-back outcome creates no event unless the owning
contract explicitly identifies another effective mutation in that outcome.
Audit history is never an input to current state, authorization, idempotency,
restoration, reactivation, provenance, or recovery.

### Cross-Event Ordering, Locking, and Rollback

Within one composed workflow, optional assignment and its system
`New -> Analysis` event precede direct mutation events. Derived severity,
Product, and automatic priority events follow the inputs that caused them, with
automatic `priority_changed` after the severity and Product events. Assignment-eligibility
sanitation then follows every gate-input mutation, and the final gate-derived
`status_change` is last. Ticket creation is the exception only in that
`ticket_created` remains the first event in the new Ticket's history. Within one
package-tree invocation, ascending-`User.id` `package_maintainer_added` events
precede the invocation-level `package_added` event.

The source-neutral ingestion sequence is creation events when needed, canonical
CVSS assessment events, at most one severity event, state-applicable Product
events, at most one automatic priority event, then the state-applicable final
gate event. An applicable rejection follows that batch; an
`Ignored` republication performs its deferred Product and final status events in
the subsequent manual-zone-exit sequence. Source-status and automatic-reference
writes create no Ticket event. Any reference, audit, flush, or other
pre-finalization failure rolls back all earlier ingestion events. A definitely
failed commit likewise publishes no post-commit effect; an ambiguous commit
terminates the owner without claiming rollback or publication. An exception
after successful commit leaves all committed events intact and follows its
post-commit owner contract.

Every action classification, `old_value`, `new_value`, canonical comment, and
subject snapshot comes from serialized pre/post state under the root and lock
order prescribed by the mutation owner. Applicable roots include Ticket, CVE
then Ticket, deterministically ordered multiple Tickets, and assignment-capable
User then optional CVE then ordered Tickets. A multi-User identity batch locks
every User by UUID before the union of Ticket candidates by UUID. The central
audit contract does not require every operation
to route through `ticket_mutations` or acquire a Ticket lock first.

Every required event is inserted and flushed with the mutation in the same
caller-owned transaction. Audit validation, insertion, or flush failure escapes
and rolls back the complete owning transaction. Explicit no-event boundaries
remain subject to the owning transaction's ordinary rollback contract.

### detail JSONB Schema Contract

The `detail` column carries structured context for event types where
`old_value`/`new_value` are insufficient to capture the full operational
context (e.g., which track/package/product is affected). Every event type that
populates `detail` MUST have its schema defined in the table below. Event
types not listed here MUST set `detail` to `NULL`.

| Event Type | Required Keys | Optional Keys | Example |
|---|---|---|---|
| `track_status_changed` | `track` (string), `package` (string) | — | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl"}` |
| `track_excluded` | `track` (string), `package` (string) | — | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl"}` |
| `track_restored` | `track` (string), `package` (string) | — | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl"}` |
| `product_released` | `track` (string), `package` (string), `product_name` (string), `product_cpe` (string), `advisory_id` (string) | — | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl", "product_name": "SLES 15 SP6", "product_cpe": "cpe:/o:suse:sles:15:sp6", "advisory_id": "SUSE-SU-2025:1234-1"}` |
| `product_eligibility_changed` | `track` (string), `package` (string), `product_name` (string), `product_cpe` (string), `reason` (string) | `override_action` (string; conditionally required) | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl", "product_name": "SLES 15 SP6", "product_cpe": "cpe:/o:suse:sles:15:sp6", "reason": "threshold"}` |
| `product_excluded` | `track` (string), `package` (string), `product_name` (string), `product_cpe` (string) | — | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl", "product_name": "SLES 15 SP6", "product_cpe": "cpe:/o:suse:sles:15:sp6"}` |
| `product_restored` | `track` (string), `package` (string), `product_name` (string), `product_cpe` (string) | — | `{"track": "SUSE:SLE-15-SP6:Update", "package": "openssl", "product_name": "SLES 15 SP6", "product_cpe": "cpe:/o:suse:sles:15:sp6"}` |
| `reference_type_changed` | `url` (string) | — | `{"url": "https://bugzilla.suse.com/show_bug.cgi?id=12345"}` |
| `reference_title_changed` | `url` (string) | — | `{"url": "https://bugzilla.suse.com/show_bug.cgi?id=12345"}` |
| `reference_description_changed` | `url` (string) | — | `{"url": "https://bugzilla.suse.com/show_bug.cgi?id=12345"}` |
| `duplicate_target_changed` | `triggered_by_ticket` (string) | — | `{"triggered_by_ticket": "SNTL-42"}` |
| `package_maintainer_added` | `package` (string) | — | `{"package": "fictional-package"}` |
| `priority_changed` | `override_action` (string; conditionally required) | — | `{"override_action": "set"}` |

**Notes**:

- `package_maintainer_added` is emitted once for each newly created immutable
  association, including when maintainer associations are the only database
  mutation. Its `new_value` snapshots the target username so the event remains
  readable after a later username change. The event is system-attributed even
  when acquisition was triggered by a user-facing package addition. A repeated
  acquisition that finds the association already present emits no event.
- `product_eligibility_changed`: `reason` values are `reactive_ltss`,
  `threshold`, `reactivation`, `cvss`, or `va_override`. Product-originated
  automatic recalculation (`reactive_ltss` or `threshold`), synchronous
  manual-zone-exit convergence (`reactivation`), and the atomic assessment or
  default-version chain (`cvss`) emit one event per changed
  `TicketPackageProduct`, with `user_id = NULL` and `comment = NULL`, in the
  same per-Ticket transaction as the eligibility update. Unchanged and
  manual-override records emit no event. When
  `reason = va_override`,
  `override_action` is required and equals `set` when automatic management
  becomes a manual override, `changed` when an existing override changes
  value, or `cleared` when the override is removed. For every other reason,
  `override_action` is absent. `TicketAuditLog.log_event()` MUST enforce this
  conditional requirement — reject an `override_action` key when
  `reason ≠ va_override`, and reject a missing `override_action` key when
  `reason = va_override` — rather than relying solely on caller correctness.
  `log_event()` MUST also reject a `reason` value outside the five listed
  values and an `override_action` value outside `set`, `changed`, or
  `cleared`. Every rejection under this rule raises `ValueError`, consistent
  with the base `log_event()` contract in
  `docs/features/platform/audit-trail-infrastructure.md` for other kwarg
  validation failures.
- `priority_changed`: a direct override event (non-NULL `user_id`) requires
  `detail = {"override_action": ...}` with exactly `set` (no override to a
  value), `changed` (one override value to another), or `cleared` (a value to
  no override). An automatic event (`user_id = NULL`) requires `detail = NULL`.
  `TicketAuditLog.log_event()` MUST reject a missing or non-NULL `detail` in
  the respective case, any other key, and any other `override_action` value,
  raising `ValueError`.
- Product event details intentionally omit both `TicketPackageProduct.id` and
  internal `Product.id`. Within the ticket-scoped audit log, the event-time
  `package`, `track`, and canonical `product_cpe` identify the occurrence, and
  `product_name` keeps the event directly readable and searchable by analysts.
  `detail.product_name` and the "Product display name" recorded in
  `old_value`/`new_value` (for `product_excluded`/`product_restored`) are the
  same value: `Product.display_name` at mutation time. Services MUST NOT
  populate either field from `Product.name` (the short SMELT identifier).
- `reference_type_changed`, `reference_title_changed`,
  `reference_description_changed`: `url` is the post-normalization URL of the
  reference being modified — used as the locator since a ticket can have
  multiple references. For `reference_url_changed`, both old and new URLs are
  carried in `old_value`/`new_value`, so `detail` is NULL.
- Validate the event-specific schema before measuring size. Serialize non-NULL
  `detail` solely for measurement as compact deterministic JSON with
  `ensure_ascii=False`, sorted keys, separators `,` and `:` without spaces, and
  no non-finite numbers. Encode the complete representation as UTF-8. A payload
  of at most 4096 bytes is accepted; more than 4096 bytes raises `ValueError`
  before insertion. An empty mapping is invalid; use `detail = NULL`.
- The service layer MUST validate that `detail` contains only keys defined in
  this contract for the given event type — undocumented keys are rejected.
- When a new `TicketAuditEventType` is added that uses the `detail` column,
  this table MUST be extended with the corresponding schema definition before
  the implementation proceeds.

## API

### List Ticket Events

```
GET /api/v1/tickets/{ticket_id}/audit-log
```

Returns a paginated list of events for a specific ticket, ordered by
`created_at DESC, id DESC` (newest first, with UUIDv7 as the deterministic
tie-breaker for equal transaction timestamps and stable pagination). Sorting
is fixed — client-controlled `sort_by` / `sort_order` parameters are not
supported (timeline display requires chronological ordering).

The parent `ticket_id` uses the SNTL-only Ticket identity. The event's own `id`
and a non-null actor's `id` retain their event and User UUID contracts.

**Path parameters**:

| Parameter   | Type | Description          |
|-------------|------|----------------------|
| `ticket_id` | string | Canonical Ticket identity (`SNTL-{n}`) |

**Query parameters**:

| Parameter    | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `page`       | int    | 1       | Page number (1-indexed) |
| `per_page`   | int    | 20      | Items per page (max 100) |
| `event_type` | string (repeatable) | —       | Filter by event type. Multiple values use OR semantics (e.g., `?event_type=status_change&event_type=assignment`). See `docs/api-spec.md` (Enum Filter Validation) for handling of invalid values |
| `actor`      | string | —       | Filter by actor: user UUID, username, or `system` for automated events (where `user_id IS NULL`). If omitted, all actors are returned. |
| `search`     | string | —       | Case-insensitive substring search across `comment`, `old_value`, `new_value`, and `detail` (cast to text). Matches on any field are included (OR logic). Outer whitespace is trimmed once; an empty result means no text filter. `%`, `_`, and backslash are literal characters rather than SQL pattern syntax. |
| `from_date`  | string | —       | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date`    | string | —       | ISO 8601 date/datetime. Include events up to this date (inclusive) |

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "ticket_id": "SNTL-42",
      "event_type": "status_change",
      "old_value": "New",
      "new_value": "Analysis",
      "comment": null,
      "detail": null,
      "created_at": "2025-03-15T10:30:00Z",
      "actor": {
        "id": "uuid",
        "username": "fictional.analyst",
        "full_name": "Fictional Analyst",
        "active": true
      }
    }
  ],
  "meta": {
    "total": 42,
    "page": 1,
    "per_page": 20
  }
}
```

**Notes**:

- `actor` is `null` for system-generated events (where `user_id IS NULL`).
- `actor` is the complete current User reference (`id`, `username`, nullable
  `full_name`, and current `active`) for user-initiated events.
- The `search` filter applies its normalized literal case-insensitive substring
  to `comment`, `old_value`, `new_value`, and `detail::text` with OR semantics.
  This allows searching for product names, track names, statuses, or contextual
  data across all event fields without exposing SQL wildcard syntax.

**`Access: Authenticated`**

Confidentiality filtering is enforced centrally — see `docs/api-spec.md`
([Scoped Responses](../../api-spec.md#scoped-responses)).

The event page and `meta.total` are both constrained by the same accessible
parent Ticket in one database operation or equivalent single database view,
using the canonical predicate in `docs/features/identity/rbac.md` (Scope and
Confidential Ticket Visibility). Missing and inaccessible Tickets both return
`404 TICKET_NOT_FOUND`; an inaccessible Ticket never produces an empty event
page or a zero count. Ticket accessibility constrains the query before actor,
event-type, search, or date filters and before pagination. The count and page
therefore cannot be derived from different visibility decisions.

## Service Contract

Every event required by the owning domain contract is part of the same database
transaction as its mutation. If an audited mutation succeeds, its complete
event sequence is guaranteed to be recorded; if it fails, no orphan event is
created. An explicit no-event boundary in the canonical matrix is intentional
and is not a failure of atomicity.

Audit reads are model-aware service operations. API handlers delegate list and
count construction to `list_ticket_events()` in the service layer rather than
issuing business ORM queries, and Core has no model imports. Audit history is
historical evidence only: no event, actor, payload, or inferred history may be
an input to Ticket accessibility or any current authorization or operational
state decision.

### `list_ticket_events()`

This Category B operation accepts `db: AsyncSession`, public
`ticket_id: str`, request-resolved authenticated caller information, repeatable
`event_type` supplied state plus valid values, optional `actor: str`, optional
`search: str`, optional normalized `from_date`/`to_date` bounds, positive `page`, and
`per_page` from 1 through 100. The result contains service-layer event
projections plus `total`, `page`, and `per_page`; it does not return or depend on
Pydantic schemas. It creates no event, acquires no mutation lock, and does not
commit or roll back. Database exceptions propagate unchanged.

Behavior:

1. Parse and resolve `ticket_id` using the SNTL-only Ticket Identifier
   Resolution contract and select the parent through the canonical visibility
   predicate. Malformed values, Ticket UUIDs, missing Tickets, and inaccessible
   Tickets raise `TicketNotFoundError` before any event filter is evaluated.
2. Apply repeatable `event_type` with OR semantics. The typed semantic input
   preserves omission versus supplied-but-empty state after invalid members are
   removed. The latter returns an empty page only after the accessible parent
   has been established.
3. Apply `actor` through `BaseAuditLog.filter_by_actor()`. Literal `system`
   matches `user_id IS NULL`; a UUID matches User ID; all other values match
   exact username. An unknown optional actor yields an empty page rather than
   `UserNotFoundError`, but only for an accessible Ticket.
4. Normalize `search` by trimming outer whitespace once. Empty means absent;
   percent, underscore, and backslash remain literal. Match case-insensitive
   substrings across the four declared fields with OR semantics.
5. Apply inclusive date bounds through `BaseAuditLog.apply_date_filters()` and
   the shared UTC interpretation. Different supplied filter parameters compose
   with AND.
6. Order by `created_at DESC, id DESC`, compute `total` after all filters and
   before page slicing, and return the requested page. A page beyond the last is
   empty with the correct total.
7. Project each event's `ticket_id` as the parent `SNTL-{n}`. Project a non-null
   actor from the current User row as the complete reference (`id`, `username`,
   nullable `full_name`, current `active`); system events use `actor = null`.

Parent accessibility, filtered events, actor projection, count, ordering, and
page derive from one coherent PostgreSQL observation. Concurrent changes may be
observed entirely before or after that view, never as a page/count or actor/event
mixture from incompatible views. Join fan-out cannot duplicate events or inflate
the total.

### Implementation Guidelines

1. **Same transaction**: the `TicketAuditEvent` insert MUST happen in the same
   database session/transaction as the ticket mutation. Do NOT create events
   in a separate transaction or after committing the main change.

2. **Service layer responsibility**: event creation belongs in the service
   layer (`app/services/`), not in the API layer or model layer. The service
   function that performs the mutation also creates the event.

3. **Event creation**: services MUST use `TicketAuditLog.log_event()` to
   create events, ensuring consistent field population and registration
   in the global audit trail registry.

4. **No undefined audit boundaries**: a Ticket-related mutation must match
   either its exact event contract or an explicit no-event row in the canonical
   matrix. Lacking both is a bug. Emitting an event for an explicit no-event
   boundary is also a bug.

5. **detail validation**: `TicketAuditLog` MUST override `log_event()` to
   validate that `detail` contains every required key and only keys defined in
   the JSONB Schema Contract for the given event type. Missing required and
   undocumented keys MUST be rejected. Where the contract makes a key's
   presence conditional on another field's value (e.g.,
   `product_eligibility_changed`'s `override_action`), `log_event()` MUST enforce
   that condition, not just flat key membership. The maximum `detail` payload is
   4096 UTF-8 bytes under the deterministic serialization contract above.

6. **comment validation**: `TicketAuditLog.log_event()` MUST validate `comment`
   against the exact canonical value or `NULL` allowed for the event type and
   context. Any other value raises `ValueError` before insertion.

7. **Concurrency correctness**: correctness depends on the mutation owner's
   documented root-lock order. Services derive event values and action
   classification only from state reloaded under those locks. This prevents a
   concurrent operation from producing stale values, duplicate events, or an
   event for a losing no-op.

## Testing Requirements

Tests for every Ticket-related mutation and operational boundary MUST verify its
required event sequence or explicit no-event outcome. For audited mutations:

1. A `TicketAuditEvent` record is created after the operation
2. The `event_type` matches the expected value
3. `old_value` and `new_value` are correctly populated
4. `user_id` matches the semantic actor, including system attribution for
   derived consequences inside a user-initiated workflow
5. `comment` is the exact canonical value or `NULL` as required
6. `detail` is correctly populated according to the JSONB Schema Contract
   (expected keys present, no extra keys, `NULL` when required)
7. The event is created in the same transaction (i.e., if the operation is
   rolled back, no event exists)
8. Product events preserve event-time `product_name` and `product_cpe`, remain
   searchable by both values, and do not expose an internal Product or
   TicketPackageProduct UUID as the subject. `product_name` equals
   `Product.display_name` at mutation time, never `Product.name`
9. `product_released.new_value` equals the actual persisted `released_at`
   timestamp, including retroactive advisory dates
10. Authorized-user eligibility events distinguish `override_action` values `set`,
    `changed`, and `cleared`; automatic events omit that key
11. Maintainer acquisition creates one `package_maintainer_added` event per new
    association in ascending `User.id` order, with exact detail schema and
    system attribution; duplicate, inactive-user, and unmatched-email outcomes
    create none
12. Every explicit no-event matrix row has a zero-event assertion for its
    effective and no-op outcomes where applicable, including delivery, IBS
    evidence, checkpoints, derived actionability, automatic references,
    convergence outcomes, ticketless CVE/CVSS changes, automatic
    declassification deletion, and deactivation/reactivation grant retention
13. Each package, track, and Product exclusion/restore persists exactly one
    direct event with the authenticated acting user and exact payload; adding a
    marker beneath an excluded ancestor and restoring beneath an ancestor or
    EOL still emits that event
14. Repeated-call losers, path/operability rejection, EOL-only changes, and
    audit/reconciliation/flush rollback leave zero direct exclusion or restore
    events and zero other durable effects
15. CVSS assessment tests assert the exact canonical provider/version/vector/
    score old and new values, `detail = NULL`, manual-SUSE versus external
    actor semantics, and direct event presence in every Ticket status
16. Ticketless, unchanged, rejected, not-found, concurrent-loser, and rollback
    CVSS outcomes assert no Ticket event; independent-session races assert one
    event sequence for each effective serialized winner and no stale old value
17. CVSS-derived `severity_changed` always has `user_id = NULL`, including the
    association handover, while the preceding `cve_associated` retains the
    acting user; tests assert the documented event order
18. Manual-SUSE CVSS chains assert optional assignment and system
    `New → Analysis` precede direct CVSS records, changed automatic Product
    events follow severity in `TicketPackageProduct.id` order, optional
    assignment-eligibility sanitation follows all gate-input mutations, and any
    final gate status event is last. External and default-version system chains
    never auto-assign an actor, but may create the system sanitation event when
    their final result is `Analysis` or `Analyzed`. Sanitation covers inactive,
    active-without-VA, and both-invalid precedence
19. Identity-driven unassignment selects every assigned Ticket before status
    locking, clears only locked-current `New`, `Analysis`, or `Analyzed`, and
    preserves `Resolved`, `Ignored`, and `Duplicated`. Rejected, stale,
    already-cleared, inactive-status, repeated, concurrent-loser, and rolled-back
    outcomes create no event. Effective events use the stabilized username,
    exact closed reason, `new_value = NULL`, and `detail = NULL` in Ticket UUID
    order
20. Automatic eligibility tests assert exact actor, reason, cardinality, and
    no-event behavior for unchanged, override-skipped, manual-zone-deferred or
    skipped, rejected, not-found, concurrent no-op, and rollback outcomes;
    `Resolved` chains assert immediate Product events when values change
21. Override set/change/clear tests assert that a marker-changing metadata-only
    mutation creates one event even when `old_value == new_value`, while a true
    marker-and-value no-op creates none
22. Multi-record tests assert Product, maintainer, duplicate-dependent, and
    reference-PATCH ordering exactly as specified; API tests assert stable
    `created_at DESC, id DESC` pagination when timestamps tie
23. Independent-session winner/loser tests prove that every event uses the true
    locked pre-state and that a loser that observes the target state creates no
    event
24. Whole-chain rollback tests inject settings, database, eligibility, audit,
    flush, and reconciliation failures and assert no durable assessment,
    severity, assignment, Product, Ticket-status, or audit effect
25. Tests and architecture review prove no mutation, authorization,
    idempotency, restoration, reactivation, provenance, or recovery path reads
    Ticket audit history as current operational state
26. Audit API tests cover scope `all`, explicit grant, included-package
    maintainership, loss of the final visibility path, and inaccessible/missing
    Tickets. They prove list rows and `meta.total` use the same accessible
    Ticket/database view, accessibility is applied before actor/search/date and
    other event filters, and an inaccessible Ticket returns `TICKET_NOT_FOUND`
    rather than an empty page or zero count
27. Republication ingestion tests combine `REJECTED -> PUBLISHED` with changed
    external assessments and prove direct CVSS events precede manual-zone-exit
    Product/final-status events whose values derive from the current payload's
    final assessment set, not stale pre-ingest state
28. `priority_changed` tests assert effective old/new values, system attribution
    and `detail = NULL` for automatic changes, the documented position before
    sanitation and the final gate event, no event for a masked or unchanged
    automatic value, and acting-user override events with exact
    `override_action` (`set`, `changed`, `cleared`), including equal old/new
    values; `log_event()` rejects mismatched `detail` for either actor case

See Guardrail 6 (Mandatory testing) and Guardrail 11 (Ticket event logging)
in `AGENTS.md` for enforcement.

## Data Retention

Indefinite. TicketAuditEvent records are never automatically deleted.

## Cross-references

- `docs/features/platform/audit-trail-infrastructure.md` — BaseAuditLog,
  AuditEventMixin, naming conventions
- `docs/features/identity/identity-audit-log.md` — IdentityAuditEvent detail
  JSONB pattern (reference implementation for the detail column contract)
- `docs/conventions.md` — Audit Trail
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
- `docs/features/identity/rbac.md` — canonical Ticket visibility predicate
- `docs/features/platform/testing-strategy.md` — shared Ticket accessibility
  matrix
- `docs/features/tickets/ticket-priority.md` — `priority_changed` triggers,
  refresh points, and override
