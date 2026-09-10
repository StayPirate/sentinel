# Ticket Audit Log

## Purpose

Provide a complete, searchable audit trail for every ticket in Sentinel. Every
modification to a ticket or its related data MUST produce a `TicketAuditEvent`,
except `TicketPackageTrack.delivery_status`: that sole named package-policy
exception records an independently derived delivery fact but creates no Ticket
audit event, assignment, or Ticket reconciliation.
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

Every service that mutates a ticket MUST create a `TicketAuditEvent` with the
fields populated according to this table, except the named delivery-status
boundary, which is intentionally not represented by an event type.

| `event_type` | Trigger | `user_id` | `old_value` | `new_value` | `comment` | `detail` |
|---|---|---|---|---|---|---|
| `status_change` | Ticket status transitions (manual or system-initiated) | VA user for manual, `NULL` for system (e.g., NVD rejection, CVSS recalculation) | Previous status (e.g., `New`) | New status (e.g., `Analysis`) | `NULL` for manual; system-generated description for automatic (e.g., `"CVE rejected by NVD"`) | `NULL` |
| `assignment` | Ticket assigned or reassigned | VA user for manual, `NULL` for system (e.g., employee deactivation) | Previous assignee username or `NULL` | New assignee username or `NULL` (unassigned) | `NULL` for manual; system-generated description for automatic (e.g., `"Unassigned from {old}: employee deactivated"`) | `NULL` |
| `duplicate_set` | Ticket marked as duplicate | VA user | `NULL` | `SNTL-{n}` identifier of the original ticket | `NULL` | `NULL` |
| `duplicate_removed` | Duplicate mark reverted | VA user | `SNTL-{n}` identifier of the original ticket | `NULL` | `NULL` | `NULL` |
| `duplicate_target_changed` | Atomic repoint: the ticket's `duplicate_of_id` was updated within the same transaction as the triggering mark-as-duplicate operation, because the ticket's previous target was itself marked as duplicate | `NULL` | `SNTL-{n}` identifier of the previous target | `SNTL-{n}` identifier of the new target | `NULL` | `{"triggered_by_ticket": "SNTL-{n}"}` — the identifier of the ticket whose mark-as-duplicate operation triggered this repoint |
| `package_added` | Package tree created or incrementally completed (manual or automatic). One event per invocation that creates at least one package, track, or Product record; child records do not generate separate events. A completely no-op invocation creates no `package_added` event. | Acting user for manual, `NULL` for automatic | `NULL` | Package name | `NULL` for manual; contextual description for automatic (e.g., `"CPE match"`, `"vendor:product match"`, `"resolved_packages"`, `"Product catalog backfill"`) | `NULL` |
| `package_maintainer_added` | Package resolution creates one `TicketPackageMaintainer` association | `NULL` | `NULL` | Event-time target username | `NULL` | `{"package": "fictional-package"}` |
| `package_excluded` | Package directly soft-deleted by an authorized acting user. Child tracks and Products are not modified and do not generate events; they become effectively excluded through the hierarchy | Acting user | Package name | `NULL` | `NULL` | `NULL` |
| `package_restored` | Directly excluded package restored to ticket. Only the package record is restored — child records are not modified | Acting user | `NULL` | Package name | `NULL` | `NULL` |
| `track_status_changed` | Track status changed (VA action, admin force-FIXED, or release detection) | Acting user for user-attributed changes, `NULL` for automatic transitions (e.g., release detected sets FIXED) | Old status | New status | `NULL` | `{"track": "...", "package": "..."}` (see detail contract) |
| `product_released` | Product release detected via updateinfo.xml | `NULL` | `NULL` | Advisory-issued `released_at` timestamp in UTC ISO 8601 format | `NULL` | Product subject plus `advisory_id` (see detail contract) |
| `ticket_created` | Ticket created (CVE ingestion or manual creation) | `NULL` for automatic creation, creating user for manual creation | `NULL` | `NULL` | Creation source description (e.g., `"CVE ingested from NVD"` or `"Ticket created manually"`) | `NULL` |
| `cve_associated` | CVE associated with a ticket that previously had no CVE | Acting user for explicit association; creating user or `NULL` when included in Ticket creation | `NULL` | CVE-ID string (e.g., `"CVE-2024-1234"`) | `NULL` | `NULL` |
| `severity_changed` | CVSS resolution changes `CVE.severity`, VA sets/clears manual severity, or CVE association hands over from manual to CVSS-derived severity | `NULL` for every CVSS-derived value, including association handover; acting user only for direct `set_severity_manual()` | Old severity (e.g., `High`) or `NULL` | New severity (e.g., `Critical`) or `NULL` | `NULL` | `NULL` |
| `cvss_assessment_changed` | CVSS assessment added, modified, or removed | Acting user for manual SUSE changes, `NULL` for trusted external ingestion | Previous canonical `"provider_name vX.Y vector_string (score)"` or `NULL` if new | Current canonical `"provider_name vX.Y vector_string (score)"` or `NULL` if removed | `NULL` | `NULL` |
| `product_eligibility_changed` | Product eligibility or its manual-override ownership changed due to CVSS/default-version recalculation, reactivation, lifecycle phase transition (Reactive Support), threshold change, or VA override | VA user for VA overrides, `NULL` for system-triggered changes | Old eligibility (`true` or `false`) | New eligibility (`true` or `false`); may equal old value for a metadata-only override set/clear | `NULL` | Product subject plus `reason` and conditional `override_action` (see detail contract) |
| `track_excluded` | Track directly soft-deleted by an authorized acting user. Child Products are not modified and do not generate events; they become effectively excluded through the hierarchy | Acting user | Track name | `NULL` | `NULL` | `{"track": "...", "package": "..."}` (see detail contract) |
| `track_restored` | Directly excluded track restored to ticket. Only the track record is restored — child products are not modified | Acting user | `NULL` | Track name | `NULL` | `{"track": "...", "package": "..."}` (see detail contract) |
| `product_excluded` | Product directly soft-deleted by an authorized acting user | Acting user | Product display name | `NULL` | `NULL` | Product subject (see detail contract) |
| `product_restored` | Directly excluded product restored to ticket | Acting user | `NULL` | Product display name | `NULL` | Product subject (see detail contract) |
| `confidentiality_changed` | Ticket `is_confidential` flag toggled | Acting user | `"true"` or `"false"` | `"true"` or `"false"` | `NULL` | `NULL` |
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

- `user_id` MUST be set for user-initiated actions and `NULL` for system
  actions.
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
  `ticket_created` first, before optional initial events. CVE association
  records `cve_associated` before its derived severity handover. An effective
  manual SUSE chain records optional `assignment`, optional system
  `New → Analysis`, `cvss_assessment_changed`, optional derived
  `severity_changed`, automatic Product eligibility events, and optional final
  gate `status_change`, in that order. An external chain begins with
  `cvss_assessment_changed` because it never assigns. Product events are ordered
  by `TicketPackageProduct.id` ascending; the UUID is an ordering input and is
  not included in `detail`.
- Automatic Product recalculation creates exactly one event for each occurrence
  whose persisted boolean changes. Override-skipped, unchanged, manual-zone-
  deferred or skipped, rejected, not-found, and rolled-back Product outcomes
  create none. `Resolved` is not a deferred state. A VA override set or clear
  remains an effective metadata
  mutation when `is_eligible_override` changes even if the boolean does not;
  that one event truthfully carries equal old/new booleans and the applicable
  `override_action`.
- `comment` is used exclusively for system-generated human-readable
  descriptions (e.g., creation source, deactivation reason, detection
  context). It is NOT populated by user input — no API endpoint exposes
  `comment` as a user-provided field. If VA notes become a desired feature
  in the future, they should be introduced as a dedicated feature (new
  parameter across all relevant endpoints, consistent UX, proper spec)
  rather than an ad-hoc addition to individual endpoints. `comment` MUST
  NOT contain structured data intended for programmatic parsing.
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
- All events include an implicit `created_at` timestamp set by the database
  default.

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
- Maximum payload size: 4 KB. The service layer MUST reject any `detail` value
  exceeding this limit.
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
`created_at` descending (newest first). Sorting is fixed —
client-controlled `sort_by` / `sort_order` parameters are not supported
(timeline display requires chronological ordering).

**Path parameters**:

| Parameter   | Type | Description          |
|-------------|------|----------------------|
| `ticket_id` | UUID or `SNTL-{n}` | The ticket identifier (supports dual lookup) |

**Query parameters**:

| Parameter    | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `page`       | int    | 1       | Page number (1-indexed) |
| `per_page`   | int    | 20      | Items per page (max 100) |
| `event_type` | string (repeatable) | —       | Filter by event type. Multiple values use OR semantics (e.g., `?event_type=status_change&event_type=assignment`). See `docs/api-spec.md` (Enum Filter Validation) for handling of invalid values |
| `actor`      | string | —       | Filter by actor: user UUID, username, or `system` for automated events (where `user_id IS NULL`). If omitted, all actors are returned. |
| `search`     | string | —       | Case-insensitive substring search across `comment`, `old_value`, `new_value`, and `detail` (cast to text). Matches on any field are included (OR logic). If omitted, no text filtering is applied. |
| `from_date`  | string | —       | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date`    | string | —       | ISO 8601 date/datetime. Include events up to this date (inclusive) |

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "ticket_id": "uuid",
      "event_type": "status_change",
      "old_value": "New",
      "new_value": "Analysis",
      "comment": null,
      "detail": null,
      "created_at": "2025-03-15T10:30:00Z",
      "actor": {
        "id": "uuid",
        "username": "jdoe",
        "full_name": "John Doe",
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
- `actor` contains `id`, `username`, and `full_name` for user-initiated
  events.
- The `search` filter performs a case-insensitive `ILIKE '%term%'` on
  `comment`, `old_value`, `new_value`, and `detail::text` (OR). This allows
  searching for product names, track names, statuses, or any contextual data
  across all event fields.

**`Access: Authenticated`**

Confidentiality filtering is enforced centrally — see `docs/api-spec.md`
([Scoped Responses](../../api-spec.md#scoped-responses)).

## Service Contract

Every service function that modifies a ticket MUST create a `TicketAuditEvent`
as part of the same database transaction, except
`set_track_delivery_status()`. This ensures atomicity — if an audited mutation
succeeds, the event is guaranteed to be recorded; if the mutation fails, no
orphan event is created. The named delivery-status no-event contract is not a
failure of atomicity.

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

4. **No silent mutations**: if a service modifies Ticket-related data without
   creating a `TicketAuditEvent`, it is a bug, except for the explicit
   `delivery_status` boundary.

5. **detail validation**: `TicketAuditLog` MUST override `log_event()` to
   validate that `detail` contains only keys defined in the JSONB Schema
   Contract for the given event type. Undocumented keys MUST be rejected.
   Where the contract makes a key's presence conditional on another field's
   value (e.g., `product_eligibility_changed`'s `override_action`), `log_event()`
   MUST enforce that condition, not just flat key membership. The maximum
   `detail` payload is 4 KB.

6. **Concurrency correctness**: the correctness of `old_value` and
   `new_value` fields depends on the pessimistic locking enforced by
   the `ticket_mutations` module (see `docs/features/tickets/ticket-mutations.md`,
   Concurrency Control). The `FOR UPDATE` lock on the `Ticket` row
   serializes concurrent mutations, ensuring that each audit event
   captures the true pre-mutation state. Without this lock, concurrent
   transactions could record stale `old_value` entries.

## Testing Requirements

Tests for any Ticket mutation that requires an event MUST verify:

1. A `TicketAuditEvent` record is created after the operation
2. The `event_type` matches the expected value
3. `old_value` and `new_value` are correctly populated
4. `user_id` is set for user actions and `NULL` for system actions
5. `detail` is correctly populated according to the JSONB Schema Contract
   (expected keys present, no extra keys, `NULL` when required)
6. The event is created in the same transaction (i.e., if the operation is
   rolled back, no event exists)
7. Product events preserve event-time `product_name` and `product_cpe`, remain
   searchable by both values, and do not expose an internal Product or
   TicketPackageProduct UUID as the subject. `product_name` equals
   `Product.display_name` at mutation time, never `Product.name`
8. `product_released.new_value` equals the actual persisted `released_at`
   timestamp, including retroactive advisory dates
9. VA eligibility events distinguish `override_action` values `set`,
   `changed`, and `cleared`; automatic events omit that key
10. Maintainer acquisition creates one `package_maintainer_added` event per new
    association, with exact detail schema and system attribution; duplicate,
    inactive-user, and unmatched-email outcomes create none
11. Delivery-status mutation creates no Ticket event, assignment, or Ticket
    reconciliation, both for an effective transition and an idempotent no-op
12. Each package, track, and Product exclusion/restore persists exactly one
    direct event with the authenticated acting user and exact payload; adding a
    marker beneath an excluded ancestor and restoring beneath an ancestor or
    EOL still emits that event
13. Repeated-call losers, path/operability rejection, EOL-only changes, and
    audit/reconciliation/flush rollback leave zero direct exclusion or restore
    events and zero other durable effects
14. CVSS assessment tests assert the exact canonical provider/version/vector/
    score old and new values, `detail = NULL`, manual-SUSE versus external
    actor semantics, and direct event presence in every Ticket status
15. Ticketless, unchanged, rejected, not-found, concurrent-loser, and rollback
    CVSS outcomes assert no Ticket event; independent-session races assert one
    event sequence for each effective serialized winner and no stale old value
16. CVSS-derived `severity_changed` always has `user_id = NULL`, including the
    association handover, while the preceding `cve_associated` retains the
    acting user; tests assert the documented event order
17. Manual-SUSE CVSS chains assert optional assignment and system
    `New → Analysis` precede direct CVSS records, changed automatic Product
    events follow severity in `TicketPackageProduct.id` order, and any final
    gate status event is last. External and default-version system chains never
    create assignment
18. Automatic eligibility tests assert exact actor, reason, cardinality, and
    no-event behavior for unchanged, override-skipped, manual-zone-deferred or
    skipped, rejected, not-found, concurrent no-op, and rollback outcomes;
    `Resolved` chains assert immediate Product events when values change
19. Override set/change/clear tests assert that a marker-changing metadata-only
    mutation creates one event even when `old_value == new_value`, while a true
    marker-and-value no-op creates none
20. Whole-chain rollback tests inject settings, database, eligibility, audit,
    flush, and reconciliation failures and assert no durable assessment,
    severity, assignment, Product, Ticket-status, or audit effect

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
