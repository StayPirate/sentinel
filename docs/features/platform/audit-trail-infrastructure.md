# Audit Trail Infrastructure

## Purpose

Define the shared infrastructure for all audit trails in Sentinel:
the `BaseAuditLog` service-layer base class, the `AuditEventMixin`
model-layer mixin, naming conventions, atomicity rules, actor field
semantics, date filtering convention, indexing criteria, and the
Audit Trail Index.

This is the single canonical source for all cross-cutting audit trail
rules. Domain-specific audit trail specifications (ticket, identity,
setting, fetcher) reference this document for shared conventions and
extend it with their domain-specific event types and data.

## AuditEventMixin

Every audit event SQLAlchemy model MUST inherit from `AuditEventMixin`
(`backend/app/models/mixins.py`). The mixin provides the columns common
to all audit trail tables:

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PK | Internal identifier |
| `created_at` | TIMESTAMPTZ | NOT NULL, server default, indexed | When the event occurred |
| `user_id` | UUID | FK(user.id) ON DELETE RESTRICT, nullable, indexed | Actor of the semantic event. NULL for system-attributed consequences or when no authenticated Sentinel user is attributable |

Sentinel only performs soft-delete (deactivation) on users, never
hard-delete. The FK on `user_id` uses `ON DELETE RESTRICT` explicitly
(even though it is the PostgreSQL default) to make the constraint visible
and prevent accidental data loss. If a hard-delete were attempted, it
would fail with a FK violation, protecting audit history.

All audit event models inherit these columns from the mixin and add
their own domain-specific columns (e.g., `ticket_id`, `event_type`,
`target_user_id`).

## BaseAuditLog Class

Every audit trail in Sentinel MUST be implemented as a subclass of
`BaseAuditLog` (`backend/app/services/base_audit_log.py`). The base class
defines:

- **Auto-registration**: all subclasses are automatically registered in a
  global registry, keyed by `name`. If a subclass attempts to register
  with a `name` that already exists in the registry, a `ValueError` MUST
  be raised at startup to prevent silent overwrites. A subclass that
  omits `name`, `description`, or `model_class` MUST raise `TypeError`
  at class-definition time instead of registering incompletely
- **Event creation**: `log_event()` class method inserts a record within
  the caller's database transaction. Subclasses may override to add
  domain-specific validation (e.g., ensuring `user_id` is provided for
  admin-only trails)
- **Date filtering**: `apply_date_filters()` class method applies
  `from_date` / `to_date` filters on `created_at`. Every audit trail API
  endpoint MUST use this method for uniform date filtering behavior
- **Actor filtering**: `filter_by_actor()` class method filters by
  `user_id` column (inherited from `AuditEventMixin`). Accepts `"system"`
  for NULL actor, a UUID string for direct match, or a username for
  lookup via JOIN. Every audit trail API endpoint with an `actor` filter
  MUST use this method. **Note**: this method operates exclusively on the
  `user_id` column (the actor). Domain-specific filters on other user FK
  columns (e.g., `target_user_id` in `IdentityAuditEvent`) are the
  responsibility of the endpoint implementation, not the base class

### Abstract Interface

```python
class BaseAuditLog:
    """Base for all audit trail implementations."""

    # Subclass MUST define:
    name: str                          # e.g., "ticket", "identity", "setting"
    description: str                   # human-readable purpose
    model_class: type                  # SQLAlchemy model (e.g., TicketAuditEvent)

    # Auto-registration in global registry (populated by __init_subclass__)

    @classmethod
    async def log_event(cls, session: AsyncSession, **kwargs) -> None:
        """Create an audit record in the current transaction.

        Subclasses may override to add domain-specific validation.
        The base class uses **kwargs for flexibility (each trail has
        different fields). Subclasses SHOULD override with a typed
        signature that validates expected fields for their event types
        before calling super().log_event(). The base implementation
        MUST validate that all kwargs correspond to column names on
        model_class — any kwarg that does not match a mapped column
        MUST raise ValueError immediately, preventing misspelled or
        unexpected fields from being silently ignored. Database NOT
        NULL constraints serve as an additional safety net for required
        fields.
        """
        ...

    @classmethod
    def apply_date_filters(
        cls,
        query: Select,
        from_date: date | datetime | None = None,
        to_date: date | datetime | None = None,
    ) -> Select:
        """Apply created_at date range filters to a query.

        - from_date only: WHERE created_at >= from_date
        - to_date only:   WHERE created_at <= to_date
        - both:           WHERE created_at >= from_date
                            AND created_at <= to_date
        - neither:        no filter applied
        """
        ...

    @classmethod
    def filter_by_actor(
        cls,
        query: Select,
        actor: str | None = None,
    ) -> Select:
        """Filter audit events by actor (user_id column).

        - actor is None:     no filter applied
        - actor == "system": WHERE user_id IS NULL
        - actor is a UUID:   WHERE user_id = <uuid>
        - actor is a string: JOIN User, WHERE username = <actor>

        The `actor` parameter follows the User Identifier Resolution
        convention defined in `docs/api-spec.md`: if the value is a
        valid UUID, lookup is by `user.id`; otherwise, lookup is by
        `user.username` (exact match). If the provided username or UUID
        does not match any user in the system, the method returns an
        empty result set (no 404 error). See `docs/api-spec.md`, User
        Identifier Resolution — the 404 convention applies only to
        single-resource target parameters, not to optional filter
        parameters on list endpoints.

        Relies on the uniform user_id column provided by
        AuditEventMixin across all audit event models.

        This method operates exclusively on the `user_id` column
        (the actor). Domain-specific filters on other user FK columns
        (e.g., `target_user_id` in IdentityAuditEvent) are the
        responsibility of the endpoint implementation, not the base
        class.
        """
        ...
```

### Concrete Subclasses

```python
class TicketAuditLog(BaseAuditLog):
    name = "ticket"
    description = "Ticket lifecycle and mutation events"
    model_class = TicketAuditEvent


class IdentityAuditLog(BaseAuditLog):
    name = "identity"
    description = "User lifecycle, roles, API keys, and role mappings"
    model_class = IdentityAuditEvent


class SettingAuditLog(BaseAuditLog):
    name = "setting"
    description = "System setting modifications"
    model_class = SettingAuditEvent


class FetcherAuditLog(BaseAuditLog):
    name = "fetcher"
    description = "Administrative actions on fetchers"
    model_class = FetcherAuditEvent
```

`SettingAuditLog`, `IdentityAuditLog`, and `FetcherAuditLog` override
`log_event()` with the typed domain signatures and validation defined in
their owning specifications. They inherit the flush-before-return,
no-commit, exception propagation, and caller-owned transaction guarantees
below.

**Note**: these subclasses define only service-layer attributes (name,
description, model reference, retention). Database columns (`id`,
`created_at`, `user_id`, and domain-specific columns) are defined in the
SQLAlchemy models pointed to by `model_class`, which inherit from
`AuditEventMixin` for the common columns.

### Retention Policy

Retention is **permanently indefinite** for all audit trails. Audit
records are compliance and forensic evidence that must remain available
at all times — there is no plan for cleanup, archival, or deletion.
The expected volume of audit events over the lifetime of the system
does not justify a retention mechanism.

### Operational State Authority

Audit events are append-only historical evidence. They are authoritative
records of the events they contain, but they are not the authoritative source
of current operational state. Application code MUST NOT use audit events to
determine current state or as input to mutation, authorization, idempotency,
or restoration decisions.

Current operational state MUST instead be persisted on the owning entities or
derived from sources that the owning feature specification explicitly
designates as authoritative. If a future operation needs provenance or a
current cause in order to behave correctly, that information belongs in the
owning domain model; it must not be reconstructed from audit history.

Audit events MAY be queried or projected into historical, forensic,
analytical, or presentational read models, including timelines and historical
intervals, provided those projections do not govern current operational
decisions. For example, fetcher audit events may reconstruct disabled periods
for the fetcher timeline, while `FetcherConfig.enabled` remains the authority
for whether a fetcher is currently enabled.

### Human-Readable Subjects

An audit event intended for human review MUST identify its subject without
requiring the reader to resolve an opaque internal UUID. Internal identifiers
may remain as top-level event metadata or structured correlation fields when
they serve a concrete machine or follow-up-operation need, but they are not a
substitute for a stable domain identifier and readable label.

Each owning audit specification defines the appropriate subject fields. When a
label or canonical identifier can change or disappear from current operational
state, the event stores an event-time snapshot in `old_value`, `new_value`, or
`detail`; the audit API does not reconstruct historical meaning by joining the
current entity. Examples include ticket identifiers, usernames carried as
event *content* (e.g., the `username_changed` old/new values, or a username
referenced in a `comment`), setting keys, fetcher names, Product CPEs, and
Product display names.

This rule governs event *content* — the subject the event is about. It does
not apply to the actor/target *metadata* columns defined by `AuditEventMixin`
(`user_id`) and its per-trail extensions (e.g., `target_user_id` in
`IdentityAuditEvent`). Those columns intentionally resolve to the live,
current user reference at read time, as specified by the owning audit trail
(e.g., `docs/features/platform/system-settings.md`, "actor is always the
complete current user reference object"). A user rename is therefore reflected
retroactively in who is shown as having performed a historical action, which
is a deliberate, separate design choice from this rule.

### Relationship to AuditEventMixin

```
Service layer (behavior)               Model layer (data structure)
─────────────────────────               ────────────────────────────
BaseAuditLog                            AuditEventMixin (id, created_at, user_id)
  │  - log_event()                          │
  │  - apply_date_filters()                 │
  │  - filter_by_actor()                    │
  │  - registry                             │
  │                                         │
  ├── TicketAuditLog ──model_class──▶  TicketAuditEvent (Base + Mixin)
  ├── IdentityAuditLog ─model_class─▶  IdentityAuditEvent (Base + Mixin)
  ├── SettingAuditLog ──model_class──▶  SettingAuditEvent (Base + Mixin)
  └── FetcherAuditLog ─model_class──▶  FetcherAuditEvent (Base + Mixin)
```

`BaseAuditLog` references the model via `model_class` and provides
behavioral methods. `AuditEventMixin` provides the structural columns.
Together they ensure that all audit trails are both structurally
consistent (same base columns) and behaviorally consistent (same
service-layer interface).

## Naming

| Element | Pattern | Example |
|---|---|---|
| Database table | `{domain}_audit_event` | `ticket_audit_event`, `identity_audit_event` |
| SQLAlchemy model | `{Domain}AuditEvent` | `TicketAuditEvent`, `IdentityAuditEvent` |
| Enum | `{Domain}AuditEventType` | `TicketAuditEventType`, `IdentityAuditEventType` |
| BaseAuditLog subclass | `{Domain}AuditLog` | `TicketAuditLog`, `IdentityAuditLog` |
| Spec file (standalone) | `{domain}-audit-log.md` | `ticket-audit-log.md`, `identity-audit-log.md` |
| Event type column | `event_type` | All audit event tables |
| Change value columns | `old_value`, `new_value` (TEXT, nullable) | All audit event tables. `SettingAuditEvent.new_value` is NOT NULL |
| JSONB context column | `detail` (singular) | `TicketAuditEvent.detail`, `IdentityAuditEvent.detail`, `FetcherAuditEvent.detail`. Not present in `SettingAuditEvent` (not needed) |

Endpoint naming convention: see `docs/api-spec.md` (Audit Trail Endpoint
Naming section).

## Idempotent No-ops

When a service operation returns early because the desired state is already
reached and no mutation occurs, no audit event is created. Audit events
record state changes, not access attempts.

## Atomicity

Every audit event required by an owning domain contract MUST be created in the
same database transaction as the mutation it records. If the mutation is rolled
back, the audit event must not persist. This is enforced by using
`BaseAuditLog.log_event()` with the same `AsyncSession` as the mutation. An
owning domain may instead define an explicit no-event boundary for an effective
factual or operational mutation; that absence is intentional and is not an
atomicity failure.

If `log_event()` fails for any reason (FK constraint violation, invalid
event_type, serialization error), the entire transaction — including the
business mutation — MUST roll back. The caller MUST NOT catch exceptions from
`log_event()` separately from the main transaction. A mutation covered by a
registered audit trail must have either its required event contract or an
explicit no-event contract in the owning domain specification; lacking both is
a specification defect.

`log_event()` MUST force the pending insert to reach the database before
returning, so constraint violations (FK, NOT NULL, CHECK) surface at the
point of the call rather than at commit time. It MUST NOT commit — the
caller's transaction governs durability.

## Actor Field

- `user_id` is inherited from `AuditEventMixin` and is nullable at the
  database level in all audit event models
- `user_id` identifies the actor of the semantic event represented. A direct
  authenticated user action uses that user's UUID. A derived consequence may
  use `NULL` even when a user initiated the containing workflow, when the owning
  domain contract attributes that consequence to the system
- `user_id` is also `NULL` when no authenticated Sentinel user is attributable
  to the operation (e.g., CLI, background task, external sync, automated
  detection)
- Subclasses that only record human-initiated actions (e.g.,
  `SettingAuditLog`, `FetcherAuditLog`) MUST override `log_event()` to
  validate that `user_id` is provided, raising `ValueError` if it is
  `None`

## Date Filtering

Every audit trail API endpoint MUST support `from_date` and `to_date`
query parameters (ISO 8601 date or datetime, both optional, inclusive
bounds). Filtering is provided by the `BaseAuditLog.apply_date_filters()`
class method to ensure uniform behavior across all audit trails:

- `from_date` only → records where `created_at >= from_date`
- `to_date` only → records where `created_at <= to_date`
- Both → records in the inclusive range
- Neither → no date filter applied

Date-only values (without a time component) are interpreted following the
convention defined in `docs/api-spec.md` (Date Range Interpretation).

## Indexing

Every audit event table MUST have indexes on:

1. `created_at` — all audit trail endpoints support date range filtering
2. Every column used as a mandatory scope filter (e.g., `ticket_id` for
   ticket audit events, `fetcher_name` for fetcher audit events)
3. Every nullable FK column used as an optional filter (e.g.,
   `target_user_id`, `user_id`)

Criterion 1 and the `user_id` case of criterion 3 are satisfied by
inheritance: every concrete audit event table has both indexes
automatically from `AuditEventMixin`. Concrete tables declare indexes
only for their own mandatory scope columns (criterion 2) and for any
additional optional filter columns beyond `user_id` (e.g.,
`target_user_id`).

The `event_type` column does NOT require a dedicated index — its low
cardinality makes it ineffective as a standalone index. When filtered
alongside `created_at` or a scope column, the existing indexes provide
sufficient selectivity.

Specific index definitions per table are left to implementation. This
convention provides the criteria; the developer applies them to each
concrete table.

## Audit Trail Index

When adding a new audit trail, update this index.

| Audit Trail | Table | Event Types | Retention | Owning Spec |
|---|---|---|---|---|
| Ticket | `ticket_audit_event` | 29 | Indefinite | `docs/features/tickets/ticket-audit-log.md` |
| Fetcher | `fetcher_audit_event` | 4 | Indefinite | `docs/features/platform/fetcher-infrastructure.md` |
| Identity | `identity_audit_event` | 14 | Indefinite | `docs/features/identity/identity-audit-log.md` |
| Setting | `setting_audit_event` | 1 | Indefinite | `docs/features/platform/system-settings.md` |

## Access Level

Most audit trail endpoints require a specific capability (typically
`manage_users`, `manage_settings`, or `manage_fetchers`). Two exceptions
exist:

- **Ticket audit log** (`GET /api/v1/tickets/{ticket_id}/audit-log`):
  **Authenticated**, because the response includes actor details
  (username, full name, UUID) that could aid reconnaissance if exposed
  publicly. This endpoint is entity-scoped (always filtered by
  `ticket_id`) and does not expose cross-entity audit data.

- **Identity audit log — self-service**
  (`GET /api/v1/users/me/audit-log`): **Authenticated**, scoped to
  `target_user_id = current_user.id`. Users can view events that affect
  their own account (role changes, password resets, API key operations,
   field changes from external sync). The actor field is anonymized to
  `"system"`, `"self"`, or `"admin"` to prevent identification of the
  specific administrator. The full, unmasked audit log remains
  restricted to users with `manage_users` capability at
  `GET /api/v1/admin/identity/audit-log`.

The self-service pattern (authenticated access with implicit user
scoping and actor anonymization) is reusable for future audit trails
that need to give users visibility into events affecting them without
exposing cross-user data or actor identities.

## Immutability

Audit event tables are append-only. No application-level UPDATE or DELETE
operations are permitted on these tables. This is a project convention
enforced via code review (guardrails) and mechanically by a structural
test — see `docs/features/platform/testing-strategy.md` (Structural
Tests, "Audit immutability"). There are no exceptions to this rule (see
Retention Policy above).

## Scalability Considerations

Current indexes cover primary query patterns (per-entity lookups).
Cross-entity queries at high volume may degrade on very large tables.
The expected event volume does not justify additional partitioning or
performance measures at this time. See Retention Policy for the
rationale.

## Enforcement

Guardrail 11 (AGENTS.md) and reviewer agents
(`@ticket-integrity-reviewer`, `@identity-integrity-reviewer`) verify
audit compliance during PR review. Integration tests for each mutation service
verify the exact event sequence required by the owning contract or the exact
absence required by an explicit no-event boundary. No additional runtime
detection mechanism is needed at this time.

## Filtering

All audit trail endpoints MUST apply standard pagination as defined in
`docs/api-spec.md` (default `per_page`: 20, max: 100).

## Cross-references

- `docs/conventions.md` — Audit Trail reference paragraph
- `docs/api-spec.md` — `/audit-log` endpoint suffix convention, pagination conventions
- `docs/data-model.md` — table definitions for all audit event models
- `docs/features/tickets/ticket-audit-log.md` — ticket audit trail
- `docs/features/identity/identity-audit-log.md` — identity audit trail
- `docs/features/platform/system-settings.md` — setting audit trail
- `docs/features/platform/fetcher-infrastructure.md` — fetcher audit trail
- `AGENTS.md` — Audit trail atomicity guardrail
- `docs/features/platform/testing-strategy.md` — Audit trail testing
  requirements, immutability verification
