# Review: ticket-mutations

**Spec**: `docs/features/tickets/ticket-mutations.md`
**Last reviewed**: 2026-07-25
**Reviewers**: Gap Analysis, Coherence, Design, Security, API Conventions

---

## Gap Analysis

### TKM-GAP-01 — No exception for duplicate CVSS assessment (Medium)

**Status**: RESOLVED — Originally added `DuplicateCVSSAssessmentError` (2026-05-25). Subsequently eliminated: `create_cvss_assessment()` and `update_cvss_assessment()` replaced by `upsert_cvss_assessment()` which handles duplicates via `INSERT ... ON CONFLICT DO UPDATE`. `DuplicateCVSSAssessmentError` removed (2026-06-09)

### TKM-GAP-02 — Assessment not found has no defined exception (Medium)

**Status**: RESOLVED — Added CVSSAssessmentNotFoundError to Service Exceptions table with HTTP 404 mapping and explicit references in update/delete functions and endpoints (2026-05-25)

### TKM-GAP-03 — reopen_from_ignored 'last active assignee' restoration undefined (Medium)

**Status**: RESOLVED — Clarified 'last active assignee' source as current ticket.assignee_id value; added note that Ignored status preserves assignee_id (2026-05-25)

### TKM-GAP-04 — Severity recalculation after CVSS delete may leave ticket with no severity (Medium)

**Status**: RESOLVED — Auto-resolved: finding no longer applicable; cvss-scoring.md defines severity=None when no score available and gate blocking behavior (2026-05-25)

### TKM-GAP-05 — auto_assign_if_needed creates audit event but reconcile_ticket_status also creates one — ordering unspecified (Low)

**Status**: RESOLVED — Accepted risk: ordering is implicitly guaranteed by sequential execution within a single transaction; explicit documentation not warranted for Low-severity implicit behavior (2026-05-25)

### TKM-GAP-06 — resolve_canonical_target behavior when starting ticket is not Duplicated (Low)

**Status**: RESOLVED — Auto-resolved: finding invalid — the termination condition "until a non-Duplicated ticket is found" inherently covers the base case where the starting ticket is already non-Duplicated (chain length = 0) (2026-05-25)

### TKM-GAP-07 — revert_duplicate acting_user_id is required UUID but no handling for invalid/nonexistent user (Low)

**Status**: RESOLVED — Auto-resolved: finding invalid — auth layer (get_current_user) guarantees user existence before service functions are called; parameter is UUID | None not required UUID as described (2026-05-25)

### TKM-GAP-08 — No specification of what happens when ticket has no CVE and CVSS operations are attempted (Low)

**Status**: RESOLVED — Preconditions in ticket_mutations naturally reject operations on assessments whose CVE has no parent ticket; assessments are preserved for data reuse on re-association (2026-05-25)

### TKM-GAP-09 — Missing exception for upsert_cvss_assessment when ticket has no CVE (Medium)

**Status**: RESOLVED — Added TicketNoCVEError exception to Service Exceptions table and precondition reference (2026-05-25). Function renamed from `create_cvss_assessment()` to `upsert_cvss_assessment()` (2026-06-09)

### TKM-GAP-10 — update_cvss_assessment None semantics ambiguity (Medium)

**Status**: RESOLVED — Redesigned CVSS functions: removed score/cvss_version inputs, derived from vector via cvss library (2026-05-25). `update_cvss_assessment()` subsequently eliminated — replaced by `upsert_cvss_assessment()` (2026-06-09)

### TKM-GAP-11 — Missing exception for reopen_from_ignored wrong status (Medium)

**Status**: RESOLVED — Added TicketInvalidTransitionError to Service Exceptions table covering both reopen_from_ignored and revert_duplicate precondition violations (2026-05-25)

### TKM-GAP-12 — Missing exception for revert_duplicate wrong status (Medium)

**Status**: RESOLVED — Added TicketInvalidTransitionError to Service Exceptions table covering both reopen_from_ignored and revert_duplicate precondition violations (2026-05-25)

### TKM-GAP-13 — Analysis gate not defined within this document (Low)

**Status**: RESOLVED — Auto-resolved (2026-05-25). **Amended (2026-06-04)**: the Analysis gate (`assignee_id IS NOT NULL`) has been removed entirely by the orphaned-ticket-status change. There is no longer a gate to define — the Analysis tier was eliminated and `Analysis` is now the unconditional floor of `reconcile_ticket_status`. Finding remains resolved (trivially — nothing to define).

### TKM-GAP-14 — Severity becoming None after last CVSS deletion not documented (Low)

**Status**: RESOLVED — Auto-resolved: separation of concerns — gate behavior is documented in reconcile_ticket_status, not in each caller; scenario acknowledged in Testing section line 696 (2026-05-25)

### TKM-GAP-15 — CVSS assessments linked to CVE persist after dissociation (Low)

**Status**: RESOLVED — Design decision: assessments intentionally persist after dissociation for data preservation; unreachable for mutation without parent ticket, available for immediate reuse on re-association (2026-05-25)

### TKM-GAP-16 — auto_assign_actor with force=True creates noise on self-reassignment (Low)

**Status**: RESOLVED — Added idempotency check in auto_assign_actor force=True path: skip when acting_user_id == current assignee_id (2026-05-25)

### TKM-GAP-17 — Gate interaction with configurable CVSS version (Low)

**Status**: RESOLVED — Added clarifying note to Analyzed gate #4 in tickets.md: gate is data completeness requirement independent of default_cvss_version setting (2026-05-25)

### TKM-GAP-18 — Post-regression catch-up delegation is caller-dependent (Medium)

**Category**: Missing error paths
**Status**: RESOLVED — Internalized post-regression catch-up inside `reconcile_ticket_status()` step 4; caller delegation eliminated (2026-06-10)

---

## Coherence

### TKM-COH-01 — severity_changed audit event user_id conflict between ticket-mutations and audit-log contract (Medium)

**Status**: RESOLVED — Updated severity_changed event to conditional user_id (NULL for system, acting_user for manual override), aligning with established audit event pattern (2026-05-25)

### TKM-COH-02 — reopen_from_ignored auto_assign_if_needed not called in documented behavior (Low)

**Status**: RESOLVED — auto_assign_actor(force=True) unifies assignment logic; reopen_from_ignored now follows the same pattern as all other mutation functions (2026-05-25)

### TKM-COH-03 — Internal ordering discrepancy in revert_duplicate audit events (Low)

**Status**: RESOLVED — Inverted steps 5/6 in revert_duplicate to semantic order (duplicate_removed before status_change) and aligned summary prose (2026-05-25)

### TKM-COH-04 — Per-function behavior steps bundle unconditional `CVE.severity` update inside ticket-conditional branch (Low)

**Status**: RESOLVED — Acceptable by design: CVE.severity staleness window is negligible due to automatic ticket creation during ingestion; associate_cve() triggers recalculate_cvss_chain() immediately upon association (2026-06-11)

---

## Design

### TKM-DES-01 — Inactive assignee sanitization inside reconcile_ticket_status creates hidden side effects (Medium)

**Status**: RESOLVED — Renamed to reconcile_ticket_status() with explicit reconciler contract documenting side effects (inactive assignee sanitization, audit events) as intentional behavior (2026-05-25)

### TKM-DES-02 — resolve_canonical_target 50-hop limit and cycle detection (Low)

**Status**: RESOLVED — Cross-agent duplicate of TKM-SEC-03 (2026-05-25)

### TKM-DES-03 — reopen_from_ignored assignee logic splits decision across caller and function (Medium)

**Status**: RESOLVED — Cross-agent duplicate of TKM-SEC-05 (2026-05-25)

### TKM-DES-04 — Multiple reconcile_ticket_status calls per transaction during orphan chains lack deduplication (Low)

**Status**: RESOLVED — Auto-resolved: finding invalid — this is a deliberate documented design decision prioritizing correctness over performance, explicitly imposed as an implementation constraint (2026-05-25)

### TKM-DES-05 — User deactivation unassigns via direct query bypassing ticket_mutations (Medium)

**Status**: RESOLVED — Spec updated (2026-05-25). **Amended (2026-06-04)**: the resolution note is outdated. The orphaned-ticket-status change removed the per-ticket `reconcile_ticket_status()` call from `_unassign_active_tickets` — unassignment no longer affects ticket status, so calling reconcile is not required. Finding remains resolved: the decision is intentional, not a bypass. The spec now documents the correct behavior (unassignment without status change, per-ticket `FOR UPDATE` lock, warning log in the sanitization catch-up).

### TKM-DES-06 — Duplicate chains not flattened at mark-time (Medium)

**Status**: RESOLVED — Auto-resolved: design intentionally rejects guaranteed flattening — single-ticket-scope rule (ticket-mutations.md §Single-ticket scope) prohibits FOR UPDATE on multiple tickets in one transaction to structurally prevent deadlocks; correctness guaranteed by canonical resolver regardless of chain depth (tickets.md §Best-Effort Flattening) (2026-05-25)

### TKM-DES-07 — Race window between deactivate_user and concurrent ticket mutations (Medium)

**Status**: RESOLVED — Auto-resolved: race window is a benign transient handled by design — reconcile_ticket_status includes Inactive Assignee Sanitization (ticket-mutations.md lines 173-197) that catches missed tickets on next mutation (2026-05-25)

### TKM-DES-08 — Redundant gate evaluation for inactive assignees (Low)

**Status**: RESOLVED — Auto-resolved: by design — readability preferred over micro-optimization; double evaluation cost is microseconds on rare case (inactive assignees); current ordering (evaluate → sanitize → re-evaluate) is more comprehensible (2026-05-25)

### TKM-DES-09 — Multiple reconcile calls in orphan chains produce multiple audit events (Low)

**Status**: RESOLVED — Auto-resolved: package-service.md (lines 788-794) documents single reconcile_ticket_status call after complete orphan chain; residual incoherence in ticket-mutations.md corrected (2026-05-25)

### TKM-DES-10 — force=True reassignment overwrites without notification (Low)

**Status**: RESOLVED — Acceptable by design: force=True reassignment only occurs when reactivating tickets from inactive states (Ignored/Duplicated) where no active work is in progress; audit trail provides sufficient traceability (2026-06-11)

---

## Security

### TKM-SEC-01 — No authorization check inside service functions for CVSS assessment operations (Medium)

**Status**: RESOLVED — Authorization responsibility contract added to Acting user convention section (2026-05-25)

### TKM-SEC-02 — resolve_canonical_target bypasses confidentiality checks (Medium)

**Status**: RESOLVED — Risk accepted: documented in tickets.md "Accepted risk — duplicate_of_id and confidential targets" section; target scope validation added to ticket-service.md (2026-05-25)

### TKM-SEC-03 — Duplicate chain traversal as potential DoS vector (Low)

**Status**: RESOLVED — Auto-resolved: finding invalid — threat is purely theoretical: requires compromised privileged account, 50 manual ticket creations, and 50 PK lookups take milliseconds total (2026-05-25)

### TKM-SEC-04 — set_severity_override business rule enforced only at API layer (Medium)

**Status**: RESOLVED — Precondition moved to service layer: set_severity_override() now raises SeverityDerivedError when cve_id IS NOT NULL (2026-05-25)

### TKM-SEC-05 — reopen_from_ignored assignee_id parameter trust boundary (Medium)

**Status**: RESOLVED — assignee_id parameter removed; _assign_actor_if_va() helper centralizes VA role validation internally (2026-05-25)

### TKM-SEC-06 — Authorization enforcement is purely contractual (Medium)

**Status**: RESOLVED — Auto-resolved: intentional architectural choice — service layer does not perform capability checks by design (ticket-mutations.md lines 72-79); authorization is API-layer responsibility per rbac.md and conventions.md (2026-05-25)

### TKM-SEC-07 — No CVSS score/vector bounds validation at service layer (Low)

**Status**: RESOLVED — Auto-resolved: score is now computed from vector (not user input); vector validated at service layer via cvss library parsing raising InvalidCVSSVectorError (2026-05-25)

### TKM-SEC-08 — resolve_canonical_target bypasses confidentiality checks (Low)

**Status**: RESOLVED — Auto-resolved: explicitly documented as 'Accepted risk — duplicate_of_id and confidential targets' in tickets.md (lines 966-985) with detailed rationale (2026-05-25)

### TKM-SEC-09 — force=True lacks explicit caller restriction (Low)

**Status**: RESOLVED — Added explicit caller restriction contract: force=True MUST only be used by manual-zone exit functions within this module (2026-05-25)

---

## API Conventions

_No findings. The spec is a service-layer specification with no API endpoint definitions._
