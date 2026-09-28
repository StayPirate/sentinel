# Review: cvss-scoring

**Spec**: `docs/features/tickets/cvss-scoring.md`
**Last reviewed**: 2026-06-09
**Reviewers**: Gap Analysis, Coherence, Design, Security, API Conventions

---

## Gap Analysis

### CVS-GAP-10 — SUSE CVSS POST endpoint specifies upsert but service function rejects duplicates (Medium)

**Category**: Error and failure paths
**Status**: RESOLVED — Eliminated by replacing `create_cvss_assessment()` and `update_cvss_assessment()` with a single `upsert_cvss_assessment()` that handles create-or-update internally via `INSERT ... ON CONFLICT DO UPDATE`. `DuplicateCVSSAssessmentError` removed. (2026-06-09)

### CVS-GAP-11 — CVSS v2.0 inclusion in Severity Resolution Cascade contradicts Key Principle 2 (Medium)

**Status**: RESOLVED — Key Principle 2 rewritten: all stored CVSS versions (including v2.0, v3.0) participate in the Severity Resolution Cascade as fallback; explicit version priority order (4.0 > 3.1 > 3.0 > 2.0) added to steps 2 and 4; step 5 updated from "any supported version" to "any version" (2026-06-09)

### CVS-GAP-13 — CVSS v3.0 vectors accepted by endpoint but v3.1 required by gate (Medium)

**Status**: RESOLVED — Clarified: API accepts any valid CVSS version for SUSE assessments; ticket progression gate requires SUSE v3.1 AND v4.0; UI presents only v3.1 and v4.0 to VAs; assessments for other versions are stored but do not satisfy the gate (2026-06-09)

### CVS-GAP-12 — Severity and eligibility response objects have unspecified null/absent structure (Low)

**Status**: RESOLVED — Specified response structure for absent severity (severity: null) with example, and formalized contract for severity.provider (2026-06-09)

### CVS-GAP-14 — SUSE-defined severity thresholds per version referenced but never defined (Low)

**Status**: RESOLVED — Removed reference to SUSE-defined severity thresholds and specified standard CVSS scale, adding a note about SUSE's internal scale mapped at the boundary. (2026-06-10)

### CVS-GAP-15 — Resolved CVSS version not included in severity response object (Low)

**Status**: RESOLVED — Added version field to severity response object and resolve_severity_score output (score, version, provider); updated response example and field description (2026-06-09)

### CVS-GAP-03 — No explicit specification for batch recalculation when SUSE has old-default-version assessment only (High)

**Status**: RESOLVED — Auto-resolved: the spec already covers this scenario — "SUSE has not scored the default version" is listed as an explicit condition in Eligibility Score Resolution (line 90), and the gate requiring both v3.1 and v4.0 for Analysis→Analyzed limits the impact to in-progress Analysis tickets, which is expected behavior (2026-06-07)

### CVS-GAP-08 — `sync_redhat_cves` fetcher error handling explicitly marked TBD (High)

**Status**: RESOLVED — Error handling fully specified in cve-tracking.md (Fetcher: sync_redhat_cves, Error Handling section): HTTP 404 and no-CVSS-fields map to missing (existing assessments preserved), HTTP 429/5xx/timeout retry 3x then failure, unparseable data is non-retryable failure, batch run uses per-CVE error handling with 3-consecutive-failure abort (2026-06-08)

### CVS-GAP-01 — `resolve_eligibility_score` input contract does not specify pre-filtering of assessments (Medium)

**Status**: RESOLVED — Input contract clarified: both functions receive full unfiltered assessments; filtering is internal (2026-06-08)

### CVS-GAP-02 — Batch recalculation for default version change has no named entry point in `ticket_mutations` (Medium)

**Status**: RESOLVED — Defined recalculate_cvss_chain() in ticket-mutations.md as dedicated entry point for batch recalculation; updated cvss-scoring.md and system-settings.md references (2026-06-08)

### CVS-GAP-04 — Step numbering 4 and 4b creates ordering ambiguity for `CVE.severity` update (Medium)

**Status**: RESOLVED — Write-path section rewritten as conceptual overview referencing ticket-mutations.md; eliminates step numbering ambiguity (2026-06-08)

### CVS-GAP-05 — Recalculation Chain note on Resolved tickets inconsistent with `ensure_ticket_operable()` semantics (Medium)

**Status**: RESOLVED — Auto-resolved: behavior for Resolved tickets now explicitly specified in both cvss-scoring.md and ticket-mutations.md (reconcile deterministic gate evaluation, backward transitions documented) (2026-06-08)

### CVS-GAP-06 — Concurrency gap in batch recalculation for concurrent default version changes (Medium)

**Status**: RESOLVED — Specified singleton Redis lock with read-after-lock pattern for batch recalculation; added mandatory default_cvss_version parameter to recalculate_cvss_chain() (2026-06-08)

### CVS-GAP-16 — DELETE endpoint cvss_version path parameter has no format validation specified (Low)

**Status**: RESOLVED — Cross-agent duplicate of CVS-API-05 (2026-06-09)

### CVS-GAP-07 — `GET /cves/{cve_id}/cvss` exposes severity cascade resolved fields but no eligibility score (Low)

**Status**: RESOLVED — Restructured /cvss response with nested severity and eligibility objects; eligibility.source disambiguates SUSE assessment vs 10.0 fallback (2026-06-08)

### CVS-GAP-09 — Batch recalculation scope for soft-deleted products not explicitly confirmed (Low)

**Status**: RESOLVED — Added explicit parenthetical reference to package-model.md DD8 confirming soft-deleted products are included in eligibility recalculation scope (2026-06-08)

---

## Coherence

### CVS-COH-11 — `severity_changed` audit event `user_id` definition contradicts between data-model.md and ticket-audit-log.md/ticket-mutations.md (Medium)

**Status**: RESOLVED — Corrected definition of user_id for severity_changed in data-model.md (2026-06-09)

### CVS-COH-12 — DELETE endpoint error table uses `RESOURCE_NOT_FOUND` but ticket-mutations.md defines `CVSS_ASSESSMENT_NOT_FOUND` (Medium)

**Status**: RESOLVED — DELETE endpoint error code changed from RESOURCE_NOT_FOUND to CVSS_ASSESSMENT_NOT_FOUND, aligning with ticket-mutations.md exception table (2026-06-09)

### CVS-COH-13 — POST endpoint error table omits `CVSS_DUPLICATE_ASSESSMENT` from ticket-mutations.md (Low)

**Status**: RESOLVED — Superseded: `CVSS_DUPLICATE_ASSESSMENT` and `DuplicateCVSSAssessmentError` eliminated entirely by the upsert unification. The POST endpoint now calls `upsert_cvss_assessment()` directly; no dispatch note needed (2026-06-09)

### CVS-COH-14 — GET response example shows score 8.1 for a CVSS:3.1 vector that computes to 9.8 (Low)

**Status**: RESOLVED — Fixed GET response example: score corrected from 8.1 to 9.8 (matching vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), severity label from High to Critical (2026-06-09)

### CVS-COH-06 — Recalculation Chain step 2 implies direct eligibility writes; must route through `package_service` (High)

**Status**: RESOLVED — Auto-resolved: finding no longer applicable after spec changes (2026-06-08)

### CVS-COH-01 — Eligibility Threshold section contradicts Eligibility Score Resolution (Medium)

**Status**: RESOLVED — Eligibility cascade aligned to 2-step SUSE-only; resolve_cvss_score renamed to resolve_severity_score; resolve_eligibility_score added as dedicated function (2026-06-03)

### CVS-COH-04 — Recalculation Chain audit trail omits `cvss_assessment_changed` event (Medium)

**Status**: RESOLVED — Auto-resolved: finding no longer applicable after spec changes (2026-06-08)

### CVS-COH-07 — Recalculation Chain step 3 note overstates restriction as architectural invariant (Medium)

**Status**: RESOLVED — Auto-resolved: finding no longer applicable after spec changes (2026-06-08)

### CVS-COH-02 — Write-path flow uses non-standard step label `4b` instead of renumbered sequence (Low)

**Status**: RESOLVED — Auto-resolved: finding no longer applicable after spec changes (2026-06-08)

### CVS-COH-03 — `auto_assign_actor()` call absent from CVSS write-path summary (Low)

**Status**: RESOLVED — Auto-resolved: write-path section rewritten as conceptual overview; no longer lists implementation steps (2026-06-08)

### CVS-COH-05 — When Severity is Recalculated lists a redundant trigger (Low)

**Status**: RESOLVED — Removed redundant SUSE-specific trigger; already covered by the general "CVSS assessment added/modified/removed" trigger (2026-06-08)

### CVS-COH-08 — Term "cascade" overloaded across Severity Resolution Cascade and Recalculation Chain (Low)

**Status**: RESOLVED — Terminology disambiguated: cascade reserved for resolution strategies, chain for propagation, flattening for duplicate pointer resolution. Convention added to docs/conventions.md. ~179 lines renamed across 21 files (2026-06-08)

### CVS-COH-09 — `product-lifecycle-transitions.md` implies async path where `cvss-scoring.md` describes synchronous path (Low)

**Status**: RESOLVED — Removed cvss_change from re_evaluate_product_eligibility reasons; added boundary note clarifying sync path via ticket_mutations (2026-06-08)

### CVS-COH-10 — Cross-references omits `ticket-mutations.md`, `package-model.md`, and `system-settings.md` (Low)

**Status**: RESOLVED — Auto-resolved: finding no longer applicable after spec changes (2026-06-08)

---

## Design

### CVS-DES-02 — API upsert endpoint inconsistent with service layer's separate create/update functions (Medium)

**Category**: Architectural fitness
**Status**: RESOLVED — Eliminated by replacing `create_cvss_assessment()` and `update_cvss_assessment()` with a single `upsert_cvss_assessment()`. Service API now matches the domain operation. (2026-06-09)

### CVS-DES-03 — Batch CVSS recalculation has no defined result storage or admin feedback mechanism (Medium)

**Status**: RESOLVED — Specified admin feedback mechanism: UI confirmation dialog with ticket count + structured application logging for batch results (2026-06-09)

### CVS-DES-05 — Recalculation Chain description broader than `recalculate_cvss_chain()` specification (Low)

**Status**: RESOLVED — Auto-resolved: the Recalculation Chain section functions as a high-level overview operating at an appropriate abstraction level; the authoritative details are correctly defined in `ticket-mutations.md` and the existing cross-reference to `package-model.md` Axis 2 is sufficient. (2026-06-10)

### CVS-DES-06 — Redis lock crash scenario produces misleading error message and no automatic recovery (Low)

**Status**: RESOLVED — Lock TTL reduced to 1 hour. A periodic heartbeat timestamp is now written to the lock key every 60s, allowing the retry logic to differentiate between an active batch and a stale lock from a crashed worker. (2026-06-10)

### CVS-DES-07 — Severity and eligibility response objects may be stale on read path for CVEs without active tickets (Low)

**Status**: RESOLVED — Auto-resolved: by design, clients can infer sync staleness from the ticket status (Resolved/Ignored/Duplicated indicate that active CVSS tracking has stopped). The overhead of adding a dedicated indicator or continuing tracking indefinitely is not justified. (2026-06-10)

### CVS-DES-01 — Ambiguous version tie-breaking in severity cascade allows v2.0 participation despite stated exclusion (High)

**Status**: RESOLVED — Cross-agent duplicate of CVS-GAP-11 (2026-06-09)

### CVS-DES-04 — Cross-version severity mapping references undefined custom SUSE thresholds (Low)

**Status**: RESOLVED — Cross-agent duplicate of CVS-GAP-14 (2026-06-09)

---

## Security

### CVS-SEC-01 — Public CVSS endpoint may expose eligibility data during CVE-to-confidential-ticket transition (Medium)

**Status**: RESOLVED — Accepted risk: eligibility score is derived from CVSS data already public in the same response; require_accessible_cve gates access once CVE is linked to confidential ticket (2026-06-09)

### CVS-SEC-02 — No rate limiting on CVSS mutation endpoints that trigger expensive recalculation chains (Medium)

**Status**: RESOLVED — Accepted risk: rate limiting is a platform-wide concern tracked separately in api-spec.md; not specific to this endpoint (2026-06-09)

### CVS-SEC-04 — No explicit input length constraint on CVSS vector string in request schema (Low)

**Status**: RESOLVED — Added maximum 200 characters constraint to vector input field description, matching VARCHAR(200) DB column (2026-06-09)

### CVS-SEC-05 — CVSS library error handling and input sanitization not specified (Low)

**Status**: RESOLVED — Auto-resolved: the specifications have been updated to explicitly cover error handling and input validation/sanitization across both the API mutations and the background fetchers (NVD, Red Hat, etc.). (2026-06-10)

### CVS-SEC-06 — Unbounded public CVSS GET response relies on implicit natural bound (Low)

**Status**: RESOLVED — Accepted risk: natural bound from unique constraint (provider_name, cvss_version) is sufficient; provider cardinality controlled by fetcher configuration (2026-06-09)

### CVS-SEC-07 — No audit trail for failed CVSS mutation attempts (Low)

**Status**: RESOLVED — Auto-resolved: by design, the audit trail captures successful state changes only ("Audit events record state changes, not access attempts"). Failed attempts are surfaced to callers via HTTP error responses and captured in application/access logs. (2026-06-10)

### CVS-SEC-03 — Batch recalculation lock failure may silently leave tickets in stale state (Low)

**Status**: RESOLVED — Cross-agent duplicate of CVS-DES-06 (2026-06-09)

---

## API Conventions

### CVS-API-01 — POST endpoint uses wrong HTTP method for upsert semantics (Medium)

**Status**: RESOLVED — Added "Note on POST with upsert semantics" justifying method choice per api-spec.md Mutation Patterns (2026-06-09)

### CVS-API-02 — GET endpoint response uses non-standard data wrapper structure (Medium)

**Status**: RESOLVED — Added composite CVSS view justification to GET endpoint response description; data object documented as structured view of all CVSS data for the CVE (2026-06-09)

### CVS-API-03 — Authorization format inconsistency (Low)

**Status**: RESOLVED — GET endpoint authorization changed from prose to formal Access: Public format per api-spec.md convention (2026-06-09)

### CVS-API-04 — GET endpoint missing explicit sorting statement (Low)

**Status**: RESOLVED — Added explicit sorting statement: client-controlled sorting not supported; assessments returned in fixed order grouped by CVSS version (2026-06-09)

### CVS-API-05 — DELETE endpoint path uses cvss_version which may accept ambiguous values (Low)

**Status**: RESOLVED — Documented valid cvss_version path parameter values (2.0, 3.0, 3.1, 4.0); unrecognized values treated as CVSS_ASSESSMENT_NOT_FOUND (2026-06-09)
