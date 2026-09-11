# CVSS Scoring

## Purpose

Manage Common Vulnerability Scoring System (CVSS) Base assessments from
multiple providers for each CVE. This specification is the central authority
for accepted vectors, parsing and canonicalization, assessment representation,
severity and eligibility score resolution, provider ownership, and the CVSS
API representation.

Sentinel stores each provider's assessment independently. The vector is the
only input authority: version, Base score, assessment severity, and expanded
Base metrics are always derived locally from the vector.

## Core Distinctions

The following values have different meanings and MUST NOT be substituted for
one another:

1. **Assessment severity** belongs to one `CVECVSSAssessment`. CVSS v2.0 uses
   Sentinel's legacy three-label qualitative mapping; v3.0, v3.1, and v4.0 use
   the FIRST qualitative scale. CVSS v2.0 produces `low`, `medium`, or `high`;
   v3.0, v3.1, and v4.0 produce `none`, `low`, `medium`, `high`, or `critical`.
2. **Resolved CVE severity** belongs to `CVE.severity`. It uses the unified
   `none`, `low`, `medium`, `high`, `critical` scale defined below, regardless
   of the version of the winning assessment. It is `NULL` only when resolution
   is absent.
3. **Eligibility score** is a separate pure resolution result. It uses only a
   SUSE assessment for the configured default version, with a conservative
   fallback. It is not the Severity Resolution Cascade result.

The `default_cvss_version` setting is either `3.1` or `4.0`. It selects the
preferred version in the Severity Resolution Cascade and the required version
for Eligibility Score Resolution. It does not exclude v2.0 or v3.0 from
severity resolution and does not make one version control all severity.

## Accepted Base Vectors

Sentinel accepts exactly complete CVSS Base vectors for versions `2.0`, `3.0`,
`3.1`, and `4.0`. Temporal, Environmental, Threat, and Supplemental metrics
are not accepted. A vector with any non-Base metric is invalid even when a
third-party CVSS library could calculate a Base score from it.

### Input Rules

Validation and normalization occur in this order:

1. The received string must contain at most 200 characters **before** any
   trimming. Pydantic enforces the JSON string type, required-field rule, and
   this received-length limit.
2. Sentinel trims leading and trailing whitespace only. It never removes or
   changes whitespace inside the vector.
3. The remaining syntax must use the official case for the version prefix,
   metric abbreviations, and metric values. Case variants are rejected rather
   than repaired.
4. CVSS v2.0 is unprefixed. CVSS v3.0, v3.1, and v4.0 require exactly
   `CVSS:3.0/`, `CVSS:3.1/`, and `CVSS:4.0/`, respectively. Any other or
   mismatched prefix is invalid.
5. Input Base metrics may appear in any order. For v4.0 this is an explicit
   Sentinel compatibility extension to FIRST's fixed-order vector grammar;
   Sentinel still emits only the standard fixed order.
6. Every required Base metric for the detected version must occur exactly
   once. Missing, duplicate, unknown, or non-Base metrics are invalid.
7. Successful output is canonical: it uses the official prefix rule and the
   FIRST Base metric order listed below. The canonical vector is the value
   persisted and returned by the API.

Empty input after trimming, embedded whitespace, an unsupported version, and
any violation of rules 3 through 6 produce `InvalidCVSSVectorError`, exposed by
the CVSS API as `422 CVSS_INVALID_VECTOR`. They are domain vector failures, not
Pydantic shape failures. Pydantic type, required-field, and pre-trim length
failures produce the global `422 VALIDATION_ERROR` response instead.

### Stable Parsed Result

The shared parser accepts one string and returns one immutable semantic result:

| Field | Type | Meaning |
|---|---|---|
| `canonical_vector` | `str` | Canonical complete Base vector |
| `version` | `Literal["2.0", "3.0", "3.1", "4.0"]` | Exact detected version |
| `score` | `Decimal` | Locally calculated Base score, from `0.0` through `10.0` |
| `severity` | version-specific severity enum | Severity from the version-specific mapping below |
| `metrics` | version-specific typed Base-metrics result | Expanded metrics for the detected version |

Callers never supply score, version, severity, or expanded metrics as an
independent authority. All manual and external ingestion paths use this shared
parser. A source-neutral CVE record parser extracts candidate vector strings
and delegates each candidate to this parser; it skips a rejected external
candidate according to its own per-entry ingestion contract rather than
reimplementing CVSS semantics.

### CVSS v2.0 Base Metrics

Canonical order: `AV/AC/Au/C/I/A`.

| Metric | Meaning | Official vector values | API wire values |
|---|---|---|---|
| `AV` | Access Vector | `L`, `A`, `N` | `local`, `adjacent_network`, `network` |
| `AC` | Access Complexity | `H`, `M`, `L` | `high`, `medium`, `low` |
| `Au` | Authentication | `M`, `S`, `N` | `multiple`, `single`, `none` |
| `C` | Confidentiality Impact | `N`, `P`, `C` | `none`, `partial`, `complete` |
| `I` | Integrity Impact | `N`, `P`, `C` | `none`, `partial`, `complete` |
| `A` | Availability Impact | `N`, `P`, `C` | `none`, `partial`, `complete` |

Expanded API shape:

```json
{
  "access_vector": "network",
  "access_complexity": "low",
  "authentication": "none",
  "confidentiality_impact": "complete",
  "integrity_impact": "complete",
  "availability_impact": "complete"
}
```

### CVSS v3.0 and v3.1 Base Metrics

Both versions have the same Base metric shape. Their version identities and
prefixes remain distinct. Canonical order: `AV/AC/PR/UI/S/C/I/A`.

| Metric | Meaning | Official vector values | API wire values |
|---|---|---|---|
| `AV` | Attack Vector | `N`, `A`, `L`, `P` | `network`, `adjacent`, `local`, `physical` |
| `AC` | Attack Complexity | `L`, `H` | `low`, `high` |
| `PR` | Privileges Required | `N`, `L`, `H` | `none`, `low`, `high` |
| `UI` | User Interaction | `N`, `R` | `none`, `required` |
| `S` | Scope | `U`, `C` | `unchanged`, `changed` |
| `C` | Confidentiality Impact | `N`, `L`, `H` | `none`, `low`, `high` |
| `I` | Integrity Impact | `N`, `L`, `H` | `none`, `low`, `high` |
| `A` | Availability Impact | `N`, `L`, `H` | `none`, `low`, `high` |

Expanded API shape:

```json
{
  "attack_vector": "network",
  "attack_complexity": "low",
  "privileges_required": "none",
  "user_interaction": "none",
  "scope": "unchanged",
  "confidentiality_impact": "high",
  "integrity_impact": "high",
  "availability_impact": "high"
}
```

### CVSS v4.0 Base Metrics

Canonical order: `AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA`.

| Metric | Meaning | Official vector values | API wire values |
|---|---|---|---|
| `AV` | Attack Vector | `N`, `A`, `L`, `P` | `network`, `adjacent`, `local`, `physical` |
| `AC` | Attack Complexity | `L`, `H` | `low`, `high` |
| `AT` | Attack Requirements | `N`, `P` | `none`, `present` |
| `PR` | Privileges Required | `N`, `L`, `H` | `none`, `low`, `high` |
| `UI` | User Interaction | `N`, `P`, `A` | `none`, `passive`, `active` |
| `VC` | Vulnerable System Confidentiality | `H`, `L`, `N` | `high`, `low`, `none` |
| `VI` | Vulnerable System Integrity | `H`, `L`, `N` | `high`, `low`, `none` |
| `VA` | Vulnerable System Availability | `H`, `L`, `N` | `high`, `low`, `none` |
| `SC` | Subsequent System Confidentiality | `H`, `L`, `N` | `high`, `low`, `none` |
| `SI` | Subsequent System Integrity | `H`, `L`, `N` | `high`, `low`, `none` |
| `SA` | Subsequent System Availability | `H`, `L`, `N` | `high`, `low`, `none` |

Expanded API shape:

```json
{
  "attack_vector": "network",
  "attack_complexity": "low",
  "attack_requirements": "none",
  "privileges_required": "none",
  "user_interaction": "none",
  "vulnerable_system_confidentiality": "high",
  "vulnerable_system_integrity": "high",
  "vulnerable_system_availability": "high",
  "subsequent_system_confidentiality": "none",
  "subsequent_system_integrity": "none",
  "subsequent_system_availability": "none"
}
```

## Severity

### Version-Specific Assessment Severity

`CVECVSSAssessment.severity` is calculated with the version-specific mapping
below and stored as a lowercase classification label. The v2.0 mapping is
Sentinel's NVD-compatible legacy qualitative mapping; v3.0, v3.1, and v4.0 use
the FIRST qualitative scale.

| Version | Score | Assessment severity |
|---|---|---|
| 2.0 | 0.0-3.9 | `low` |
| 2.0 | 4.0-6.9 | `medium` |
| 2.0 | 7.0-10.0 | `high` |
| 3.0, 3.1, 4.0 | 0.0 | `none` |
| 3.0, 3.1, 4.0 | 0.1-3.9 | `low` |
| 3.0, 3.1, 4.0 | 4.0-6.9 | `medium` |
| 3.0, 3.1, 4.0 | 7.0-8.9 | `high` |
| 3.0, 3.1, 4.0 | 9.0-10.0 | `critical` |

In particular, a v2.0 score of `0.0` has assessment severity `low`, as defined
by the v2.0 scale. That does not control the unified CVE severity.

### Unified CVE Severity

After the Severity Resolution Cascade selects an assessment, Sentinel maps its
score to the following unified scale without regard to the source version:

| Score | Unified severity |
|---|---|
| 0.0 | `none` |
| 0.1-3.9 | `low` |
| 4.0-6.9 | `medium` |
| 7.0-8.9 | `high` |
| 9.0-10.0 | `critical` |

The `none` label is a resolved score of exactly `0.0`; SQL `NULL` means no
assessment won the cascade. `CVE.severity` is denormalized from this result and
is never accepted as manual input. Tickets without a CVE continue to use
`Ticket.severity_manual` under `tickets.md`; that separate field is not a CVSS
assessment.

### Severity Resolution Cascade

`resolve_severity_score(assessments, default_cvss_version)` is pure and receives
the complete, unfiltered set of assessments for one CVE. Pre-filtering by
provider or version is a caller bug. The configured default must be `3.1` or
`4.0`.

Each candidate receives the following deterministic key, compared in the
listed order:

1. **Cascade step**, ascending:
   1. canonical SUSE assessment at the default version;
   2. canonical SUSE assessment at another accepted version;
   3. non-SUSE assessment at the default version;
   4. non-SUSE assessment at another accepted version.
2. **Applicable version priority**, highest first: `4.0`, `3.1`, `3.0`,
   `2.0`. Within default-version steps there is only one applicable version,
   so this component is equal for every candidate in that step.
3. **Score**, descending.
4. **Provider name**, ascending by Unicode code-point lexical order on the
   exact persisted string. This comparison is performed independently of
   database collation and locale.

The natural-key uniqueness of `(cve_id, provider_name, cvss_version)` makes
this key total for a valid assessment set. Input order and database row order
cannot change the winner.

The function returns either one stable result or absence:

| Field | Type | Meaning |
|---|---|---|
| `score` | `Decimal` | Winning assessment's Base score |
| `version` | accepted-version literal | Winning assessment's exact version |
| `provider` | `str` | Winning assessment's canonical persisted provider name |
| `label` | unified severity enum | Severity calculated from `score` using the unified scale |

Absence means the CVE has no assessment and therefore has
`CVE.severity = NULL`. Ticket existence and Ticket status never cause severity
resolution to be skipped.

### SUSE Internal Severity Terminology

External SUSE metadata may use `Moderate` and `Important`. Those labels are not
CVSS assessment severity or unified CVE severity. Owning ingestion contracts
may treat them as informational or map them at their boundary; they never
replace vector-derived values in this specification.

## Eligibility Score Resolution

`resolve_eligibility_score(assessments, default_cvss_version)` is pure and also
receives the complete, unfiltered assessment set. It returns exactly:

```text
{score: Decimal, source: suse | fallback}
```

Resolution is:

1. If the canonical SUSE assessment for the configured default version exists,
   return its score with `source = suse`.
2. Otherwise return `10.0` with `source = fallback`.

There is no fallback to another version or external provider. The result always
exists, including for a ticketless CVE or a Ticket without a CVE. Product
threshold, lifecycle, override, persistence, audit, and Ticket reconciliation
behavior are owned by `package-model.md`, `package-service.md`, and the narrow
atomic CVSS-chain exception in `ticket-mutations.md`. The exception applies the
package-model-owned pure evaluator; it does not change this resolution or create
a second formula owner.

Severity and eligibility are deliberately separate. A consumer MUST NOT use
the Severity Resolution Cascade winner for eligibility or use the eligibility
fallback to populate `CVE.severity`.

## Provider Identity and Authority

Each assessment is identified by `(cve_id, provider_name, cvss_version)`.
Provider names are human-readable and otherwise source-owned.

`SUSE` is the reserved internal provider identity. To test whether any supplied
provider name is reserved, trim its outer whitespace and apply Unicode
case-folding, then compare with the case-folded string `suse`. Every equivalent
value, including whitespace and case variants, is reserved. The only stored
form is exactly `SUSE`.

Caller authority is exhaustive:

| Caller category | Allowed operations |
|---|---|
| Authorized user through the existing SUSE API | Create, update, or delete only canonical `SUSE` assessments |
| Trusted system ingestion | Create or update only non-reserved external-provider assessments |
| Any consumer API caller | No mutation of external-provider assessments |

An ingestion caller that supplies `SUSE` or any reserved equivalent is
rejected before persistence. Source-specific normalization of non-reserved
provider names remains with each ingestion specification. System ingestion
does not delete external assessments: if a source stops publishing an
assessment, Sentinel retains the last persisted value until an explicit
source-owned withdrawal contract exists.

## Assessment Persistence and Ticket Status

An effective assessment create, update, or delete first maintains CVE-owned
state: the canonical assessment and the resolved `CVE.severity`. Ticket-owned
Product eligibility and gate effects are a separate propagation concern.

The mutation result includes the committed assessment action (`created`,
`updated`, `unchanged`, `deleted`, or `not_found` as applicable), the new
Severity Resolution result, whether unified severity changed, and one of these
propagation dispositions:

- `not_applicable`: no associated Ticket;
- `immediate`: the current locked CVSS chain applies automatic Product
  eligibility and any required final Ticket reconciliation before returning;
- `deferred_until_reactivation`: Ticket-owned propagation waits for the
  Ticket convergence workflow registered by manual-zone exit; or
- `none`: the serialized operation made no effective mutation.

The following matrix is authoritative:

| CVE/Ticket state | Manual SUSE mutation | External assessment update |
|---|---|---|
| No associated Ticket | Persist and recalculate; `not_applicable` | Persist and recalculate; `not_applicable` |
| `New` | Persist and recalculate; `immediate` | Persist and recalculate; `immediate` |
| `Analysis` | Persist and recalculate; `immediate` | Persist and recalculate; `immediate` |
| `Analyzed` | Persist and recalculate; `immediate` | Persist and recalculate; `immediate` |
| `Resolved` | Persist and recalculate; `immediate` | Persist and recalculate; `immediate` |
| `Ignored` | Reject with `TICKET_NOT_MUTABLE`; no result | Persist and recalculate; `deferred_until_reactivation` |
| `Duplicated` | Reject with `TICKET_NOT_MUTABLE`; no result | Persist and recalculate; `deferred_until_reactivation` |

External persistence is source-owned CVE maintenance and therefore is not
blocked by Ticket manual-zone immutability. Deferral never delays the direct
assessment write, `CVE.severity`, or their direct Ticket audit records. It
delays only package-owned and gate-owned propagation.

`Resolved` is part of the gate zone. Manual SUSE mutation and trusted external
ingestion therefore both apply automatic Product eligibility immediately and
may cause an ordinary gate-driven regression. Only `Ignored` and `Duplicated`
defer Product and gate effects until their explicit manual-zone exit.

Only an effective manual SUSE mutation may apply ordinary auto-assignment after
the serialized no-op/not-found classification. Trusted external ingestion and
default-version recalculation are system actions and never assign.

### Direct Audit Summary

If the CVE has an associated Ticket, every effective assessment mutation
creates `cvss_assessment_changed` in the same transaction. A manual SUSE
mutation uses the acting user; external ingestion uses the system actor
(`user_id = NULL`). The event's old and new values reflect the actual
serialized assessment states.

If unified `CVE.severity` changes, the same transaction also creates
`severity_changed`. This derived event always uses the system actor, including
when a user supplied the SUSE vector. Ticketless CVEs create no
`TicketAuditEvent`; this specification introduces no CVE audit trail.

Rejected requests raise and return no mutation result. Unchanged, not-found,
and rolled-back outcomes create no direct event. Audit failure rolls back the
assessment, `CVE.severity`, and every other change in the caller-owned
transaction.

For an effective manual SUSE chain, deterministic insertion order is optional
`assignment`, optional system `New → Analysis`, `cvss_assessment_changed`,
optional derived `severity_changed`, changed-Product eligibility events ordered
by `TicketPackageProduct.id`, and optional final gate `status_change`. Deferred
external mutations stop after the direct CVSS records.

### Serialization and Concurrent Outcomes

Assessment mutations serialize on the `CVE` root. When both CVE-owned and
Ticket-owned state participate, the global root-lock order is `CVE` then
`Ticket`. Ticketless mutations therefore still have a serialization root, and
concurrent association of a Ticket cannot invert lock order.

After obtaining the applicable locks, the operation reloads the assessment and
association state before classifying its result. Create, update, unchanged,
delete, and not-found outcomes, metrics, HTTP status, direct audit old/new
values, and propagation disposition all reflect that serialized state, not an
unlocked pre-read. A waiting equal upsert is `unchanged`; a waiting delete after
another delete is `not_found`. `cve_service.upsert_cve()` composes under the
same CVE root and does not acquire a second root in the opposite order.

Services flush but do not commit or roll back. The caller owns the transaction.

## Workflow Gate

For a Ticket with a CVE, the Analysis to Analyzed gate requires at least one
canonical `SUSE` assessment in any version currently accepted by Sentinel.
SUSE v2.0, v3.0, v3.1, or v4.0 each satisfies the gate. An assessment from any
other provider does not, and a SUSE assessment in the configured default
version is not specifically required. Tickets without a CVE use their manual
severity gate instead. See `tickets.md` for the complete gate.

## External Synchronization

External fetchers persist every accepted assessment available within their
own source scope. Persistence is conceptually independent of recalculation
scope and Ticket status. A source whose API or rate limits require a narrower
fetch scope documents that limitation and provides the applicable catch-up
behavior in its owning fetcher specification.

Current provider examples include NVD, CNA organizations, and Red Hat. Their
source URLs, extraction rules, schedules, provider-name normalization, and
catch-up behavior remain in their owning fetcher specifications. All of them
use the common parser, reserved-name rule, and persistence matrix above.

## API Endpoints

The existing CVSS endpoints and authorization levels are unchanged.

### Shared Assessment Item

GET and POST serialize exactly the same assessment item schema:

| Field | Type | Contract |
|---|---|---|
| `id` | UUID | Assessment identifier |
| `provider_name` | string | Canonical persisted provider name |
| `cvss_version` | `2.0`, `3.0`, `3.1`, or `4.0` | Exact vector version |
| `score` | decimal number | Calculated Base score |
| `severity` | version-specific lowercase enum | Assessment severity, not unified CVE severity |
| `vector_string` | string | Canonical complete Base vector |
| `metrics` | version-discriminated metrics object | Exact shape defined in Accepted Base Vectors |
| `created_at` | UTC datetime | Creation timestamp with `Z` suffix |
| `updated_at` | UTC datetime | Last-update timestamp with `Z` suffix |

Metric and severity wire values are lowercase with underscores for multi-word
values. The `cvss_version` discriminator determines the exact `metrics` shape;
fields from another version are never present and metrics are never returned as
an untyped abbreviation map.

### Get CVSS Assessments for a CVE

```text
GET /api/v1/cves/{cve_id}/cvss
```

**`Access: Public`**
**`Authentication: Optional`**

The path uses the CVE Identifier Resolution contract in `docs/api-spec.md`.
The endpoint returns one bounded composite resource and is not paginated.
Client-controlled sorting is not supported because the bounded assessment set
has one canonical order. Assessments are ordered by version `4.0`, `3.1`,
`3.0`, `2.0`, then provider name ascending using the same code-point lexical
comparison as resolution. This list order is independent of which assessment
wins severity.

`severity` is the stable Severity Resolution result or JSON `null` when absent.
`eligibility` is always present and is the stable Eligibility Score Resolution
result.

```json
{
  "data": {
    "assessments": [
      {
        "id": "01994c20-7c00-7000-8000-000000000001",
        "provider_name": "NVD",
        "cvss_version": "4.0",
        "score": 9.3,
        "severity": "critical",
        "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "metrics": {
          "attack_vector": "network",
          "attack_complexity": "low",
          "attack_requirements": "none",
          "privileges_required": "none",
          "user_interaction": "none",
          "vulnerable_system_confidentiality": "high",
          "vulnerable_system_integrity": "high",
          "vulnerable_system_availability": "high",
          "subsequent_system_confidentiality": "none",
          "subsequent_system_integrity": "none",
          "subsequent_system_availability": "none"
        },
        "created_at": "2026-09-10T10:30:00Z",
        "updated_at": "2026-09-10T10:30:00Z"
      },
      {
        "id": "01994c20-7c00-7000-8000-000000000002",
        "provider_name": "SUSE",
        "cvss_version": "3.1",
        "score": 9.8,
        "severity": "critical",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "metrics": {
          "attack_vector": "network",
          "attack_complexity": "low",
          "privileges_required": "none",
          "user_interaction": "none",
          "scope": "unchanged",
          "confidentiality_impact": "high",
          "integrity_impact": "high",
          "availability_impact": "high"
        },
        "created_at": "2026-09-10T10:31:00Z",
        "updated_at": "2026-09-10T10:31:00Z"
      }
    ],
    "default_cvss_version": "3.1",
    "severity": {
      "score": 9.8,
      "version": "3.1",
      "provider": "SUSE",
      "label": "critical"
    },
    "eligibility": {
      "score": 9.8,
      "source": "suse"
    }
  }
}
```

When there are no assessments, `assessments` is empty, `severity` is `null`,
and `eligibility` is `{"score": 10.0, "source": "fallback"}`.

### Set or Update SUSE CVSS Assessment

```text
POST /api/v1/cves/{cve_id}/cvss/suse
```

```json
{
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

`vector_string` is a required JSON string with a maximum received length of
200 characters. The shared parser applies the remaining domain rules. All four
accepted versions may be stored for SUSE, and any one canonical SUSE assessment
in an accepted version satisfies the workflow gate.

The endpoint returns the shared assessment item in the standard `data`
envelope. It returns **201 Created only when this serialized invocation is the
create winner**. It returns **200 OK** for an update or unchanged result,
including a concurrent caller that waited and found the same canonical vector
already created. POST remains appropriate because the vector determines the
version component of the target natural key.

| Status | Code | Condition |
|---|---|---|
| 422 | `CVSS_INVALID_VECTOR` | String passes Pydantic shape checks but violates the accepted Base-vector contract |

**`Capability: manage_cvss`**

### Delete SUSE CVSS Assessment

```text
DELETE /api/v1/cves/{cve_id}/cvss/suse/{cvss_version}
```

`cvss_version` accepts exactly `2.0`, `3.0`, `3.1`, or `4.0`. An unrecognized
value or absent canonical SUSE assessment returns the existing not-found error.
An effective delete returns 204 No Content.

| Status | Code | Condition |
|---|---|---|
| 404 | `CVSS_ASSESSMENT_NOT_FOUND` | No canonical SUSE assessment exists for the accepted version |

**`Capability: manage_cvss`**

## Service Boundaries

### Pure CVSS Logic

`services/cvss.py` contains database-free functions:

| Function | Input | Output |
|---|---|---|
| `validate_cvss_vector` | received vector string | Stable parsed result or `InvalidCVSSVectorError` |
| `resolve_severity_score` | complete assessment set, default version | Stable severity result or absence |
| `resolve_eligibility_score` | complete assessment set, default version | Stable `{score, source}` result |
| `calculate_severity` | `Decimal` score | Unified severity label |

The functions are deterministic and side-effect-free. They perform no database
access and never read settings directly; callers pass the configured default
version.

### Persistence and Propagation Boundary

The CVSS mutation service owns assessment persistence, `CVE.severity`, direct
audit records, lock ordering, and the stable committed result. For an immediate
disposition it also applies the sole narrow write exception: system-managed
Product eligibility is updated inline, through the package-model-owned pure
evaluator, before one final Ticket reconciliation. `package_service` retains
all ordinary Product mutation ownership and is not imported by
`ticket_mutations`. Resolution and eligibility algorithms are never copied
into either mutation boundary.

Changing `default_cvss_version` retains the system-settings endpoint, batch,
and recovery contracts in `system-settings.md`. This specification defines the
pure results that such workflows consume; it does not redefine settings
mutation, Redis coordination, task scope, or recovery.

## Required Tests

Implementation must provide the following coverage in addition to the shared
testing strategy.

### Parser Unit Tests

- One valid complete vector and correct canonical parsed result for every
  accepted version, including every Base metric field and lowercase wire value.
- Arbitrary metric order canonicalizes to FIRST order for every version.
- Received lengths of exactly 200 and 201 characters, proving length is checked
  before trimming; leading and trailing whitespace at a valid length; empty
  after trim; and embedded whitespace.
- Official-case acceptance and rejection of lowercase or mixed-case prefixes,
  abbreviations, and values; v2.0 unprefixed acceptance; missing or unexpected
  prefixes for every version.
- Every required metric missing in turn, every duplicate metric, unknown
  metrics, and representative Temporal, Environmental, Threat, and Supplemental
  metrics.
- Score boundaries and version-specific assessment severity, including v2.0
  score `0.0` as assessment `low` and v3/v4 score `0.0` as assessment `none`.
- Proof that supplied numeric score, version, severity, or metrics cannot enter
  the parsing interface as independent authorities.

### Resolution Unit Tests

- Every Severity Resolution Cascade step, absent result, and unified severity
  boundary at `0.0`, `0.1`, `3.9`, `4.0`, `6.9`, `7.0`, `8.9`, `9.0`, and
  `10.0`, including a v2.0 winner mapped to the unified scale.
- Default-version preference, all non-default version priorities, descending
  score, ascending provider tie-break, Unicode code-point ordering that differs
  from database collation, and shuffled input producing an identical result.
- Eligibility SUSE/default success and every fallback cause, with exact Decimal
  score and `suse` or `fallback` source; proof that another SUSE version and a
  higher external score do not participate.
- Reserved SUSE comparison across canonical, case, and outer-whitespace
  variants.

### Persistence and API Tests

- Manual SUSE create, update, unchanged, and delete, plus external create,
  update, unchanged, retained-on-source-absence behavior, and rejection of
  every reserved-name variant from system ingestion.
- Ticketless CVEs and associated Tickets in each of `New`, `Analysis`,
  `Analyzed`, `Resolved`, `Ignored`, and `Duplicated`, covering the complete
  persistence matrix, immediate propagation including both caller categories on
  `Resolved`, Product deferral only in the manual zone, and manual-SUSE
  assignment behavior.
- Gate completeness with exactly one canonical SUSE assessment in turn for
  each accepted version; an external-only assessment set; adding the first
  SUSE assessment; deleting the last SUSE assessment; and adding or deleting
  one of multiple SUSE assessments while another remains.
- With default v4.0 and only a canonical SUSE v2.0, v3.0, or v3.1 assessment,
  prove independently that severity follows the full cascade, eligibility uses
  the 10.0 fallback, and the SUSE workflow gate is satisfied.
- Trusted external CVSS on `Resolved`, starting from converged Product values,
  proves that the immediate chain reloads current inputs but does not change the
  Eligibility Score Resolution because external assessments never participate
  in it. A stale automatic Product value is still repaired from the current
  eligibility inputs. Manual SUSE and default-version cases separately cover
  false-to-true regression, true-to-false preservation or advancement,
  override skips, and at most one final reconciliation.
- Immediate `CVE.severity` maintenance for external updates in every Ticket
  status and for ticketless CVEs; no assessment means `NULL`, while score 0.0
  means unified `none`.
- Exact direct audit count, actor, old/new values, no-op absence, and atomic
  rollback. Manual assessment events use the acting user; external assessment
  and every derived severity event use the system actor; ticketless changes
  create no Ticket event.
- Two-session lock tests for concurrent equal and differing upserts,
  upsert/delete, delete/delete, Ticket association races, and composition with
  CVE ingestion. Assert `CVE` then `Ticket` acquisition, truthful winner action,
  HTTP status, metric, audit value, and propagation disposition.
- Cross-reference the complete Product formula, audit ordering, one-date,
  one-reconciliation, rollback, association, convergence, default-version,
  and CVSS/override race coverage required by `ticket-mutations.md` and
  `package-service.md`; parser and resolution tests remain owned here.
- GET and POST reuse of the same item schema for all four versions; exact
  version-discriminated metric shapes; lowercase enum values; canonical vector;
  deterministic `4.0 > 3.1 > 3.0 > 2.0`, provider-ascending list order;
  nullable severity; and always-present eligibility.
- POST returns 201 only to the serialized create winner and 200 to update and
  unchanged outcomes. DELETE covers each accepted path version, not found,
  and manual-zone rejection.
- Public optional-auth GET behavior, `manage_cvss` authorization on mutations,
  CVE accessibility, global Pydantic validation responses, and the domain
  `CVSS_INVALID_VECTOR` response without changing external HTTP mappings.

## Data Model

See `docs/data-model.md`. This contract uses the existing `CVE.severity` and
`CVECVSSAssessment` columns, unique constraint, and timestamps. It requires no
new table, column, enum, constraint, or migration.

## Cross-references

- `docs/features/tickets/tickets.md` - Ticket severity and workflow gates
- `docs/features/tickets/ticket-mutations.md` - CVSS mutation service
- `docs/features/tickets/ticket-audit-log.md` - Direct Ticket audit fields
- `docs/features/tickets/cve-service.md` - Source-neutral CVE ingestion
- `docs/features/platform/cve-record-parser.md` - CVE Record extraction
- `docs/features/packages/package-model.md` - Orthogonal eligibility rules
- `docs/features/packages/package-service.md` - Ordinary Product mutation and Ticket convergence ownership
- `docs/features/platform/system-settings.md` - Default-version operations
- `docs/features/platform/testing-strategy.md` - Test tiers and requirements
- `docs/features/identity/rbac.md` - Capabilities and endpoint permission map
- `docs/api-spec.md` - API envelopes, validation, and scoped responses
- `docs/data-model.md` - Persisted CVE and assessment schema
