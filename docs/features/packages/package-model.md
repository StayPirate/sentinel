# Package Model

## Purpose

Track the affectedness of source packages across maintenance tracks and
SUSE products in the context of tickets. See
`docs/features/tickets/tickets.md` for the ticket specification
(identification, creation, lifecycle).

## Design Rationale

The package tracking model separates three orthogonal concepts into
independent dimensions:

1. **Affectedness** — is the source code vulnerable?
2. **Eligibility** — will this product receive the fix?
3. **Delivery** — has the fix been distributed?

Each dimension is independently computable — its value depends only on
its own inputs, never on the current state of another dimension.
Status propagation does not affect eligibility computation, eligibility
never changes the status label, and delivery tracking is fully
independent from both. The dimensions may be observed together only at
the following exhaustive boundaries:

- Ticket gate evaluation combines affectedness, eligibility,
  actionability, and Product `released_at` as defined in `tickets.md`;
  track `delivery_status` is not a gate input;
- presentation fields and views may project multiple persisted values,
  including `delivery_relevant`;
- the affectedness/delivery anomaly matrix classifies combinations for
  analyst attention without changing either value; and
- post-mutation Ticket reconciliation may observe the gate-relevant
  values after an owning mutation has completed.

No other computation may derive one dimension from another or use one
dimension to suppress an independently owned mutation. A caller may
persist multiple independently computed results atomically when one
workflow has established each result under its own contract; atomic
persistence does not make either result an input to the other.

The entity hierarchy (Ticket → Package → Track → Product) uses a
workflow-agnostic abstraction ("track") that covers both IBS codestreams
and git branches, allowing the same business logic to operate
transparently across both workflows.

## Design Decisions

### 1. Explicit TicketPackage entity

A `TicketPackage` table anchors a source package within a ticket,
providing:

- A clear anchor for package-level maintainership provenance and future notes
- A single grouping point for tracks of both workflows
- Cleaner API design (`/tickets/{id}/packages/{id}/tracks`)

### 2. Workflow-agnostic "track" abstraction

The intermediate level is called "track" — a neutral term for "a
maintenance track for a package that serves one or more products." A
single `TicketPackageTrack` table with a `workflow_type` enum (`ibs` |
`git`) discriminates between IBS codestreams and git branches. This was
chosen over separate tables because the differences are minimal at the
data level and all business logic (status propagation, eligibility,
gates) is identical.

A single `reference` VARCHAR field identifies the track in its external
system (IBS codestream project name or git branch name). Both are
human-readable. For git, the full repository URL is derivable from
`package_name` (convention: `src.suse.de/pool/{package_name}`).

The SMELT v2 maintained-package endpoint provides the codestream-level
`maintenance_process_type`. Sentinel maps supported values directly to
`workflow_type` at ingestion time: `SLFO` maps to `git` and `SLE_15` maps to
`ibs`. The target-level `product_definition.type` (`channel` or `compose`)
describes Product-definition provenance and is not workflow authority. Both
supported workflows can coexist under the same package. See
[SMELT Query for Package Resolution](#smelt-query-for-package-resolution)
for the full resolution contract.

`workflow_type` is captured when a `TicketPackageTrack` is first created.
Subsequent resolution of the same track reference does not reconcile a later
SMELT maintenance-process reclassification; the existing track retains its
persisted `workflow_type`.

### 3. Eligibility as a separate dimension

Product eligibility (whether a product will receive the fix) is a
separate persisted boolean (`eligible`) on `TicketPackageProduct`, with
its own override mechanism (`is_eligible_override`). The track retains
its affectedness status regardless of whether any product is eligible.
Eligibility recalculation never changes affectedness or delivery and has
no rollup chain. After an owning workflow has completed all eligibility
changes, Ticket gate reconciliation may observe the new values at the
documented post-mutation boundary.

### 4. Delivery as a separate dimension

Delivery progress is tracked independently from affectedness:

- **Delivery status** (`delivery_status` on `TicketPackageTrack`):
  tracks the fix through the maintenance pipeline (PENDING →
  IN_PROGRESS → RELEASED), derived from authoritative IBS request-action and
  source-history evidence
- **Product release confirmation** (`released_at` on
  `TicketPackageProduct`): confirms the fix appeared in the product's
  update repository via `updateinfo.xml` verification

The `delivery_status` is persisted as a column (not computed from request-action
joins at query time) because request reconciliation, presentation, and anomaly
detection require the accepted current fact without rebuilding it from joins.
It is not an input to the Ticket resolution gates.
Disalignment risk is mitigated by `package_service` and the authoritative
`SyncIbsRequests` reconciliation (see
[Delivery Reconciliation](#delivery-reconciliation)).

### 5. FIXED as a distinct affectedness state

`FIXED` distinguishes "was vulnerable, now remediated" from "was never
vulnerable" (`NOT_AFFECTED`). Both mean the code is not currently
vulnerable, but they carry different history and workload implications.

- `FIXED` is restricted — set only by track release detection when a
  structured source diff contains qualifying evidence for the Ticket CVE (see
  `docs/features/packages/ibs-track-release-detection.md`)
  or via the admin escape hatch (`admin_ticket_ops` capability)
- A caller with `manage_packages` can change `FIXED` back to `AFFECTED` or
  `ANALYSIS`, or to any other non-`FIXED` affectedness state
- No `is_status_override` flag is needed on tracks — the VA has direct
  control over non-FIXED target statuses

### 6. Affectedness and delivery are independent axes

Neither axis resets nor constrains the other. "Anomalous" combinations
(e.g., `AFFECTED` + `RELEASED`) are valid system states that signal
situations requiring VA attention. See
[Anomaly Detection](#anomaly-detection-future-review-queue).

### 7. Manual exclusion and derived actionability

Spurious packages, tracks, or Products are excluded by an authorized acting
user through
hierarchical soft-deletion rather than an `IGNORED` status. Each `deleted_at`
marker records an explicit user decision at that exact scope; automated
workflows never set or clear these markers.

Whether a record currently participates in operational work is represented by
the derived `actionable` property. Actionability combines the hierarchical
manual
exclusion markers with the authoritative Product lifecycle phase. In
particular, EOL is derived from AIMAAS lifecycle dates and never copied into a
package-tree `deleted_at` field. See [Exclusion and Actionability](#exclusion-and-actionability).

### 8. Non-actionable records continue to receive factual updates

Manually excluded and lifecycle-non-actionable records are omitted from operational
views and gates, but they **continue to receive factual and independently
derived updates** within the scope of each owning process. Local eligibility
and lifecycle reconciliation continues while the Ticket is operable. External
IBS delivery and release monitoring is limited to active Tickets and catches up
if an inactive Ticket returns to an active status. This preserves dimension
independence without imposing continuous external traffic for resolved
history.

---

## Domain Concepts

### IBS (Internal Build Service)

The internal OBS instance at build.suse.de used for all SUSE commercial
products. Packages are built and maintained here.

### Codestream

An IBS project where source packages live and are built. Each codestream
follows the naming pattern `SUSE:SLE-<version>:GA` (development phase) or
`SUSE:SLE-<version>:Update` (maintenance phase after GA freeze).

- **GA codestream**: receives packages during development of a Service
  Pack. Once the SP is finalized, this codestream is frozen.
- **Update codestream**: receives all maintenance updates after GA
  freeze. This is where security fixes land.

A source package may exist in multiple codestreams. If a newer SP inherits
a package from an older SP without changes, the newer codestream contains
an IBS link to the older codestream's package — updates to the source
codestream automatically propagate to the linked codestreams.

### Git Track (SLFO)

A branch in a git repository on `src.suse.de` (e.g., `slfo-main`,
`slfo-1.2`) that serves the same role as an IBS codestream: it represents
a maintained version of a package, serving one or more products. The
repository URL follows the convention `src.suse.de/pool/{package_name}`.

### Track (Generic)

A maintenance track for a package — the workflow-agnostic abstraction
that covers both IBS codestreams and git branches. In Sentinel's data
model this is `TicketPackageTrack`. All business logic (status
propagation, eligibility, gates) operates on tracks regardless of
`workflow_type`.

### Product

A SUSE product with its own repositories from which end users receive
updates via the package manager. Each variant (base, LTSS, ESPOS, SAP)
is a separate product with its own CPE identifier. See
`docs/features/packages/product-catalog.md` for the full product
definition, lifecycle phases, and AIMAAS integration.

### Channel File

An XML file in the IBS project `SUSE:Channels` that defines which
packages from which codestreams are shipped to which products. There is
one channel file per product. Sentinel does not parse channel files
directly — it relies on SMELT to resolve these mappings.

### SMELT

An internal SUSE aggregator service (REST API at `smelt.suse.de/api`)
that provides:

1. **Product listing** (`v1/basic/products/` relative to the configured SMELT
   API prefix): paginated list of all SUSE products with name, version,
   CPE, and repository project names. See
   `docs/features/packages/product-catalog.md` (SMELT Integration) for the
   product sync specification.
2. **Per-package maintenance info**
   (package-scoped `experimental/v2/maintained/{package_name}` relative to the
   configured SMELT API prefix): returns the list of codestreams where the
   package is maintained and the Products it is shipped to, with direct CPE
   identification, authoritative codestream maintenance process, and
   target-level Product-definition provenance. See
   [SMELT Query for Package Resolution](#smelt-query-for-package-resolution)
   for the complete request contract.
3. **Per-package maintainership**
   (`experimental/v2/packages/{package_name}/maintainership` relative to the
   configured API prefix): returns direct users and groups with members.
   Sentinel extracts only individual emails and applies them package-wide; see
   `docs/features/packages/package-maintainership.md`.

SMELT reads from IBS, Git Product catalogs, Product build SBOM snapshots,
and other sources internally.

### AIMAAS

See `docs/features/packages/product-catalog.md` (Domain Concepts:
AIMAAS) for the full description of the AIMAAS service and its
endpoints. AIMAAS provides product lifecycle data and CVSS thresholds
used by the eligibility rules in this spec.

---

## Data Model

See `docs/data-model.md` for the full schema. The tables defined by this
feature are:

### Product / ProductRepository

See `docs/features/packages/product-catalog.md` (Data Model) for the
Product and ProductRepository tables. These are owned by the product
catalog feature. `Product` is consumed here for CPE-based package
resolution (see [SMELT Query for Package Resolution](#smelt-query-for-package-resolution))
and eligibility evaluation. `ProductRepository` is not used by package
resolution — it remains scoped to catalog sync and release detection.

### TicketPackage

An explicit entity that anchors a source package within a ticket. Replaces
the implicit grouping by `package_name` across
`TicketPackageTrack` records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK | Internal identifier |
| `ticket_id` | UUID | FK(ticket.id), NOT NULL | Related ticket |
| `package_name` | VARCHAR(255) | NOT NULL | Source package name |
| `deleted_at` | TIMESTAMPTZ | nullable | Direct manual-exclusion timestamp. NULL = not directly excluded |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Record creation timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Record update timestamp |

**Unique constraint**: `(ticket_id, package_name)`

### TicketPackageMaintainer

Immutable, additive association between one `TicketPackage` occurrence and one
existing active User acquired from SMELT maintainership data. It has standard
UUIDv7 `id`, `ticket_package_id` and `user_id` foreign keys with `ON DELETE
RESTRICT`, and `created_at`; it has no `updated_at`. The pair
`(ticket_package_id, user_id)` is unique. See
`docs/features/packages/package-maintainership.md` for acquisition,
authorization, audit, and retention semantics.

### TicketPackageTrack

Records the affectedness and delivery status of a source package in a
specific maintenance track within the context of a ticket. Affectedness caller
authority and source-state rules are defined in
[Status Behavior](#status-behavior). Delivery status is maintained by the
system based on the authoritative IBS request-action and provenance rules in
`ibs-submission-tracking.md`.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK | Internal identifier |
| `ticket_package_id` | UUID | FK(ticket_package.id), NOT NULL | Parent package record |
| `workflow_type` | VARCHAR(20) | NOT NULL | `ibs` or `git` |
| `reference` | VARCHAR(255) | NOT NULL | Track identifier: IBS codestream name or git branch name |
| `status` | VARCHAR(20) | NOT NULL, DEFAULT ANALYSIS | Affectedness status |
| `delivery_status` | VARCHAR(20) | NOT NULL, DEFAULT PENDING | Delivery pipeline status |
| `deleted_at` | TIMESTAMPTZ | nullable | Direct manual-exclusion timestamp. NULL = not directly excluded |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Record creation timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Record update timestamp |

**Unique constraint**: `(ticket_package_id, reference)`

The track is identified by `reference` (a string), not by a foreign key.
Tracks are not maintained as a separate table — they are discovered
per-package via the SMELT v2 maintained-package endpoint.

An IBS track may have one operational `TrackReleaseCheckpoint`, which stores
the expanded IBS source state last successfully examined for that exact track.
The checkpoint is not exposed in Ticket/package responses, does not create a
Ticket audit event, and does not update the track's `updated_at`. See
`ibs-track-release-detection.md` and `docs/data-model.md`.

### TicketPackageProduct

Records the eligibility and release confirmation of a source package for
a specific product, within the context of a ticket and track.
Affectedness is determined exclusively at the track level (see
[Axis 1](#axis-1-affectedness-per-track)). Products track only
eligibility and delivery confirmation.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK | Internal identifier |
| `ticket_package_track_id` | UUID | FK(ticket_package_track.id), NOT NULL | Parent track record |
| `product_id` | UUID | FK(product.id), NOT NULL | Related product |
| `eligible` | BOOLEAN | NOT NULL, DEFAULT true | Effective eligibility |
| `is_eligible_override` | BOOLEAN | NOT NULL, DEFAULT false | True if VA has manually set the eligibility |
| `released_at` | TIMESTAMPTZ | nullable | Authoritative stable security advisory-issued time in UTC; NULL until Product release detection confirms a match |
| `deleted_at` | TIMESTAMPTZ | nullable | Direct manual-exclusion timestamp. NULL = not directly excluded |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Record creation timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT | Record update timestamp |

**Unique constraint**: `(ticket_package_track_id, product_id)`

### Enums

See `docs/data-model.md` for the full definitions of `PackageStatus`,
`DeliveryStatus`, and `WorkflowType` enums (values and descriptions).
The semantic meaning of each value in the context of package tracking is
described in [Three Orthogonal Dimensions](#three-orthogonal-dimensions)
below.

---

## Three Orthogonal Dimensions

The package tracking model separates three independent dimensions:

### Axis 1: Affectedness (per track)

Property of the source code relative to the CVE. Determined by a user with
`manage_packages` during analysis, by an administrator with
`admin_ticket_ops` for a forced `FIXED` result, or automatically by track
release detection within the transition matrix below.
Affectedness depends only on whether the source code contains the
vulnerability — it is independent of CVSS thresholds, product
lifecycle phase, and delivery pipeline state.

| State | Meaning |
|-------|---------|
| `ANALYSIS` | Not yet determined |
| `AFFECTED` | Code is vulnerable, fix needed |
| `NOT_AFFECTED` | Code was never vulnerable to this CVE |
| `FIXED` | Code was vulnerable, fix has been applied |
| `WONT_FIX` | Code is vulnerable, decision not to fix |

**Status classification**: statuses are classified as either *final* or
*non-final*. A final status indicates that no further work is expected on
the track for this ticket. A non-final status indicates that the track
still requires attention (analysis pending or fix in progress).

- **Final statuses**: `NOT_AFFECTED`, `FIXED`, `WONT_FIX`
- **Non-final statuses**: `ANALYSIS`, `AFFECTED`

Other specifications that reference "final status" or "non-final status"
use this classification as defined here.

Affectedness is set at the **track level** under the caller-capability and
system-authority matrix below. Products do not have their own affectedness
status — they inherit the track's affectedness implicitly through the
hierarchy.

### Axis 2: Eligibility (per product only)

Property of the product relative to the CVE. Determined purely by CVSS
score vs. product threshold and product lifecycle phase. Eligibility
does not logically depend on whether the code is vulnerable — it
answers "does this product meet the criteria for receiving a fix?"
regardless of the current affectedness status.

| Eligible | Meaning |
|----------|---------|
| `true` | Product meets the CVSS threshold and lifecycle criteria for receiving the update |
| `false` | Product does not meet the criteria (CVSS below threshold or Reactive Support phase) |

Eligibility is evaluated for all products regardless of affectedness
status. It represents whether the product meets the CVSS threshold and
lifecycle criteria for receiving a fix.

The database default is `true` (conservative toward fix delivery — a
missing calculation results in a visible product rather than a silently
hidden one, consistent with the CVSS 10.0 fallback principle). If
eligibility calculation is skipped due to a bug, falsely-eligible
products block ticket resolution (the Resolved gate requires
`released_at IS NOT NULL` for all `eligible = true` products under
FIXED tracks). This is the intended safety net — blocked resolution is
visible and correctable; silent omission of eligible products is not.

**Eligibility rules** (evaluated in order for one Product occurrence):

1. **Preserve a manual override**: when `is_eligible_override = true`, retain
   the persisted `eligible` value. Automatic workflows skip the occurrence
   without changing either field or creating an eligibility event.
2. **Apply the Reactive Support rule to automatic records**: when the Product
   is currently in the `reactive_support` lifecycle phase, set
   `eligible = false` regardless of CVSS score. A `NULL` lifecycle phase means
   that lifecycle is unavailable; it does not activate this rule and does not
   otherwise force either eligibility value.
3. **Resolve the threshold**: read `Product.cvss_threshold`, synchronized from
   AIMAAS. `NULL` means an implicit threshold of `0.0`.
4. **Resolve the eligibility score** through the Eligibility Score Resolution
   in `docs/features/tickets/cvss-scoring.md`. Only the canonical SUSE
   assessment of the system-wide default CVSS version is used:
   - when that assessment exists, use its score;
   - otherwise use **10.0**, including when the Ticket has no CVE.
5. **Compare**: set `eligible = false` when the score is below the threshold;
   otherwise set `eligible = true`.

The CVE-less fallback is a package eligibility input only. It does not make
CVSS assessments, CVSS synchronization, or CVSS API operations applicable to a
Ticket without a CVE.

The complete automatic evaluator takes only the current override marker,
lifecycle phase, Product threshold, and Eligibility Score Resolution as inputs.
Ticket status, affectedness, delivery, Product release state, EOL, and direct or
effective manual exclusion are not formula inputs. EOL and exclusion affect
derived actionability and meet eligibility only at Ticket gates. Every creation,
override-clear, threshold, lifecycle, reactivation, CVSS, and default-version
workflow MUST use one shared pure service-layer implementation of these ordered
rules rather than copying the formula. Its concrete function name and module are
implementation choices; it performs no database access, mutation, audit, or
I/O and raises no domain exception for valid typed inputs.

**Important**: the CVSS version used for threshold comparison MUST always
be resolved from the system-wide default CVSS version configuration —
never hardcoded. See `docs/features/tickets/cvss-scoring.md` and
`docs/features/platform/system-settings.md`.

**Override model**: the VA can override eligibility on individual Products by
setting `is_eligible_override = true`. Rule 1 above is authoritative for every
automatic workflow.

### Axis 3: Delivery and Release Observation

Factual observation of the fix's progress through the SUSE maintenance
pipeline (request-action/incident provenance at the track level,
`updateinfo.xml` advisory detection at the product level). Delivery tracking
records what Sentinel has established from IBS evidence; it is independent of
whether the code is vulnerable (affectedness) or whether the product meets
threshold criteria (eligibility).

This axis has two distinct persisted facts: track `delivery_status` records
maintenance-pipeline progress, while Product `released_at` confirms repository
publication for one Product occurrence. Neither fact derives the other, and
neither changes affectedness or eligibility. Only Product `released_at`, not
track `delivery_status`, participates in the Resolved gate.

| State | Meaning | Condition |
|-------|---------|-----------|
| `PENDING` | Relevant delivery progress has not been established | Initial state, or a complete non-stale reconciliation found no relevant current progress. This does not prove that no SR exists or that synchronization succeeded |
| `IN_PROGRESS` | Relevant fix delivery is authoritatively in progress | Complete evidence establishes a relevant current SR or effective incident chain, but does not prove that an accepted RR released the effective SR contents |
| `RELEASED` | Release to the track is proven | Exact accepted-RR and source/target provenance proves that the RR released the effective SR contents; this state is irreversible |

The delivery status is updated only by the shared authoritative IBS request
reconciliation. IBS RabbitMQ events, package-add catch-up, Ticket-reactivation
catch-up, and the daily `SyncIbsRequests` fetcher all invoke that same
reconciliation and cannot establish different results.

The two axes are independent — see
[Affectedness-Delivery Independence](#affectedness-delivery-independence).

#### Delivery Relevance Indicator

The `delivery_status` column on `TicketPackageTrack` always contains the
real system value (`PENDING`, `IN_PROGRESS`, or `RELEASED`). However,
`PENDING` is the system default and carries no operational meaning when
the track's affectedness status does not imply that a fix is expected.
For example, a track with `NOT_AFFECTED + PENDING` simply means no relevant
delivery progress has been established; it does not prove whether an SR exists.
The `PENDING` value is noise in this affectedness context, not a delivery
signal.

To help API consumers distinguish meaningful delivery states from default
noise, API responses for tracks include a computed boolean field
`delivery_relevant`:

```python
delivery_relevant = (
    track.status in ("ANALYSIS", "AFFECTED")
    or track.delivery_status != "PENDING"
)
```

Rules:

- `delivery_relevant = true`: the delivery status has operational
  meaning. Either the track is still being analyzed / is affected (so
  delivery progress matters), or authoritative evidence has moved the delivery
  state beyond the default.
- `delivery_relevant = false`: the delivery status is the system default
  (`PENDING`) on a track with a final affectedness status
  (`NOT_AFFECTED`, `FIXED`, `WONT_FIX`). Consumers SHOULD treat the delivery
  status as noise and not display or act on it; `PENDING` does not prove the
  absence of delivery activity.

When `delivery_relevant = true` **and** the affectedness is
`NOT_AFFECTED` or `WONT_FIX`, the combination is anomalous: it signals
that delivery activity exists for a track that was assessed as not
requiring a fix. `FIXED` with delivery activity (`IN_PROGRESS` or
`RELEASED`) is not anomalous — it is the expected progression of a fix.
See [Anomaly Detection](#anomaly-detection-future-review-queue).

**Important**: `delivery_relevant` is a **computed API field only** — it
is not a database column. It is derived from `status` and
`delivery_status` at serialization time in the Pydantic response schema.
The database schema is not affected.

**OpenAPI documentation**: since external consumers will discover
`delivery_relevant` and `delivery_status` through the generated OpenAPI
documentation (not through internal specs), the Pydantic response schema
MUST include `Field(description=...)` on both fields that conveys the
consumer-facing guidance:

- `delivery_status`: explain that `PENDING` is the system default and
  does not imply a fix is expected, prove the absence of an SR, or establish
  synchronization success; reference `delivery_relevant` for operational
  significance
- `delivery_relevant`: explain that when `false`, consumers should not
  display `delivery_status` or make decisions based on it

#### SUSE Maintenance Workflow Mapping

The delivery pipeline maps to the SUSE maintenance process as follows:

```
VA sets track to AFFECTED
        |
        v
Maintainer prepares fix
        |
        v
Relevant SR/current incident proven      --> delivery: IN_PROGRESS
        |
        v
Incident (SUSE:Maintenance:XXXXX)
    - builds package
    - runs QA tests
    - specifies eligible products
        |
        v
RR (Release Request) created
        |
        v
RR acceptance and exact source/target provenance proven
                                          --> delivery: RELEASED
        |
        v
Fix evidence appears in track source     --> affectedness: FIXED (automatic, via expanded source diff)
        |
        v
Fix lands in Product repositories (updateinfo.xml) --> released_at set
```

The two axes are managed independently:
- `delivery_status` transitions to `RELEASED` only when IBS submission
  tracking proves that an accepted RR released the effective SR contents to
  the track
- `status` transitions to `FIXED` when track release detection confirms the
  Ticket CVE in the expanded codestream source diff

RR acceptance by itself is insufficient delivery proof. Sentinel validates the
effective SR, accepted RR, and target source-history provenance independently
from track affectedness detection and Product publication detection.

#### Product Release Confirmation

Product-level release is confirmed independently via `updateinfo.xml`:

- `detect_ibs_product_releases` traverses current Product repository
  associations first and retained historical associations as fallback.
- A completely validated stable security advisory must reference the exact
  Ticket CVE and contain an exact validated `src` or `nosrc` source-package
  entry for the occurrence.
- Matching completes independently for each `TicketPackageProduct`; one
  Product/package match never suppresses an unresolved sibling package.
- `released_at` is the earliest valid advisory-issued UTC time in the first
  successfully matching repository, not Sentinel's observation time.

Observation remains visible through the package-tree row's `updated_at` and the
`product_released` audit event's `created_at`. `released_at` is irreversible;
later retraction, correction, disappearance, or no-match does not clear or
replace a successful factual observation. See
`ibs-product-release-detection.md` for repository, integrity, resource-safety,
and concurrency rules.

Codestream/track delivery tracking and product release confirmation are
independent and complementary mechanisms. Track delivery tracks the
maintenance process. Product confirmation verifies the end result.

#### Delivery Reconciliation

`SyncIbsRequests` runs the complete state-based reconciliation daily at 02:30
UTC for every IBS track (`workflow_type = 'ibs'`) belonging to an active
Ticket, including tracks in every affectedness, delivery, exclusion, and
actionability state. It is the permanent recovery owner for missed events,
failed accelerators, request reopens, supersession, first enablement, and long
gaps while sufficient upstream evidence remains discoverable.

Each track observation is classified as complete positive, complete no-match,
incomplete, or failed under `ibs-submission-tracking.md`. Only a complete
observation may change delivery. Incomplete, failed, retention-limited,
ambiguous, or stale evidence preserves the persisted status. This
reconciliation applies only to IBS tracks. Git tracks will have their own
delivery detection and reconciliation mechanism (TBD).

---

## Affectedness-Delivery Independence

The affectedness status and the delivery status are tracked as
independent axes. Neither resets nor constrains the other. All
combinations are valid system states. The `delivery_relevant` field
indicates whether the delivery status carries operational meaning in the
context of the current affectedness — see
[Delivery Relevance Indicator](#delivery-relevance-indicator).

| Affectedness | Delivery | Relevant | Anomaly | Meaning |
|-------------|----------|----------|---------|---------|
| `ANALYSIS` | `PENDING` | Yes | | Not yet analyzed; relevant delivery progress is not established |
| `ANALYSIS` | `IN_PROGRESS` | Yes | | Relevant SR/incident progress is established before VA analysis |
| `ANALYSIS` | `RELEASED` | Yes | | Fix released before VA analyzed the track |
| `AFFECTED` | `PENDING` | Yes | | Affected, fix expected, relevant delivery progress not established |
| `AFFECTED` | `IN_PROGRESS` | Yes | | Fix in the pipeline |
| `AFFECTED` | `RELEASED` | Yes | Yes | Fix released but VA considers it insufficient — needs review |
| `NOT_AFFECTED` | `PENDING` | **No** | | Not affected; default delivery state is not meaningful and proves no negative |
| `NOT_AFFECTED` | `IN_PROGRESS` | Yes | Yes | SR in progress for unaffected code — possible confusion |
| `NOT_AFFECTED` | `RELEASED` | Yes | Yes | Fix released for unaffected code — possible confusion |
| `FIXED` | `PENDING` | **No** | | Fix confirmed via track release detection; delivery progress not established and not meaningful here |
| `FIXED` | `IN_PROGRESS` | Yes | | Fix confirmed, SR still in pipeline |
| `FIXED` | `RELEASED` | Yes | | Fix confirmed and delivered |
| `WONT_FIX` | `PENDING` | **No** | | Decided not to fix; delivery is the system default — not meaningful |
| `WONT_FIX` | `IN_PROGRESS` | Yes | Yes | SR in progress despite won't-fix decision — conflicting |
| `WONT_FIX` | `RELEASED` | Yes | Yes | Fix released despite won't-fix decision — conflicting |

### Anomaly Detection (future: Review Queue)

Anomalous combinations (marked in the table above) indicate situations
that require VA attention — a possible bug, a maintainer not following
the workflow, or an outdated VA assessment. Note that all anomalous
combinations have `delivery_relevant = true` by definition: if delivery
has moved beyond the default, it is always relevant regardless of
affectedness. Conversely, the three `delivery_relevant = false`
combinations (`NOT_AFFECTED + PENDING`, `FIXED + PENDING`,
`WONT_FIX + PENDING`) are never anomalous — they are simply the system
default without established relevant delivery progress.

These anomalous combinations are destined to be integrated into the
future **Review Queue** — a mechanism that will automatically tag
tickets presenting anomalies, making them visible to VAs for review.
The specification of the Review Queue and the tagging mechanism will be
defined in a dedicated specification.

---

## Status Behavior

All track status changes and product eligibility overrides described in
this section MUST go through the `package_service` module (see
`docs/features/packages/package-service.md`). An effective gate-relevant change
causes Ticket status re-evaluation; a true no-op does not.

### User-Attributed Status Change

For an effective authorized change:

1. Track status is set to the chosen value via `package_service`.
2. A `TicketAuditEvent` (`track_status_changed`) is created with the true
   locked old and new values.
3. Ticket status is re-evaluated via `reconcile_ticket_status()`.

If the locked track already has the requested status, the operation is a true
no-op: it does not assign the actor, create an audit event, reconcile the
Ticket, or register a post-commit effect.

There is **no codestream eligibility rollup** — the track retains its
affectedness status regardless of whether any product is eligible. The
question "is there work to do on this track?" is answered by checking
whether any actionable Product under it has `eligible = true`.

### VA Overrides Product Eligibility

1. Product `eligible` is set to the chosen value
2. `is_eligible_override` is set to `true`
3. The track status is not affected

### Automatic Transitions

| From | To | Applies to | Trigger |
|------|----|------------|---------|
| `AFFECTED` or `ANALYSIS` | `FIXED` | TicketPackageTrack | Track release detection finds qualifying canonical Ticket-CVE evidence in an expanded source diff |

Track release detection requests only `FIXED`. `ANALYSIS` and `AFFECTED` are
the only automatic source states that can change. If external I/O began while
one of those states was present but the locked state is now `NOT_AFFECTED`,
`FIXED`, or `WONT_FIX`, the request is a protected no-op. Successful source
examination may still advance the detector's checkpoint under
`ibs-track-release-detection.md`. A system request whose target is anything
other than `FIXED` is rejected, emits a sanitized warning, performs no
mutation, assignment, audit, reconciliation, or post-commit effect, and causes
the calling workflow's unit to fail. The caller consumes the `rejected` service
result and routes it through its documented per-item failure handling; the
service result itself does not prescribe an exception type.

**Delivery status transitions** (system-managed):

| From | To | Trigger |
|------|----|---------|
| `PENDING` | `IN_PROGRESS` | Complete authoritative evidence establishes a relevant `new` or `review` SR, effective accepted SR/incident chain, or complete relevant supersession successor |
| `IN_PROGRESS` | `RELEASED` | Exact accepted-RR and source/target provenance proves release of the effective SR contents to the track |
| `IN_PROGRESS` | `PENDING` | Complete authoritative reconciliation establishes no relevant current delivery progress, and the negative observation passes the stale-result guard |

When a complete observation proves `RELEASED` while the persisted value is
`PENDING`, the same transaction applies `PENDING → IN_PROGRESS → RELEASED`.
No intermediate state is externally committed. An unchanged value is an
idempotent no-op.

#### Delivery status regression

`delivery_status` can regress from `IN_PROGRESS` to `PENDING` only when the
shared reconciliation completely exhausts every required discovery root and
artifact and establishes that no relevant current SR, effective incident, or
complete relevant supersession successor remains. Exact request states are
evaluated under `ibs-submission-tracking.md`: `declined`, `revoked`, and
`deleted` do not establish current progress; a `superseded` request establishes
progress only through a completely traversed relevant successor chain.

A request-state change alone never proves the negative. A required detail 404,
missing or retained-away history, search truncation, malformed data, ambiguous
provenance, or any other incomplete or failed observation preserves
`IN_PROGRESS`. A complete negative also preserves `IN_PROGRESS` when relevant
request/action evidence changed after the observation began or the persisted
delivery value changed during external I/O.

#### RELEASED is irreversible

Once `delivery_status` reaches `RELEASED`, it cannot regress. The state records
an accepted RR whose exact source and target provenance passed the complete
proof contract at observation time; later disappearance or incomplete evidence
does not reverse that accepted factual observation.

These transitions are derived by the shared authoritative reconciliation,
invoked by IBS RabbitMQ wake-ups and the `SyncIbsRequests` scheduled or targeted
catch-up paths. See
`docs/features/packages/ibs-submission-tracking.md`.

### Manual Transitions

Affectedness transition authority is exhaustive:

In this matrix, a user-attributed caller supplies a non-null `acting_user_id`;
a system caller supplies `None`.

| Caller authority | Requested target | Allowed source states | Outcome |
|---|---|---|---|
| User-attributed caller with `manage_packages` | `ANALYSIS`, `AFFECTED`, `NOT_AFFECTED`, or `WONT_FIX` | Any affectedness state | Effective change, or true no-op when unchanged |
| User-attributed caller with `manage_packages` but without `admin_ticket_ops` | `FIXED` | Any | Authorization rejection before Ticket accessibility |
| User-attributed caller with `admin_ticket_ops` | `FIXED` | Any affectedness state | Forced effective change, or true no-op when already `FIXED`; `manage_packages` is not additionally required |
| User-attributed caller with only `admin_ticket_ops` | Any non-`FIXED` target | Any | Authorization rejection before Ticket accessibility |
| System caller | `FIXED` | `ANALYSIS` or `AFFECTED` | Effective automatic change |
| System caller | `FIXED` | `NOT_AFFECTED`, `FIXED`, or `WONT_FIX` | Protected no-op |
| System caller | Any non-`FIXED` target | Any | Rejected workflow unit with warning and no effects |

The capability union applies normally: a user holding both capabilities uses
`admin_ticket_ops` for `FIXED` and `manage_packages` for every other target.
User-attributed callers cannot change `delivery_status`; it is system-managed.

---

## Exclusion and Actionability

### Manual Exclusion Markers

An authenticated user whose caller has verified `manage_packages` can
soft-delete packages, tracks, or Products to exclude them from the Ticket. A
non-null `deleted_at` is a durable record of that user's explicit decision at
that exact scope:

- `deleted_at IS NOT NULL` means directly excluded;
- `deleted_at IS NULL` means not directly excluded.

The acting user is recorded in the corresponding `TicketAuditEvent`, not on
the package-tree record. Automated workflows MUST NOT set or clear any package,
track, or Product `deleted_at` field.

Manual exclusion is hierarchical. Only the record targeted by the acting user
is modified:

- excluding a package sets only `TicketPackage.deleted_at`;
- excluding a track sets only `TicketPackageTrack.deleted_at`;
- excluding a Product sets only `TicketPackageProduct.deleted_at`.

A descendant is **effectively excluded** when its own marker or any ancestor
marker is non-null:

| Record type | Effectively excluded when |
|-------------|------------------------------|
| Package | `package.deleted_at IS NOT NULL` |
| Track | `package.deleted_at IS NOT NULL` or `track.deleted_at IS NOT NULL` |
| Product | `package.deleted_at IS NOT NULL`, `track.deleted_at IS NOT NULL`, or `product.deleted_at IS NOT NULL` |

There is no automatic orphan soft-deletion. A parent with no participating
descendants retains `deleted_at = NULL` unless an authorized user explicitly
excludes that parent.

The exclusion guard inspects only the selected record's direct marker. An
exclude succeeds whenever that marker is NULL, including when an ancestor is
already excluded, every descendant is excluded or EOL, or the target is
already non-actionable for another reason. It sets only the selected marker.
The operation therefore records an independent user intention even when the
target was already effectively excluded and its current effective exclusion
does not change. Descendant markers likewise do not prevent excluding a
package or track.

For one Product occurrence, all eight direct-marker combinations have the
following deterministic meaning before applying lifecycle:

| Package marker | Track marker | Product marker | Product effectively excluded | Product reason |
|---|---|---|---|---|
| clear | clear | clear | No | `NULL` |
| clear | clear | set | Yes | `product_excluded` |
| clear | set | clear | Yes | `track_excluded` |
| clear | set | set | Yes | `track_excluded` |
| set | clear | clear | Yes | `package_excluded` |
| set | clear | set | Yes | `package_excluded` |
| set | set | clear | Yes | `package_excluded` |
| set | set | set | Yes | `package_excluded` |

If the Product is EOL, each row keeps the same marker result and reason when a
manual marker applies; only the all-clear row changes to non-actionable with
reason `eol`. Thus reason precedence is package, then track, then Product, then
EOL. Track and package actionability are then derived from whether any child is
actionable; their `no_actionable_products` and `no_actionable_tracks` reasons
never create or clear a marker.

### Derived Actionability

`actionable` is a derived property, not a database column. It is evaluated
from current package-tree markers, Product lifecycle data, and one UTC
`evaluation_date` captured for the complete request or transaction:

```text
product.actionable =
    package.deleted_at IS NULL
    AND track.deleted_at IS NULL
    AND product.deleted_at IS NULL
    AND (
        lifecycle_phase(catalog_product, evaluation_date) IS NULL
        OR lifecycle_phase(catalog_product, evaluation_date) != eol
    )

track.actionable =
    package.deleted_at IS NULL
    AND track.deleted_at IS NULL
    AND EXISTS(product where product.actionable)

package.actionable =
    package.deleted_at IS NULL
    AND EXISTS(track where track.actionable)
```

A `NULL` lifecycle phase means lifecycle is unavailable and does not make a
Product non-actionable. Product lifecycle evaluation is defined in
`product-catalog.md` (Lifecycle Evaluator).

The service layer MUST expose reusable SQL/SQLAlchemy expressions implementing
these predicates for filters, aggregate counts, and Ticket gates. The pure
lifecycle evaluator and SQL lifecycle expression MUST produce identical
results for the same dates and `evaluation_date`. Implementations MUST NOT
persist `lifecycle_phase` or `actionable` as current-state columns.

Each package-tree response includes `actionable` and a nullable
`non_actionable_reason`. The reason uses the first applicable value in this
ordered list, which makes the result deterministic when multiple conditions
apply:

| Level | Ordered `non_actionable_reason` values |
|-------|----------------------------------------|
| Package | `package_excluded`, `no_actionable_tracks` |
| Track | `package_excluded`, `track_excluded`, `no_actionable_products` |
| Product | `package_excluded`, `track_excluded`, `product_excluded`, `eol` |

An actionable record has `non_actionable_reason = NULL`. Parent reasons
describe the absence of actionable descendants without changing any parent
row. Consumers MUST use these fields rather than infer current participation
from `deleted_at` alone.

A mutating request that changes package-tree participation or returns
package-tree actionability data resolves one UTC `evaluation_date` for its
complete workflow. The direct mutation, Ticket gate reconciliation,
locked-current result projection, and API response reuse that date; a response
serializer MUST NOT recapture the date after the mutation.
Read-only requests independently capture one date for their complete response.
Consequently, crossing midnight UTC cannot make one mutation reconcile against
one date and return actionability computed against another.

### Gate Participation

Actionability is an observation-point combination of manual exclusion and
lifecycle; it does not modify affectedness, eligibility, or delivery.

- The Analyzed gate's minimum-presence condition requires at least one track
  that is not effectively manually excluded. This proves that package analysis data
  exists even when every Product is currently EOL.
- Only actionable tracks participate in the undecided-affectedness check and
  the Resolved gate.
- Only actionable Products participate in Product-level resolution
  conditions.
- Therefore a Ticket with at least one manually included track but no actionable
  tracks can be Resolved once the non-lifecycle Analyzed requirements are met.
  If a Product later leaves EOL, its track becomes actionable and normal gate
  reconciliation may regress the Ticket.

### Continued Updates

Directly or effectively manually excluded records and EOL Products continue to
receive locally derived eligibility and lifecycle reconciliation within each
owning workflow's Ticket-status scope. Exclusion and EOL never suppress a
permitted eligibility update. The CVSS state/caller matrix in
`ticket-mutations.md` maintains CVSS- and default-version-originated Product
updates immediately throughout the gate zone, including `Resolved`. It defers
them only in the `Ignored` and `Duplicated` manual zone; explicit manual-zone
exit converges current automatic eligibility before its final gate result. External IBS
delivery updates and release observations remain limited to active Tickets
(`New`, `Analysis`, or `Analyzed`).

### Restore

Restore clears `deleted_at` only on the directly excluded record selected by
the acting user. It never modifies descendants and is permitted while an ancestor is
excluded or while the restored record remains non-actionable for another
reason. No child-existence or actionability precondition applies.

For example, restoring a Product while its track remains excluded clears the
Product's direct marker but leaves it effectively excluded through the
track. Restoring a track while all its Products are EOL clears the manual
marker but leaves the track non-actionable until at least one Product becomes
actionable. Each effective restore creates one acting-user-attributed audit event and
reconciles the Ticket once.

Entering or leaving EOL never sets or clears a direct marker, never invokes
restore, and never creates an exclusion or restoration event. A Product that
leaves EOL becomes actionable immediately when all three direct markers are
clear; its ancestors derive their current actionability from the resulting
descendant set.

### Interaction with add_package_to_ticket

For internal re-resolution callers, `add_package_to_ticket` proceeds normally
regardless of whether the `TicketPackage` is soft-deleted. It queries SMELT, and
creates any missing `TicketPackageTrack` and `TicketPackageProduct`
records. Existing records (active or soft-deleted) are skipped.
It also performs the normal additive maintainership acquisition for that
package occurrence; any new association remains ineffective while the package
is excluded.

New records are created with `deleted_at = NULL`. If the parent package or
track is manually excluded, these records are effectively excluded through the
hierarchy. If their Product is EOL, they are independently non-actionable.

The public `POST /api/v1/tickets/{ticket_id}/packages` call asks the package
service to apply the public excluded-package guard. The service owns the
state-dependent query and returns `409 PACKAGE_ALREADY_EXCLUDED` when the
existing package occurrence is directly excluded. Ticket reactivation invokes
the documented internal re-resolution mode, which may complete descendants and
maintainership without restoring the package. CVE ingestion and Product catalog
backfill omit existing soft-deleted package markers during their owning
candidate selection and therefore do not need that bypass. API handlers do not
query package-tree state or decide this business condition. Track release
detection never calls this function because it reconciles only tracks that
already exist.

### Ticket Events for Exclusion

A single acting-user-attributed `TicketAuditEvent` is created for each effective
exclusion or restore operation, only for the directly affected record. Child
records that become effectively excluded through the hierarchy do not
generate events. Derived EOL/actionability changes do not create exclusion or
restore events because they do not mutate package-tree records.

| Action | `event_type` | `user_id` | Details recorded |
|--------|-------------|-----------|------------------|
| Authorized user soft-deletes a package | `package_excluded` | Acting user | `package_name` |
| Authorized user soft-deletes a track | `track_excluded` | Acting user | `track_name`, `package_name` |
| Authorized user soft-deletes a product | `product_excluded` | Acting user | `track_name`, `package_name`, event-time Product name and CPE |
| Authorized user restores a package | `package_restored` | Acting user | `package_name` |
| Authorized user restores a track | `track_restored` | Acting user | `track_name`, `package_name` |
| Authorized user restores a product | `product_restored` | Acting user | `track_name`, `package_name`, event-time Product name and CPE |

---

## Package Eligibility

Eligibility determines whether a product will receive a security update
for a given CVE. The eligibility computation rules, default value
rationale, and override model are defined in
[Axis 2: Eligibility](#axis-2-eligibility-per-product-only).

### Override Model

Product-level eligibility has an override mechanism:

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `eligible` | bool | calculated | Effective eligibility |
| `is_eligible_override` | bool | false | VA has manually set the eligibility |

When `is_eligible_override = false`, the system maintains `eligible`
automatically via CVSS threshold + lifecycle phase calculation. When
`is_eligible_override = true`, automatic recalculation skips the
product.

Standalone overrides, record creation, Product-threshold/lifecycle
recalculation, and synchronous manual-zone-exit convergence go through
`package_service`. Product-originated automatic recalculation groups all
matching records by Ticket, locks and processes one Ticket transaction at a
time, and calls `reconcile_ticket_status()` once only when at least one value
changed.

The higher-level `ticket_service` owns each manual-zone exit workflow. While it
retains the Ticket lock, it invokes the package-owned synchronous convergence
boundary and then the `ticket_mutations` gate-reconciliation primitive. This
composition does not make either lower service import `ticket_service` and does
not transfer Product mutation ownership.

The sole ownership exception is the atomic CVSS chain in `ticket_mutations`.
That chain may update system-managed `TicketPackageProduct.eligible` inline for
an associated Ticket so assessment, unified severity, eligibility, audit, and
one final Ticket reconciliation commit or roll back together. It MUST use the
same pure evaluator defined above, MUST NOT import `package_service`, and MUST
NOT set or clear an override or perform any other package mutation.

Clearing an existing override always returns the Product occurrence to
automatic management and recalculates it from current inputs. The clear is an
effective metadata mutation even when the calculated boolean equals the
persisted `eligible` value; its audit event then truthfully has equal
`old_value` and `new_value` and records `override_action = cleared`. Subsequent
automatic workflows may update the occurrence normally.

---

## Adding Packages to a Ticket

### Centralized Function: `add_package_to_ticket`

All package additions — regardless of the trigger — MUST go through a
single centralized service function. This function is the only place where
SMELT is queried to resolve tracks/Products and package maintainership, and
where the corresponding package-tree and maintainer records are created.

**Signature** (conceptual):

```python
add_package_to_ticket(ticket_id, package_name) -> AddPackageResult
```

**Behavior**:

1. Query SMELT and resolve Products as specified in
   [SMELT Query for Package Resolution](#smelt-query-for-package-resolution):
   external I/O, envelope validation, catalog readiness check, CPE matching,
   synthetic channel/compose deduplication, unsupported-process filtering, and
   `workflow_type` determination from `codestream.maintenance_process_type`.
   If no Product is resolved across the complete response, reject the
   operation without database writes.
2. After successful maintained-package target resolution and before acquiring
   the Ticket lock, query the SMELT maintainership endpoint on every invocation.
   A valid response supplies the globally deduplicated lowercase individual
   email set. Any maintainership-only error supplies an empty set, emits the
   specified PII-free warning, and does not block package-tree mutation. See
   `docs/features/packages/package-maintainership.md`.
3. Delegate to `package_service` under the Ticket lock. Create or find the
   `TicketPackage`, then create missing tracks and Products from the validated
   targets and missing `TicketPackageMaintainer` rows for exact matching
   currently active Users. Package-tree and maintainer audit events are atomic.
   Existing records and associations are never removed or rewritten.
   Association-only mutation neither auto-assigns nor reconciles the Ticket.
4. If at least one new `TicketPackageTrack` with `workflow_type = ibs` was
   created, register one best-effort post-commit invocation of the existing
   generic `run_catch_up("sync_ibs_requests", ticket_id)` mechanism. The
   catch-up uses the complete shared reconciliation for every IBS track now
   belonging to the Ticket. This effect runs after commit. Creating only the
   package marker, only Products, only Git tracks, or only maintainer
   associations registers no request catch-up. The daily complete
   `sync_ibs_requests` fetcher remains the permanent recovery owner; package
   addition introduces no dedicated submission discovery or correlation task.
5. Return an `AddPackageResult` containing:
   - `tracks_created`, `tracks_skipped`, `products_created`,
     `products_skipped`: counts of records created vs. skipped.
   - The identities and persisted workflow types of newly created tracks, or
     an equivalent semantic signal sufficient for the workflow owner to know
     whether at least one IBS track was created. The concrete in-memory
     representation is an implementation choice.

For the public endpoint, failures and outcomes have this strict precedence:

1. authentication, `manage_packages`, and Ticket accessibility;
2. maintained-package transport, JSON, JSend, HTTP-pairing, and applicable
   structural response validation;
3. Product catalog readiness;
4. package-not-found classification;
5. package-target resolution;
6. best-effort maintainership acquisition;
7. locked Ticket existence and operability;
8. the existing package occurrence's direct exclusion marker;
9. package-tree no-op, maintainer-only mutation, or effective package-tree
   mutation.

Accordingly, `PACKAGE_ALREADY_EXCLUDED` is decided only after every blocking
external package-target gate and the best-effort maintainership request. The
request may obtain valid maintainer emails, but the locked exclusion guard
rejects before any package-tree or maintainer association is persisted.

`package_service` handles idempotency (skipping existing records, including
soft-deleted), initial status determination, eligibility logic, and additive
maintainer association internally. A fully no-op package-tree invocation can
still add maintainers while all public creation counts remain zero. See
`docs/features/packages/package-service.md`.

New records are created with `deleted_at = NULL`. A new descendant under a
manually excluded parent is effectively excluded through the hierarchy, and a new
EOL Product is non-actionable without any mutation. See
[Exclusion and Actionability](#exclusion-and-actionability).

When a Product is added beneath an existing track, the track retains its
current affectedness and delivery statuses. The Product therefore inherits
the track's affectedness through the hierarchy. Its eligibility is calculated
independently at creation time, and its Product-level `released_at` starts as
`NULL`.

**Idempotency**: the function is safe to call multiple times for the
same package. If SMELT adds new tracks or products for a package after
the initial addition, calling the function again will add only the new
records. Existing records (active or soft-deleted) are skipped. The SMELT and
current-catalog validation gates run before this no-op determination, so a
repeat call can still fail with `PACKAGE_NOT_FOUND_IN_SMELT`,
`PACKAGE_TARGETS_UNRESOLVED`, `PRODUCT_CATALOG_NOT_READY`, or
`SMELT_UNAVAILABLE`.

### Triggers

The following scenarios invoke `add_package_to_ticket`:

1. **Automatic (CVE ingestion)**: when a CVE is ingested, Sentinel
   resolves package names from the CVE data (NVD CPE package candidates
   selected by the NVD ingestion contract, CNA/ADP CPE strings, CNA/ADP
   vendor:product pairs, or pre-resolved packages). For each resolved
   package name,
   `add_package_to_ticket` is called. See
   `docs/features/tickets/cve-service.md` (Phase 2).
2. **Manual**: an authorized user manually adds a package by name via the UI.
   `add_package_to_ticket` is called with the entered name.
3. **Restore from soft-deletion**: restoring a package, track, or
   product clears its `deleted_at` only. New tracks/products that
   appeared on SMELT since the deletion are picked up by subsequent
   calls to `add_package_to_ticket` (for example CVE ingestion or Product
   catalog backfill) — no explicit call is needed at restore time.
4. **Product catalog backfill**: after a successful SMELT Product catalog
   sync makes at least one Product newly current, a system workflow calls
   `add_package_to_ticket` for each active-Ticket package whose package marker
   is not soft-deleted. Lifecycle actionability does not filter this recovery
   scan because a currently EOL Product can later become actionable without a
   new catalog association. See `product-catalog.md` (Product Catalog
   Backfill).
5. **Ticket reactivation**: after an inactive Ticket enters an active status,
   the package reactivation workflow calls `add_package_to_ticket` once for
   every persisted `TicketPackage.package_name`, including package markers that
   are soft-deleted. Existing exclusion markers are preserved; missing tracks
   and Products are created but no record is restored. The complete package
   reactivation contract is defined in
   [Reactivation and Convergence](#reactivation-and-convergence).

### Package Management Constraints

An authorized user manages packages at the **package level only**:

- The user can **add** packages to a ticket.
- The user can **soft-delete** entire packages, individual tracks, or
  individual Products from a ticket (see
  [Exclusion and Actionability](#exclusion-and-actionability)).
- The user **cannot** add individual tracks or products — these are
  determined exclusively by SMELT when a package is added via
  `add_package_to_ticket`.
- The user **can** change the affectedness status of individual tracks
  (via the status dropdown) and override the eligibility of individual
  products.

### Removing a Package from a Ticket

When an authorized user removes a package from a ticket, Sentinel performs a
**soft-deletion** (see
[Exclusion and Actionability](#exclusion-and-actionability)): `deleted_at`
is set on the `TicketPackage` record only. Child `TicketPackageTrack`
and `TicketPackageProduct` records are not modified — they become
effectively excluded via the hierarchy.

### SMELT Query for Package Resolution

When `add_package_to_ticket` resolves a package, it calls the SMELT v2
maintained-package endpoint:

```
experimental/v2/maintained/{url_encode(name)}?include_reactive_ltss=true
```

The package name is URL-encoded before interpolation into the path segment.
This package-scoped operation is distinct from the paginated
`experimental/v2/maintained/` sweep operation. The response is a single
non-paginated JSend envelope.

**Envelope and error handling**:

- A successful response has HTTP status 200 and body
  `{"status": "success", "data": [...]}` where `data` is a non-empty array
  of codestream entries.
- A successful response with an empty `data` array (`{"status": "success",
  "data": []}`) is treated as package-not-found. This covers packages known
  to SMELT but currently maintained in zero codestreams.
- A package-not-found response arrives with HTTP status 404 and body
  `{"status": "error", "data": "Package X not found"}`.
- Both package-not-found cases map to `PackageNotFoundInSmeltError`.
- A connection failure, timeout, proxy error, or remote-protocol error after
  the shared transport retries are exhausted maps to `SmeltUnavailableError`.
  No HTTP response exists to inspect in these cases.
- Sentinel MUST parse the JSON body regardless of HTTP status and check the
  JSend `status` field before applying the catch-all rule below. A 404 with
  a valid `status: "error"` body is a package-not-found, not an availability
  failure.
- Sentinel recognizes only the JSend `status` values `success` and `error` in
  this endpoint's responses. Any other value — including JSend `fail`, which
  this experimental endpoint does not document a use for — is unrecognized.
- Any non-200 response other than the valid 404 package-not-found response,
  any body that cannot be parsed as JSON, any unrecognized `status` field, or
  any entry-validation failure maps to `SmeltUnavailableError`.
- Live verification confirmed that the package-name path segment is
  case-sensitive: canonical `kernel-default` returned results, while case
  variants returned the error envelope. Sentinel does not normalize
  package-name case before constructing the request.

**Entry validation**:

- The `include_reactive_ltss=true` parameter MUST always be included to
  ensure Products in Reactive LTSS are returned.
- Each entry in `data` must have a `codestream` object with a non-empty
  string `name` that fits the persisted track-reference column length and a
  non-null string `maintenance_process_type`. Codestream names must be unique
  across the grouped response.
- `maintenance_process_type` must be one of the declared SMELT values `SLFO`,
  `SLFO_IBS`, or `SLE_15`. A missing, null, non-string, or unknown value, or a
  repeated codestream name, rejects the complete response and raises
  `SmeltUnavailableError`.
- A supported `SLFO` or `SLE_15` entry must have a non-empty `targets` array.
  Each target must have `product.cpe` as a non-empty string and
  `product_definition.type` with a value of `"channel"` or `"compose"`.
  An invalid supported entry or target rejects the complete response and
  raises `SmeltUnavailableError`; targets are never individually skipped for
  structural validation failures.
- `SLFO_IBS` is a known but unsupported maintenance process. Sentinel skips
  the complete codestream without validating or consuming its targets and
  emits one WARNING-level
  `package_codestream_maintenance_process_unsupported` event containing
  `package_name`, `codestream`, and `maintenance_process_type`. Processing
  continues with supported codestreams.
- `product.friendly_name` is used only for logging and warning messages.
  If absent or empty, the `product.cpe` value is used as a fallback in
  log messages. A missing `friendly_name` does not reject the response.

**Consumed fields** (minimal integration):

| Field | Purpose |
|-------|---------|
| `data[].codestream.name` | Track reference (`TicketPackageTrack.reference`) |
| `data[].codestream.maintenance_process_type` | Authoritative track workflow: `SLFO` → `git`, `SLE_15` → `ibs`; known `SLFO_IBS` entries are unsupported and skipped |
| `data[].targets[].product.cpe` | Product match key against local `Product.cpe` |
| `data[].targets[].product_definition.type` | Validated as `channel` or `compose`; Product-definition provenance used for synthetic same-CPE channel/compose deduplication |
| `data[].targets[].product.friendly_name` | Logging and warning messages |

All other response fields (`codestream.url`, `product.id`,
`product.support_status`, `product_definition.name`, `product_definition.url`,
`binary_packages`, `repository`) are not consumed by Sentinel.

**Deduplication**:

The v2 endpoint aggregates results from both IBS channel records and
Git/SLFO compose records. During a transitional period, some Products may
appear under two different codestreams: once via a synthetic channel file
and once via the real compose resolution. When the same Product CPE appears
in targets under both a `channel` and `compose` entry, the `channel` entry
for that Product is discarded and only the `compose` entry is retained. This
deduplication is a no-op once the transitional synthetic channel files are
removed by SMELT.

**Processing**:

1. Retrieve the response. If transport fails after shared retries, or the
   response does not have a valid JSON/JSend envelope, expected HTTP/status
   pairing, and applicable structural shape, raise `SmeltUnavailableError`.
   For a non-empty successful response, this includes validating every
   codestream identity and maintenance-process value, skipping known
   unsupported `SLFO_IBS` entries as specified above, and validating all
   targets of supported codestreams. No local Product lookup occurs yet.
2. Require a ready Product catalog as defined in `product-catalog.md`. If no
   complete Product snapshot has committed, raise
   `ProductCatalogNotReadyError` before interpreting the response content.
   Readiness failure takes precedence over both package-not-found and
   targets-unresolved outcomes.
3. If HTTP status is 404 with a valid `status = "error"` envelope, or status
   is 200 with `status = "success"` and an empty `data` array, raise
   `PackageNotFoundInSmeltError`. Any other combination of HTTP status and
   JSend `status` — including HTTP 200 with `status = "error"` — raises
   `SmeltUnavailableError`.
4. Map each structurally validated supported codestream to one `workflow_type`:
   `SLFO` maps to `git`
   and `SLE_15` maps to `ibs`.
5. Collect all `(codestream.name, workflow_type, product.cpe,
   product_definition.type)` records from supported entries. Apply the
   deduplication rule above.
6. For each remaining record:
   a. Look up the Product by exact `Product.cpe` match in the local catalog.
      If no local Product matches, ignore this triple and continue.
   b. Create or find a `TicketPackageTrack` with `reference =
      codestream.name` and the determined `workflow_type` (if one does not
      already exist for this package + reference combination, including
      soft-deleted).
   c. Create a `TicketPackageProduct` linking the track to the matched
      Product (if one does not already exist).
7. If no Product was resolved across the entire response, including when all
   returned codestreams were skipped as unsupported, fail with
   `PackageTargetsUnresolvedError`; no package-tree record is created.

When at least one Product CPE has no local match in an otherwise successful
resolution, log a WARNING-level `package_target_resolution_partial` event with
the package name and unmatched CPEs. This accepted partial result does not
change the API response shape.

For a package tree that is created partially, a newly introduced Product may
be omitted until the Product catalog sync adds the corresponding `Product` row
and invokes Product catalog backfill. A zero-resolution failure creates no
`TicketPackage` and therefore cannot be discovered by backfill; recovery
requires a later manual or automatic invocation. A CPE that remains absent
from the local Product catalog is intentionally ignored on every invocation.
Sentinel never creates a Product from a CPE string or falls back to
name/version matching.

---

## Ticket Events for Package Changes

Every modification represented in the table below MUST produce its specified
`TicketAuditEvent` for audit and traceability. Delivery-status mutation is the
explicit exception: it creates no Ticket event, assignment, or Ticket
reconciliation. The following event types are defined:

| Action | `event_type` | `user_id` | Details recorded |
|--------|-------------|-----------|------------------|
| Authorized user adds or completes package tree | `package_added` | Acting user | `package_name` |
| Package auto-added or completed (CVE ingestion or Product catalog backfill) | `package_added` | `NULL` | `package_name`, contextual `comment` |
| Active User acquired as package maintainer | `package_maintainer_added` | `NULL` | Target username in `new_value`; package name in `detail` |
| Authorized user soft-deletes package | `package_excluded` | Acting user | `package_name` |
| Authorized user soft-deletes track | `track_excluded` | Acting user | `track_name`, `package_name` |
| Authorized user soft-deletes product | `product_excluded` | Acting user | `track_name`, `package_name`, event-time Product name and CPE |
| Authorized user restores package | `package_restored` | Acting user | `package_name` |
| Authorized user restores track | `track_restored` | Acting user | `track_name`, `package_name` |
| Authorized user restores product | `product_restored` | Acting user | `track_name`, `package_name`, event-time Product name and CPE |
| User-attributed or system change to track status | `track_status_changed` | Acting user for user-attributed changes; `NULL` for automatic release detection | `track_name`, `package_name`, `old_status`, `new_status` |
| VA overrides or resets Product eligibility | `product_eligibility_changed` | VA user | `track_name`, `package_name`, event-time Product name and CPE, `old_eligible`, `new_eligible`, `reason = va_override`, and `override_action` |
| Ticket created | `ticket_created` | `NULL` | Creation source description |
| Product release detected | `product_released` | `NULL` | `track_name`, `package_name`, event-time Product name and CPE, `released_at`, `advisory_id` |
| Product eligibility recalculated | `product_eligibility_changed` | `NULL` | `track_name`, `package_name`, event-time Product name and CPE, `old_eligible`, `new_eligible`, `reason` |

- `user_id = NULL` indicates an automatic system action. For
  `package_added`, this distinguishes manual additions (acting user) from
  automatic ones (CVE ingestion or Product catalog backfill). The `comment` field
  provides context for automatic additions.
- Exactly one `package_added` event is created when an invocation creates at
  least one package, track, or Product record. A completely no-op invocation
  creates no `package_added` event. Product catalog backfill uses the fixed
  comment `Product catalog backfill`.
- Exactly one `package_maintainer_added` event is created per new association,
  including on a package-tree no-op. These events are system-attributed and do
  not trigger Ticket reconciliation. Existing, unmatched, or inactive-user
  outcomes create no event.
- All events include an implicit `created_at` timestamp.
- Automatic recalculation creates one event only for each Product occurrence
  whose persisted boolean changes. The CVSS chain and synchronous manual-zone exit
  order multiple events by `TicketPackageProduct.id` ascending. CVSS assessment
  and default-version propagation use `reason = cvss`; manual-zone exit uses
  `reason = reactivation`. Override-skipped and unchanged automatic occurrences
  create no event.
- The "Details recorded" column lists the values stored in the event's
  `old_value`, `new_value`, `comment`, and structured `detail` fields. See
  `docs/features/tickets/ticket-audit-log.md` for the exact field mapping
  and `docs/data-model.md` for the schema.

---

## Release Tracking

Sentinel monitors two **independent** levels of release for each
affected package:

1. **Track level**: the fix has been added to the track's IBS project
   (e.g., `SUSE:SLE-15-SP6:Update`). See
   `docs/features/packages/ibs-track-release-detection.md` for the
   full detection mechanism (per-track expanded-source checkpoint, IBS diff
   analysis, current-state fallback, and concurrency rules).
2. **Product level**: the fix has been published to the product's update
   repository (e.g., the SLES 15 SP6 update repository consumed by
   `zypper`). See
   `docs/features/packages/ibs-product-release-detection.md` for the
   full detection mechanism (deterministic repository traversal, validated
   updateinfo advisories, and exact source-package matching).

The two levels are detected through different mechanisms and update
different data:

- The track level updates `TicketPackageTrack.status` to `FIXED`
  (automatic) when track release detection finds qualifying canonical evidence
  for the Ticket CVE in the codestream's expanded source diff.
- The track level updates `TicketPackageTrack.delivery_status` to
  `RELEASED` when IBS submission tracking proves that an accepted Release
  Request released the effective SR contents to that codestream.
- The product level sets `TicketPackageProduct.released_at` when the
  fix appears in that specific product's update repository.

The track-level automatic transition applies only when the current
status is `AFFECTED` or `ANALYSIS` (see Automatic Transitions above).
The product-level `released_at` timestamp is set regardless of
affectedness status — it records a factual observation about the
product's update repository.

---

## Ticket Lifecycle Integration

Track status and ordinary Product eligibility changes go through
`package_service`, which reconciles Ticket status after each completed
gate-relevant mutation. The atomic CVSS-chain exception described in
[Override Model](#override-model) applies all of its automatic Product changes
before at most one final reconciliation. See `docs/features/tickets/tickets.md`
(Ticket Lifecycle) for the authoritative gate conditions and status transition
rules, and `docs/features/packages/package-service.md` for the ordinary module
contract, including:

- **Analysis → Analyzed**: requires at least one manually included track, all
  actionable tracks decided, severity set, and, for a Ticket with a CVE, at
  least one canonical SUSE assessment in any accepted CVSS version
- **Analyzed → Resolved**: requires every actionable track to
  be resolution-complete — either (a) `NOT_AFFECTED`/`WONT_FIX`, or
  (b) `FIXED` with all actionable eligible Products released, or
  (c) `AFFECTED` with no actionable eligible Products remaining
- Reverse transitions when gate conditions are no longer met

---

## Workflow-Agnostic vs Workflow-Specific

The following concerns are identical regardless of `workflow_type`:

- `PackageStatus` enum and all valid transitions
- `DeliveryStatus` enum (the delivery concept exists for both workflows)
- Final-status protection (automatic `FIXED` requests against
  `NOT_AFFECTED`, `FIXED`, or `WONT_FIX` are protected no-ops)
- `package_service` module — operates on `TicketPackageTrack` and
  `TicketPackageProduct`
- Ticket status gates (Analysis → Analyzed → Resolved)
- Product eligibility (CVSS threshold, Reactive Support phase)
- Soft-deletion and restore
- UI — VA sees packages → tracks → products with no workflow distinction
- Maintainership acquisition - one additive user association per
  `TicketPackage` occurrence, package-wide across all its tracks. The same
  SMELT endpoint serves IBS and Git/SLFO packages without a codestream join

The following concerns are workflow-specific (service layer only):

| Concern | IBS (`ibs`) | Git (`git`) |
|---------|-------------|-------------|
| Track + product resolution | SMELT v2 `maintained` (same endpoint) | SMELT v2 `maintained` (same endpoint) |
| Source retrieval for analysis | IBS API | src.suse.de git API |
| Release detection (track) | IBS expanded source-state diff with a per-track checkpoint | TBD |
| Release detection (product) | updateinfo.xml | TBD |
| Real-time events | IBS RabbitMQ | TBD |
| Submission tracking (SR/RR) | IBS submission tracking | TBD |

Maintainership is not represented as workflow-specific because it is
package-wide within a `TicketPackage`; its discovery and identity rules are in
`docs/features/packages/package-maintainership.md`.

## IBS Workflow Applicability and Convergence

This section owns the shared boundary used by all IBS package consumers.
Consumer specifications define their own source-specific algorithms and refer
to this section for scope, acceleration, and recovery semantics.

### Strict workflow applicability

The persisted `TicketPackageTrack.workflow_type` is the sole workflow
discriminator after track creation. Every IBS REST source operation, source
checksum or diff operation, SR/RR operation, and IBS RabbitMQ mutation MUST
operate only on tracks with `workflow_type = ibs`. A Git track's `reference`
MUST NOT be interpreted as an IBS project and a Git track MUST NOT receive an
IBS checksum, SR/RR correlation, RabbitMQ-driven mutation, or IBS release
mutation.

Product-level IBS processing is scoped to a `TicketPackageProduct` occurrence
through its parent `TicketPackageTrack.workflow_type = ibs`. A catalog Product
may occur below both IBS and Git tracks; an IBS advisory updates only the
occurrences below IBS tracks. No workflow discriminator is added to the global
`Product` catalog.

Maintainership acquisition is package-occurrence data and is independent of
track workflow. Every successful package-target resolution queries SMELT
maintainership for both IBS and Git/SLFO results. It creates additive
`TicketPackageMaintainer` rows applying to every track under that occurrence;
it never sends a Git track to IBS and never interprets either endpoint's
codestream namespace as the other.

IBS polling and RabbitMQ processing consider active Tickets only (`New`,
`Analysis`, `Analyzed`). `Resolved`, `Ignored`, and `Duplicated` Tickets do not
contribute monitored tracks or Product occurrences. Within an active Ticket,
manual exclusion, lifecycle actionability, and EOL do not narrow factual release
or delivery observation. A consumer may omit records already in a conclusive
state of its own dimension, such as `released_at IS NOT NULL` or track
affectedness statuses that automatic release detection cannot change.

### Acceleration and permanent recovery ownership

Package addition and RabbitMQ reduce latency; they are not durable recovery
mechanisms. The permanent ownership boundary is:

| Concern | Acceleration | Permanent recovery owner | Applicable records |
|---------|--------------|--------------------------|--------------------|
| Package tree | Explicit package addition; Product catalog backfill when a Product becomes newly current | Re-resolution on Ticket reactivation; no periodic per-package SMELT scan | Every persisted package marker on the reactivated Ticket, including soft-deleted markers |
| Maintainership | Every successful package-target resolution, including a package-tree no-op | A later invocation of the same idempotent package-resolution operation; no periodic owner | Every TicketPackage occurrence, package-wide across IBS and Git/SLFO tracks |
| SR/RR discovery and correlation | New-IBS-track generic per-Ticket catch-up; IBS RabbitMQ request events | Complete daily `sync_ibs_requests` reconciliation | IBS tracks of active Tickets |
| Track release observation | IBS RabbitMQ `package.commit` | `detect_ibs_track_releases` | IBS tracks of active Tickets |
| Product advisory observation | None | `detect_ibs_product_releases` | Product occurrences below IBS tracks of active Tickets |

The first normal run after a feature is first enabled or re-enabled uses the
same owning fetcher's algorithm; enabling a fetcher has no separate hook. Each
owner MUST define first-run and long-gap behavior that converges current state
for its active scope. State-based owners that already scan unresolved current
records need no distinct first-run branch. Incremental windows, checksums, and
cursors are optimizations and MUST NOT be presented as full recovery when they
cannot rediscover skipped current state.

### Reactivation and convergence

When a Ticket leaves the `Ignored` or `Duplicated` manual zone, convergence has
one synchronous PostgreSQL phase. Every inactive-to-active transition,
including an ordinary `Resolved` regression, then has two post-commit package-
domain phases:

1. For a manual-zone exit, before the relevant final Ticket gate result,
   recalculate every existing
   system-managed `TicketPackageProduct` from the current persisted assessment
   set, current `default_cvss_version`, current Product threshold and lifecycle
   dates, and current override marker. Use one UTC `evaluation_date`, include
   directly or effectively excluded and EOL occurrences, skip overrides, and
   order changed-Product events by `TicketPackageProduct.id` with
   `reason = reactivation`. This phase never recalculates or writes
   `CVE.severity`, never acquires a CVE lock after the Ticket lock, performs no
   network, Redis, or Celery I/O, and participates in the manual-zone-exit
   `ticket_service` caller-owned transaction. That lifecycle owner performs at
   most one final Ticket reconciliation after all changes.
2. After that transaction commits, re-resolve every persisted package name
   through the normal SMELT package
   resolution, maintainership acquisition, and idempotent package mutation
   path. This includes soft-deleted package markers. Existing records and
   exclusion markers are preserved; only missing tracks, Product occurrences,
   and maintainer associations are created. Each package is an independent
   unit so one failure does not roll back successful siblings.
3. After the package-tree and maintainership phase has committed its successful
   units, run the registered per-Ticket catch-up operations against the
   resulting tree, including IBS request, IBS track-release, IBS Product-release,
   and lifecycle evaluation. Failure to resolve one package does not prevent
   catch-up for records that already exist.

No special synchronous eligibility pass precedes a `Resolved` regression:
ordinary local CVSS, default-version, threshold, and lifecycle workflows already
maintain eligibility in that gate-zone state. New Product occurrences created
in phase 2 calculate eligibility immediately
through the same canonical evaluator. The later lifecycle catch-up is a safety
net for current-state mismatches, not the mechanism that first establishes
eligibility for a final manual-zone-exit gate result.

The workflow recovers current authoritative facts needed to represent the
active Ticket; it does not reproduce every external transition that occurred
while the Ticket was inactive. For example, an already-published valid
advisory sets `released_at` to its original issue time, and an SR/RR catch-up
recovers current authoritative request actions and resulting delivery status
rather than every intermediate request state.

The ordering above is a behavioral contract. Whether it is implemented with
task chaining, post-commit callbacks, or another equivalent mechanism is an
implementation choice. Reactivation work is idempotent. Per-item failures and
final catch-up failure after the shared retry policy are logged with the
sanitized cause, `ticket_id`, owning operation, affected item identity, and
`celery_task_id`. No durable per-ticket catch-up progress table is introduced.
A terminal failure of package enumeration, package-tree orchestration, catch-up
dispatch, or an individual catch-up requires an observable operator-triggered
rerun of the same complete idempotent workflow for `ticket_id`. Successful
package units and catch-ups may repeat safely; the rerun does not resume from a
persisted progress position. The concrete operator interface MUST be defined
before the workflow is implemented. This is required in particular because
there is no periodic full-tree SMELT scan; the complete daily request
reconciliation cannot create a track omitted by package resolution.

### Checkpoint safety

A checksum, cursor, temporal boundary, or message acknowledgment may prevent
future processing only after every required local outcome for that unit has
completed or an independent permanent recovery owner can still discover the
missing outcome. Otherwise the checkpoint remains at the last completely
processed unit and the next run repeats idempotent work.

IBS track release state is per `TicketPackageTrack`. A new expanded `srcmd5`
becomes that track's checkpoint only in the same transaction that completes any
required affectedness mutation, service-owned audit event, and Ticket
reconciliation. A no-match or final-status outcome may advance the checkpoint
after successful examination. A failed sibling track retains its own previous
checkpoint. Periodic polling, catch-up, RabbitMQ processing, and retries must
serialize or conditionally update the expected predecessor so an older worker
cannot regress a newer checkpoint. The detailed algorithm and unavailable-
history fallback are in `ibs-track-release-detection.md`.

### Accepted package-tree discovery gap

Sentinel deliberately performs no periodic SMELT request for every package of
every active Ticket. This also means maintainership acquisition after a failed
request, a new User, or a new upstream assignment waits for another normal
package-resolution trigger. Product catalog backfill re-resolves existing active
package trees only when a Product becomes newly current. Consequently, a new
SMELT track composed entirely of Products already present in the catalog can
remain absent from a continuously active Ticket until another package
resolution trigger occurs, such as Ticket reactivation, explicit addition, or
another owning workflow. This is a known and accepted load-versus-freshness
trade-off; no generic backfill framework, failed-resolution registry, or
periodic full-tree reconciler is introduced.

---

## External Data Sources

- **SMELT product sync** (periodic): see
  `docs/features/packages/product-catalog.md` (SMELT Integration)
- **SMELT package query** (on-demand): see
  [SMELT Query for Package Resolution](#smelt-query-for-package-resolution)
  above
- **SMELT maintainership query** (on-demand): see
  `docs/features/packages/package-maintainership.md`
- **AIMAAS lifecycle and threshold sync** (periodic): see
  `docs/features/packages/product-catalog.md` (AIMAAS Integration)

---

## API Endpoints

Every endpoint below whose path contains package, track, or Product occurrence
identifiers treats the complete path as one semantic locator. The package must
belong to `{ticket_id}`, the track must belong to that package, and the Product
occurrence must belong to that track. The package service locks the declared
Ticket first and revalidates the complete chain under that lock. A missing ID
or any ownership mismatch at any level returns the endpoint's existing `404
RESOURCE_NOT_FOUND`; no endpoint reveals that a supplied child exists under a
different path. API handlers pass the identifiers to the service and perform no
business ORM lookup.

### Add Package to Ticket

```
POST /api/v1/tickets/{ticket_id}/packages
```

Add a source package to a ticket. Sentinel queries SMELT to resolve all
maintained tracks and Products and to acquire package-wide maintainership,
creates package-tree and additive maintainer records via `package_service`,
and, when at least one new IBS track is created, registers the documented
post-commit generic `sync_ibs_requests` catch-up.
See [Adding Packages to a Ticket](#adding-packages-to-a-ticket) for the full
behavior.

**Request body**:

```json
{
  "package_name": "openssl-3"
}
```

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `package_name` | string | Yes | Max 255 chars. Pattern: `^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,253}[a-zA-Z0-9]$` (min 2 chars). Only alphanumeric, dots, underscores, hyphens, and plus signs allowed. | Source package name |

The `package_name` value is URL-encoded before interpolation in the SMELT
package-scoped path
(`experimental/v2/maintained/{url_encode(name)}?include_reactive_ltss=true`).
This prevents injection of URL control characters regardless of validation.

**Response** (201 Created):

```json
{
  "data": {
    "package_name": "openssl-3",
    "tracks_created": 3,
    "tracks_skipped": 0,
    "products_created": 7,
    "products_skipped": 0
  }
}
```

The response reports how many records were created vs. skipped (already
existed). This supports idempotent re-calls — if the package was already
added, all counts will be zero in the `created` fields.

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `PACKAGE_ALREADY_EXCLUDED` | Package exists on this ticket but is soft-deleted — use the restore endpoint |
| 422 | `PACKAGE_NOT_FOUND_IN_SMELT` | SMELT returned no results for the given package name |
| 422 | `PACKAGE_TARGETS_UNRESOLVED` | SMELT returned tracks, but none of their targets resolved to a Product in Sentinel's current catalog snapshot |
| 503 | `PRODUCT_CATALOG_NOT_READY` | No complete SMELT Product catalog snapshot has committed yet |
| 503 | `SMELT_UNAVAILABLE` | SMELT did not produce a valid successful response |

These rows are not ordered by HTTP status. The endpoint applies the strict
sequence in [Adding Packages to a Ticket](#adding-packages-to-a-ticket).

**Idempotency**: safe to call multiple times for the same **active**
package. If the package is already fully resolved, the response will
report zero created records. If the package is soft-deleted, the endpoint
returns 409 `PACKAGE_ALREADY_EXCLUDED` — the acting user must use the restore
endpoint to re-include it. The request still performs SMELT and current-catalog
validation and then the best-effort maintainership request before determining
locked package state, so documented blocking SMELT/catalog errors may be
returned on a repeat call. For an included package, missing maintainers may be
added while the public creation counts remain zero. For a directly excluded
package, the subsequent guard returns `PACKAGE_ALREADY_EXCLUDED` before any
fetched maintainer association or other database mutation is persisted.

---

### Soft-Delete Package from Ticket

```
POST /api/v1/tickets/{ticket_id}/packages/{package_id}/exclude
```

Soft-delete a package from the Ticket. Sets `deleted_at` on the package record
only; tracks and Products are not modified but become effectively excluded
through the hierarchy. Creates a single `TicketAuditEvent`.
See [Exclusion and Actionability](#exclusion-and-actionability) for the full
behavior.

After the soft-delete, the system reconciles ticket status via
`package_service`. This is necessary because excluding the package changes the
set of participating records considered by Ticket gates (Resolved gate and
Analyzed gate).

**Response** (200 OK):

```json
{
  "data": {
    "package_name": "openssl-3",
    "actionable": false,
    "non_actionable_reason": "package_excluded"
  }
}
```

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Package not found on this ticket |
| 409 | `PACKAGE_ALREADY_EXCLUDED` | Package is already soft-deleted |

---

### Restore Package

```
POST /api/v1/tickets/{ticket_id}/packages/{package_id}/restore
```

Restore a directly excluded package. Clears `deleted_at` on the package
record only; child records are not modified. The package may remain
non-actionable because every track is excluded or has no actionable Product.
Creates a single `TicketAuditEvent`. See
[Exclusion and Actionability — Restore](#restore).

**Response** (200 OK):

```json
{
  "data": {
    "package_name": "openssl-3",
    "actionable": true,
    "non_actionable_reason": null
  }
}
```

If every track remains non-actionable after the restore, the same successful
response instead returns `actionable = false` and
`non_actionable_reason = "no_actionable_tracks"`.

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Package not found on this ticket |
| 422 | `PACKAGE_NOT_EXCLUDED` | Package is not directly soft-deleted |

---

### Soft-Delete Track

```
POST /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/exclude
```

Soft-delete a track from the ticket. Sets `deleted_at` on the track record
only; Products under it are not modified but become effectively excluded
through the hierarchy. Creates one acting-user-attributed `TicketAuditEvent`.

The operation is also valid beneath an already excluded package. In that case
it records the track's independent direct marker, while the response reason is
`package_excluded` because ancestor reasons take precedence over
`track_excluded`.

For example, the successful response beneath an excluded package contains the
new direct track marker but reports:

```json
{
  "data": {
    "reference": "SUSE:SLE-15-SP6:Update",
    "actionable": false,
    "non_actionable_reason": "package_excluded"
  }
}
```

After the soft-delete, the system
reconciles ticket status via `package_service`. This is necessary
because excluding a track changes the set of participating records considered
by ticket gates (Resolved gate and Analyzed gate).

**Response** (200 OK):

```json
{
  "data": {
    "reference": "SUSE:SLE-15-SP6:Update",
    "actionable": false,
    "non_actionable_reason": "track_excluded"
  }
}
```

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Track not found on this ticket |
| 409 | `PACKAGE_ALREADY_EXCLUDED` | Track is already soft-deleted |

---

### Restore Track

```
POST /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/restore
```

Restore a directly excluded track. Clears `deleted_at` on the track record
only; Product markers are not modified. The track may remain non-actionable
because every Product is individually excluded or EOL. Creates a single
`TicketAuditEvent`.

**Response** (200 OK):

```json
{
  "data": {
    "reference": "SUSE:SLE-15-SP6:Update",
    "actionable": true,
    "non_actionable_reason": null
  }
}
```

If every Product remains non-actionable after the restore, the same successful
response instead returns `actionable = false` and
`non_actionable_reason = "no_actionable_products"`.

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Track not found on this ticket |
| 422 | `PACKAGE_NOT_EXCLUDED` | Track is not directly soft-deleted |

---

### Soft-Delete Product

```
POST /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/products/{ticket_package_product_id}/exclude
```

Soft-delete a single Product from a track. Creates one acting-user-attributed
`TicketAuditEvent` for the excluded record. Parent markers are never changed
automatically.

The operation is valid beneath an excluded package or track and while the
Product is EOL. It records the Product's independent direct marker even though
effective participation is already false. The response reason remains
`package_excluded` or `track_excluded` when either applies; otherwise
`product_excluded` takes precedence over `eol`.

For example, excluding an EOL Product beneath an excluded track succeeds and
reports `non_actionable_reason = "track_excluded"`; after the track is
restored, the still-directly-excluded Product reports
`non_actionable_reason = "product_excluded"`, not `eol`.

After the soft-delete, the system
reconciles ticket status via `package_service`. This is necessary
because excluding a Product changes the set of actionable records considered
by ticket gates (Resolved gate and Analyzed gate).

**Response** (200 OK):

```json
{
  "data": {
    "id": "uuid",
    "product_cpe": "cpe:/o:suse:sles:15:sp6",
    "product_name": "SLES 15-SP6",
    "actionable": false,
    "non_actionable_reason": "product_excluded"
  }
}
```

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Product not found on this track |
| 409 | `PACKAGE_ALREADY_EXCLUDED` | Product is already soft-deleted |

---

### Restore Product

```
POST /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/products/{ticket_package_product_id}/restore
```

Restore a directly excluded Product. Clears `deleted_at` on the Product
record. No child, ancestor, or lifecycle pre-check applies. Creates a single
`TicketAuditEvent`.

**Response** (200 OK):

```json
{
  "data": {
    "id": "uuid",
    "product_cpe": "cpe:/o:suse:sles_ltss:15:sp4",
    "product_name": "SLES-LTSS 15-SP4",
    "actionable": false,
    "non_actionable_reason": "eol"
  }
}
```

The example remains non-actionable because the restored Product is EOL. A
non-EOL Product under manually included ancestors returns `actionable = true`
and `non_actionable_reason = null`.

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Product not found on this track |
| 422 | `PACKAGE_NOT_EXCLUDED` | Product is not directly soft-deleted |

---

### Change Track Status

```
PATCH /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}
```

Change the affectedness status of a track. An effective change triggers
TicketAuditEvent creation and Ticket status re-evaluation via
`package_service`. If the locked status already equals the authorized target,
the endpoint returns the current track with `200 OK` and produces no
assignment, audit, reconciliation, or post-commit effect.

**Request body**:

```json
{
  "status": "affected"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | Yes | New status value. Valid values: `analysis`, `affected`, `not_affected`, `fixed`†, `wont_fix` |

† Setting `status` to `FIXED` requires `admin_ticket_ops` instead of
`manage_packages`; the capabilities are alternatives selected from the
validated payload, not cumulative requirements. Every non-`FIXED` target
requires `manage_packages`. The selected capability is checked before Ticket
accessibility.

**Response** (200 OK):

```json
{
  "data": {
    "ticket_id": "uuid",
    "package_name": "openssl-3",
    "reference": "SUSE:SLE-15-SP6:Update",
    "status": "affected",
    "delivery_status": "pending",
    "delivery_relevant": true,
    "actionable": true,
    "non_actionable_reason": null,
    "products": [
      {
        "id": "uuid",
        "product_cpe": "cpe:/o:suse:sles:15:sp6",
        "product_name": "SLES 15 SP6",
        "eligible": true,
        "is_eligible_override": false,
        "lifecycle_phase": "general_support",
        "actionable": true,
        "non_actionable_reason": null
      },
      {
        "id": "uuid",
        "product_cpe": "cpe:/o:suse:sles_ltss:15:sp4",
        "product_name": "SLES-LTSS 15-SP4",
        "eligible": false,
        "is_eligible_override": false,
        "lifecycle_phase": "eol",
        "actionable": false,
        "non_actionable_reason": "eol"
      }
    ]
  }
}
```

The response includes the updated track and all its child Products with their
current eligibility and actionability, allowing the client to update
the UI tree without a separate fetch.

**`Capability: admin_ticket_ops when status = fixed; manage_packages for every
other status`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Package or track not found on this ticket |

---

### Override Product Eligibility

```
PATCH /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/products/{ticket_package_product_id}
```

Override the eligibility of a specific product. Sets
`is_eligible_override = true`. An effective override or reset triggers
TicketAuditEvent creation and Ticket status re-evaluation via
`package_service`; a true no-op produces neither.

**Request body**:

```json
{
  "eligible": false
}
```

Reset eligibility override:

```json
{"eligible": null}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `eligible` | boolean \| null | Yes | Eligibility override value, or `null` to reset to automatic calculation |

#### Reset behavior

When `eligible` is sent as `null`, the override is removed and the value
reverts to automatic:

- **`eligible: null`** — sets `is_eligible_override = false`. Eligibility is
  immediately recalculated using the standard rules (CVSS threshold + lifecycle
  phase). The recalculation uses the Eligibility Score Resolution: only the
  SUSE assessment of the default CVSS version is considered. If not resolvable
  (including tickets without an associated CVE), the 10.0 fallback applies —
   making the Product eligible unless the Reactive Support override applies.

For an effective override or reset, both operations follow the same
post-modification flow:

1. A `TicketAuditEvent` (`product_eligibility_changed`) is created
2. A single ticket status re-evaluation is performed at the end of the
   transaction (via `package_service`)

This applies to all operations through this endpoint: setting an override,
changing an override value, and resetting an override.

If the locked Product occurrence already has the requested override state and
value, or is already automatically managed when reset is requested, the
endpoint returns the current Product with `200 OK` and performs no assignment,
audit, Ticket reconciliation, or post-commit effect.

**Response** (200 OK):

```json
{
  "data": {
    "ticket_id": "uuid",
    "package_name": "openssl-3",
    "reference": "SUSE:SLE-15-SP6:Update",
    "id": "uuid",
    "product_cpe": "cpe:/o:suse:sles_ltss:15:sp4",
    "product_name": "SLES-LTSS 15-SP4",
    "eligible": false,
    "is_eligible_override": true,
    "lifecycle_phase": "reactive_support",
    "actionable": true,
    "non_actionable_reason": null
  }
}
```

**`Capability: manage_packages`**

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Package, track, or product not found on this ticket |

---

### List Ticket Packages

```
GET /api/v1/tickets/{ticket_id}/packages
```

Returns the complete package tree for a specific Ticket — all packages,
tracks, and Products including non-actionable records. Direct manual-exclusion
timestamps and current actionability are visible on each level. Identical data
to the `packages` field in
`TicketDetail` from `GET /api/v1/tickets/{ticket_id}`, but available as
a standalone endpoint for clients that only need package data.

| Aspect | Design |
|--------|--------|
| **`Access: Public`** | Consistent with `GET /api/v1/tickets/{ticket_id}` |
| **`Authentication: Optional`** | Resolves caller identity for ticket accessibility |
| **Guard** | `require_accessible_ticket` (404 for missing/confidential tickets) |
| **Pagination** | No — package count per ticket is bounded (typically 1-5, rarely >20) |
| **Envelope** | `{"data": [...]}` (unpaginated list) |
| **Excluded records** | All package/track/Product records are returned, including directly or effectively manually excluded and lifecycle-non-actionable records |
| **Actionability** | Every level includes derived `actionable` and `non_actionable_reason` values evaluated with one UTC date shared by the response |
| **Response schema** | `PackageDetail[]` — reuses the existing schema (full tree: package -> tracks -> products) |
| **Sorting** | Fixed alphabetical order by `package_name`. Client-controlled sorting (`sort_by`/`sort_order`) is not supported — the dataset has bounded cardinality and fixed ordering provides consistent display without configuration overhead. |
| **Delegation** | Delegates to `package_service.get_ticket_packages()` |

**Response** (200 OK):

```json
{
  "data": [...]
}
```

The response body is a `PackageDetail[]` array — the same schema used in
`TicketDetail.packages`.

---

### Search Packages Across Tickets

```
GET /api/v1/packages
```

Search and list packages across all tickets. Each result represents a
single `TicketPackage` record — i.e., one `(package_name, ticket)` pair.
If the same source package is tracked in multiple tickets, it appears
once per ticket in the results.

| Aspect | Design |
|--------|--------|
| **`Access: Public`** | Consistent with `GET /api/v1/tickets` |
| **`Authentication: Optional`** | Resolves caller identity for confidentiality filtering |
| **Confidentiality** | Packages belonging to confidential tickets are excluded for unauthorized callers (same filter as `GET /api/v1/tickets`). The endpoint handler constructs `confidential_ticket_filter()` and passes it to `search_packages(confidentiality_filter=...)` |
| **Non-actionable packages** | Always excluded. This includes directly excluded packages and packages with no actionable tracks |
| **Pagination** | Yes — `page` (default 1), `per_page` (default 20, max 100) |
| **Envelope** | `{"data": [...], "meta": {"total": N, "page": P, "per_page": PP}}` |
| **Delegation** | Delegates to `package_service.search_packages()` |

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Substring match on `package_name` (case-insensitive, equivalent to SQL ILIKE `%term%`). Max 500 chars |
| `name` | string | Exact match on `package_name`. Max 500 chars |
| `ticket_status` | string (repeatable) | Ticket statuses to include: `new`, `analysis`, `analyzed`, `resolved`, `ignored`, `duplicated`. Repeatable — multiple values are specified as separate query parameters (e.g., `?ticket_status=new&ticket_status=analysis`). Invalid values are silently ignored per `api-spec.md` (Enum Filter Validation). If all values are invalid, an empty result set is returned. Default: no filter (all statuses) |
| `sort_by` | string | `package_name` or `created_at` (default: `created_at`). Refers to `TicketPackage.created_at` (the date the package was added to the ticket), not `Ticket.created_at`. Deterministic tiebreaker per `docs/api-spec.md` (Deterministic Pagination Ordering) |
| `sort_order` | string | `asc` or `desc` (default: `desc`) |
| `page` | integer | Page number (default: 1, min: 1) |
| `per_page` | integer | Items per page (default: 20, min: 1, max: 100) |

`search` and `name` are mutually exclusive. If both are provided,
return 422 `VALIDATION_ERROR`.

Pagination constraints follow the standard rule in `docs/api-spec.md`
(Pagination).

**Naming note**: the parameter is named `ticket_status` (not `status`)
to disambiguate from package-level statuses visible in `track_summary`.
On `GET /api/v1/tickets`, `status` is unambiguous because the resource
itself is a ticket.

#### Response Schema: `PackageListItem`

```json
{
  "id": "uuid",
  "package_name": "openssl-3",
  "ticket": {
    "id": "uuid",
    "identifier": "SNTL-123",
    "status": "analysis",
    "severity": "high"
  },
  "track_summary": {
    "total": 5,
    "affected": 2,
    "fixed": 1,
    "not_affected": 1,
    "wont_fix": 0,
    "analysis": 1
  },
  "created_at": "2026-05-15T10:30:00Z",
  "updated_at": "2026-05-16T08:00:00Z"
}
```

**`ticket`** (`TicketPackageRef`) — lightweight ticket reference:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Ticket ID |
| `identifier` | string | Human-readable identifier (e.g., `SNTL-123`) |
| `status` | string | Current ticket status |
| `severity` | string \| null | Ticket severity |

**`track_summary`** (`TrackSummary`) — aggregated track status counts for the
package within this Ticket. Counts only actionable tracks, using the same UTC
`evaluation_date` as package filtering and pagination:

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total actionable tracks |
| `affected` | integer | Tracks with status `AFFECTED` |
| `fixed` | integer | Tracks with status `FIXED` |
| `not_affected` | integer | Tracks with status `NOT_AFFECTED` |
| `wont_fix` | integer | Tracks with status `WONT_FIX` |
| `analysis` | integer | Tracks with status `ANALYSIS` |

---

---

## Background Tasks

Product sync tasks (`sync_smelt_products`, `sync_aimaas_lifecycle`,
`sync_aimaas_thresholds`) are specified in
`docs/features/packages/product-catalog.md` (Background Tasks).

- `sync_ibs_requests`: complete daily state-based fetcher (02:30 UTC) that
  reconciles current IBS request actions and track delivery for all IBS tracks
  belonging to active Tickets. It is the permanent recovery owner; package-add,
  reactivation, and RabbitMQ paths invoke the same algorithm only to reduce
  latency. See `docs/features/packages/ibs-submission-tracking.md`.
- `detect_ibs_track_releases`: periodic task (every 24 hours at 02:00
  UTC via Celery Beat) that runs the `DetectIbsTrackReleases` fetcher and its
  shared reconciliation boundary. Serves as a catch-up mechanism for events missed by the
  real-time `IBSEventConsumer` (see
  `docs/features/integrations/ibs-rabbitmq-integration.md`). See
  `docs/features/packages/ibs-track-release-detection.md` for the
  full procedure. When a release is detected, sets
  `TicketPackageTrack.status = FIXED`.
- `detect_ibs_product_releases`: periodic task (daily at 04:00 UTC) that
  validates `updateinfo.xml` stable security advisories for unreleased
  `TicketPackageProduct` occurrences and sets `released_at`. See
  `docs/features/packages/ibs-product-release-detection.md` for the
  full procedure. Scope is Product occurrences below IBS tracks of active
  Tickets.
- `evaluate_lifecycle_transitions`: periodic task (daily at 04:15 UTC) that
  reconciles lifecycle-derived eligibility and Ticket gate state from current
  Product dates. EOL changes derived actionability without mutating
  package-tree exclusion markers. Idempotent — operates on current state with
  no lifecycle cache. See
  `docs/features/packages/product-lifecycle-transitions.md` for the
  full specification.

---

## Security

- Adding/removing/excluding/restoring packages on a ticket requires the
  `manage_packages` capability
- Changing Product eligibility or changing a track to a non-`FIXED` status
  requires `manage_packages`
- Changing a track to `FIXED` requires `admin_ticket_ops` instead; it does not
  additionally require `manage_packages`
- Viewing affectedness data is publicly accessible (no authentication
  required):
  - `GET /api/v1/tickets/{ticket_id}/packages` — subject to
    `require_accessible_ticket` (confidentiality check)
  - `GET /api/v1/packages` — packages belonging to confidential tickets
    are excluded for unauthorized callers via
    `confidential_ticket_filter()`

---

## Future Considerations

- **openSUSE / OBS public**: tracking packages in build.opensuse.org for
  openSUSE Tumbleweed and Leap will be addressed in a separate spec.
- **Channel file parsing**: direct parsing of channel files from
  `SUSE:Channels` may be added if SMELT data is insufficient.
- **Git workflow specifics**: release detection (track and product level),
  real-time events, and submission tracking for the git workflow are TBD and
  will be specified when the SLFO workflow is better defined. Maintainership
  remains package-wide and does not depend on those release mechanisms.
- **Review Queue**: anomalous combinations of affectedness and delivery
  status will be integrated into a ticket review queue. See
  [Anomaly Detection](#anomaly-detection-future-review-queue).

---

## Open Items

- [ ] Release detection mechanism for git workflow (track-level and
      product-level)
- [ ] Real-time event source for git workflow (webhook? polling?)
- [x] SMELT API evolution — the v2 `maintained` endpoint exposes
      `codestream.maintenance_process_type` as the authoritative workflow
      discriminator
- [x] Workflow type mapping — `SLFO` maps to `git`, `SLE_15` maps to `ibs`,
      and known unsupported `SLFO_IBS` codestreams are skipped
- [ ] Submission tracking (SR/RR) equivalent for git workflow, if any

---

## Cross-references

- `docs/api-spec.md` — global API conventions (envelope format, error
  codes, pagination, shared 422 responses)
- `docs/features/packages/package-service.md` — package-centric
  mutations, orchestration, and query operations
- `docs/features/packages/product-catalog.md` — product catalog, SMELT
  product sync, AIMAAS lifecycle/threshold sync, `GET /api/v1/products`
- `docs/features/tickets/tickets.md` — ticket lifecycle, status gates,
  confidentiality filtering (`confidential_ticket_filter()`)
- `docs/features/tickets/ticket-mutations.md` — ticket-centric mutations,
  `reconcile_ticket_status()`, `auto_assign_actor()`
- `docs/features/tickets/cvss-scoring.md` — CVSS resolution cascade,
  eligibility threshold comparison
- `docs/features/tickets/ticket-audit-log.md` — TicketAuditEvent field mapping
- `docs/features/packages/ibs-track-release-detection.md` — IBS
  track-level release detection
- `docs/features/packages/ibs-product-release-detection.md` — IBS
  product-level release detection
- `docs/features/packages/ibs-submission-tracking.md` — SR/RR tracking,
  delivery pipeline, SyncIbsRequests
- `docs/features/integrations/ibs-rabbitmq-integration.md` — real-time
  IBS event consumption
- `docs/features/packages/product-lifecycle-transitions.md` — EOL and
  Reactive Support handling
- `docs/features/packages/package-maintainership.md` — package-wide maintainer
  acquisition, persistence, privacy, and authorization
- `docs/features/platform/system-settings.md` — default CVSS version configuration
- `docs/data-model.md` — full database schema
