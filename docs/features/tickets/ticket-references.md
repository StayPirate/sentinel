# Ticket References

## Purpose

Provide a curated collection of external links on each ticket that helps
Vulnerability Analysts study and understand the vulnerability being
tracked. References connect tickets to external resources such as NVD
entries, vendor advisories, GitHub Security Advisories, upstream patches,
commits, pull requests, bug tracker entries, blog posts, and any other
relevant web resource.

References come from two sources:

- **Automatic**: created by CVE fetchers during ingestion. Each fetcher
  adds its own source URL (if it has a human-readable page) plus all
  references extracted from the CVE data. Automatic references are
  system-managed and cannot be edited or deleted by users.
- **Manual**: added by users with the `manage_references` capability
  through the API for any purpose (e.g., linking a Bugzilla bug, an
  upstream commit, a blog post with analysis). Manual references can be
  freely edited and deleted by any user with the `manage_references`
  capability.

All references are stored in a single `TicketReference` table associated
with the ticket, regardless of their origin. The UI presents references
grouped by type so the VA can quickly scan them and follow relevant links
for deeper analysis.

## Data Model

See `docs/data-model.md` for the full schema. Key entities:

- **ReferenceType**: content classification enum
- **TicketReference**: stores external links associated with a ticket

### ReferenceType Enum

Classifies the content that a reference URL points to.

| Value      | Description                                              |
|------------|----------------------------------------------------------|
| `advisory` | Security advisory (NVD, GHSA, vendor advisory, VDB entry) |
| `patch`    | Fix artifact: patch, commit, pull request, merge request |
| `issue`    | Bug tracker entry, issue report                          |
| `article`  | Blog post, write-up, technical analysis, mailing list post |

A `NULL` type means the reference could not be classified by any
available mechanism (upstream tags, URL pattern matching, or explicit
user choice). It is functionally equivalent to "uncategorized".

### TicketReference

| Column      | Type                       | Constraints                  | Description                        |
|-------------|----------------------------|------------------------------|------------------------------------|
| id          | UUID                       | PK                           | Internal identifier                |
| ticket_id   | UUID                       | FK(ticket.id) ON DELETE CASCADE, NOT NULL | Related ticket                     |
| url         | VARCHAR(2048)              | NOT NULL                     | URL of the external resource       |
| title       | VARCHAR(500)               | nullable                     | Human-readable label               |
| description | VARCHAR(2000)              | nullable                     | Short note explaining relevance    |
| type        | VARCHAR(20)                | nullable                     | Content classification. NULL = uncategorized |
| source      | VARCHAR(100)               | NOT NULL                     | Origin: fetcher name (e.g., `"sync_nvd_cves"`) or `"manual"` for user-added references |
| created_at  | TIMESTAMPTZ                | NOT NULL, DEFAULT            | Record creation timestamp          |
| updated_at  | TIMESTAMPTZ                | NOT NULL, DEFAULT            | Record update timestamp            |

**Unique constraint**: `(ticket_id, url)` — a URL cannot appear twice on
the same ticket.

**Field lengths**:
- `url`: max 2048 characters (covers virtually all real URLs)
- `title`: max 500 characters
- `description`: max 2000 characters

## Type Auto-Classification

References receive a `type` value through three mechanisms, applied in
priority order.

### Classification Priority

1. **Explicit choice** (highest): the user provides `type` in the API
   request (manual references only)
2. **CVE source tag mapping**: the fetcher maps upstream tags (e.g., NVD
   reference tags) to a `ReferenceType` value
3. **URL pattern matching**: the system infers `type` from known URL
   patterns
4. **Default** (lowest): `NULL` (uncategorized)

### CVE Source Tag Mapping

When a CVE fetcher processes references from upstream data, each
reference may carry tags from the source. NVD API v2 uses Title Case
strings (e.g., `"Vendor Advisory"`); MITRE CVE JSON 5.x uses kebab-case
(e.g., `"vendor-advisory"`). Both formats are mapped to `ReferenceType`
values but are **not stored** on the `TicketReference` record — they are
consumed during classification only.

| NVD Tag                  | MITRE Tag              | ReferenceType |
|--------------------------|------------------------|---------------|
| `Patch`                  | `patch`                | `patch`       |
| `Vendor Advisory`        | `vendor-advisory`      | `advisory`    |
| `Third Party Advisory`   | `third-party-advisory` | `advisory`    |
| `US Government Resource` | `government-resource`  | `advisory`    |
| `VDB Entry`              | `vdb-entry`            | `advisory`    |
| `Issue Tracking`         | `issue-tracking`       | `issue`       |
| `Exploit`                | `exploit`              | `article`     |
| `Mailing List`           | `mailing-list`         | `article`     |
| `Release Notes`          | `release-notes`        | `article`     |
| `Technical Description`  | `technical-description`| `article`     |
| `Mitigation`             | `mitigation`           | `article`     |
| `Press/Media Coverage`   | `media-coverage`       | `article`     |
| `Tool Signature`         | `signature`            | `article`     |
| `Broken Link`            | `broken-link`          | `NULL`        |
| `Not Applicable`         | `not-applicable`       | `NULL`        |
| `Permissions Required`   | `permissions-required` | `NULL`        |
| `URL Repurposed`         | —                      | `NULL`        |
| `Product`                | `product`              | `NULL`        |
| —                        | `customer-entitlement` | `NULL`        |
| —                        | `related`              | `NULL`        |
| All others / no tags     |                        | `NULL`        |

When a reference has multiple tags, the highest-priority type wins.
Priority order: `patch` > `advisory` > `issue` > `article`.

### URL Pattern Matching

When no upstream tag is available (or tags do not map to a known type),
the system attempts to infer the type from the URL. This applies to
both automatic and manual references.

| URL Pattern                              | ReferenceType |
|------------------------------------------|---------------|
| `github.com/*/commit/*`                  | `patch`       |
| `github.com/*/pull/*`                    | `patch`       |
| `gitlab.com/*/commit/*`                  | `patch`       |
| `gitlab.com/*/-/merge_requests/*`        | `patch`       |
| `git.kernel.org/*/commit/*`              | `patch`       |
| `github.com/advisories/GHSA-*`          | `advisory`    |
| `github.com/*/security/advisories/*`    | `advisory`    |
| `nvd.nist.gov/vuln/detail/*`            | `advisory`    |
| `cve.org/CVERecord*`                    | `advisory`    |
| `access.redhat.com/security/cve/*`      | `advisory`    |
| `access.redhat.com/errata/*`            | `advisory`    |
| `ubuntu.com/security/CVE-*`             | `advisory`    |
| `www.debian.org/security/*`             | `advisory`    |
| `security.gentoo.org/*`                 | `advisory`    |
| `www.oracle.com/security-alerts/*`      | `advisory`    |
| `security.netapp.com/advisory/*`        | `advisory`    |
| `www.zerodayinitiative.com/advisories/*`| `advisory`    |
| `msrc.microsoft.com/*`                  | `advisory`    |
| `support.apple.com/*`                   | `advisory`    |
| `www.mozilla.org/*/security/advisories/*`| `advisory`   |
| `errata.almalinux.org/*`               | `advisory`    |
| `bugzilla.suse.com/*`                   | `issue`       |
| `bugzilla.redhat.com/*`                 | `issue`       |
| `bugs.launchpad.net/*`                  | `issue`       |
| `savannah.gnu.org/bugs/*`              | `issue`       |
| `sourceware.org/bugzilla/*`            | `issue`       |
| `lists.fedoraproject.org/*`            | `article`     |
| `www.openwall.com/lists/*`             | `article`     |
| `seclists.org/*`                       | `article`     |
| `www.exploit-db.com/*`                 | `article`     |
| `lists.apache.org/*`                   | `article`     |

Patterns are matched case-insensitively against the URL host and path.
Case-insensitive host matching conforms to RFC 3986 §3.2.2.
Case-insensitive path matching deviates from RFC 3986 §3.3 (which
defines paths as case-sensitive). This is a deliberate choice: it
broadens classification matching without narrowing it, and the risk of
false-positive classification is negligible because the URL patterns
target well-known domains where path case variants point to the same
resource.

URLs that do not match any pattern remain with `type = NULL`
(uncategorized).

The pattern list is maintained in code and can be extended without schema
changes. Adding a new pattern does not retroactively reclassify existing
references — new patterns apply only to references created or updated
after the change.

## Fetcher Integration

### source_reference_url_pattern

CVE fetchers that inherit from `BaseCVEFetcher` (see
`docs/features/platform/cve-fetcher-infrastructure.md`) have an optional class
attribute `source_reference_url_pattern` that defines the URL pattern for
the fetcher's human-readable CVE page.

```python
class SyncNvdCves(BaseCVEFetcher):
    name = "sync_nvd_cves"
    description = "Incremental CVE sync from NVD"
    default_schedule = "0 */6 * * *"
    source_reference_url_pattern: str | None = "https://nvd.nist.gov/vuln/detail/{cve_id}"

class SyncMitreCves(BaseGitFetcher):  # inherits BaseCVEFetcher via BaseGitFetcher
    name = "sync_mitre_cves"
    description = "Syncs CVEs from MITRE"
    default_schedule = "0 */6 * * *"
    source_reference_url_pattern: str | None = "https://cve.org/CVERecord?id={cve_id}"
```

- When `source_reference_url_pattern` is set, the fetcher creates a
  `TicketReference` with the URL built from the pattern (replacing
  `{cve_id}` with the actual CVE ID).
- When `source_reference_url_pattern` is `None`, the fetcher does not
  use the automatic `{cve_id}` template mechanism to build the source
  URL. It may still create a source `TicketReference` by passing a
  manually constructed `source_url` to `upsert_references()` — for
  example, `sync_ghsa_advisories` uses the advisory's `html_url`
  (which contains the GHSA-ID, not the CVE-ID) and `sync_kernel_cves`
  constructs the URL from the git file path. If the fetcher passes
  `source_url=None`, no source reference is created (but upstream
  references from CVE data are still processed).
- The pattern uses `{cve_id}` as the only placeholder, formatted with
  the CVE identifier (e.g., `CVE-2026-3317`).

**Convention for new CVE fetchers**: when implementing a new fetcher that
ingests CVE data, the implementer must determine whether the fetcher's
source has a human-readable web page for each CVE. If it does,
`source_reference_url_pattern` must be set with the appropriate URL
pattern so that the URL is automatically added as a `TicketReference`.

### Ingestion Flow

When a CVE fetcher processes a CVE (new or updated), the following
reference-related steps are performed **after** the ticket exists (i.e.,
after CVE upsert and ticket creation for new CVEs). The fetcher calls
`reference_service.upsert_references()` (see Service Layer) with:

- `source`: the fetcher name (e.g., `"sync_nvd_cves"`)
- `source_url`: the source reference URL — built from
  `source_reference_url_pattern` when the pattern is defined, or
  manually constructed by the fetcher when the URL is not derivable
  from the CVE-ID alone, or `None` if no source reference applies
- `upstream_references`: the normalized list of references from the CVE
  data

**URL acceptance gate**: before writing any URL to the database (both
source reference and upstream references), `upsert_references()` applies a
lightweight validation gate:

1. Value must be a non-empty string (`None`, non-string types, or empty
   string `""` → skip)
2. Length ≤ 2048 characters
3. No control characters (U+0000–U+001F, U+007F)
4. Scheme must be `http` or `https`

URLs failing any criterion are skipped (not inserted or updated), the
violation is logged at WARNING level with the CVE ID and source for
operational visibility, and processing continues with the remaining
references (skip-and-continue strategy).

This gate is defense-in-depth for data arriving from external sources
(NVD, MITRE, etc.) where no Pydantic schema boundary exists. Manual
references validated at the API layer by Pydantic `HttpUrl` will never
reach this gate with invalid data, but the gate remains active for all
paths as a safety net.

**URL normalization**: before storage, all URLs are normalized as described
in the Upsert Strategy § URL Normalization section below. The unique
constraint `(ticket_id, url)` operates on the post-normalization value.

The service performs the following steps:

1. **Source reference** (if `source_url` is provided): upsert a
   `TicketReference` with:
   - `url`: the source URL (e.g.,
     `https://nvd.nist.gov/vuln/detail/CVE-2026-3317`)
   - `title`: short label derived from the source name (e.g., `"NVD"`
     for `sync_nvd_cves`, `"MITRE"` for `sync_mitre_cves`)
   - `type`: `advisory` (source pages are always advisories)
   - `source`: fetcher name (e.g., `"sync_nvd_cves"`)

2. **CVE data references**: for each reference in `upstream_references`,
   upsert a `TicketReference` with:
   - `url`: the reference URL from the CVE data
   - `title`: from the reference's `name` field when available (MITRE
     CVE JSON 5.x and kernel CVE data provide this field; NVD API v2
     does not). `NULL` when absent
   - `description`: `NULL`
   - `type`: auto-classified from source tags, then URL pattern, then
     `NULL` (see Type Auto-Classification)
       - `source`: fetcher name (e.g., `"sync_nvd_cves"`)

When `upstream_references` is an empty list, step 2 is a no-op — no
reference records are created or updated from CVE data. Step 1 (source
reference) executes normally if `source_url` is provided. The caller
must not skip the `upsert_references()` call when there are no upstream
references, because source reference creation is independent.

**Transaction boundary**: `upsert_references()` runs in the **same
per-CVE transaction** as `cve_service.upsert_cve()`. Both write to the
session buffer; the caller commits via `commit_and_dispatch()` after
both operations complete. Since all `upsert_references()` failure modes
are handled internally (URL validation gate: skip-and-continue;
IntegrityError: catch-and-merge), no exception propagates to the caller
under normal operation. Each individual reference upsert is independent
— if a single reference fails (e.g., a URL from upstream data exceeds
the 2048-character limit), the service logs the failure and continues
with the remaining references (skip-and-continue).

There is no stale reference cleanup step. Fetchers only insert and update
references — they never delete them. If an upstream source removes a
reference URL, the corresponding `TicketReference` remains in Sentinel.
This is by design: references are informational links collected over
time, and removal from an upstream source does not invalidate the
information at the URL.

### Upsert Strategy

#### URL Normalization

Before comparison or storage, every URL (automatic and manual) is
normalized:

1. **Scheme + host lowercased** (per RFC 3986 §3.1 and §3.2.2)
2. **`http://` normalized to `https://`**
3. **Trailing slash removed** when the path is empty or consists only
   of `"/"`

Normalization is applied at insertion time — the stored `url` field
contains the normalized form, so the uniqueness constraint
`(ticket_id, url)` automatically prevents near-duplicates.

#### Match Rules

References are matched by `(ticket_id, url)` — the unique constraint,
evaluated against the normalized URL.

- **New URL**: INSERT a new `TicketReference` with all fields from the
  fetcher data.
- **Existing URL, same source**: UPDATE `title`, `description`, and
  `type` if the fetcher provides new values. Since users cannot edit
  automatic references, the fetcher is the sole writer and can safely
  overwrite all fields.
- **Existing URL, different source**: fill in NULL fields only. For each
  of `type`, `title`, and `description`: if the existing value is NULL
  and the new source provides a non-NULL value, update the field.
  Non-NULL values are never overwritten by a different source.
- **Existing URL, manual source**: if the existing reference has
  `source = "manual"`, the fetcher skips it entirely — no fields are
  updated. This rule takes precedence over the cross-source
  fill-in-NULL-only rule above.

**Source field stability**: the `source` column is a stable identifier — the upsert strategy's same-source vs. different-source logic depends on its consistency over time. If a fetcher is renamed (its `BaseFetcher.name` attribute changes), an Alembic data migration is required to update the `source` field on existing `TicketReference` records. Without such migration, references from the renamed fetcher would be treated as originating from a "different source", degrading update propagation to fill-NULL-only semantics. See `docs/features/platform/fetcher-infrastructure.md` for the fetcher naming contract.

References are upserted individually within the batch. Each reference is
attempted as an INSERT. If the unique constraint `(ticket_id, url)` is
violated, the service catches the `IntegrityError`, re-queries the
existing record, and applies the merge rules above.

### Race Condition: Manual vs. Automatic

If a user adds a manual reference for a URL that a fetcher creates
moments later (or vice versa), the unique constraint prevents
duplicates:

- **Fetcher wins first**: the user's POST returns
  `409 RESOURCE_CONFLICT`. The user cannot edit the automatic
  reference (`409 RESOURCE_NOT_EDITABLE`). Any custom title or
  description the user intended is lost. The user can add a manual
  reference with a different URL if needed (e.g., a more specific
  anchor fragment).
- **User wins first**: the fetcher encounters the manual reference
  during upsert. Per the "existing URL, manual source" rule above,
  the fetcher skips it entirely — the user's title, description, and
  type are preserved.

This asymmetry is by design: manual references have editorial intent
that should not be overwritten by automated systems. The reverse
direction (automatic reference blocking a manual addition) is an
accepted trade-off — the URL is already present on the ticket and
accessible to the VA.

### Example

When the NVD fetcher processes CVE-2026-3317 for the first time, it
creates the following `TicketReference` records:

| url | title | type | source |
|-----|-------|------|--------|
| `https://nvd.nist.gov/vuln/detail/CVE-2026-3317` | `NVD` | `advisory` | `sync_nvd_cves` |
| `https://github.com/example/project/commit/a1b2c3` | NULL | `patch` | `sync_nvd_cves` |
| `https://www.example.com/en/security-notice/vuln-2026-001` | NULL | `advisory` | `sync_nvd_cves` |

If the MITRE fetcher later processes the same CVE and finds the same
GitHub commit URL, it skips that reference (already exists with
`source = "sync_nvd_cves"`). It adds only references with new URLs.

## Mutability

### Manual references

Users with the `manage_references` capability can add, edit, and delete
manual references (`source = "manual"`) on any ticket **regardless of
ticket status**, including tickets in an inactive status (Resolved, Ignored,
Duplicated).
References are supplementary metadata — adding, editing, or removing a
link does not constitute a ticket state change and is not subject to the
`ensure_ticket_operable()` guard.

### Automatic references

Automatic references (`source != "manual"`) are system-managed. They are
created and updated exclusively by fetchers. Users **cannot** edit or
delete automatic references through the API — the PATCH and DELETE
endpoints reject operations on automatic references with
`409 RESOURCE_NOT_EDITABLE`.

This separation ensures:

- **No delete+re-creation cycle**: users cannot delete an automatic
  reference that the fetcher would re-create on the next sync
- **No edit conflicts**: fetchers can safely update their references
  without overwriting user edits
- **Clear ownership**: fetchers own their references, users own theirs

**Tickets in inactive statuses**: fetchers still call
`upsert_references()` for tickets in inactive statuses (Resolved, Ignored,
Duplicated). `cve_service.upsert_cve()` processes CVE data regardless
of ticket status, and reference upserts follow the same policy —
existing references may be updated with new upstream data, and new
references from upstream are added. However, tickets in inactive statuses
will not receive new automatic references in practice unless the CVE
data itself is updated upstream, since the fetcher only processes CVEs
that have changed.

### CVE lifecycle events

- **CVE association with an existing CVE**: when a known CVE is
  associated with a ticket (via `associate-cve` or ticket creation with
  `cve_id`), references are **not** populated immediately. They are
  created by the periodic sync cycle when the fetcher next processes this
  CVE. This delay is accepted behavior — the VA can add manual
  references in the meantime if needed.

When a CVE is associated with a ticket that already has manual references
(e.g., references added by a VA while the ticket had no CVE), the
fetcher applies the standard upsert strategy at the next sync cycle.
URLs already present as manual references are skipped per the "existing
URL, manual source" match rule — the VA's chosen title, description, and
type are preserved. Only URLs not yet present on the ticket are added as
automatic references. See the Upsert Strategy section for the full merge
rules.

## Service Layer

All reference operations are implemented through `reference_service`
(`backend/app/services/reference_service.py`). Endpoint handlers and
fetchers delegate to this service rather than performing database
operations directly.

| Function | Caller | Responsibility |
|----------|--------|----------------|
| `upsert_references()` | CVE fetchers (`execute`, `fetch_single`) | Batch upsert of automatic references with type classification and source ownership |
| `create_reference()` | API POST handler | Create a manual reference with `source="manual"`, auto-classify type from URL |
| `update_reference()` | API PATCH handler | Update a manual reference, enforce immutability of automatic references, preserve type on URL change unless explicitly provided |
| `delete_reference()` | API DELETE handler | Delete a manual reference, enforce immutability of automatic references |
| `list_references()` | API GET handler | Query references with optional filters, ordered by type priority |

All functions receive the database session from the caller (never create
their own) to ensure transactional atomicity with the surrounding
operation.

Manual POST, PATCH, and DELETE mutations use the parent Ticket as their
serialization root. After input-only validation, the first persistent read
acquires `FOR UPDATE` on `ticket_id`. The service then resolves the target
reference, when applicable, under that lock and scopes it to
`(ticket_id, reference_id)`. Mutation classification, `old_value`, `new_value`,
and URL snapshots come only from this locked-current state. The unique
`(ticket_id, url)` constraint remains the final defense against concurrent
manual creation and automatic upsert races. Automatic fetcher upserts retain
their owning per-CVE transaction and conflict-merge contract; they do not
acquire Ticket after a CVE lock or create Ticket audit events.

### `upsert_references` signature

```python
async def upsert_references(
    session: AsyncSession,
    ticket_id: UUID,
    source: str,
    source_url: str | None,
    upstream_references: list[UpstreamReference],
) -> None
```

- `source`: the fetcher name (e.g., `"sync_nvd_cves"`)
- `source_url`: the fetcher's human-readable CVE page URL, either
  pre-built from `source_reference_url_pattern` or manually
  constructed by the fetcher when the source URL is not derivable
  from the CVE-ID (e.g., GHSA advisory URLs use the GHSA-ID). `None`
  if the fetcher does not produce a source reference for this CVE
- `upstream_references`: normalized list of references extracted from the
  CVE data by the fetcher, typed as:

  ```python
  class UpstreamReference(TypedDict):
      url: str                  # Reference URL from the CVE data
      tags: list[str] | None    # Upstream tags (e.g., ["Patch", "Vendor Advisory"])
      name: str | None          # Reference title from upstream data
  ```

  `name` is the reference title from the upstream data (MITRE CVE JSON
  5.x `name` field), or `None` when the source does not provide it (NVD
  API v2). `tags` carries the source classification labels consumed
  during type auto-classification (see CVE Source Tag Mapping)

The function handles: source reference creation, type classification
(tag mapping -> URL pattern -> default), and the upsert strategy (see
Upsert Strategy). Type classification logic is implemented internally
via `_classify_type()`.

## API Endpoints

### List References

```
GET /api/v1/tickets/{ticket_id}/references
```

**`Access: Public`**
**`Authentication: Optional`**

Returns all references for a ticket (both automatic and manual). This
endpoint is **not paginated** because the number of references per ticket
is expected to be small (typically fewer than 30). All references are
returned in a single response.

**Operational limit**: the design is optimized for ≤ 200 references per ticket. No hard cap is enforced. If production monitoring reveals tickets consistently exceeding this threshold, cursor-based pagination will be introduced as a backwards-compatible addition (the unpaginated response remains the default; pagination activates only when a `cursor` parameter is provided).

**Query parameters**:

| Parameter | Type   | Default | Description                                              |
|-----------|--------|---------|----------------------------------------------------------|
| source    | string | —       | Filter by source (e.g., `"sync_nvd_cves"`, `"manual"`)  |
| type      | string | —       | Filter by type (e.g., `"patch"`, `"advisory"`)           |

The `type` parameter follows the enum filter validation convention in
`docs/api-spec.md` — invalid values are silently ignored. The `source`
parameter is a free-form string; non-matching values return an empty
result set.

**Sorting**: results are ordered by type group priority, then by
`created_at` ascending within each group. The type group order is:

| Type       | Sort Priority |
|------------|---------------|
| `advisory` | 1             |
| `patch`    | 2             |
| `issue`    | 3             |
| `article`  | 4             |
| `NULL`     | 5 (last)      |

Client-controlled sorting is not supported (small dataset, defined
grouping order). When a ticket has no references (or all are filtered
out), the response returns `{"data": []}`.

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "ticket_id": "uuid",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-3317",
      "title": "NVD",
      "description": null,
      "type": "advisory",
      "source": "sync_nvd_cves",
      "created_at": "2026-04-21T10:20:00Z",
      "updated_at": "2026-04-21T10:20:00Z"
    },
    {
      "id": "uuid",
      "ticket_id": "uuid",
      "url": "https://github.com/example/project/commit/a1b2c3",
      "title": null,
      "description": null,
      "type": "patch",
      "source": "sync_nvd_cves",
      "created_at": "2026-04-21T10:20:00Z",
      "updated_at": "2026-04-21T10:20:00Z"
    },
    {
      "id": "uuid",
      "ticket_id": "uuid",
      "url": "https://bugzilla.suse.com/show_bug.cgi?id=12345",
      "title": "SUSE Bugzilla #12345",
      "description": "Upstream confirmed the fix; tracking SUSE-side packaging",
      "type": "issue",
      "source": "manual",
      "created_at": "2026-04-21T14:30:00Z",
      "updated_at": "2026-04-21T14:30:00Z"
    }
  ]
}
```

### Add Reference

```
POST /api/v1/tickets/{ticket_id}/references
```

Adds a manual reference to a ticket.

**Request body**:

```json
{
  "url": "https://bugzilla.suse.com/show_bug.cgi?id=12345",
  "title": "SUSE Bugzilla #12345",
  "description": "Upstream confirmed the fix; tracking SUSE-side packaging",
  "type": "issue"
}
```

| Field       | Type   | Required | Description                                |
|-------------|--------|----------|--------------------------------------------|
| url         | string | yes      | URL of the external resource               |
| title       | string | no       | Human-readable label                       |
| description | string | no       | Short note explaining relevance            |
| type        | string | no       | Content type (`advisory`, `patch`, `issue`, `article`). If omitted, auto-detected from URL pattern; `null` if no pattern matches |

**Response** (201 Created):

```json
{
  "data": {
    "id": "uuid",
    "ticket_id": "uuid",
    "url": "https://bugzilla.suse.com/show_bug.cgi?id=12345",
    "title": "SUSE Bugzilla #12345",
    "description": "Upstream confirmed the fix; tracking SUSE-side packaging",
    "type": "issue",
    "source": "manual",
    "created_at": "2026-04-21T14:30:00Z",
    "updated_at": "2026-04-21T14:30:00Z"
  }
}
```

**Validation rules**:
- `url` is validated as a Pydantic `HttpUrl` type, which enforces RFC 3986
  conformance. This guarantees: scheme is `https` or `http` (other schemes
  such as `javascript:`, `data:`, `ftp:` are rejected), a non-empty host
  component is present, and control characters (U+0000–U+001F, U+007F)
  are rejected. After validation, URL normalization is applied (see Upsert
  Strategy § URL Normalization); the post-normalization scheme is always
  `https://`. Only `https://` URLs are stored
- `url` must not exceed 2048 characters
- `url` must not already exist for this ticket (unique constraint)
- `title`, if provided, must not exceed 500 characters or be
  blank/whitespace-only
- `description`, if provided, must not exceed 2000 characters or be
  blank/whitespace-only
- `type`, if provided, must be a valid `ReferenceType` value

**Side effects**:
- `source` is always set to `"manual"`
- `type` is set to the provided value, or auto-detected from URL pattern,
  or `null` if no pattern matches
- A `reference_added` audit event is created with `new_value` = the
  normalized URL

The service holds the parent Ticket lock while classifying the normalized URL
and inserting the reference and event. If a concurrent create or automatic
upsert wins the unique key, the manual request returns `RESOURCE_CONFLICT` and
creates no event.

**`Capability: manage_references`**

**Error responses**:

| Status | Code                | Condition                                     |
|--------|---------------------|-----------------------------------------------|
| 409    | `RESOURCE_CONFLICT` | URL already exists for this ticket             |

### Update Reference

```
PATCH /api/v1/tickets/{ticket_id}/references/{reference_id}
```

Updates an existing manual reference (see Mutability for the
automatic/manual distinction). Follows partial update semantics (see
`docs/api-spec.md`, Partial Update Semantics). Sending `null` for
`title` or `description` clears the field.

The `reference_id` lookup is scoped to the `ticket_id` in the URL path.
A valid reference belonging to a different ticket returns
`404 RESOURCE_NOT_FOUND`.

When `url` is changed without an explicit `type` in the request body,
the existing `type` value is preserved unchanged. Automatic
re-classification from URL pattern matching applies only at creation time
(POST without `type`). To re-classify after a URL change, the client must
include `type` explicitly in the PATCH body (including `null` to reset to
uncategorized).

**Request body**:

```json
{
  "title": "Updated title",
  "description": "Added context after further analysis",
  "type": "patch"
}
```

| Field       | Type   | Required | Description                     |
|-------------|--------|----------|---------------------------------|
| url         | string | no       | URL of the external resource    |
| title       | string | no       | Human-readable label            |
| description | string | no       | Short note explaining relevance |
| type        | string | no       | Content type                    |

At least one field must be provided.

**Side effects**:
- For each field that changes, a corresponding audit event is created:
  `reference_url_changed`, `reference_type_changed`,
  `reference_title_changed`, or `reference_description_changed`
- A PATCH that changes multiple fields generates multiple audit events in
  the same transaction
- Changed-field events use this fixed insertion order:
  `reference_url_changed`, `reference_type_changed`,
  `reference_title_changed`, `reference_description_changed`
- The `detail` field on type/title/description events carries the
  post-normalization URL as locator (`{"url": "..."}`)

**Response** (200 OK):

```json
{
  "data": {
    "id": "uuid",
    "ticket_id": "uuid",
    "url": "https://bugzilla.suse.com/show_bug.cgi?id=12345",
    "title": "Updated title",
    "description": "Added context after further analysis",
    "type": "patch",
    "source": "manual",
    "created_at": "2026-04-21T14:30:00Z",
    "updated_at": "2026-04-22T09:15:00Z"
  }
}
```

**`Capability: manage_references`**

**Error responses**:

| Status | Code                    | Condition                                                |
|--------|-------------------------|----------------------------------------------------------|
| 404    | `RESOURCE_NOT_FOUND`    | Reference does not exist on this ticket                  |
| 409    | `RESOURCE_NOT_EDITABLE` | Reference is automatic (`source != "manual"`) — cannot be modified by users |
| 409    | `RESOURCE_CONFLICT`     | URL already exists for this ticket (if URL was changed)  |

### Delete Reference

```
DELETE /api/v1/tickets/{ticket_id}/references/{reference_id}
```

Deletes a manual reference (see Mutability for the automatic/manual
distinction).

The `reference_id` lookup is scoped to the `ticket_id` in the URL path.
A valid reference belonging to a different ticket returns
`404 RESOURCE_NOT_FOUND`.

**Response** (204 No Content)

**Side effects**:
- A `reference_deleted` audit event is created with `old_value` = the
  reference URL

If the locked lookup is missing, belongs to another Ticket, or was already
deleted by a concurrent winner, the operation returns the documented not-found
outcome and creates no event.

**`Capability: manage_references`**

**Error responses**:

| Status | Code                    | Condition                                        |
|--------|-------------------------|--------------------------------------------------|
| 404    | `RESOURCE_NOT_FOUND`    | Reference does not exist on this ticket           |
| 409    | `RESOURCE_NOT_EDITABLE` | Reference is automatic (`source != "manual"`) — cannot be deleted by users |

## Ticket Event Logging

Manual reference mutations generate `TicketAuditEvent` records. Automatic
reference operations (fetcher-driven) do NOT generate audit events — they
are traceable via fetcher execution history.

| Operation | Event types created |
|-----------|---------------------|
| Add (POST) | `reference_added` |
| Update (PATCH) | One event per changed field: `reference_url_changed`, `reference_type_changed`, `reference_title_changed`, `reference_description_changed` |
| Delete (DELETE) | `reference_deleted` |

All reference audit events set `user_id` to the acting user.
`comment` is always `NULL`. See `docs/features/tickets/ticket-audit-log.md`
for the full event type contract and detail JSONB schema.

Rejected, unchanged, not-found, and concurrent-loser manual outcomes create no
event. Every effective manual mutation and all of its events flush in the same
caller-owned transaction; an audit or database failure rolls back the complete
reference mutation. Automatic reference insert/update is an explicit no-event
boundary: current rows and fetcher execution history are its evidence, and
audit history is never reference state or upsert idempotency input.

## Security

- Reference list is publicly accessible (no authentication required)
- Adding, editing, and deleting references requires the `manage_references`
  capability
- Edit and delete operations are restricted to manual references
  (see Mutability)
- All manual references are editable/deletable by any user with the
  `manage_references` capability, regardless of who created them. All
  mutations are recorded in the ticket audit log for accountability
- URL scheme is restricted to `https://` after normalization (input
  `http://` is upgraded; all other schemes are rejected)
- The URL acceptance gate in `upsert_references()` provides defense-in-depth
  against injection vectors from compromised upstream sources (NVD, MITRE,
  etc.) by enforcing scheme, length, and control character validation on all
  automatic references before database insertion
- RFC 3986 conformance (enforced by Pydantic `HttpUrl`) rejects URLs
  containing control characters (U+0000–U+001F, U+007F), eliminating
  injection vectors from embedded control sequences in URL strings
- See `docs/features/identity/rbac.md` for the full permission model

## Testing Requirements

Implementation tests cover manual POST, PATCH, and DELETE with the parent
Ticket lock, exact event actor/values/comment/detail, rollback on audit failure,
and no-event outcomes for rejection, not found, unchanged PATCH fields, and a
concurrent loser. A multi-field PATCH asserts the fixed URL, type, title,
description event order. Independent-session tests prove that competing manual
mutations serialize on the Ticket and do not record stale old values.

Fetcher-upsert tests assert zero Ticket events for effective insert/update and
no-op outcomes while preserving current rows and fetcher execution evidence.

## Boundary with CVEExternalIdentifier

`TicketReference` and `CVEExternalIdentifier` (see `docs/data-model.md`)
are related but distinct concepts:

| Aspect      | TicketReference                               | CVEExternalIdentifier                          |
|-------------|-----------------------------------------------|------------------------------------------------|
| **Purpose** | Clickable links for the VA to research the vulnerability | Identity mapping: "this CVE is also known as GHSA-xxx" |
| **Scope**   | Ticket-level (one ticket, many links)         | CVE-level (one CVE, many external IDs)         |
| **Source**   | Automatic (fetchers) + manual (VAs)           | Automatic only (fetchers, read-only)           |
| **Content** | Any relevant URL (advisories, patches, blogs) | Structured identifiers from naming authorities |

A GitHub Security Advisory (GHSA) will typically appear in both:
- `CVEExternalIdentifier`: stores the `GHSA-xxxx-xxxx-xxxx` identifier
  and its canonical URL
- `TicketReference`: stores the same URL as a clickable advisory link
  for the VA

This is not redundancy — they serve different consumers and are
maintained independently. `CVEExternalIdentifier` feeds ticket search
(searching by GHSA-ID finds the ticket). `TicketReference` feeds the
VA's research workflow.

## Dependencies

- `docs/features/tickets/cve-tracking.md` — CVE ingestion flow creates
  references. Contains the full `sync_nvd_cves` fetcher definition
  (algorithm, NVD Source API caching, metrics)
- `docs/features/platform/cve-fetcher-infrastructure.md` — `BaseCVEFetcher`
  contract for `source_reference_url_pattern`
- `docs/features/tickets/cve-service.md` — `UpsertResult` usage for
  post-upsert reference creation

## Cross-references

- `docs/api-spec.md` — global API conventions (envelope format, error
  codes, pagination, shared 422 responses)
- `docs/features/identity/rbac.md` — `manage_references` capability,
  endpoint permission map
- `docs/data-model.md` — `TicketReference` table definition,
  `ReferenceType` enum, `CVEExternalIdentifier` boundary
