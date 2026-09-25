# CPE-to-Package Mapping

## Summary

Sentinel needs to convert NVD CPE strings (e.g.,
`cpe:2.3:a:gnu:emacs:*:*:*:*:*:*:*:*`) into SUSE source package names
(e.g., `emacs`) so the post-ingest package-resolution workflow can add affected
packages to Tickets after CVE ingestion. This spec defines:

1. A static JSON mapping file shipped with the application at
   `backend/app/data/cpe-package-mapping.json`
2. A resolution function (`resolve_cpe_packages`) that performs an
   in-memory lookup against the mapping, consumed by `package_service`'s
   post-ingest package-resolution workflow

## Context

An earlier design proposed a `BaseFetcher` subclass syncing a
`CPEPackageMapping` database table from the AIMAAS `cpe-map` endpoint.
That endpoint exposes complete CPE 2.3 names and their associated SUSE
packages. A daily fetcher, a dedicated database table, and a runtime
dependency on AIMAAS are unnecessary for this lookup.

This spec uses a static mapping file committed to the repository. The
tradeoff is explicit:

| Aspect | Fetcher approach | Static file approach |
|--------|-------------|-------------------|
| Update mechanism | Automatic daily sync | Manual file edit + deploy |
| External dependency | AIMAAS at runtime | None |
| DB table + migration | Yes | No |
| Risk of empty/truncated upstream data | Yes (requires safety guards) | None at runtime |
| Mapping precision | Depends on imported projection | Canonical `vendor:product` key |
| Complexity | BaseFetcher + error handling + metrics | One JSON file + dict lookup |

The static file approach is appropriate because:

- Mapping changes can be reviewed and deployed with the application
- The dataset is small (~2,500 entries, <200 KB)
- Eliminating runtime AIMAAS dependency reduces failure modes
- The file is version-controlled, providing full change history via git

## Static Mapping File

### Location

`backend/app/data/cpe-package-mapping.json`

### Format

A JSON object where each key is a canonical `vendor:product` pair and
each value is an array of SUSE source package names:

```json
{
  "apache:commons_compress": ["apache-commons-compress"],
  "gnu:emacs": ["emacs"],
  "alsa-project:alsa": ["alsa", "python-alsa", "python3-alsa"],
  "rust-lang:rust": ["cargo", "rust", "rust1.84", "..."]
}
```

Key characteristics:

- **Key format**: the canonical serialization defined in CPE String
  Parsing. One unescaped `:` separates vendor from product; literal
  colons and backslashes inside either component are escaped
- **Semantic form**: CPE formatted-string escapes other than `\:` and
  `\\` do not appear in mapping keys. For example, CPE component
  `xerces-c\+\+` is stored as `xerces-c++`
- **1:N mapping**: a single CPE key can map to multiple SUSE packages
  (~8% of entries). Example: `rust-lang:rust` maps to 45 packages
- **Sorted**: entries are sorted alphabetically by key for readability
  and merge-friendly diffs. Ordering uses Python `sorted()` semantics on
  the raw canonical key text, not the decoded semantic pair
- **No soft-delete**: if a mapping is no longer relevant, the entry is
  removed from the file entirely

### Statistics

| Metric | Value |
|--------|-------|
| Total entries (vendor:product keys) | ~2,450 |
| Total package mappings (flattened) | ~2,800 |
| 1:N entries (multiple packages) | ~190 |
| Max packages per key | 45 (`rust-lang:rust`) |
| File size | <200 KB |

### Maintenance

The mapping file is maintained through reviewed repository changes. When
a new CPE product needs to be mapped to a SUSE source package (e.g., a
new upstream project starts being tracked by SUSE), a developer or
security engineer adds the entry and deploys the update.

The AIMAAS `GET /api/entity/cpe-map` endpoint may be used as an
out-of-band input to a manual update, but its complete CPE names must be
parsed and canonicalized according to this specification before review.
There is no automated sync. The committed file is the sole runtime
source of truth; AIMAAS is not a Sentinel runtime dependency.

Every deployed mapping file MUST conform to the canonical grammar before
the loader and CI validation are enabled for it. Repository work that
introduces validation is responsible for normalizing any pre-existing
non-canonical entries in the same change.

**Operational workflow for mapping changes**: when a mapping entry is
added or modified, the person making the change SHOULD:

1. Identify active tickets whose CVEs include the affected
   `vendor:product` CPE entry (search via the NVD API or the ticket
   list filtered by CVE)
2. Manually add the newly mapped package(s) to any relevant tickets
   via `add_package_to_ticket()`
3. Document the affected CVEs in the commit message for traceability

This manual step is necessary because existing tickets are not
automatically re-resolved when the mapping changes (see Integration
notes, "Mapping changes vs existing CVEs").

**CI validation**: the focused mapping tests validate the committed file
on every change through the repository's existing blocking test workflow:

- Valid UTF-8 and JSON object syntax
- Keys are canonical, unique after semantic decoding, and sorted
  alphabetically
- Every value is a non-empty array of strings (no empty arrays, no
  non-string elements, no empty or untrimmed strings)

This prevents manual editing errors from reaching deployment. An empty
array value would suppress the raw-product fallback (the key exists,
so the function returns the mapped value instead of falling back),
effectively making the CPE entry unmappable -- the CI check rejects
this case.

## CPE String Parsing

Both the resolution function and any future consumer that needs to
extract fields for package lookup use the same parsing and canonical
serialization rules.

**Supported format**: CPE 2.3 only. NVD API v2 uses CPE 2.3
exclusively. CPE 2.2 strings (`cpe:/...`) are treated as parse errors
(logged and skipped) because the encoding rules differ (URI
percent-encoding vs. backslash escaping) and the current dataset
contains no CPE 2.2 entries. If a future data source provides CPE 2.2
strings, the parser must be extended with proper encoding handling at
that time.

### Formatted-string decoding

The parser treats an unescaped `:` as a component separator. Within a
component, `\` escapes the following character; that character becomes
part of the semantic component value and the escape marker is removed.
A trailing unpaired `\` is invalid. This rule applies to all components,
so an escaped colon in version or edition data does not shift the vendor
or product indexes.

The algorithm is:

1. Require the exact `cpe:2.3:` prefix; otherwise report a parse error.
2. Scan the remainder once, splitting only on unescaped `:` and decoding
   each escaped character into its semantic value.
3. Require exactly 11 decoded components: `part`, `vendor`, `product`,
   `version`, `update`, `edition`, `language`, `sw_edition`, `target_sw`,
   `target_hw`, and `other`. A different count or an unpaired escape is a
   parse error.
4. Extract `vendor` and `product`; the other components do not affect
   package lookup.
5. Trim leading/trailing whitespace from and lowercase the two extracted
   semantic values. The parser does not replace spaces or punctuation
   within CPE components.

On a parse error, `resolve_cpe_packages()` logs WARNING
`cpe_parse_failed` without logging the complete untrusted CPE string and
returns an empty set. Parse errors do not raise an exception.

### Canonical mapping-key serialization

The mapping key is a reversible serialization of the normalized semantic
vendor and product values:

1. Within each component, serialize a literal `\` as `\\` and a literal
   `:` as `\:`. All other characters are serialized unchanged.
2. Join the serialized components with one unescaped `:`.

The result therefore contains exactly one unescaped separator. JSON then
applies its own string escaping to the serialized key; JSON escaping is
not part of the mapping-key grammar.

The loader validates canonical form by decoding each key, serializing it
again, and requiring byte-for-byte equality. This rejects multiple textual
representations of the same semantic pair. Examples below show mapping-key
text before JSON escaping:

| CPE vendor/product fields | Canonical key |
|---|---|
| `apache`, `xerces-c\+\+` | `apache:xerces-c++` |
| `criu`, `checkpoint\/restore_in_userspace` | `criu:checkpoint/restore_in_userspace` |
| `cpan`, `file\:\:temp` | `cpan:file\:\:temp` |
| `example`, `path\\name` | `example:path\\name` |

**Example** (standard):

```
Input:  cpe:2.3:a:apache:commons_compress:1.21:*:*:*:*:*:*:*
Strip:  a:apache:commons_compress:1.21:*:*:*:*:*:*:*
Decode: [a, apache, commons_compress, 1.21, *, *, *, *, *, *, *]
Key:    apache:commons_compress
```

**Example** (escaped colon):

```
Input:  cpe:2.3:a:cpan:file\:\:temp:*:*:*:*:*:*:*:*
Decode: [a, cpan, file::temp, *, *, *, *, *, *, *, *]
Key:    cpan:file\:\:temp
```

### Wildcard and NA values

The unescaped CPE formatted-string components `*` (ANY) and `-` (NA)
retain their special meaning only when the encoded component consists of
that single character. The parser retains this classification while
decoding the semantic value:

- Product `*`, product `-`, or an empty product produces no package
  candidate. `resolve_cpe_packages()` returns an empty set without
  loading the mapping.
- Vendor `*`, vendor `-`, or an empty vendor cannot form an exact mapping
  lookup. With a concrete product, the resolver returns the normalized
  semantic product through the raw-product fallback.
- An escaped literal asterisk or hyphen is a normal component value, not
  ANY or NA.

## Resolution Function

The functions in this section create no audit events. A successful first
call may read and cache the mapping file; later calls use that process-local
cache. They do not mutate database state or invoke external services.

### `resolve_cpe_packages()`

Converts a CPE 2.3 string into a set of SUSE source package names.
It performs file I/O only when a concrete lookup first requires the lazy
mapping loader.

**Signature**:

```python
def resolve_cpe_packages(cpe_criteria: str) -> set[str]:
```

Note: the function is **synchronous** (no `async`, no database session).
It can be called from any context without performance concerns.

**Algorithm**:

1. Parse and decode the CPE using CPE String Parsing.
2. On a parse error or non-concrete product, return an empty set.
3. If the vendor is non-concrete, return the normalized semantic product
   as a single-element set without loading the mapping.
4. Serialize the canonical vendor/product key and load the cached mapping.
5. If the key exists, return a new set containing its mapped SUSE package
   names. Otherwise return the normalized semantic product as a
   single-element set.

**Fallback behavior**: when no mapping exists for a concrete product,
the function returns its decoded, lowercased semantic value as a
single-element set. CPE escape markers are never passed to SMELT. This
optimistic fallback is consistent with SMASH (the predecessor system)
and works correctly when the CPE product name happens to match the SUSE
package name (e.g., `emacs`). When the names differ (e.g., CPE
`linux_kernel` vs SUSE `kernel-source`), the subsequent
`add_package_to_ticket()` call queries SMELT, which returns zero
results, and the package is not added (see `package-service.md`,
`add_package_to_ticket()`, `PACKAGE_NOT_FOUND_IN_SMELT` error). No
phantom data is created.

**Loading**: the mapping dict is loaded lazily on the first lookup that
has concrete vendor and product values, then cached for subsequent calls
via `functools.lru_cache(maxsize=1)` on the internal loader function.
The loader resolves `data/cpe-package-mapping.json` relative to the
installed `app` package. Its behavior is independent of the process
working directory. The resource MUST be included in the installed wheel
and container image.

The lazy-init pattern avoids coupling all modules that transitively
import `cpe_mapping` to the existence of the JSON file, improving
test ergonomics (tests that don't exercise CPE resolution can import
the module freely without requiring the data file).

**Runtime validation contract**:

Package resolution is a best-effort mechanism — the platform functions
without curated overrides (tickets are created normally, the raw-product
fallback remains active, and VAs can add packages manually). This informs
the loader's error handling: absence or emptiness of the file is a
degraded-but-operational state, not a fatal error.

**Exception**: `CPEMappingLoadError` — a `RuntimeError` subclass
defined beside the loader in `backend/app/services/cpe_mapping.py`.
Message format: `CPE mapping load failed at {path}: {reason}`.
`{reason}` identifies the failed rule and, for structural failures,
the offending key or zero-based array index; it never includes file
contents or package values.

**Loader behavior by file state**:

| Condition | Behavior | Rationale |
|-----------|----------|-----------|
| File does not exist | Log WARNING `cpe_mapping_absent`; return empty dict | Curated overrides unavailable; raw-product fallback remains active |
| File exists, zero bytes or whitespace-only | Log WARNING `cpe_mapping_absent`; return empty dict | Equivalent to absent — no meaningful content to parse |
| File exists, parsed root is an empty JSON object | Log WARNING `cpe_mapping_empty`; return empty dict | Explicitly no curated overrides; raw-product fallback remains active |
| File exists, parsed root has at least one entry and is structurally valid | Return populated dict | Normal operation |
| File exists, non-empty, structurally invalid | Raise `CPEMappingLoadError` | Corrupted file = deployment bug; partial/wrong mappings are worse than no mappings |

A zero-byte or whitespace-only file is treated as absent. After parsing,
any root object with zero entries (including `{}`, `{ }`, or a
pretty-printed equivalent) is the `cpe_mapping_empty` case. Validation
rules 4–6 apply only when the parsed object contains at least one entry.

**Validation rules** (applied only when file exists and is non-empty;
checked in order, first failure raises `CPEMappingLoadError`):

1. The file is readable and valid UTF-8.
2. The content is syntactically valid JSON.
3. The root value is an object (not array, string, null, etc.).
4. No duplicate keys exist. The loader MUST use a pair-preserving
   decoder hook because a standard dict silently retains only the last
   duplicate.
5. Every key decodes to exactly two non-empty components separated by
   one unescaped `:`. Both decoded components are lowercase and equal
   their whitespace-trimmed forms. Re-serializing them with Canonical
   Mapping-Key Serialization must reproduce the original key exactly.
6. Every value is a non-empty array of strings. Every string is
   non-empty after trimming and must equal its trimmed form.

Semantic key uniqueness needs no separate rule. Rule 5 makes every key
the canonical serialization of its decoded pair, and canonical
serialization is injective, so two keys decoding to the same pair would be
textually identical and rejected by rule 4. A non-canonical spelling of an
existing pair (for example, `apache:xerces-c\+\+` beside
`apache:xerces-c++`) fails rule 5.

**Not enforced at runtime** (CI-only): alphabetical key ordering.
Unsorted but otherwise valid JSON loads successfully.

**Cache behavior**: the loader uses `@lru_cache(maxsize=1)` and
returns `dict[str, tuple[str, ...]]` (immutable tuples for package
lists). Both successful loads (populated or empty dict) are cached. A
load that raises `CPEMappingLoadError` stores no entry — the next
call retries a full read and revalidation. After one successful load,
subsequent calls return the cached mapping without file I/O. There is
no hot-reload or cache invalidation; a mapping update requires a new
deployment and process restart.

`FileNotFoundError` and `NotADirectoryError` are treated as the absent-file
case even if raised while opening the package-relative resource. Other
file I/O errors (`PermissionError`, `IsADirectoryError`, and other
`OSError` subclasses) are wrapped in `CPEMappingLoadError` with the
underlying OS error as `{reason}`. These indicate deployment or mount
issues that prevent determining file state.

Non-`OSError` exceptions (`MemoryError`, `KeyboardInterrupt`, etc.)
propagate unchanged — they are not wrapped in `CPEMappingLoadError`.

**Operational semantics**: the mapping file is treated as source code —
committed to the repository, versioned, and reviewed via normal code
review. A process loads it only when it invokes a resolver with concrete
lookup values. A successful result remains immutable in memory for the
process lifetime. Modifications require a commit and new deployment;
there is no hot reload or runtime cache invalidation.

Generic worker startup never imports or validates CPE mapping data. A
corrupt non-empty file therefore fails the first task that requires a
concrete mapping lookup, while unrelated generic worker tasks remain
operational. Any future eager check may run only in a process or task
role dedicated to a real mapping consumer. No eager check is currently
required. If one is introduced, its reusable contract belongs to the
mapping module and its invocation belongs to the consuming workflow. Such
a check belongs in the Service or Task layer, never in `app/core`, because
Core cannot import Service code.

**Location**: `backend/app/services/cpe_mapping.py`

**Re-invocation and exceptions**: calls are deterministic for a fixed
process cache. Parse errors and non-concrete products return an empty set.
The function propagates `CPEMappingLoadError` and unexpected loader
exceptions unchanged. It does not cache failures.

### `resolve_vendor_product()`

Converts a free-text vendor/product pair (from CNA/ADP `affected[]`
arrays) into a set of SUSE source package names. Uses the same mapping
dict as `resolve_cpe_packages()`, bypassing CPE 2.3 string parsing.

**Signature**:

```python
def resolve_vendor_product(vendor: str, product: str) -> set[str]:
```

Note: the function is **synchronous** (no `async`, no database session).
It can be called from any context without performance concerns.

**Algorithm**:

1. Strip leading/trailing whitespace, lowercase both inputs, and replace
   each internal space with `_`. Other punctuation is preserved.
2. If product is empty, `*`, or `-`, return an empty set.
3. If vendor is empty, `*`, or `-`, return the normalized product as the
   raw-product fallback without loading the mapping.
4. Canonically serialize the normalized vendor/product pair and load the
   cached mapping.
5. If the key exists, return a new set containing its mapped package
   names. Otherwise return the normalized product as a single-element
   set.

**Normalization rationale**: CNA/ADP values are free text, while CPE
multi-word values commonly use underscores. The space-to-underscore
heuristic preserves the existing best-effort match behavior without
rewriting other punctuation. Both resolvers produce identical keys when
the free-text values correspond to CPE-normalized words — e.g., CNA
`vendor = "Apache"`, `product = "Commons Compress"` and CPE fields
`apache`, `commons_compress`.

**Fallback behavior**: identical to `resolve_cpe_packages()` — when no
mapping exists, returns the normalized product name as a single-element
set. The subsequent `add_package_to_ticket()` call validates against
SMELT. No phantom data is created.

**Match rate expectations**: this is a best-effort mechanism. Many
CNA-provided vendor/product values use marketing names that differ from
CPE-normalized identifiers (e.g., `"Google"` / `"Chrome"` vs CPE
`"google"` / `"chrome"` — matches; but `"The Apache Foundation"` /
`"HTTP Server"` vs CPE `"apache"` / `"http_server"` — does not match
because the vendor identifiers differ).
Even a partial match rate provides value by reducing manual VA work.

**Loading**: shares the same lazily-loaded mapping dict as
`resolve_cpe_packages()`. No additional file reads or initialization.

**Re-invocation and exceptions**: identical to
`resolve_cpe_packages()`. It propagates `CPEMappingLoadError` and
unexpected loader exceptions unchanged.

**Location**: `backend/app/services/cpe_mapping.py` (same module as
`resolve_cpe_packages()`)

### Consumers

| Consumer | Where | How |
|----------|-------|-----|
| Post-ingest CVE package resolution — NVD CPE | `package_service` post-ingest workflow | Exact-deduplicate transported criteria, then call `resolve_cpe_packages(criteria)` for each CPE entry already selected by the NVD ingestion contract; do not reinterpret NVD applicability |
| Post-ingest CVE package resolution — affected-entry CPE | `package_service` post-ingest workflow | Exact-deduplicate with all other transported CPE criteria, then call `resolve_cpe_packages(cpe)` |
| Post-ingest CVE package resolution — affected-entry vendor/product | `package_service` post-ingest workflow | Exact-deduplicate pairs, then call `resolve_vendor_product(vendor, product)` |
| Post-ingest CVE package resolution — package-name candidate | `package_service` post-ingest workflow | Combine each transported value with resolver results before the package-domain grammar, exact-deduplication, and ordering gate; the historical field name does not assert an exact SUSE package match |

`cve_service` only builds the deterministic serializable handoff; it does not
call either resolver or `add_package_to_ticket()`. Deduplication and ordering of
transported values are owned by `build_post_ingest_tasks()`. The complete
resolver-result combination, package validation, transaction, task, and
recovery lifecycle is owned by `package-service.md` (Post-ingest CVE package
resolution) and is not duplicated here.

**Integration notes**:

- **NVD applicability ownership**: the resolution function accepts one
  CPE already selected by its caller and is intentionally unaware of NVD
  configuration trees, logical operators, `negate`, version ranges, and
  the `vulnerable` flag. The NVD ingestion specification must define
  which CPE entries are package candidates before any consumer processes
  NVD configuration data. This specification neither includes nor
  excludes `vulnerable=false` entries
- **Version data is informational only**: version ranges from
  `CVEAffectedVersion` records are stored and displayed to VAs but
  are NOT used for package resolution or affectedness determination.
  SUSE backport practices make upstream version information unreliable
  for determining whether a specific track is affected. The VA
  determines affectedness at the track level after packages are added
- **Mapping changes vs existing CVEs**: recovery and re-resolution after a
  mapping change follow the opportunistic recovery paths owned by
  `package-service.md` (Post-ingest CVE package resolution). This resolver
  contract creates no separate rescan or progress model

## Verification

The focused mapping tests cover at least:

- package-relative loading from a working directory outside the source
  tree and presence of the resource in the installed package;
- absent, zero-byte, whitespace-only, empty-object, valid, malformed,
  unreadable, and structurally invalid files;
- duplicate textual keys, duplicate semantic keys, key round trips,
  ordering, and value validation against the committed file;
- success and empty-result caching, failure non-caching, and exception
  propagation;
- standard CPEs, escaped punctuation, escaped colons and backslashes,
  malformed strings, CPE 2.2 rejection, and ANY/NA handling; and
- exact mapping hits, one-to-many mappings, raw-product fallback, and
  equivalent results from both public resolvers.

Consumer integration tests do not duplicate the loader and resolver
contract tests. Runtime AIMAAS ingestion, database persistence, and a
`BaseFetcher` mapping synchronization remain out of scope.

## Security

- **No external I/O**: the resolution function reads from an in-memory
  dict loaded lazily at first use (in worker processes). No network
  calls, no database queries
- **Input validation**: CPE strings are validated during parsing. Strings
  that cannot be parsed are logged and skipped, never passed through
  to downstream operations
- **No user-controlled input**: the mapping data is committed to the
  repository and reviewed via normal code review. The resolution
  function receives CPE strings from the NVD ingestion payload
  (`CVEIngestPayload`), not from user input
- **No secrets**: no credentials, tokens, or API keys are involved

## Cross-references

- `docs/features/tickets/cve-service.md` -- pure PostIngestTasks candidate
  extraction; not a consumer of either resolver
- `docs/features/tickets/cve-tracking.md` -- post-ingest candidate handoff
- `docs/features/packages/package-model.md` -- Adding Packages to a
  Ticket (`add_package_to_ticket()`)
- `docs/features/packages/package-service.md` --
  `add_package_to_ticket()` function specification
- `docs/features/platform/fetcher-infrastructure.md` -- generic Worker
  Startup Handler
- `docs/architecture.md` -- Backend Layer Architecture
- `docs/data-sources.md` -- AIMAAS endpoint catalog
- `docs/api-spec.md` -- global API conventions (envelope format, error
  codes, pagination)
