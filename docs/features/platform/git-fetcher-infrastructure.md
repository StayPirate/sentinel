# Git-Based Fetcher Infrastructure

## Purpose

Shared infrastructure for fetchers that synchronize data from external
Git repositories. Defines the BaseGitFetcher template-method class, the
git_operations.py utility module, and operational requirements (clone
pattern, cursor, recovery, worker affinity).

Current consumers: `sync_mitre_cves`, `sync_kernel_cves`.

Note: `git_operations.py` is independently usable by non-BaseGitFetcher
fetchers that need git operations without the template-method lifecycle
(see "When NOT to Use BaseGitFetcher" section).

## Position in Hierarchy

```
fetcher-infrastructure.md
  BaseFetcher (lifecycle, metrics, FetcherRun, cursor, registry)
  │
  │  cve-fetcher-infrastructure.md
  └── BaseCVEFetcher (cve_source_type, fetch_single, catch_up)
      │
      │  git-fetcher-infrastructure.md (this document)
      └── BaseGitFetcher (clone, fetch, delta, recovery, SHA ops,
          │               queue="git", template method execute(),
          │               default fetch_single implementation)
          ├── SyncMitreCves
          └── SyncKernelCves
```


Some fetchers synchronize data from external Git repositories rather
than HTTP APIs. These fetchers share common infrastructure requirements
documented in this document. Individual fetcher specs define their own
algorithm, metrics, and source-specific behavior; this document defines
only the shared operational pattern.

## Bare Clone Pattern

Git-based fetchers use **bare clones without a working tree**. This
minimizes disk usage (no checkout of hundreds of thousands of files)
while providing full access to file contents via Git object store
operations.

The pattern:

1. **Clone** (first run only — clone directory does not exist OR is not
   a valid bare git repository): `git clone --bare --single-branch -- <url> <dest>`
   into `$GIT_CLONE_BASE_DIR/<subdirectory>/`. All git-based fetchers use
   plain bare clones. The `clone_filter` attribute is available for
   sources that require deferred blob downloads (partial clone), but no
   current fetcher uses it. All blobs are downloaded during `git clone`
   and `git fetch`, making subsequent `show_file()` calls purely local.
   **Validity check**: before deciding "first run vs. subsequent run",
   verify the directory is a valid bare git repository via
   `git rev-parse --git-dir`. If the directory exists but the check
   fails (partially-initialized clone from a previous interrupted
   attempt), delete the directory and proceed with a fresh clone.
2. **Fetch** (subsequent runs): `git fetch origin` updates refs and
   downloads new objects. This is incremental and typically completes in
   seconds.
3. **Delta detection**: `git diff --name-only --no-renames
   --diff-filter=AM <old_sha>..<new_sha>` returns the list of Added and
   Modified files.    Deleted files are excluded — they do not represent
   CVE data that needs processing. Rename detection is explicitly
   disabled (`--no-renames`) so that the diff operates exclusively on
   local tree/commit objects — no blob content comparison is needed,
   ensuring deterministic output regardless of clone type. A file rename appears as
   a separate Delete (old path, excluded) + Add (new path, included);
   the new path is processed normally.
4. **File content access**: `git show -- <ref>:<path>` reads a single
   file's content from the object store without creating a working tree.
   All blobs are present locally after `git fetch`, so this operation
   requires no network access.

No `git merge`, `git checkout`, or working tree manipulation is
performed at any point.

## Cursor Persistence

Git-based fetchers persist their checkpoint (the last successfully
processed commit SHA) in the `FetcherRun.cursor` JSONB column. After
a run completes with `success` or `partial` status, the fetcher writes:

```json
{"sha": "<40-char hex SHA>", "committed_at": "<ISO 8601 date>"}
```

The next run reads the cursor from the most recent `FetcherRun` with
`status IN ('success', 'partial')` for the same `fetcher_name`:

- `sha`: the HEAD commit SHA at the end of a `success` or `partial` run
- `committed_at`: the committer date of that commit (ISO 8601
  format). Used as the recovery boundary when the cursor SHA becomes
  unreachable (see "Cursor SHA Unreachable" below)

If no run with a cursor exists (first run), the fetcher applies its own
first-run strategy (see the individual fetcher spec — e.g., "record
HEAD only" for CVE fetchers). For recovery scenarios where a stored
SHA is unreachable, the fetcher applies the date-based recovery
strategy (see "Cursor SHA Unreachable" below).

This mechanism is generic — non-git fetchers may use `cursor` for any
checkpoint data (timestamps, offsets, page tokens). The column is
nullable; fetchers that derive their cursor from other fields (e.g.,
NVD uses `started_at`) leave it NULL.

## Write Mechanism

Inside `execute()`, the fetcher sets `self._cursor` (a dict) with the
checkpoint data. After `execute()` returns, `run()` determines the
final status (see "Status determination precedence" in
`fetcher-infrastructure.md`) and then, only if
the final status is `success` or `partial`, reads `self._cursor` and
writes it to the `FetcherRun` row in the same transaction that sets
`status` and `finished_at`. If `self._cursor` is None (not set), or
the final status is `failure` (including the all-items-failed case),
no cursor is written.

This avoids giving `execute()` direct access to the `FetcherRun` row
and keeps cursor persistence as a `run()` responsibility — consistent
with how `run()` already manages metrics (`items_created`,
`items_updated`, `items_failed`).

## Empty Delta

If `git fetch` succeeds but the delta contains zero files matching
the fetcher's filter (no CVE files changed), the run completes with
`status = success`, zero metrics, and the cursor advances to the new
HEAD SHA. This is the normal case during low-activity periods.

## First-Run Detection

A git-based fetcher determines "first run" by the absence of a
`FetcherRun` record with a cursor — NOT by the presence or absence of
the clone directory. The clone directory state is a sub-condition of
the first-run logic:

| Cursor exists? | Clone valid? | Action |
|---|---|---|
| No | No (absent or invalid) | If directory exists but is invalid (fails `git rev-parse --git-dir`): delete entirely. Clone repository. Record HEAD without processing |
| No | Yes | Skip clone (previous attempt succeeded but cursor was not persisted). Record HEAD without processing |
| Yes | Yes | Subsequent run: fetch + delta detection from cursor |
| Yes | No (absent or invalid) | Delete invalid directory if present. Re-clone. Then apply cursor reachability check (see "Recovery" and "Cursor SHA Unreachable" below) |

"Invalid" means: the directory exists but `git rev-parse --git-dir`
fails (corrupted pack files, incomplete clone from interrupted
previous attempt, filesystem corruption, etc.).

The cursor-based approach ensures correctness when the first run
clones successfully but fails before persisting the cursor. In that
scenario, a clone-state-based check would incorrectly conclude
"subsequent run" and attempt delta detection without a stored SHA.
The cursor-based check correctly identifies this as a first run and
records HEAD without processing.

For `BaseGitFetcher` subclasses, this decision matrix is implemented
by `BaseGitFetcher.execute()` — concrete fetchers do not reimplement
it. See "BaseGitFetcher Class" below.

## Environment Configuration

| Env Var | Type | Default | Description |
|---------|------|---------|-------------|
| `GIT_CLONE_BASE_DIR` | string (path) | `/var/lib/sentinel/git` | Base directory for all git-based fetcher clones |

Each fetcher creates a subdirectory named after its repository:

```
$GIT_CLONE_BASE_DIR/
├── cvelistV5/      (sync_mitre_cves — bare clone of github.com/CVEProject/cvelistV5)
└── vulns.git/      (sync_kernel_cves — bare clone of git.kernel.org/.../vulns.git)
```

The base directory MUST be backed by persistent storage in containerized
deployments (named volume in a container runtime, PersistentVolumeClaim in
Kubernetes). The storage is treated as a **recoverable cache**, not as a
source of truth — if lost or corrupted, the fetcher re-clones
automatically (see Recovery below).

## Volume Requirements

| Property | Value |
|----------|-------|
| Persistence | Required across container restarts |
| Capacity | 8 GB minimum (current usage ~2.4 GB; provides headroom for git repack operations — which temporarily require old + new pack coexistence (~4.7 GB peak) — plus future growth at ~150 MB/year) |
| Access mode | ReadWriteOnce (single worker pod) |
| Filesystem | Any POSIX-compliant filesystem |
| Backup | Not required (recoverable from upstream repos) |

## Worker Affinity

Git-based fetcher tasks MUST execute on a Celery worker with the Git
volume mounted. This is achieved via a dedicated Celery queue:

- **Queue name**: `git`
- **Routing**: `BaseGitFetcher` sets `queue = "git"` as a fixed class
  attribute — all concrete subclasses inherit this value automatically.
  Fetchers that inherit from `BaseFetcher` directly and need git queue
  affinity set it in their own class body
- **`queue` class attribute on BaseFetcher**: `BaseFetcher` defines a
  `queue: str | None = None` class attribute (default = default Celery
  queue). `BaseGitFetcher` overrides it to `"git"` for the entire
  git-fetcher hierarchy. Non-git fetchers that omit it are routed
  normally — safe by default
- **Worker configuration**: the worker process with access to the Git
  volume consumes from the `git` queue (in addition to the default
  queue, if desired)
- **`fetch_single()` routing**: `trigger_on_demand_fetch()` reads
  `fetcher_cls.queue` when dispatching via `.apply_async(queue=...)`.
  If `None`, no queue parameter is passed and Celery uses default
  routing. This ensures on-demand fetches for git-based fetchers
  reach the worker with the volume mounted
- **`catch_up()` routing**: Ticket convergence applies the same rule when
  publishing the generic `run_catch_up` task. Git-based catch-ups therefore
  reach the `git` worker, while a fetcher whose `queue` is `None` uses default
  routing

In single-worker deployments (local dev, simple container runtime), all
queues are consumed by the same worker process and no explicit routing
configuration is needed.

## Concurrency Rules

These rules apply to ALL git-based fetchers sharing the same volume:

1. **Only the periodic sync modifies the clone**: `git fetch` and any
   other write operations are performed exclusively by the periodic
   sync task. `fetch_single()` MUST NOT run `git fetch` or any
   operation that modifies the object store or refs.
2. **`fetch_single()` reads from the object store only**: uses
   `git show -- <ref>:<path>` (via async subprocess) to read committed
   objects. The Git object store is append-only with atomic file
   operations — concurrent reads during a `git fetch` are safe.
3. **Stale reads are acceptable**: if `fetch_single()` reads HEAD just
   before `git fetch` updates it, a recently-published CVE might not be
   found. This is not an error — `trigger_on_demand_fetch()` dispatches
   all registered fetchers and other sources may succeed.
4. **No concurrent fetches per repo**: two periodic sync tasks for the
   same repository MUST NOT run concurrently. The fetcher infrastructure
   already enforces this via the singleton execution guarantee
   (BaseFetcher prevents overlapping runs for the same fetcher).
5. **Cross-fetcher concurrency is safe**: different git-based fetchers
   operating on distinct subdirectories within `$GIT_CLONE_BASE_DIR`
   MAY execute concurrently. The singleton constraint — no overlapping
   runs of the same fetcher — is enforced by `BaseFetcher` (see
   `docs/features/platform/fetcher-infrastructure.md`,
   BaseFetcher Base Class). It applies per-fetcher, not
   per-volume. A `sync_mitre_cves` run and a `sync_kernel_cves` run
   can overlap without conflict.

## Recovery

**Volume loss** (directory does not exist):

1. Re-clone the repository (same clone command as first run)
2. Read the `cursor` from the last `FetcherRun` with
   `status IN ('success', 'partial')` for this fetcher in the database
3. Check if the stored SHA exists in the new clone
   (`git cat-file -t -- <sha>`)
4. If reachable: normal delta processing from stored SHA to HEAD
5. If not reachable (upstream force-push, branch deletion, or SHA
   garbage-collected): apply the date-based recovery strategy (see
   "Cursor SHA Unreachable" below). For `BaseGitFetcher` subclasses
   this is handled automatically by `execute()` — only
   `recovery_path_prefix` varies per fetcher

**Corrupted clone** (read-phase git operations fail persistently after
retry exhaustion):

1. Read-phase operation fails; `git_operations` retries up to 3 times
   with exponential backoff (2s, 4s, 8s)
2. If failure persists: raise `GitCorruptionError`
3. `execute()` catches the exception, logs WARNING with error details
4. Delete the entire clone directory (via `_delete_if_exists()`)
5. Raise `FetcherError` to terminate the current run (`status = failure`,
   cursor not advanced)
6. On the next scheduled run: First-Run Detection finds clone absent
   with cursor present → re-clone + SHA reachability check → normal
   recovery flow (same as volume loss)

## Cursor SHA Unreachable

When a git-based fetcher's stored cursor SHA is not reachable in the
local clone (detected via `git cat-file -t -- <sha>` returning non-zero),
it applies a date-based recovery strategy using the `committed_at`
field stored in the cursor. This situation occurs when:

- The clone was rebuilt (row 4 of the First-Run Detection table)
- The upstream repository was force-pushed or rebased (rare for
  published CVE/advisory repos)
- Git garbage collection pruned unreachable objects (should not
  happen for commits reachable from HEAD, but possible with
  corrupted state)

**Algorithm**:

1. Compute `before_date` as `cursor_committed_at` minus 1 day (the
   1-day margin ensures no items are missed around the boundary —
   reprocessing is idempotent)
2. Determine boundary SHA:
   `git rev-list -1 --before="<before_date>" HEAD`
3. If no commit exists before `before_date` (empty output — the
   repository history does not extend that far back): log WARNING
   ("Recovery boundary not found — treating as first-run"), return
   empty delta. Cursor advances to HEAD
4. Compute delta:
   `git diff --name-only --no-renames --diff-filter=AM
   <boundary_sha>..HEAD -- '<recovery_path_prefix>'`
   (same `--no-renames` flag as normal delta — guarantees local-only
   operation; see "Bare Clone Compatibility")
5. Apply the fetcher's normal file filtering and per-item processing
   logic (MUST be idempotent — previously ingested items produce no
   observable side effects on re-processing)
6. Write HEAD as new cursor on completion

Each git-based fetcher declares this parameter in its properties
table:

| Parameter | Description | Example values |
|---|---|---|
| `recovery_path_prefix` | Path filter for the recovery delta command | `cves/` (MITRE), `cve/` (kernel) |

**Advantages over a fixed window**: the date-based approach always
covers the exact gap regardless of how long the fetcher was offline.
Reprocessing overlap is always ~1 day (idempotent, negligible cost).
No configurable `recovery_window` parameter is needed.

**Normal case after re-clone**: when a clone is rebuilt from the
same remote (row 4 of First-Run Detection), the cursor SHA is
almost always reachable because git history is preserved. In this
case, normal delta detection proceeds — no recovery is needed. The
recovery strategy is a fallback for the rare case where the SHA
truly does not exist in the fresh clone.

For `BaseGitFetcher` subclasses, this recovery algorithm is
implemented by `BaseGitFetcher.execute()` — concrete fetchers only
declare `recovery_path_prefix` as a class attribute. See
"BaseGitFetcher Class" below.

### Operational: large delta convergence

After an extended outage (weeks or longer), the recovery delta may
contain thousands of files. Since all blobs are present locally after
`git fetch`, processing speed is bounded only by database throughput
and `process_item()` complexity — not network latency. If the delta
cannot be fully processed within `run_timeout`, the soft time limit
fires, the run ends as `failure`, and the cursor does not advance.

On the next scheduled execution, the same delta is recomputed. Items
already processed produce idempotent upserts (no observable side
effects). The loop processes items until the timeout fires again. This
continues across successive runs until all items are processed —
**convergence is guaranteed** through the combination of idempotent
processing and stable cursor position.

To accelerate recovery, an admin can temporarily increase `run_timeout`
for the specific fetcher via FetcherConfig (e.g., from 3600 to 36000
for a one-time large delta), then reset it after the recovery completes.
The dashboard's `error_message` field includes the number of items
processed before timeout, allowing the admin to estimate the required
duration.

This scenario is uncommon in normal operation:
- First-run records HEAD without processing (no delta)
- Recovery delta uses `cursor_committed_at - 1 day` as boundary (not
  full repo history)
- Only extended outages (weeks+) produce deltas exceeding 1 hour of
  processing time

## Runtime Dependencies

Git-based fetchers require the `git` binary available in the
container image of the worker that consumes the `git` queue.

| Dependency | Minimum version | Reason |
|---|---|---|
| `git` | 2.25 | Minimum version for protocol v2, improved bare-clone performance, and `--filter` support (retained for future extensibility) |

The `python:<version>-slim` base image (where `<version>` is the
project's Python target — see `docs/conventions.md`, Runtime Version) does not include git — it must be added explicitly to the
container image.

**No Python Git library is used.** All git operations are performed
via async subprocess invocation of the system `git` binary through a
shared internal helper. This decision is based on:

- `pygit2` (libgit2 bindings): **eliminated** — libgit2 cannot open
  repositories with the `extensions.partialclone` extension
  (libgit2/libgit2#5564, open since Jun 2020; #6880 confirms the
  error persists in v1.7.2, Sep 2024). While no current fetcher uses
  partial clones, this blocks future extensibility. Additionally,
  libgit2 lacks a direct `git show` equivalent for bare repository
  blob access, requiring workaround code
- `GitPython`: **eliminated** — 8 security advisories including 5
  High-severity RCE/command-injection vulnerabilities published
  April–May 2026 affecting all platforms. Unacceptable for a security
  platform
- Raw subprocess: no additional Python dependency, full access to all
  git features (partial clone, protocol v2), no additional attack
  surface

The helper provides typed exceptions for phase-based error
classification (see "Error Classification" below), with hardcoded
timeouts and retry policy per operation category:

| Operation | Timeout | Retries | Examples |
|---|---|---|---|
| Clone | 30 minutes | 0 | Initial bare clone (~2.3 GB download for cvelistV5) |
| Fetch | 5 minutes | 0 | Incremental `git fetch origin` |
| Read | 30 seconds | 3 (backoff: 2s, 4s, 8s) | `git diff`, `git rev-parse`, `git ls-tree`, `git cat-file -t`, `git rev-list`, `git log` |
| Show | 30 seconds | 0 | `git show -- <ref>:<path>` (per-file blob access) |

**Read retry policy**: read-phase operations are retried up to 3 times
(4 attempts total) with exponential backoff (2 seconds, 4 seconds, 8
seconds) before raising `GitCorruptionError`. This absorbs transient
I/O faults on networked storage (NFS, PVC with remote backend) without
misclassifying them as repository corruption. The worst-case added
latency per operation is ~14 seconds (negligible vs. the 30-second
timeout and vastly cheaper than a false-positive re-clone of ~2.3 GB). Clone and Fetch are not retried because they already handle
transient network errors through git's own retry logic. Show is not
retried because per-file failures are already non-fatal (`GitFileError`
→ `record_failed()`, continue to next item).

## Error Classification

Git operation failures are classified by the **phase** in which they
occur, not by parsing exit codes or stderr messages. This avoids
fragile dependencies on git's unstable error message format.

```python
class GitError(Exception): ...
class GitFetchError(GitError): ...       # Transient — clone is intact
class GitCorruptionError(GitError): ...  # Delete + re-clone required
class GitFileError(GitError): ...        # Per-file — continue processing
```

| Phase | Failure condition | Exception | Fetcher action |
|-------|-------------------|-----------|----------------|
| `git clone` / `git fetch` | Any failure (network, auth, timeout) | `GitFetchError` | Do NOT delete clone. Raise `FetcherError`. Next cycle retries |
| Read after successful fetch (`git diff`, `git rev-parse`, `git ls-tree`, `git cat-file -t`, `git rev-list`, `git log`) | Persistent failure after retry exhaustion (3 retries with exponential backoff) | `GitCorruptionError` | Delete clone directory. Raise `FetcherError`. Next cycle re-clones + applies recovery strategy |
| `git show` during delta file processing | Any failure (timeout, corrupt/missing blob in local store) | `GitFileError` | `record_failed()` for that item. Continue to next file |
| Directory deletion (recovery/cleanup) | Filesystem rejection (permissions, read-only mount, busy handle) | `OSError` | Log ERROR with distinct message: path, errno, and guidance ("Manual intervention required — check filesystem permissions and mount state"). Raise `FetcherError`. Next cycle re-attempts (permanent until operator resolves filesystem issue) |

**Design rationale**: classification is phase-based. A successful
`git fetch` proves network connectivity to the remote. A subsequent
read-phase failure is therefore *presumed* to be local corruption —
but the presumption accounts for transient I/O faults on networked
storage (NFS, PVC with remote backend) by retrying before concluding
corruption. If retries are exhausted and the failure persists, the
conclusion is firm: the local object store is damaged, and the only
reliable recovery is deletion + re-clone. No stderr parsing or exit
code mapping is needed — the phase plus retry exhaustion is sufficient
for classification.

Note: `diff_names` uses `--no-renames`, ensuring it operates
exclusively on local tree/commit objects (no blob content needed).
This means read-phase failures in `diff_names` are genuinely
storage-related, not network-related — reinforcing the corruption
classification after retry exhaustion.

**No anti-loop logic**: the Celery hard time limit (`time_limit =
run_timeout`) guarantees each run's duration is bounded. The soft time
limit (at 95% of `run_timeout`) provides early warning for clean
shutdown. Step 10d ensures `SoftTimeLimitExceeded` propagates rather
than being caught as a per-item error. Repeated failures (e.g.,
persistent filesystem damage) produce visible `failure` records in
the fetcher dashboard for operator intervention — but each cycle
attempts self-healing (delete + re-clone) rather than looping on the
same corrupt state.

## Implementation Location

The shared async subprocess helper for git operations lives at
`backend/app/services/git_operations.py`. All git-based fetchers
import from this module — they MUST NOT invoke `subprocess` or
`asyncio.create_subprocess_exec` for git commands directly.

The module exports:
- Async functions for each git operation category (clone, fetch, read
  operations, show)
- The exception hierarchy (`GitError`, `GitFetchError`,
  `GitCorruptionError`, `GitFileError`)
- Timeout constants per operation category

## Design Principles

The git operations module is NOT a "service" in the Sentinel
service-layer sense:

- Contains stateless utility functions (no database interaction, no
  business logic)
- Centralizes subprocess error handling and maps git failures to the
  typed exception hierarchy
- Is consumed by `BaseGitFetcher` methods, which delegate subprocess
  execution to this module. Can also be used independently by code that
  needs git operations without the `BaseGitFetcher` lifecycle (e.g.,
  fetchers inheriting from `BaseFetcher` directly)
- Provides a clean mocking boundary for unit tests (mock one function
  instead of `subprocess.run`)

Fetchers that inherit from `BaseGitFetcher` delegate execution flow
to the template method — they implement only processing hooks.
Fetchers that inherit from `BaseFetcher` directly retain full control
over their execution flow, using the utility functions as building
blocks.

## Responsibility Separation

The utility module is **policy-free** — it executes git commands with
the parameters it receives. It does not apply domain-specific defaults.

- **Domain defaults** (bare=True, filter=None, single-branch=True)
  live on `BaseGitFetcher` class attributes
- **`BaseGitFetcher` methods** read `self.*` attributes and pass them as
  explicit parameters to `git_operations` functions
- **Concrete subclasses** override class attributes to change behavior
  (e.g., a future fetcher might set `clone_filter = "blob:none"` for a
  source requiring deferred blob downloads)

This separation ensures `git_operations.py` remains general-purpose and
independently usable.

## Function Catalog

The following sections define the complete public interface of
`git_operations.py`. These are the functions that `BaseGitFetcher`
delegates to and that any `BaseFetcher`-direct subclass may also call.

### Module Invariants

Three mandatory rules apply to all functions in this module:

**Rule 1 — SHA Format Validation:**

Applies ONLY to `check_sha_reachable` (the single entry point for
database-sourced SHA values). Before invoking `git cat-file`, validate
the `sha` parameter against regex `^[0-9a-f]{40}$`. If validation fails:
log WARNING with the invalid value, return `False` immediately (do NOT
invoke git, do NOT raise an exception). This triggers the natural
date-based recovery flow (same as unreachable SHA) — no re-clone, cursor
advances on next successful run.

**Rule 2 — End-of-options separator (`--`):**

Every git command constructed by this module that accepts positional
arguments (SHA, ref, object specifiers) MUST insert `--` between
options/flags and positional arguments to prevent argument injection.
Applicable commands: `git cat-file -t -- <sha>`,
`git show -- <ref>:<path>`, `git clone <flags> -- <url> <dest>`.

Note: `--` is NOT applicable to commands where it has pathspec semantics
rather than end-of-options semantics (`git log`, `git rev-list`,
`git diff` revision arguments). For these commands, the defense against
argument injection is SHA format validation at the entry point
(`check_sha_reachable`).

**Rule 3 — Subprocess environment:**

Every function that invokes `asyncio.create_subprocess_exec` for a git
command MUST pass `env=_git_subprocess_env()` to guarantee deterministic
output regardless of the host locale or timezone configuration.

The module defines:

```python
_GIT_ENV_OVERRIDES: Final[dict[str, str]] = {
    "LC_ALL": "C",
    "GIT_TERMINAL_PROMPT": "0",
    "TZ": "UTC",
}

def _git_subprocess_env() -> dict[str, str]:
    """Merge process environment with git-specific overrides."""
    return {**os.environ, **_GIT_ENV_OVERRIDES}
```

Rationale for each variable:

- `LC_ALL=C` — forces English output from git, ensuring that stderr
  string parsing (e.g., "does not exist in", "not a valid object name")
  works correctly regardless of container locale. Without this, error
  classification in `show_file` and `check_sha_reachable` would break
  on non-English locales.
- `GIT_TERMINAL_PROMPT=0` — disables interactive prompts (credential
  requests, pager) that would block the async worker indefinitely.
- `TZ=UTC` — ensures timestamp output (e.g., `--format=%cI`) is
  directly in UTC without requiring post-hoc conversion in Python.
  Follows the project's "UTC everywhere" convention.

The merge with `os.environ` is required because
`asyncio.create_subprocess_exec(env=<dict>)` replaces (rather than
extends) the inherited process environment. Without the merge, essential
variables like `PATH` (needed to locate the `git` binary) and
`HOME`/`XDG_CONFIG_HOME` would be absent.

Adding or removing a git-specific environment variable requires
changing only the `_GIT_ENV_OVERRIDES` constant — no per-function
modifications needed.

### Clone Operations

| Function | Signature | Returns | Timeout | Raises |
|----------|-----------|---------|---------|--------|
| `clone` | `async def clone(url: str, dest: Path, *, bare: bool = False, filter_spec: str \| None = None, single_branch: bool = False) -> None` | `None` | Clone (30 min) | `GitFetchError` |

**Behavior**:

1. Build the command with all flags before positional arguments,
   separated by `--`:
   a. Start with `["git", "clone"]`
   b. If `bare` is `True`: append `--bare`
   c. If `filter_spec` is not `None`: append `--filter=<filter_spec>`
   d. If `single_branch` is `True`: append `--single-branch`
   e. Append `--` (end-of-options separator)
   f. Append `url` and `str(dest)` as positional arguments
   Result example: `["git", "clone", "--bare", "--single-branch", "--", url, str(dest)]`
   (if `filter_spec` is set: `["git", "clone", "--bare", "--filter=<value>", "--single-branch", "--", url, str(dest)]`)
2. Execute the command via `asyncio.create_subprocess_exec` with the
   clone timeout (30 minutes)
3. If the process exits with non-zero code: raise `GitFetchError` with
   stderr content

### Fetch Operations

| Function | Signature | Returns | Timeout | Raises |
|----------|-----------|---------|---------|--------|
| `fetch_origin` | `async def fetch_origin(repo_path: Path) -> None` | `None` | Fetch (5 min) | `GitFetchError` |

Semantics: runs `git fetch origin` in the specified repository.
Incremental — only new objects are transferred.

### Read Operations

All read-phase functions apply the retry policy (3 retries, backoff
2s/4s/8s) internally before raising `GitCorruptionError`. Callers
observe a single function call that either succeeds or raises — the
retry is transparent. Exempt functions: `is_clone_valid` (never
raises). For `check_sha_reachable`, the retry applies only to the
code path that raises `GitCorruptionError` (unexpected I/O failures);
the `return False` path (SHA not found — exit code 1 with "not a valid
object name") is a definitive negative response and is NOT retried.

| Function | Signature | Returns | Timeout | Raises |
|----------|-----------|---------|---------|--------|
| `get_head_sha` | `async def get_head_sha(repo_path: Path) -> str` | 40-char hex SHA | Read (30 sec) | `GitCorruptionError` |
| `get_commit_date` | `async def get_commit_date(repo_path: Path, ref: str) -> str` | ISO 8601 date string in UTC (e.g., `2025-06-01T18:00:00+00:00`) | Read (30 sec) | `GitCorruptionError` |
| `is_clone_valid` | `async def is_clone_valid(repo_path: Path) -> bool` | `bool` | Read (30 sec) | Never (returns `False` on any failure) |
| `check_sha_reachable` | `async def check_sha_reachable(repo_path: Path, sha: str) -> bool` | `bool` | Read (30 sec) | `GitCorruptionError` (only for unexpected failures; unreachable SHA returns `False`) |
| `diff_names` | `async def diff_names(repo_path: Path, from_sha: str, to_sha: str, *, path_filter: str \| None = None) -> list[str]` | List of file paths | Read (30 sec) | `GitCorruptionError` |
| `rev_list_before` | `async def rev_list_before(repo_path: Path, before_date: str) -> str \| None` | 40-char hex SHA or `None` | Read (30 sec) | `GitCorruptionError` |

Semantics:

- **`get_head_sha`**: returns the commit SHA that HEAD points to
  (`git rev-parse HEAD`)
- **`get_commit_date`**: returns the committer date of the specified ref
  as an ISO 8601 string normalized to UTC
  (`git log -1 --format=%cI <ref>`). The subprocess environment includes
  `TZ=UTC` (via Rule 3), so git produces UTC output directly — no
  post-hoc conversion needed. Follows the project's "UTC everywhere"
  convention (`docs/conventions.md`, Timestamps & Timezones). Used to
  store `committed_at` in the cursor for recovery boundary computation
- **`is_clone_valid`**: returns `True` if `repo_path` is a valid git
  repository (`git rev-parse --git-dir` succeeds). Returns `False` if
  the directory does not exist, is not a git repository, or the check
  fails for any reason. NEVER raises — used as a guard condition
- **`check_sha_reachable`**: determines whether a given SHA exists in
  the local object store as a valid git object
  (`git cat-file -t -- <sha>`).

  **Behavior**:

  0. Validate `sha` against `^[0-9a-f]{40}$`. If invalid: log WARNING
     ("Invalid SHA format: {sha} — treating as unreachable"), return
     `False`
  1. Execute `git cat-file -t -- <sha>` in the repository
  2. If exit code is 0: return `True` (object exists and is valid)
  3. If exit code is 1 and stderr indicates "not a valid object name" or
     similar: return `False` (SHA not reachable — expected condition)
  4. If exit code indicates a different failure (I/O error, repository
     corruption): raise `GitCorruptionError`

- **`diff_names`**: returns the list of added and modified files
  between two commits
  (`git diff --name-only --no-renames --diff-filter=AM <from>..<to>`).
  Rename detection is disabled (`--no-renames`) to ensure deterministic
  diff output and avoid expensive blob-content similarity computation on
  large repositories. Renames appear as separate delete + add pairs; the
  `A` is captured by the filter. If `path_filter` is set, appends
  `-- '<path_filter>'` to restrict results. Deleted files are excluded
- **`rev_list_before`**: returns the most recent commit SHA on HEAD
  before the specified date
  (`git rev-list -1 --before="<before_date>" HEAD`). Returns `None` if
  no commit exists before the specified date (empty output from git).
  Used for recovery boundary detection

### Show Operations

| Function | Signature | Returns | Timeout | Raises |
|----------|-----------|---------|---------|--------|
| `show_file` | `async def show_file(repo_path: Path, ref: str, file_path: str) -> bytes \| None` | File content as `bytes`, or `None` if path does not exist | Show (30 sec) | `GitFileError` (for errors other than "path not found") |

**Behavior**:

1. Execute `git show -- <ref>:<file_path>` in the repository
2. If exit code is 0: return stdout as `bytes` (file content)
3. If exit code is 128 and stderr contains "does not exist in" or
   "path not found": return `None` (file does not exist at this ref —
   expected condition, not an error)
4. If exit code indicates a different failure (corrupt object, timeout):
   raise `GitFileError` with stderr content

In a plain bare clone, blob content is already present in the local
object store. Network access is not required. If the blob is
unexpectedly absent (corrupt pack file), step 4 fires.

### Filesystem Operations

| Function | Signature | Returns | Timeout | Raises |
|----------|-----------|---------|---------|--------|
| `delete_clone` | `async def delete_clone(path: Path) -> None` | `None` | N/A | `OSError` (filesystem errors) |

Semantics: recursively deletes the directory at `path` if it exists.
No-op if the path does not exist. This is NOT a git operation — it is
included in the module for co-location with clone lifecycle management.

### Bare Clone Compatibility

All git operations in the function catalog are designed for bare
repositories (no working tree). Every operation accesses the git object
store directly:

- **Commit/tree operations** (`get_head_sha`, `get_commit_date`,
  `is_clone_valid`, `check_sha_reachable`, `diff_names`,
  `rev_list_before`): read commit and tree objects only.
- **Blob operations** (`show_file`): read file content from the local
  object store via `git show`. All blobs are present locally after
  the initial clone and subsequent fetches.

The `--no-renames` flag on `diff_names` ensures diffs operate
exclusively on tree objects without comparing blob content. This
avoids expensive similarity computation on large repositories and
produces deterministic output (renames appear as separate delete + add
pairs).

Note: the `clone_filter` class attribute supports partial clones
(`--filter=blob:none`) for sources where deferred blob downloads are
operationally required. No current fetcher uses this mode. If enabled,
`show_file()` would trigger on-demand blob downloads requiring network
access during processing — introducing per-item network failure risk.
This mode is retained for future extensibility only.

## BaseGitFetcher Class

Template Method intermediate class for fetchers that follow the standard
delta-based git flow (clone → fetch → SHA reachability → delta detection
→ per-item processing → cursor advance). Eliminates duplicated state
machine code by providing a single `execute()` implementation that
delegates per-item processing to concrete subclasses via hook methods.

**Class hierarchy**:

```
BaseFetcher (generic: lifecycle, metrics, FetcherRun, cursor, registry)
  └── BaseCVEFetcher (CVE-specific: cve_source_type, fetch_single (opt-out), catch_up)
        └── BaseGitFetcher (git-specific: clone, fetch, delta, recovery, SHA ops)
              ├── SyncMitreCves (per-item: cvelistV5 JSON, CNA+ADP containers)
              └── SyncKernelCves (per-item: vulns.git JSON, kernel-specific mapping)
```

**File location**: `backend/app/services/base_git_fetcher.py`

## Class Attributes

Concrete subclasses declare the configurable attributes as class-level
values. The fixed attributes are set by `BaseGitFetcher` and inherited
automatically.

**Configurable (declared by subclasses)**:

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo_url` | `str` | (required) | Git remote URL |
| `clone_dir_name` | `str` | (required) | Directory name under `$GIT_CLONE_BASE_DIR` |
| `clone_bare` | `bool` | `True` | Whether to use `--bare` |
| `clone_filter` | `str \| None` | `None` | Git `--filter=` value. `None` = plain bare clone (recommended). Set to `"blob:none"` only if the source requires deferred blob downloads for operational reasons. No current fetcher uses a non-None value |
| `clone_single_branch` | `bool` | `True` | Whether to use `--single-branch` |
| `recovery_path_prefix` | `str` | (required) | Path prefix for recovery delta (`-- '<prefix>'`) |
| `delta_path_prefix` | `str` | (required) | Path prefix for normal delta detection |

**Fixed (set by `BaseGitFetcher`, not overridable)**:

| Attribute | Value | Description |
|-----------|-------|-------------|
| `abstract` | `True` | Prevents registration in `FETCHER_REGISTRY` (intermediate class, not a concrete fetcher). Both `BaseCVEFetcher` and `BaseGitFetcher` set `abstract = True` (both are intermediate classes). Concrete subclasses do not set `abstract` in their own class body; `__init_subclass__` checks `cls.__dict__.get('abstract', False)` and proceeds with registration when the attribute is absent from the subclass's own namespace |
| `queue` | `"git"` | Celery queue for worker affinity. Ensures tasks execute on the worker with the git volume mounted. Inherited from `BaseFetcher` interface (default `None`), overridden at the `BaseGitFetcher` level |

These configurable attributes are also exposed in each fetcher's
properties table in its specification document. The fixed `queue`
attribute is inherited automatically and does not appear in
per-fetcher properties tables.

## Template Method: `execute()`

The `execute()` method implements the full git-based fetcher state
machine. Concrete subclasses MUST NOT override `execute()` (they
implement hooks instead).

Implements the First-Run Detection truth table and the recovery
algorithm ("Recovery" and "Cursor SHA Unreachable") from the sections
above.

**Behavior**:

1. Resolve repository path from `$GIT_CLONE_BASE_DIR / clone_dir_name`
2. Read last cursor from the previous successful `FetcherRun.cursor`
   (via `BaseFetcher`). Extract `cursor_sha` and `cursor_committed_at`
   from the stored dict. If no prior successful run exists, both are
   `None`
3. **First-run branch** — if `cursor_sha` is `None`:
   a. If clone is NOT valid at `repo_path`: delete directory if it
      exists (if `_delete_if_exists()` raises `OSError`: log ERROR
      "Cannot delete clone directory at {repo_path}: {e}. Manual
      intervention required — check filesystem permissions and mount
      state.", propagate as `FetcherError`), then clone repository
      with configured options
   b. If clone IS valid: skip clone (reuse existing)
   c. Read HEAD SHA from the repository
   d. Read HEAD commit date via `get_commit_date(repo_path, "HEAD")`
   e. Set cursor to `{"sha": head_sha, "committed_at": head_date}`
   f. Return — first-run complete, no items processed
4. **Subsequent-run branch** — `cursor_sha` exists:
   a. If clone is NOT valid: log WARNING ("Clone invalid but cursor
      exists — rebuilding"), delete directory if exists (if
      `_delete_if_exists()` raises `OSError`: log ERROR "Cannot delete
      clone directory at {repo_path}: {e}. Manual intervention required
      — check filesystem permissions and mount state.", propagate as
      `FetcherError`), clone repository
   b. If clone IS valid: fetch origin (incremental update)
5. Read HEAD SHA from the repository
6. Read HEAD commit date via `get_commit_date(repo_path, "HEAD")`
7. **SHA reachability check**:
   a. If `cursor_sha` is NOT reachable in the local object store:
      - If `cursor_committed_at` is `None`: log ERROR ("Cursor SHA
        unreachable and committed_at absent — cannot compute recovery
        boundary. Treating as first-run."), set delta to empty list
      - Otherwise: log WARNING ("Cursor SHA unreachable — applying
        recovery"), compute recovery delta via
        `_compute_recovery_delta(repo_path, head_sha, cursor_committed_at)`
   b. If `cursor_sha` IS reachable: compute normal delta via
      `diff_names(repo_path, cursor_sha, head_sha)` with
      `delta_path_prefix` as path filter
8. Apply `filter_delta_files()` hook on the file list
9. Apply `deduplicate_items()` hook on the filtered list
10. **Per-item processing loop** — for each `path` in the deduplicated
    list:
    a. Read file content via `show_file(repo_path, "HEAD", path)`
    b. If content is `None` (file not found at HEAD — file was added
       then deleted/renamed between cursor and HEAD): log WARNING
       ("File {path} in delta but not at HEAD — skipping"), continue
       to next item. No metric is recorded
    c. Call `post_ingest = process_item(path, content, session)` →
       returns `PostIngestTasks | None`. On successful return, call
       `self.commit_and_dispatch(session, post_ingest)`
    d. If `SoftTimeLimitExceeded` or `MemoryError` is raised during
       steps 10a, 10c, or `commit_and_dispatch()`: **re-raise
       immediately** (these are whole-run signals, not per-item errors;
       see "`SoftTimeLimitExceeded` handling convention" in
       `fetcher-infrastructure.md`).
    e. If any other exception is raised during steps 10a, 10c, or
       `commit_and_dispatch()`: call `session.rollback()`, extract
       CVE-ID via `cve_id = self._extract_item_id(path)`, call
       `await self._isolated_status_commit(cve_id, "failure")`, log
       WARNING (`logger.warning("Failed to process item %s: %s",
       cve_id, e)`), call `record_failed()`, continue to next item

    **Transaction boundaries**: each iteration of the processing loop
    operates in its own transaction boundary. `process_item()` returns
    `PostIngestTasks | None`; after a successful return, the template
    calls `self.commit_and_dispatch(session, post_ingest)` which
    commits the session and dispatches Phase 2 tasks if `post_ingest`
    is not `None`. On exception (caught by step 10e), the template
    calls `session.rollback()` before `record_failed()`. This ensures
    that a failure in one item does not corrupt the session or affect
    the processing of subsequent items.

    **Session state on timeout propagation**: when `SoftTimeLimitExceeded`
    propagates via step 10d, the session may contain uncommitted changes
    and hold a `FOR UPDATE` lock from `process_item()`. No explicit
    rollback is performed — the exception propagates directly to
    `BaseFetcher.run()`. This is safe because: (1) `run()` uses
    independent short-lived sessions for `FetcherRun` finalization, not
    the `execute()` session; (2) SQLAlchemy performs an implicit rollback
    when the session is closed or garbage-collected, releasing any held
    locks. The window between propagation and implicit rollback is
    negligible (milliseconds).

11. Set cursor to `{"sha": head_sha, "committed_at": head_date}`

Note: the all-items-failed safety check (preventing cursor advance when
every item fails) is handled by `BaseFetcher.run()` after `execute()`
returns — see "Status determination precedence" in
`fetcher-infrastructure.md`. Items skipped in step 10b (file not at HEAD) do not increment
any counter and do not trigger the safety check.

**Infrastructure errors**: the template method catches all known
infrastructure exceptions and wraps them in `FetcherError` with a
sanitized message before propagating to `BaseFetcher.run()`. This
ensures git-specific exceptions never leak beyond the
`BaseGitFetcher` boundary:

- **`GitFetchError`** (clone/fetch failures): `execute()` **catches**
  this exception and raises `FetcherError("External git repository
  unreachable — {sanitized reason}")`. The clone is intact — next
  cycle retries.
- **`GitCorruptionError`** (read-phase failures after retry
  exhaustion): `execute()` **catches** this exception, deletes the
  clone directory via `_delete_if_exists()`, then raises `FetcherError`
  to fail the run. This ensures self-healing: the next cycle finds the
  clone absent, re-clones, and applies recovery. Without this explicit
  deletion, a partial corruption (e.g., corrupt pack file that still
  passes `git rev-parse --git-dir`) would loop indefinitely without
  repair. If `_delete_if_exists()` raises `OSError`: log ERROR
  ("Cannot delete clone directory at {repo_path}: {e}. Manual
  intervention required — check filesystem permissions and mount
  state."), propagate as `FetcherError` (deletion failure is a distinct
  problem requiring operator intervention).

On the next scheduled run, the First-Run Detection truth table
re-evaluates the clone state and applies appropriate recovery
(row "Cursor exists + Clone absent" → re-clone + SHA reachability
check).

**Error Handling Strategy**:

Infrastructure failures and their outcomes:

| Infrastructure failure | Exception | `execute()` action | BaseFetcher behavior |
|------------------------|-----------|--------------------|---------------------|
| Clone fails (network) | `GitFetchError` | Catch → raise `FetcherError` (clone intact) | `status = failure`, cursor not advanced |
| Fetch fails (network) | `GitFetchError` | Catch → raise `FetcherError` (clone intact) | `status = failure`, cursor not advanced |
| HEAD unreadable (corruption after retries) | `GitCorruptionError` | Delete clone → raise `FetcherError` | `status = failure`, cursor not advanced |
| Delta computation fails (corruption after retries) | `GitCorruptionError` | Delete clone → raise `FetcherError` | `status = failure`, cursor not advanced |
| Directory deletion fails (filesystem) | `OSError` | Log ERROR → raise `FetcherError` | `status = failure`, cursor not advanced. Requires operator filesystem intervention |

**Clone availability window**: between the corruption-triggered
deletion and the next scheduled run's re-clone, `fetch_single()` will
find the clone absent and degrade gracefully (raises `RuntimeError` →
dispatch system tries the next fetcher). This window lasts at most one
scheduling interval (typically hours). The trade-off is accepted:
immediate self-healing of corruption outweighs temporary
`fetch_single()` unavailability for one source.

The **all-items-failed safety check** is handled by
`BaseFetcher.run()` (see "Status determination precedence" in
`fetcher-infrastructure.md`). If all items fail (e.g., local storage
failure making every `show_file()` fail, or database connection loss
causing every `process_item()` to raise), `run()` sets
`status = failure` directly after `execute()` returns. Since the cursor
is only persisted on `success` or `partial`, the previous cursor is
preserved and the next run retries the same delta. This applies to all
fetcher subclasses uniformly, not just git-based fetchers.

**Status Determination**:

`BaseGitFetcher` relies entirely on `BaseFetcher`'s existing status
mechanism — no additional logic is needed:

| Scenario | Status | Cursor advances? |
|----------|--------|-----------------|
| First run (no processing) | `success` | Yes (step 3e) |
| Empty delta (HEAD unchanged) | `success` | Yes (step 11) |
| All items succeed | `success` | Yes (step 11) |
| Some items fail, some succeed | `partial` | Yes (step 11) |
| All items fail | `failure` | No (`BaseFetcher.run()` safety check) |
| Infrastructure error | `failure` | No (propagates) |

**Design note — cursor advancement on `partial` (commit `a7e2632`):**
advancing the cursor on `partial` runs is an intentional trade-off.
Failed items are not automatically retried — they reappear naturally
when upstream modifies them (git's change-tracking provides recovery).
Persistent failures indicate code bugs requiring human intervention,
not automated retry; the alternative (not advancing the cursor) creates
an ever-growing reprocessing loop that is operationally worse. Failed
items are identified in WARNING logs by CVE-ID (step 10e:
`"Failed to process item %s: %s", cve_id, e`), enabling operators to invoke
`fetch_single()` for targeted recovery. See also: rejected alternatives
(threshold-based cursor, per-item retry tracking) were rejected during initial design.

## Hook Methods (Override Points)

These are the extension points for concrete subclasses:

**Hooks for `execute()`**:

| Method | Required? | Default | Purpose |
|--------|-----------|---------|---------|
| `process_item(path, content, session)` | **Yes** (abstract) | — | Process a single file from the delta. Calls `self.record_created()` or `self.record_updated()` on success |
| `filter_delta_files(file_list)` | No | Return all | Filter raw delta output to relevant files (e.g., only `.json` in specific dirs) |
| `deduplicate_items(file_list)` | No | No-op | Deduplicate items before processing (e.g., same CVE-ID in both `published/` and `rejected/`) |

**Hooks for `fetch_single()`**:

| Method | Required? | Default | Purpose |
|--------|-----------|---------|---------|
| `_construct_candidate_paths(item_id)` | **Yes** (abstract) | — | Return ordered list of candidate file paths for local clone lookup |

## `process_item(path: str, content: bytes, session: AsyncSession) -> PostIngestTasks | None`

The core extension point. Receives:
- `path`: relative path within the repository (e.g., `cve/published/2024/CVE-2024-50055.json`)
- `content`: raw file content as bytes (from `git show`)
- `session`: the database session for the current execution (same
  `AsyncSession` instance passed to `execute()` by `BaseFetcher.run()`)

The hook is responsible for:
1. Parsing the content and applying business logic (upsert, etc.)
2. Calling `self.record_created()` or `self.record_updated()` to report
   the outcome (same pattern as non-git `BaseFetcher` subclasses)
3. Returning `PostIngestTasks` if post-ingest dispatch is needed, or
   `None` in two cases: (a) the item was skipped (already up-to-date,
   no work done — no metric is recorded), or (b) the item was
   processed but no post-ingest tasks are needed (e.g.,
   enrichment-only upsert with no ticket or no CPE data — metric IS
   recorded). Both `None` cases result in
   `commit_and_dispatch(session, None)` — the template commits without
   dispatching Phase 2 tasks

Raises any exception on failure → caught by `execute()`, logged,
`record_failed()` called.

**Order independence**: the iteration order in which `process_item()`
is called within a single `execute()` run is undefined — it is
determined by `git diff` output order (tree-traversal), which has no
semantic significance. Implementations MUST be order-independent: the
result of processing any single item must not depend on whether other
items in the same delta have already been processed.

**Phase 2 side effects**: hooks that call `cve_service.upsert_cve()`
return `PostIngestTasks` containing the Phase 2 task arguments. The
`BaseGitFetcher` template dispatches these tasks via
`commit_and_dispatch()` after committing the per-item transaction.
No post-processing batch hook is needed — Phase 2 is per-item and
self-contained.

## `filter_delta_files(file_list: list[str]) -> list[str]`

Optional override. Receives the file list from `git diff` (after
applying `delta_path_prefix` path restriction at the git level).
Returns only the files that should be processed.

The two-level filtering design:
- **`delta_path_prefix`** (class attribute): coarse path-prefix
  filtering at the git subprocess level (`-- '<prefix>'`). Reduces the
  diff output before it reaches Python
- **`filter_delta_files()`** (hook): fine-grained filtering in Python
  (e.g., regex matching, extension checks, directory logic)

Example (kernel): keep only `.json` files matching
`cve/{published,rejected}/YEAR/CVE-YEAR-ID.json`.

## `deduplicate_items(file_list: list[str]) -> list[str]`

Optional override. Receives the filtered file list. Returns a
deduplicated list resolving conflicts (e.g., if same CVE appears in
both `published/` and `rejected/`, keep only the `rejected/` entry).

Default implementation returns the list unchanged.

## Default `fetch_single()` Implementation

`BaseGitFetcher` provides a concrete implementation of `fetch_single()`
that overrides the `BaseCVEFetcher` default (which raises `RuntimeError`).
Concrete subclasses inherit it automatically (no override needed).

**Behavior**:

1. Resolve repository path from `$GIT_CLONE_BASE_DIR / clone_dir_name`
2. Check if clone is valid at `repo_path`. If NOT valid: raise
   `RuntimeError` ("Clone not available at {repo_path} for single-item
   lookup")
3. Call `_construct_candidate_paths(item_id)` to obtain an ordered list
   of candidate file paths. If the hook raises `ValueError` (malformed
   `item_id` for this source's format): log ERROR ("Malformed item_id
   '{item_id}' for {fetcher_name} — format not recognized by
   _construct_candidate_paths"), raise `CVENotInSource`
4. For each `path` in the candidate list:
   a. Read file content via `show_file(repo_path, "HEAD", path)`
   b. If `show_file` raises `GitFileError`: log WARNING ("File read
      failed for {path} — skipping candidate"), record the
      failure, continue to next candidate path
   c. If content is not `None` (file found): return the result of
      `process_item(path, content, session)` (`PostIngestTasks | None`)
5. After all candidate paths exhausted:
   a. If at least one candidate raised `GitFileError` (and none
      returned content): raise `RuntimeError` ("File read failed for
      all candidate paths for item {item_id}")
   b. Otherwise (all candidates returned `None`): raise
      `CVENotInSource()`

**Audit events**: none created directly. Side effects (DB mutations,
audit events) are delegated entirely to `process_item()` — the
concrete subclass's hook determines what is recorded.

**Re-invocation**: calling `fetch_single()` with the same `item_id`
multiple times is safe. Idempotency depends on the concrete
`process_item()` implementation — both current subclasses
(`SyncMitreCves`, `SyncKernelCves`) delegate to `cve_service.upsert_cve()`
which is idempotent (no-op if data unchanged, update if changed).

**Exceptions**:

- `RuntimeError` — clone not available (step 2), or file read failed
  for all candidate paths (step 5a). Both indicate the source is
  temporarily not queryable
- `CVENotInSource` — item not found in any candidate path (step 5b),
  or `item_id` format not recognized by this source (step 3). In the
  latter case, an ERROR is logged before raising — the exception is
  semantically correct (the item cannot exist in a source whose path
  structure cannot accommodate its format) but the ERROR signals a
  likely upstream data issue
- Exceptions from `process_item()` propagate uncaught to the caller
- Other exceptions from `_construct_candidate_paths()` (not
  `ValueError`) propagate uncaught — these indicate hook
  implementation bugs, not input format issues

The two exception types serve different purposes for the caller
(`trigger_on_demand_fetch()`):

- **`RuntimeError`** — "source not queryable right now" (clone missing,
  not yet created by the first periodic run, deleted after corruption
  detection, or local object store failure). The dispatch
  system logs a WARNING and tries the next fetcher. The clone will be
  available after the next scheduled sync re-clones it.

  **Degradation window**: after a corruption-triggered deletion (see
  "Error Handling Strategy"), the clone is absent until the next
  scheduled periodic run re-creates it. During this window (at most one
  scheduling interval — typically hours), all `fetch_single()` calls for
  this source degrade to `RuntimeError`. This is an accepted trade-off:
  other CVE sources remain available via the dispatch fan-out, and the
  specific item can be retried after the next sync restores the clone.
- **`CVENotInSource`** — "item does not exist in this source"
  (authoritative negative). The dispatch system logs INFO and tries the
  next fetcher.

## `_construct_candidate_paths(item_id: str) -> list[str]`

Abstract method. Returns an ordered list of candidate file paths where
the item might exist in the repository. The default `fetch_single()`
tries each path in order via `git show` until one succeeds.

The ordering is significant: the first match wins. If the same item
could exist in multiple locations (e.g., `published/` vs. `rejected/`),
place the most likely or authoritative path first.

**Exception contract**: implementations MUST raise `ValueError` if
`item_id` does not match the format expected by this source (e.g.,
not parseable as `CVE-YYYY-NNNN`). Raw parsing exceptions
(`IndexError`, `KeyError`, etc.) MUST NOT propagate — convert them
to `ValueError` with a descriptive message. This allows the
`fetch_single()` template to distinguish "unrecognizable input" (caught
→ `CVENotInSource` + ERROR log) from genuine hook bugs
(`AttributeError`, `TypeError`, etc. — propagate uncaught).

```python
# Kernel example:
def _construct_candidate_paths(self, cve_id: str) -> list[str]:
    parts = cve_id.split("-")
    if len(parts) < 3 or parts[0] != "CVE":
        raise ValueError(
            f"Unrecognizable item_id format for kernel source: {cve_id}"
        )
    year = parts[1]  # CVE-YYYY-NNNNN → YYYY
    return [
        f"cve/published/{year}/{cve_id}.json",
        f"cve/rejected/{year}/{cve_id}.json",
    ]
```

## Inherited Utility Methods

These methods are available to concrete subclasses (e.g., for use in
`fetch_single()`). They are NOT hook methods — subclasses call them
but do not override them.

All methods in this table propagate exceptions from the corresponding
`git_operations` function they delegate to. No method creates audit
events or mutates database state — they are pure infrastructure
operations.

| Method | Purpose |
|--------|---------|
| `_get_last_cursor_sha()` | Reads the `"sha"` field from the previous `FetcherRun.cursor` (via `BaseFetcher`). Returns `None` if no prior successful run exists |
| `_get_last_cursor_committed_at()` | Reads the `"committed_at"` field from the previous `FetcherRun.cursor` (via `BaseFetcher`). Returns `None` if no prior successful run exists or if the field is absent |
| `_repo_path()` | Returns `Path($GIT_CLONE_BASE_DIR / clone_dir_name)` |
| `_extract_item_id(path)` | Extracts CVE-ID from a file path for status tracking and logging. Default: `Path(path).stem` (e.g., `cve/published/2024/CVE-2024-50055.json` → `CVE-2024-50055`). Override only if the repository uses non-standard naming |
| `_clone_repo(path)` | Clones the repository with configured options (bare, filter, single-branch). Delegates to `git_operations.clone()` |
| `_fetch_origin(path)` | Runs `git fetch origin`. Delegates to `git_operations.fetch_origin()` |
| `_get_head_sha(path)` | Returns current HEAD SHA. Delegates to `git_operations.get_head_sha()` |
| `_get_commit_date(path, ref)` | Returns commit date as ISO 8601 string in UTC. Delegates to `git_operations.get_commit_date()` |
| `_is_clone_valid(path)` | Returns bool. Delegates to `git_operations.is_clone_valid()` |
| `_check_sha_reachable(path, sha)` | Returns bool. Delegates to `git_operations.check_sha_reachable()` |
| `_compute_delta(path, from_sha, to_sha)` | Returns file list from `git diff` with `delta_path_prefix`. Delegates to `git_operations.diff_names()` |
| `_compute_recovery_delta(repo_path, head_sha, cursor_committed_at)` | Applies recovery using stored commit date minus 1 day + `recovery_path_prefix`. See detailed behavior below |
| `_show_file(path, ref, file_path)` | Returns file content or None. Delegates to `git_operations.show_file()` |
| `_delete_if_exists(path)` | Deletes directory if it exists. Delegates to `git_operations.delete_clone()` |

## `_compute_recovery_delta()`

Computes the file delta using the stored cursor commit date when the
cursor SHA is unreachable (force-push, history rewrite, or clone
rebuild).

`async def _compute_recovery_delta(repo_path: Path, head_sha: str, cursor_committed_at: str) -> list[str]`

**Behavior**:

1. Compute `before_date` as `cursor_committed_at` minus 1 day (the
   1-day margin ensures no items are missed around the boundary —
   reprocessing is idempotent)
2. Call `rev_list_before(repo_path, before_date)` to find the boundary
   SHA — the most recent commit before `before_date`
3. If `rev_list_before` returns `None` (no commit exists before
   `before_date` — the repository history does not extend that far
   back):
   a. Log WARNING: "Recovery boundary not found — repository may have
      been completely rewritten. Treating as first-run. Cursor reset to
      HEAD. Use fetch_single() to recover specific items if needed."
   b. Return empty list
4. Call `diff_names(repo_path, boundary_sha, head_sha)` with
   `recovery_path_prefix` as path filter
5. Return the file list

**Edge case rationale (step 3)**: this scenario requires that ALL
commits reachable from HEAD have dates more recent than the stored
`cursor_committed_at - 1 day`. For repositories like cvelistV5
(history since 2022) or vulns.git (history since 2024), this is
virtually impossible — it would require complete repository recreation
with new commit dates. The first-run treatment (cursor advances to
HEAD, zero items processed) is the correct response: the fetcher
restarts cleanly and `fetch_single()` is available for manual recovery
of specific items.

**Exceptions**: propagates `GitCorruptionError` from `rev_list_before()`
(step 2) and `diff_names()` (step 4).

## Registry Detection Predicate Update

`get_catch_up_fetchers()` uses the `participates_in_catch_up` class
attribute (auto-derived from `supports_fetch_single` for CVE fetchers).
`get_fetch_single_fetchers()` uses `_CVE_SOURCE_TYPE_MAP` filtered by
`supports_fetch_single`. `BaseGitFetcher` does not override either
attribute — all git-based fetchers participate in both rosters
automatically via their inherited `supports_fetch_single = True`
(which derives `participates_in_catch_up = True`).

## When NOT to Use `BaseGitFetcher`

`BaseGitFetcher` is NOT a requirement for all fetchers that interact
with git repositories. It is the correct choice only for fetchers that
follow the standard delta-based flow (clone → fetch → SHA reachability
→ delta detection → per-item processing → cursor advance).

A future git-based fetcher MUST inherit from `BaseCVEFetcher` directly
(using `git_operations.py` as a utility module) when it is a CVE
fetcher but:

- It requires multi-branch tracking (the template assumes
  single-branch, single HEAD)
- It uses sparse checkout or non-standard clone strategies not
  expressible via the class attributes
- Its delta detection is not commit-range based (e.g., full tree scan,
  tag-based comparison)
- It needs non-linear traversal (e.g., walking merge commits
  individually)
- Its processing flow has steps between delta detection and per-item
  processing that cannot be expressed as a filter hook

A non-CVE git-based fetcher inherits from `BaseFetcher` directly
(using `git_operations.py` as a utility module).

In these cases, `BaseCVEFetcher` (or `BaseFetcher`) +
`git_operations.py` provides the same subprocess utilities without
imposing a fixed execution order.

**Note**: fetchers that need full tree enumeration (e.g., for initial
population or full-scan strategies) can use
`git ls-tree -r --name-only HEAD` on a bare clone to list all files in
the repository without checkout. This operation is classified as a Read
operation with a 30-second timeout and 3 retries per the timeout table.
The `BaseGitFetcher` template method does not invoke `ls-tree` — it is
available exclusively as a utility for non-template fetchers.


## Cross-references

- `docs/features/platform/fetcher-infrastructure.md` — BaseFetcher base
  class
- `docs/features/platform/cve-fetcher-infrastructure.md` — BaseCVEFetcher
  class (parent)
- `docs/features/tickets/cve-sync-mitre.md` — MITRE CVE fetcher
  (consumer)
- `docs/features/tickets/cve-sync-kernel.md` — Kernel CVE fetcher
  (consumer)
