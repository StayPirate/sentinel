# CLI Infrastructure

## Purpose & Scope

This specification defines the shared infrastructure underlying every
Sentinel CLI command: the package entry point, the root command group
and its bootstrap sequence, database session acquisition, error-to-exit-code
mapping, signal handling, the configuration-guard mechanism, and
interactive input helpers.

**This specification does not restate the CLI contract already defined in
`docs/conventions.md` (CLI Conventions)** — framework choice (Click),
command design principles, the Output Contract (channel separation, exit
code table, success/error message format, multi-step `✓`/`✗`/`—`
reporting, idempotency declarations), and naming conventions remain owned
by `docs/conventions.md`. This specification owns the shared *mechanism*
that implements that contract, so that individual command specs
(`user-management.md`, `api-key-management.md`, `fetcher-operations.md`) do
not each need to re-derive it.

**This specification does not define individual commands.** Each command's
parameters, behavior, and command-specific error messages remain owned by
its feature spec, per the classification rule in
`docs/conventions.md` (CLI Command Behaviors are documented via the CLI
Output Contract, not the Q1-Q6 completeness framework).

**Out of scope**: structured/machine-readable (`--json`)
output. No currently specified command defines such a flag. If a future
command requires it, the shared serialization envelope will be defined
here at that time — specifying it now would be speculative. See
`docs/conventions.md` (Human-Readable Format) for the current constraint
that plain text remains the default and any structured output must be an
explicit per-command opt-in.

## Related Specifications

| Spec | Relationship |
|------|--------------|
| `docs/conventions.md` (CLI Conventions) | Authoritative contract this spec implements: framework, Output Contract, exit codes, naming. |
| `docs/features/platform/logging.md` (Scope of this pipeline) | Defines the minimal structlog-to-stderr configuration this spec's bootstrap sequence applies at root group initialization. |
| `docs/features/platform/testing-strategy.md` (Mandatory Test Scenarios → CLI Commands, Sync Entry-Point Tests) | Defines the mandatory CLI test scenarios and the synchronous test function requirement; this spec defines the harness those tests run against. |
| `docs/features/identity/user-management.md` | Consumer: `manage-user` command group delegates to async services via the pattern defined here. |
| `docs/features/identity/api-key-management.md` | Consumer: owns the `api-key` command group behavior and delegates to async services via the pattern defined here. |
| `docs/features/platform/fetcher-operations.md` | Consumer: `fetcher` command group uses the `asyncio.run()` session mechanism defined here for its read-only queries. |
| `docs/features/identity/user-service.md`, `docs/features/identity/api-key-service.md` | Define the async service contracts invoked from within the `asyncio.run()` mechanism defined here. |
| `docs/features/platform/system-settings.md` | Defines the system settings mechanism consumed by the Configuration Guard decorator. |
| `docs/cli-reference.md` | Catalog: quick-reference index of all CLI commands with synopses, cross-referencing owning feature specs for full details. |

## Package Entry Point & Invocation

| Property | Value |
|---|---|
| Console script | `sentinel`, registered via `[project.scripts]` in `backend/pyproject.toml` (`sentinel = "app.cli:main"`) |
| Module invocation | `python -m app.cli ...`, backed by `backend/app/cli/__main__.py` delegating to the same `main()` entry point |
| Code location | `backend/app/cli/` (subpackage under `backend/app/`) |
| Group assembly | `backend/app/cli/__init__.py` defines a root Click group (`cli`) and registers each command group (`manage-user`, `fetcher`, `api-key`, and any future group) via `cli.add_command(...)`; the exported `main()` wrapper performs eager-option handling, fail-fast bootstrap, signal setup, and invokes `cli.main(standalone_mode=False)` |

Each command group (`manage-user`, `fetcher`, `api-key`) is implemented as
its own Click `Group` in a dedicated module under `backend/app/cli/`
(e.g., `backend/app/cli/manage_user.py`), imported and registered by the
root group at import time. This mirrors the fetcher registry's
import-time discovery pattern (`fetcher-infrastructure.md`, Registry)
without requiring dynamic discovery — the CLI's command surface is small
and enumerated explicitly. Those modules define only lightweight Click
metadata at import time; imports of `app.config`, `app.database`, and service
modules that transitively instantiate settings are deferred until after eager
`--help`/`--version` handling and the fail-fast settings boundary.

**Q1 (inputs)**: N/A — this section describes packaging, not a function.

## Root Command Group & Bootstrap

The root group (`sentinel`) performs the following steps, in order, before
dispatching to the invoked subcommand:

1. Parse `--version` (prints the value from
   `importlib.metadata.version("sentinel")` and exits 0, per the existing
   pattern in `backend/app/main.py`) and help at every command level. Version
   and help are eager: `sentinel --help`, `sentinel <group> --help`, and
   `sentinel <group> <command> --help` exit 0 without loading application
   settings, opening database or Redis connections, or importing modules that
   instantiate settings.
2. Load the `Settings` singleton from `backend/app/config.py` inside the entry
   point's fail-fast boundary. `app.cli` package import and command registration
   MUST remain lightweight enough to preserve step 1 even though
   `app.config` instantiates `Settings` at module import. If that import or
   initialization raises (invalid configuration), the boundary prints a
   plain-text `Error: ...` message to stderr and exits with code 2 (system
   error), without a traceback. This is consistent with the fail-fast
   precedents in `docs/conventions.md` (Runtime Version) and `logging.md`
   (Startup Validation).
3. Install the `SIGINT` and `SIGTERM` handlers defined in Signal Handling.
4. Apply the minimal structlog-to-stderr configuration required by
   `docs/features/platform/logging.md` (§"Scope of this pipeline"): route
   structlog output through stdlib `logging` to stderr, plain-text format,
   level `WARNING` or above. This ensures DEBUG/INFO messages from shared
   service code invoked by CLI commands do not pollute stdout, which
   remains reserved exclusively for the CLI Output Contract. No
   correlation IDs (`request_id`, `celery_task_id`, `fetcher_run_id`) are
   bound in this context.
5. Dispatch to the invoked subcommand.

**Q1 (inputs)**: global CLI arguments (`--version`, `--help`, and the
subcommand path) — standard Click argument parsing, no custom semantics
beyond what is described above.

**Q2 (guards)**: `Settings` validation failure aborts before any subcommand
executes (exit 2). No other root-level guard exists — per-command guards
(e.g., configuration guards, see below) are evaluated by each subcommand.

**Q3 (behavior)**: as enumerated in the five steps above; no other root
group behavior exists.

**Q6 (exceptions)**: `Settings` validation exceptions are caught at this
level and converted to the exit-2 path described in step 2. All other
exceptions propagate to the per-command error handling described in
"Error Handling & Exit Code Mapping" below.

## Database Session Management

Sentinel is an async-only project (see `docs/conventions.md`, SQLAlchemy
Conventions): no synchronous database driver or engine exists anywhere
in the codebase (`backend/app/database.py` defines only
`create_async_engine` and `async_sessionmaker`; `backend/pyproject.toml`
declares only `asyncpg`, no `psycopg`/`psycopg2`). Every CLI command,
whether read-only or mutating, follows the same mechanism — there is no
per-command path selection.

- The synchronous command boundary passes the existing
  `async_session_factory` (`backend/app/database.py`) into a single
  `asyncio.run(...)` call wrapping the **entire command workflow** — not
  just a service invocation. The async workflow creates and closes each
  `AsyncSession`; the synchronous boundary never creates a live session
  before entering `asyncio.run()`. For read-only commands
  (`fetcher list`, `fetcher config`, `manage-user list`, `manage-user
  show`, `api-key list`), the wrapped function delegates database reads
  to the architecture-approved query or service boundary. For commands
  that delegate to an async service module
  (`manage-user create`, `update`, `deactivate`, `set-password`,
  `unlock`, and `api-key revoke`), the wrapped function calls the
  service function, per the async pattern already declared in
  `user-service.md` ("Async pattern") and `api-key-service.md` ("Module
  Location and Invocation").
- For commands with pre-mutation reads or interactive prompts (e.g.,
  `manage-user deactivate` reads impact counts, prompts for
  confirmation, then deactivates), all of these steps run inside the
  same `asyncio.run()` call. Blocking terminal I/O (e.g.,
  `click.confirm()`, hidden password prompts) inside the wrapped async
  function is acceptable for one-shot CLI processes — the event loop has
  no other work scheduled while waiting for operator input, unlike in a
  server context where blocking would stall concurrent requests, e.g.:

  An interactive prompt MUST NOT run while a database session is open.
  Pre-prompt reads complete and their session closes before terminal input;
  after confirmation, the mutation opens a new session. This prevents an
  unanswered prompt from leaving a connection idle in transaction. The
  staleness contract below governs the state change between those sessions.

  ```python
  async def deactivate_flow(session_factory, username):
      async with session_factory() as db:
          user = await user_service.get_user(db, username)
          impact = await user_service.get_deactivation_impact(
              db, user.id, acting_user_id=None
          )
          if impact.already_inactive:
              print(f"User '{username}' is already inactive.")
              return                                  # exit 0, no prompt
          if user.external_id is not None:
              raise click.ClickException(              # command-owned guard for
                  "Cannot deactivate external users."  # actor-NULL CLI callers
              )
      if not click.confirm("Proceed?", default=False):  # blocking prompt
          print("Aborted.")                            # printed to stdout
          return                                        # exit 0, no mutation
      async with session_factory() as db:
          result = await user_service.deactivate_user(db, user.id, ...)
          await db.commit()
      await session_service.purge_session_cache(
          result.invalidated_session_ids
      )

  asyncio.run(deactivate_flow(async_session_factory, username))
  ```

  When the operator declines a confirmation prompt, the command prints a
  short confirmation of inaction (e.g., `"Aborted."`) to stdout and exits
  0 — declining is a valid, non-erroneous outcome (the desired state,
  "do not proceed," was honored), not a user error. The exact wording of
  the abort message is owned by the calling command's own spec; this
  section only fixes the exit code (0) and the fact that no mutation
  occurs. If the confirmation prompt receives EOF instead of an explicit
  answer (e.g., piped/closed stdin, Ctrl+D), Click raises `click.Abort`;
  this is treated identically to an explicit decline (stdout message,
  exit 0) — TTY detection (see Interactive Input Helpers) is expected to
  reject non-interactive invocations before reaching the prompt in the
  first place, so `click.Abort` from an already-detected TTY session
  represents an explicit operator-initiated cancellation, not a system
  error.

  **Note on pre-mutation read staleness**: the pre-mutation reads in the
  first session of the `deactivate_flow` example (user lookup,
  deactivation impact count) are best-effort/advisory information
  displayed to the human operator to support the confirmation decision
  — they are not authoritative inputs to the mutation itself. The
  service function (`user_service.deactivate_user()`) independently
  re-validates its applicable guards — the locked-current active state
  for every caller, plus the self-deactivation and external-status
  guards for an actor-authenticated caller — inside its own transaction
  using pessimistic locking
  (`SELECT ... FOR NO KEY UPDATE`), per `user-service.md` (Concurrency
  Considerations) and the general pattern in `docs/conventions.md`
  (Transaction and Locking). Guards that cannot apply to an actor-NULL
  caller, such as the CLI's manual-surface guard against external users
  shown above, remain the owning command's responsibility and are not
  re-checked by the service; see `user-service.md` (External Active
  Status Ownership) and `user-management.md` (`manage-user deactivate`).
  As a consequence, staleness between the
  pre-mutation reads (first session) and the actual mutation (second
  session) does not cause incorrect behavior — worst case, the
  mutation becomes a no-op or raises a service exception handled
  normally by the CLI's error handling mechanism. This is a deliberate,
  accepted design tradeoff, not a defect requiring additional
  complexity such as defensive re-checks or retry logic between the two
  sessions.

  For commands with no pre-mutation reads or prompts, the simpler
  single-call form applies directly. Mutation example:

  ```python
  async def revoke_flow(session_factory, key_id):
      async with session_factory() as db:
          try:
              await api_key_service.revoke_key(db, key_id, ...)
              await db.commit()
          except BaseException:
              await db.rollback()
              raise

  asyncio.run(revoke_flow(async_session_factory, key_id))
  ```

  Read-only example:

  ```python
  async def manage_user_list(session_factory, filters):
      async with session_factory() as db:
          page = await user_service.list_users(db, **filters)
      print_table(page.items)

  asyncio.run(manage_user_list(async_session_factory, filters))
  ```

- Each async CLI workflow that performs a PostgreSQL mutation owns one
  database transaction. It opens the transaction, invokes services that flush
  but never commit, commits exactly once after the complete database workflow
  succeeds, and rolls back on any exception or interruption before commit.
  This permits a command to compose multiple service operations atomically.
  Read-only workflows and workflows such as `manage-user unlock` that read
  PostgreSQL but mutate only ephemeral Redis state issue no empty database
  commit; session closure ends any read transaction without persisting state.
- Per the sync-to-async bridging convention (`docs/conventions.md`,
  SQLAlchemy Conventions), exactly one `asyncio.run()` call occurs per
  command invocation, wrapping the extracted `async def` flow function.
- A delegated service or workflow that uses application-owned Redis obtains
  its async client or client factory inside that same `asyncio.run()` boundary
  and closes the client before the boundary returns. No live async Redis client
  is retained across command invocations or created at module import. The
  consumer-owned factory, accessor, or equivalent replaceable boundary is an
  implementation choice; existing service signatures do not gain a Redis
  parameter solely for CLI use.
- Connection failure (database unreachable) propagates as an exception
  from the wrapped async call; see "Error Handling & Exit Code Mapping"
  below.

The transaction classification of each command follows its owning feature
specification. `docs/cli-reference.md` is the command catalog; this shared
infrastructure specification does not duplicate that inventory.

**Q4 (audit events)**: N/A — this section describes session acquisition
only. Whether a given command's operation creates audit events is
determined entirely by the delegated service function's own contract
(e.g., `user_service.create_user()` creates `IdentityAuditEvent` per
`user-service.md`); this spec introduces no additional audit trail
obligations. Read-only commands create no audit events.

**Q5 (re-invocation)**: N/A at this level — idempotency is a per-command
property already declared in each command's spec (per the CLI Output
Contract's Idempotency declaration), not a property of the session
mechanism itself.

## Error Handling & Exit Code Mapping

Every CLI command is wrapped by a single, unified exception mapper that
maps exceptions to the exit codes defined in `docs/conventions.md` (CLI
Output Contract, Exit Codes table). This mapper is implemented once, as
a top-level `try/except` in the exported `main()` entry-point wrapper around
the root Click group invocation, so individual
command specs do not need to restate this mapping.

The root group invokes Click with `standalone_mode=False`. In this
mode, Click does not perform its own `sys.exit()` calls, does not print
"Aborted!", and re-raises `click.ClickException` and `click.Abort` to
the caller instead of handling them internally — giving the mapper
below full and exclusive control over exit codes and messages for every
condition except broken-pipe handling (which Click performs internally
regardless of `standalone_mode`, by catching `OSError` with
`errno.EPIPE`, pacifying the stdout/stderr wrappers, and exiting 1
before the mapper is ever reached).

The mapper catches `Exception` (and all its subclasses, including the
ones listed below) — it does NOT catch `BaseException` subclasses such
as `SystemExit` or `KeyboardInterrupt`, so exit codes produced by signal
handling (130, 143 — see Signal Handling below) propagate through
untouched, never reaching this mapper.

| Exception / condition | Exit code | Handling |
|---|---|---|
| No exception; command completed (including idempotent no-op) | 0 | Success message printed to stdout per the command's own spec. |
| `click.ClickException` and all its subclasses (`UsageError`, `BadParameter`, `MissingParameter`, `NoSuchOption`, `NoSuchCommand`, `BadOptionUsage`, `BadArgumentUsage`, `FileError`, etc. — malformed invocation caught by Click itself before the command callback executes) | 1 | The mapper calls `e.show()` to preserve Click's native formatting (usage line, "Try '--help'" hint, message), then exits 1. All `ClickException` subclasses map to exit 1 uniformly — the mapper does not use `e.exit_code` (which Click would otherwise set to 2 for `UsageError`) — consistent with `docs/conventions.md` classifying malformed invocation as a user error (exit 1), not a system error (exit 2). |
| `click.Abort` (raised by Click when an interactive prompt, e.g. `click.confirm()` or a hidden password prompt, receives EOF/Ctrl+D — and, in non-standalone mode, also the exception type Click internally converts `KeyboardInterrupt` into during prompt handling) | 0 | The mapper prints `Aborted.` to stdout and exits 0. This is the same code path whether `Abort` originates from an explicit prompt decline (in which case the command's own code, per Database Session Management, has already printed its own cancellation message before returning/re-raising, so the mapper's `Aborted.` fallback is not what the operator sees) or from EOF bypassing the command's own code entirely (in which case the mapper's `Aborted.` is the only message printed). Treated as an operator-initiated cancellation, not an error, consistent with the Exit Codes table. TTY detection (Interactive Input Helpers) is expected to reject non-interactive invocations before a prompt is reached in the first place. |
| A `ServiceError` subclass (or any shared exception per `docs/conventions.md`, Service Exception Conventions) raised by a delegated service call | 1 | The exception's message is formatted as `Error: {message}` and printed to stderr. The specific message text is determined by the command's own spec (see each command spec's "Behavior" section for the exact error strings), not by this mechanism. |
| A validation failure raised directly by the CLI command's own input parsing (e.g., invalid username format, password length) — i.e., a guard documented in the command's own spec, not a service exception | 1 | Same formatting as above; message text owned by the command spec. |
| SQLAlchemy `OperationalError`/`DBAPIError` (or another connection-related `SQLAlchemyError` subset, e.g. database unreachable), or `RedisError` (per `docs/conventions.md`, Redis Error Handling) surfacing from a command that touches Redis | 2 | Printed to stderr as `Error: {message}`. This is the exit code that `docs/features/platform/testing-strategy.md` (Mandatory Test Scenarios → CLI Commands) requires the harness to simulate. This category is intentionally narrow: generic `OSError`/`ConnectionError` are NOT caught here. Broken-pipe scenarios are already handled by Click's own EPIPE handling before the mapper is reached (see above); other unrelated `OSError` subclasses (`FileNotFoundError`, `PermissionError`, etc.) fall through to the catch-all row below, which prints an accurate generic message rather than a misleading "database unreachable" one. |
| Any other unhandled exception | 2 | Log the exception at ERROR with exception context under `logging.md`'s secrets/PII discipline, then print `Error: {message}` to stderr. If `str(exception)` is empty, use the exception class name as `{message}`. Reserved as the catch-all "system error" path per the Exit Codes table in `docs/conventions.md`. |
| `KeyboardInterrupt` (operator sends SIGINT, e.g., Ctrl+C) | 130 | Not caught by this mapper (it is a `BaseException` subclass, and — for the direct SIGINT case — is intercepted at the OS signal level before it can even be raised as a Python exception). See Signal Handling below. |
| `SIGTERM` received while a command is running | 143 | Not caught by this mapper (`BaseException` subclass). See Signal Handling below. |

**Q6 (exceptions)**: this mechanism is the terminal exception handler for
every CLI command — no `Exception`-derived exception propagates past it
to the shell. It propagates nothing; it converts every caught exception
into the exit code above and a stdout/stderr message. `BaseException`
subclasses used for signal-derived termination (`SystemExit` raised by
the signal handlers below) are explicitly outside its scope and pass
through untouched.

**Q3 (behavior in every case)**: the table above is exhaustive for the
generic mechanism. Command-specific exception→message text mapping
remains the responsibility of each command's own spec (this mechanism
only determines the exit code and the `Error:`/`Warning:` formatting
convention, not the message content).

**Warnings**: a command may emit zero or more `Warning: {message}` lines
to stderr without affecting the exit code (per `docs/conventions.md`,
Error Output). This mechanism does not alter or intercept warnings — they
are emitted directly by command code at the point of detection.

## Signal Handling

The root Click group installs signal handlers for `SIGINT` and `SIGTERM`
that guarantee the exit codes mandated by `docs/conventions.md` (CLI
Output Contract, Exit Codes table):

| Signal | Trigger | Exit code | Behavior |
|---|---|---|---|
| `SIGINT` | Operator presses Ctrl+C | 130 | The root group installs an explicit `signal.signal(signal.SIGINT, ...)` handler that raises `SystemExit(130)` directly, at the OS signal level, before Click's own EOFError/KeyboardInterrupt-to-`Abort` conversion (see Error Handling & Exit Code Mapping) has a chance to run. This is necessary because Click internally converts both Ctrl+C (`KeyboardInterrupt`) and Ctrl+D/EOF during a prompt into the same `click.Abort` exception, making the two indistinguishable by the time either would reach the exception mapper. Intercepting SIGINT at the signal level ensures Ctrl+C reliably produces exit 130 regardless of whether a prompt is active, while Ctrl+D during a prompt still flows through Click's own EOFError→`Abort` path (mapper's `Aborted.` / exit 0). No cleanup beyond what the interrupted database session's own `__exit__`/`finally` already performs. |
| `SIGTERM` | Process manager requests shutdown | 143 | A handler is registered that raises a `SystemExit(143)`-equivalent signal at the next Python bytecode boundary. Because `SystemExit` is a `BaseException` subclass, it is not caught by the `Exception`-scoped mapper described in Error Handling & Exit Code Mapping, and propagates cleanly to terminate the process with code 143. No mid-transaction partial commit is attempted — an in-flight database transaction is left to roll back via the session's own `__aexit__`/`finally` handling, consistent with normal exception-driven rollback. |

Commands are not expected to perform custom cleanup beyond what their
database session context manager already guarantees. No command in the
current catalog holds a lock or performs a multi-step operation where
partial interruption would leave inconsistent state beyond what a single
transaction rollback already resolves (read-only commands perform no
writes; mutating async workflows own one transaction and delegate the
individual mutations to services).

**Q6 (exceptions)**: `KeyboardInterrupt` and the SIGTERM-derived exit are
both terminal — they do not propagate beyond the root group.

## Configuration Guard

`docs/conventions.md` (Command Design) states: "Commands that modify data
MAY check a configuration guard before executing. If a guard is defined
and not enabled, the command MUST exit with a clear error message
explaining which setting to enable." This section defines the shared
mechanism implementing that MAY clause.

A configuration guard is implemented as a decorator applied to a specific
command's Click callback (e.g.,
`@requires_setting("some_setting_name")`), which:

1. Reads the named setting via the system settings mechanism
   (`docs/features/platform/system-settings.md`).
2. If the setting is falsy/disabled, prints
   `Error: This command requires the '{setting_name}' setting to be enabled.`
   to stderr and exits 1 (a user/configuration error, not a system error)
   — before the command's own body executes.
3. If the setting is enabled, proceeds to execute the command body
   normally.

The guard's setting read (step 1) executes **inside** the same
`asyncio.run()` call that wraps the command's own workflow (see
Database Session Management, "exactly one `asyncio.run()` call per
command invocation") — the decorator wraps the command's async
workflow function itself and performs its check as the first step of
that function, before any command-specific logic runs. It does not
open a second `asyncio.run()` call. If the settings read itself fails
(e.g., database unreachable), that failure propagates through the same
exit-2 "connection failure" path defined in Error Handling & Exit Code
Mapping — the guard introduces no separate error-handling path.

**No currently specified command uses this mechanism.** This section exists so
that a
future command needing one has a defined shape to follow, per the MAY
clause already present in `docs/conventions.md`. This is not new
scope — it documents the mechanism for an already-declared but
previously unspecified convention.

**Q1 (inputs)**: the setting name (string) to check, provided by the
command author when applying the decorator.

**Q2 (guards)**: the guard itself IS the early-rejection condition — if
disabled, the command body never executes (exit 1).

**Q6 (exceptions)**: none beyond the exit-1 path above; this mechanism
does not raise, it exits directly.

## Interactive Input Helpers

Three shared helpers back the interactive behaviors already declared in
`user-management.md` for `manage-user create`, `manage-user
set-password`, and `manage-user deactivate`. Any command requiring
interactive terminal input SHOULD use these helpers rather than
reimplementing the pattern. The "Example consumers" column lists
representative usages, not an exhaustive registry — each command's own
spec remains authoritative for which helpers it uses, so this table
does not need to be updated every time a new command adopts one of
these helpers:

| Helper | Behavior | Example consumers |
|---|---|---|
| Hidden password prompt with confirmation | Prompts twice via a hidden (non-echoed) input (Click's `hide_input=True`), compares the two entries. If they differ, the calling command receives a mismatch signal and is responsible for its own error message and exit code (per that command's own spec — this helper does not print the error itself, to preserve each command's exact wording). | `manage-user create`, `manage-user set-password` |
| TTY detection | Checks `sys.stdin.isatty()` before invoking a prompt (password entry or confirmation). If no TTY is detected, returns a signal the calling command uses to print its own "requires an interactive terminal" error (exact wording owned by the command spec) and exit 1. | `manage-user create`, `manage-user set-password` (before password prompt), `manage-user deactivate` (before confirmation prompt) |
| Confirmation prompt | A yes/no prompt (Click's `confirm()`) for destructive operations. Exact prompt text and default answer are owned by the calling command's own spec. | `manage-user deactivate` |

These are implementation-shared utility functions (e.g.,
`backend/app/cli/_prompts.py`), not new behavioral contracts — the
behaviors themselves are already fully specified in
`user-management.md`. This section exists so the shared implementation
has one canonical home instead of being duplicated per command.

**Q1/Q3/Q6**: N/A beyond the table above — these are Category B (no side
effects beyond terminal I/O) helper functions whose complete behavior is
the table itself; they raise no exceptions of their own (a non-matching
password or non-TTY condition is communicated via return value, not by
raising, so each calling command retains full control over its own exact
error message per its own spec).

## Testing

This spec defines the harness; the mandatory test scenarios themselves are
owned by `docs/features/platform/testing-strategy.md` (Mandatory Test
Scenarios → CLI Commands) and are not restated here.

- **Test runner**: Click's `CliRunner` (`click.testing.CliRunner`),
  invoked against the root `sentinel` group.
- **Test function type**: CLI tests MUST be synchronous (`def`, not
  `async def`) — see `docs/features/platform/testing-strategy.md`
  (Sync Entry-Point Tests) for the cross-cutting rationale. Click's
  `CliRunner.invoke()` is itself synchronous; the commands under test
  internally call `asyncio.run()`, which would raise `RuntimeError` if
  invoked from within an already-running event loop.
- **Database fixture**: the async session factory is passed into the command
  under test, not a live `AsyncSession`. It targets the same test PostgreSQL
  server as the rest of the suite, but MUST NOT reuse an asyncpg connection
  acquired on pytest-asyncio's event loop. The harness satisfies this by using
  a CLI-test engine with `NullPool`, or an equivalent factory whose engine and
  connections are created, used, and disposed on the command's event loop.
  Mutation-command tests perform explicit cleanup because their successful
  commit cannot be undone by the ordinary per-test rollback fixture. See
  `docs/features/platform/testing-strategy.md` (Sync Entry-Point Tests).
- **Redis fixture**: the synchronous harness injects the designated worker
  database URL or a replaceable client factory, never a live async Redis
  client. The workflow creates, uses, and closes its client on the event loop
  established by its production `asyncio.run()` boundary. Setup and cleanup
  use independently owned clients and never share client objects across event
  loops.
- **Scenario ownership**: exit-code, channel, async-boundary, transaction,
  signal, prompt, and image-smoke scenarios are defined only in
  `docs/features/platform/testing-strategy.md` (Mandatory Test Scenarios → CLI
  Commands). They execute through this harness and the production mechanisms
  specified above.
