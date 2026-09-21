# User Management

## Purpose

Enable administrators to manage user accounts via the CLI and the
administration panel in the web UI. This spec covers both local users
(managed directly in Sentinel's database) and external users (synced from
the external identity provider).

Local users serve three primary use cases:

1. **Development and staging environments**: testing the full
   application workflow without depending on the SUSE internal network
2. **AI agents and automation**: dedicated accounts for AI agents or
   bots that operate as independent identities with their own audit
   trail (see `docs/features/identity/authentication.md`, Use Cases: Bots and
   AI Agents)
3. **Environments without SSO**: deployments outside the SUSE corporate
   network where `id.suse.com` is not reachable

External users are provisioned and maintained by the external sync process (see
`docs/features/identity/identity-provisioning.md`). Administrators can modify their
roles, but cannot deactivate/reactivate them (active status is managed
exclusively by external sync), set passwords, or create them manually.

Local users are created directly in the database, bypassing the external
sync process. They are functionally identical to externally-provisioned users for
the purposes of authorization, ticket assignment, and API key
management. The only difference is how they authenticate: local
credentials instead of SSO (see
`docs/features/identity/local-authentication.md`).

## CLI Commands

All commands are subcommands of the `sentinel manage-user` group. See
`docs/conventions.md` (CLI Conventions) for general CLI design
guidelines.

These commands require direct shell access to the host or container. They are
the bootstrap and recovery path when no administrator account is available.
An operator may create a new local administrator with `manage-user create
--role admin` or promote an existing user with `manage-user update --add-role
admin`. `manage-user create` remains available regardless of the current
administrator count, has no special zero-administrator branch, and never
modifies an existing account. Both commands delegate lifecycle and role
behavior to `user_service`; neither bypasses validation, audit, or transaction
rules. Ordinary creation after bootstrap uses the authenticated administrator
API; there are no unauthenticated HTTP endpoints for user management.

### `sentinel manage-user create`

Creates a new local user account with a password.

```
sentinel manage-user create \
  --username <username> \
  --email <email> \
  [--full-name <name>] \
  [--role <role>] ...
```

**Parameters**:

| Parameter      | Required | Repeatable | Description                                |
|----------------|----------|------------|--------------------------------------------|
| `--username`   | Yes      | No         | Unique username for the account             |
| `--email`      | Yes      | No         | Unique email address                        |
| `--full-name`  | No       | No         | Display name                                |
| `--role`       | No       | Yes        | Role to assign: `admin`, `vulnerability_analyst`, `restricted_analyst` |

The password is collected interactively via a hidden prompt (input is not
echoed to the terminal, like `sudo`). The prompt asks for the password
twice for confirmation. If the two entries do not match, the command exits
with error: `"Error: Passwords do not match."` (exit code 1). This
command cannot be used non-interactively — a TTY is required. If no TTY
is detected, prints to stderr `Error: This command requires an
interactive terminal (password input).` and exits with code 1.

**Behavior**:

1. Validates username format (see `docs/conventions.md`, Username Format).
   If invalid, exits with error:
   `"Error: Invalid username '{value}'. Username must be 1-64 characters,
   start with a letter, and contain only lowercase letters, numbers, dots,
   hyphens, and underscores."`
2. For each `--role` provided, validates that it is a recognized role. If
   not, exits with error:
   `"Error: Invalid role '{value}'. Valid roles are: {list}."`
   The list of valid roles is derived from the system's role definitions
   at runtime
3. Validates email format — if the provided email is not syntactically
   valid, exits with error:
    `"Error: Invalid email format '{value}'."`
   The CLI trims and lowercases the email before validation and passes the
   normalized value to the service
4. Validates password per the policy in
   `docs/features/identity/local-authentication.md` § Password Validation
   (16–128 characters). If too short, exits with error:
   `"Error: Password must be at least 16 characters."` If too long,
   exits with error:
   `"Error: Password must be at most 128 characters."`
5. Delegates to `user_service.create_user()` with:
   - `external_id = None` (local user)
   - `active = True`
   - `password` = provided password (service handles hashing)
   - `roles = [(role, '_manual') for role in provided_roles]`
   - `acting_user_id = None` (CLI action)
   - See `docs/features/identity/user-service.md` for the service contract
6. If the service raises `UserConflictError` (duplicate username or
   email), exits with error:
   `"Error: A user with username '{username}' already exists."` or
   `"Error: A user with email '{email}' already exists."`
7. Prints confirmation:
   `"Created user '{username}' ({email}) with roles: {roles}."`
   or `"Created user '{username}' ({email}) with no roles."` if no roles
   were specified

**Idempotency**: Not idempotent (interactive). Each invocation collects a
new password interactively; the operation inherently changes state.

**Exit codes**: 0 on success, 1 on validation error (duplicate user,
invalid role, missing flag), 2 on system error (database unreachable).

**Output channels**: confirmation message to stdout, all `"Error: ..."`
messages to stderr.

### `sentinel manage-user update`

Updates an existing user account. Each invocation operates in exactly one of
three mutually exclusive modes:

- **Profile mode** (`--email`, `--full-name`, `--clear-full-name`) updates
  identity fields. It is permitted on local users only — external users have
  their identity fields managed exclusively by external sync (see External
  User Data Ownership in `docs/features/identity/user-service.md`).
- **Role mode** (`--add-role`, `--remove-role`) changes manual (`_manual`)
  role assignments. It is permitted on both local and external users.
- **Reactivation mode** (`--reactivate`) reactivates a previously deactivated
  account. It is permitted on local users only — external users have their
  active status managed exclusively by external sync (see External Active
  Status Ownership in `docs/features/identity/user-service.md`).

Each mode corresponds to exactly one existing API operation and owns one
caller-owned transaction: profile mode maps to
`PATCH /api/v1/admin/users/{user}`, role mode maps to
`POST /api/v1/admin/users/{user}/roles`, and reactivation mode maps to
`POST /api/v1/admin/users/{user}/reactivate`. An operator needing changes of
different kinds uses one invocation per mode. The command works regardless of
whether the user is currently active or inactive (see Inactive User
Management Principle in `docs/features/identity/user-service.md`).

```
sentinel manage-user update \
  --username <username> \
  [--email <new_email>] \
  [--full-name <new_name>] \
  [--clear-full-name]

sentinel manage-user update \
  --username <username> \
  [--add-role <role>] ... \
  [--remove-role <role>] ...

sentinel manage-user update \
  --username <username> \
  --reactivate
```

**Parameters**:

| Parameter        | Required | Repeatable | Description                                |
|------------------|----------|------------|--------------------------------------------|
| `--username`     | Yes      | No         | Username of the user to update (identifier) |
| `--email`        | No       | No         | New email address                           |
| `--full-name`    | No       | No         | New display name                            |
| `--clear-full-name` | No    | No         | Clear the display name (`full_name = NULL`); mutually exclusive with `--full-name` |
| `--add-role`     | No       | Yes        | Role to add: `admin`, `vulnerability_analyst`, `restricted_analyst` |
| `--remove-role`  | No       | Yes        | Role to remove: `admin`, `vulnerability_analyst`, `restricted_analyst` |
| `--reactivate`   | No       | No         | Reactivate a previously deactivated user    |

**Mode selection**: the mode is determined by the flags present in one
invocation. Profile options (`--email`, `--full-name`, `--clear-full-name`)
MUST NOT be combined with role options (`--add-role`, `--remove-role`), and
`--reactivate` MUST NOT be combined with any other option. Any combination
spanning more than one mode is rejected before the mutating session is
opened, with:

```
Error: Profile updates, role updates, and --reactivate cannot be combined.
```

Within profile mode, `--full-name` and `--clear-full-name` are mutually
exclusive; their combination is rejected before the mutating session is
opened, with:

```
Error: --full-name and --clear-full-name cannot be used together.
```

Both rejections go to stderr, exit with code 1, and start no mutating
session. The read-only user lookup (Behavior step 3) precedes these checks,
so an unknown username is reported first.

**Behavior**:

1. Normalize the username (trim whitespace, lowercase)
2. Validate the normalized username format (see `docs/conventions.md`,
   Username Format). If invalid, exit with error:
   `"Error: Invalid username '{value}'. Username must be 1-64 characters,
   start with a letter, and contain only lowercase letters, numbers, dots,
   hyphens, and underscores."` (exit code 1, stderr) — before any database
   access
3. Look up the user by normalized username — if not found, exit with
   error: `"Error: User '{username}' not found."`
4. If no modification flags are provided (`--email`, `--full-name`,
   `--clear-full-name`, `--add-role`, `--remove-role`, `--reactivate` are
   all absent), print:
   `"No changes specified for user '{username}'."` and exit with code 0 —
   no mode is selected and no mutating session is opened
5. Determine the single mode from the provided flags. Cross-mode
   combinations and the `--full-name`/`--clear-full-name` conflict are
   rejected as described in Mode selection, before the mutating session is
   opened
6. Apply the mode-specific guards and behavior defined below
7. Invoke exactly one mutating service operation for the selected mode, with
   `acting_user_id = None` (CLI is a system action). No invocation calls
   more than one mutating service
8. Print the success or no-op message only after the commit succeeds. Never
   print a partial-success or per-step report: each invocation is one atomic
   logical operation, so the `✓`/`✗`/`—` multi-step reporting pattern does
   not apply (see `docs/conventions.md`, Multi-Step Reporting)

**Profile mode behavior**:

1. If the user is an external user (`external_id IS NOT NULL`), exit with
   error: `"Error: User '{username}' is managed by an external identity
   provider. Identity fields cannot be modified manually."` (exit code 1).
   No other mode is affected by this guard
2. If `--email` is provided, trim and lowercase it, validate the normalized
   value's format, and pass the normalized value to the service. If the
   format is invalid, exit with error:
   `"Error: Invalid email format '{value}'."`
3. Delegate once to `user_service.update_user()` with
   `acting_user_id = None`, passing `--email`, `--full-name`, or
   `--clear-full-name` (`full_name = None`) together in the same call when
   more than one is provided. An empty `--full-name ""` carries no special
   meaning: it is passed through as an ordinary provided value and stored
   verbatim; clearing the display name requires `--clear-full-name`. If the
   service raises `UserConflictError` (duplicate email), exit with error:
   `"Error: A user with email '{email}' already exists."`
4. Report exclusively from the returned `UserUpdateResult.changed_fields`:
   an empty sequence prints
   `"No changes applied to user '{username}'."` and exits with code 0;
   otherwise print
   `"Updated user '{username}': {list of changed fields}."` — for example
   `"Updated user 'jdoe': email, full name."` The CLI renders `email` as
   `email` and `full_name` as `full name`, in the result's fixed order; the
   other closed values cannot appear because this mode never sends them.
   The read-only lookup of Behavior step 3 serves only resolution and the
   guard above; it never classifies the outcome. The service remains
   authoritative: it normalizes and compares against locked-current state,
   persists only effective changes, creates one audit event per changed
   field, and reports the effective changes in the result

**Role mode behavior**:

1. For each role value in `--add-role` and `--remove-role`, validate that
   it is a recognized role. If not, exit with error:
   `"Error: Invalid role '{value}'. Valid roles are: {list}."`
   The list of valid roles is derived from the system's role definitions
   at runtime
2. Deduplicate repeated role options and silently cancel roles that appear in
   both `--add-role` and `--remove-role`. The CLI passes only `Role` values —
   not `(role, '_manual')` pairs — to `user_service.update_roles()` with
   `acting_user_id = None`. Since `acting_user_id = None`, the self-removal
   guard does not apply (CLI is a system action). The service still applies
   its own defensive set normalization and never rejects a request due to
   duplicate or overlapping input
3. The command can select only the `_manual` origin; it cannot request, and
   does not report, a change to an external role origin. External origins
   still participate in effective-role evaluation
4. Report the effective `RoleUpdateResult.added_roles` and
   `removed_roles` exactly as returned by the service. A manual addition is
   reported even when the role was already effective through an external
   origin, and a manual removal is reported even when the role remains
   effective through an external origin
5. If both result lists are empty after the operation, print:
   `"No changes applied to user '{username}'."` and exit with code 0.
   Otherwise print: `"Updated user '{username}': {role summary}."` — the
   role summary uses the form
   `roles: added 'admin'; removed 'vulnerability_analyst'`, lists added
   roles before removed roles, orders each side by wire-format role value,
   and omits a side with no effective change

**Reactivation mode behavior**:

1. If the user is an external user (`external_id IS NOT NULL`), exit with
   error: `"Error: Cannot reactivate external users."` (exit code 1).
   Active status of external users is managed exclusively by external sync
2. Delegate once to `user_service.reactivate_user()` with
   `acting_user_id = None` and report exclusively from the returned
   `ReactivationResult.reactivated`: `false` — a local user that is already
   active — prints
   `"No changes applied to user '{username}'."` with exit code 0; `true`
   prints `"Reactivated user '{username}'."`
3. The read-only lookup of Behavior step 3 serves only resolution and the
   guard above; it never classifies the outcome
4. No profile or role update occurs in this mode

Reactivation mode performs one lifecycle transition only. When an account is
being prepared for a return to service, complete profile and role changes in
earlier invocations; ordering across invocations is operator-owned.

**Error handling (atomic single operation)**: each mode executes in one
caller-owned database transaction. The service flushes but does not commit.
If the service call fails, the workflow rolls back and reports the error to
stderr; no partial-success output is printed. After the service call
succeeds, the workflow commits exactly once and then prints the mode's
success message.

**Idempotency**: Idempotent. If the requested state is already reached —
`UserUpdateResult.changed_fields` is empty, both `RoleUpdateResult` lists are
empty, or `ReactivationResult.reactivated` is `false` — the command prints an
informational no-op message and exits with code 0.

**Exit codes**: 0 on success (including no-op), 1 on validation or
operational error, 2 on system error (database unreachable).

**Output channels**: success and no-op messages to stdout. All
`"Error: ..."` messages to stderr.

### `sentinel manage-user deactivate`

Deactivates a user account (soft delete only).

```
sentinel manage-user deactivate \
  --username <username>
```

**Parameters**:

| Parameter    | Required | Description                                    |
|--------------|----------|------------------------------------------------|
| `--username` | Yes      | Username of the user to deactivate              |

**Behavior** (in this order):

1. Normalize the username (trim whitespace, lowercase)
2. Validate the normalized username format (see `docs/conventions.md`,
   Username Format). If invalid, exit with error:
   `"Error: Invalid username '{value}'. Username must be 1-64 characters,
   start with a letter, and contain only lowercase letters, numbers, dots,
   hyphens, and underscores."` (exit code 1, stderr) — before any database
   access
3. Open a read-only session and resolve the user through
   `user_service.get_user()` using the normalized username. If not found,
   exit with error: `"Error: User '{username}' not found."` (exit code 1)
4. Delegate the complete preview to
   `user_service.get_deactivation_impact(db, user.id, acting_user_id=None)`
   inside the same read-only session. The command performs no API-key,
   Session, Ticket, or UserRole query of its own. The CLI passes
   `acting_user_id = None` (system action), so the service's self-deactivation
   guard is inapplicable and its actor-dependent external guard does not
   apply; guard and no-op classification for the service-applicable cases
   belong to the service:
   - `already_inactive = true` — print
     `"User '{username}' is already inactive."` to stdout, close the
     read-only session, and exit 0 without a prompt and without opening a
     mutating session. This is the first classification; it precedes the
     external guard below
5. If the resolved user is an external user (`external_id IS NOT NULL`),
   exit with error: `"Error: Cannot deactivate external users."` (exit code
   1) without mutation. Active status of external users is managed
   exclusively by external sync. This is the CLI's own manual-surface guard,
   required because the CLI passes `acting_user_id = None`; the service's
   equivalent guard covers authenticated API callers (see
   `docs/features/identity/user-service.md`, External Active Status
   Ownership). The resolved user's `external_id` is immutable, so this check
   is not subject to a concurrent change
6. Display the impact summary to stdout:
   ```
   About to deactivate user '{username}':
     - {n} non-revoked API keys will be revoked
     - {n} active sessions will be invalidated
     - {n} active tickets will be unassigned
   ```
   The counts come exclusively from the preview result. Explicit Ticket
   grants and package-maintainer associations are not counted because
   deactivation retains them. If the result reports
   `is_last_active_admin = true`, append the warning to stderr:
   ```
   Warning: this is the last active user with Admin role.
   After deactivation, assign Admin to another user via:
     sentinel manage-user update --username <user> --add-role admin
   ```
7. Close the read-only session completely. No terminal input runs while a
   database session is open, and no pre-prompt read classifies the outcome
   of a confirmed mutation (the step-4 no-op uses the preview service's own
   classification)
8. Verify that stdin is a TTY through the shared TTY detection helper,
   immediately before the confirmation prompt. If no TTY is detected, print
   to stderr `Error: This command requires an interactive terminal
   (confirmation required).` and exit with code 1 without mutation
9. Prompt through the shared confirmation helper using Click's native
   semantics — `click.confirm("Proceed?", default=False)`:
   - A valid affirmative answer proceeds to step 10
   - A valid negative answer, or Enter accepting the `No` default, prints
     `Aborted.` to stdout and exits with code 0 without mutation
   - An unrecognized answer causes Click to repeat the prompt
   - EOF/Ctrl+D: Click raises `click.Abort`; the shared exception mapper
     prints `Aborted.` to stdout and exits with code 0 without mutation (see
     `docs/features/platform/cli-infrastructure.md`, Database Session
     Management and Error Handling & Exit Code Mapping)
   - SIGINT: the shared signal handler exits with code 130 without mutation
     (see `docs/features/platform/cli-infrastructure.md`, Signal Handling)
   - SIGTERM: the shared signal handler exits with code 143 without
     mutation
10. After confirmation, open a fresh session and delegate to
    `user_service.deactivate_user()` with `acting_user_id = None` and
    `reason = "deactivated via CLI (manage-user deactivate)"`
    as identity-audit lifecycle context. Any derived Ticket unassignment uses
    the canonical Ticket comment reason `user deactivated` instead. The
    service independently revalidates locked-current state. Commit exactly
    once after the service call succeeds; roll back on any exception or
    interruption before commit
11. After the commit, purge the session-liveness cache through
    `session_service.purge_session_cache(result.invalidated_session_ids)`.
    Redis failure is best-effort and does not turn a committed deactivation
    into a command failure. The Redis client is created and closed inside
    the single `asyncio.run()` boundary
12. Report exclusively from `DeactivationResult.deactivated`: `true` prints
    `"Deactivated user '{username}'."`; `false` prints
    `"User '{username}' is already inactive."`. The outcome of a confirmed
    invocation is never derived from a pre-prompt read

This command does not permanently remove the user record from the
database. The User record is preserved to maintain referential integrity
with TicketAuditEvent, ticket assignments, and UserRole audit data. This is
consistent with external sync deactivation behavior. For full database
cleanup in development environments, reset the database directly.

**Stale preview**: the impact summary and the inactive/external
classification printed before the prompt are advisory reads from the
read-only session; they may not match the effects of the confirmed mutation:

- resources created, cleared, or revoked after the preview (Sessions, API
  keys, or Ticket assignments) are still handled by `deactivate_user()` at
  execution time, which affects locked-current state rather than the
  previewed state;
- if another caller deactivates the target between the preview and the
  action, the service returns `deactivated = false` and the command prints
  the no-op message with exit code 0;
- if the preview observes an already-inactive target and another caller
  reactivates it before the command exits, the command still reports the
  observed no-op and exits 0 without mutation; this is an accepted
  trade-off of the unlocked advisory preview — the command performs no
  second authoritative read, and a new invocation observes the updated
  state;
- if an applicable guard changes before the action, the service raises its
  documented exception and the command reports it through its normal error
  handling;
- there is no automatic retry, no second confirmation, and no preview
  token; the preview neither reserves resources nor constrains the action.

**Interruption**: an interruption before the workflow commits (including
SIGINT or SIGTERM during the mutation) rolls back the complete workflow —
no mutation and no audit event persists. After the commit, the deactivation
is durable even when the process is interrupted before the cache purge or
the success message: the affected cache entries recover through their TTL
and the authoritative `User.active` check, and a repeated invocation
observes the committed inactive state and exits as a no-op.

**Inactive user management principle**: see
`docs/features/identity/user-service.md` (Inactive User Management Principle).

**Idempotency**: Idempotent. If the user is already inactive, the
command prints an informational message and exits with code 0.

**Exit codes**: 0 on success (including no-op and user-cancelled
confirmation), 1 on validation or operational error (invalid username,
unknown user, external user, non-TTY), 2 on system error (database
unreachable), 130 on SIGINT, 143 on SIGTERM.

**Output channels**: impact summary, prompt and its interactive retry
feedback (Click's `Error: invalid input` line for an unrecognized answer),
success/no-op messages, and `Aborted.` to stdout. Command error messages
(`"Error: ..."`) and the last-admin `"Warning: ..."` to stderr.

### `sentinel manage-user set-password`

Sets or resets the password for a local user. See
`docs/features/identity/local-authentication.md` for full details on password
policy and hashing.

```
sentinel manage-user set-password \
  --username <username>
```

**Behavior** (in this order):

1. Validate the username format (see `docs/conventions.md`, Username
   Format), trimming whitespace and lowercasing. If invalid, exit with
   error: `"Error: Invalid username '{value}'. Username must be 1-64
   characters, start with a letter, and contain only lowercase letters,
   numbers, dots, hyphens, and underscores."` (exit code 1) — before the
   TTY check and before any database access.
2. If no TTY is detected, print to stderr `Error: This command requires an
   interactive terminal (password input).` and exit with code 1 — before
   any database access.
3. Open a read-only session and resolve the user through
   `user_service.get_user()` using the normalized username. If not found,
   exit with error: `"Error: User '{username}' not found."` (exit code 1).
4. If the resolved user is an external user (`external_id IS NOT NULL`),
   exit with error: `"Error: Cannot set password for external user
   '{username}'. External users authenticate via SSO."` (exit code 1).
   This command is only valid for local users; it operates on both active
   and inactive local users — setting a password on an inactive user
   prepares credentials for reactivation, but the user cannot log in until
   reactivated.
5. Close the read-only session before prompting — an interactive prompt
   MUST NOT run while a database session is open (see
   `docs/features/platform/cli-infrastructure.md`, Database Session
   Management).
6. Collect the new password interactively via a hidden prompt (input not
   echoed to the terminal, like `sudo`), asking twice for confirmation. If
   the two entries do not match, exit with error: `"Error: Passwords do
   not match."` (exit code 1).
7. Validate the password length (16-128 characters). If it violates the
   policy, exit with the same exact messages `create` uses for each
   boundary: `"Error: Password must be at least 16 characters."` or
   `"Error: Password must be at most 128 characters."` (exit code 1).
8. Open a new session and delegate to `user_service.reset_password()` with
   `acting_user_id = None`. The service re-validates the user-not-found and
   external-user guards atomically against the locked row — a user deleted
   or converted between steps 3-4 and this step surfaces the same exact
   messages as steps 3-4, since `reset_password()` raises the same
   `UserNotFoundError`/`ExternalUserPasswordError` exceptions. Commit
   exactly once after the service call succeeds; roll back on any
   exception or interruption before commit.
9. After the commit succeeds, execute the session-cache purge and login
   lockout-counter clear from the returned `PasswordResetResult`, in that
   order, inside the same async workflow. Redis failure follows the
   best-effort behavior in `user-service.md` and does not turn a committed
   password reset into a command failure.
10. Print to stdout: `"Password updated for user '{username}'. All active
    sessions invalidated."`

The prompt labels are the CLI infrastructure's shared defaults
(`docs/features/platform/cli-infrastructure.md`, Interactive Input
Helpers): `Password` and `Confirm password`.

**Idempotency**: Not idempotent (interactive). Each invocation collects a
new password interactively; the operation inherently changes state.

**Exit codes**: 0 on success, 1 on validation error (invalid username
format, user not found, external user, passwords don't match, password
policy violation), 2 on system error (database unreachable).

**Output channels**: confirmation message to stdout. All `"Error: ..."`
messages to stderr.

### `sentinel manage-user unlock`

Clears the login lockout counter for a user, allowing them to log in
immediately without waiting for the TTL to expire.

```
sentinel manage-user unlock \
  --username <username>
```

**Parameters**:

| Parameter    | Required | Description                              |
|--------------|----------|------------------------------------------|
| `--username` | Yes      | Username of the user to unlock           |

**Behavior**:

1. Validate the username format (see `docs/conventions.md`, Username
   Format), trimming whitespace and lowercasing. If invalid, exit with
   error: `"Error: Invalid username '{value}'. Username must be 1-64
   characters, start with a letter, and contain only lowercase letters,
   numbers, dots, hyphens, and underscores."` (exit code 1) — before any
   database access.
2. Resolve the user through `user_service.get_user()` using the normalized
   username — if not
   found, exit with error:
   `"Error: User '{username}' not found."` (exit code 1)
3. If the user is inactive, print a warning to stderr:
   `"Warning: User '{username}' is inactive. Unlock has no practical
   effect until the user is reactivated."` — then continue (do not
   abort)
4. If the user is an external user (`external_id IS NOT NULL`), print a warning
   to stderr:
   `"Warning: User '{username}' is an external user. Local login lockout
   does not apply to SSO authentication."` — then continue (do not
   abort)
5. Delegate to `user_service.unlock_user(session, user.id,
   acting_user_id=None)` inside the command's single async workflow — the
   service handles Redis key deletion, logging, and idempotency (see
   `docs/features/identity/user-service.md`). `acting_user_id = None` because
   CLI is a system action.
6. Print: `"Unlocked user '{username}'."`

The command is idempotent: if the counter does not exist (user was not
locked), it succeeds silently.

**Idempotency**: Idempotent. If the user is not locked, the command
succeeds with a no-op and exits with code 0.

**Exit codes**: 0 on success (including no-op), 1 on validation error
(invalid username format, user not found), 2 on system error (database
unreachable).

**Output channels**: confirmation to stdout. `"Warning: ..."` messages
to stderr. `"Error: ..."` messages to stderr.

### `sentinel manage-user list`

Lists all users in the system with their key attributes.

```
sentinel manage-user list \
  [--active | --inactive] \
  [--role <role>] ... \
  [--type local|external]
```

**Parameters**:

| Parameter    | Required | Repeatable | Description                                    |
|--------------|----------|------------|------------------------------------------------|
| `--active`   | No       | No         | Show only active users                         |
| `--inactive` | No       | No         | Show only inactive users                       |
| `--role`     | No       | Yes        | Filter by role: `admin`, `vulnerability_analyst`, `restricted_analyst` |
| `--type`     | No       | No         | Filter by type: `local` or `external`          |

`--active` and `--inactive` are mutually exclusive. If neither is
provided, all users are shown regardless of status.

**Behavior**:

1. For each `--role` value provided, validate that it is a recognized
   role. If any value is invalid, exit with error:
   `"Error: Invalid role '{value}'. Valid roles are: {list}."`
   The list of valid roles is derived from the system's role definitions
   at runtime
2. If both `--active` and `--inactive` are provided, exit with error:
   `"Error: --active and --inactive cannot be used together."`
3. If `--type` is provided, validate that the value is `local` or
   `external`. If invalid, exit with error:
   `"Error: Invalid type '{value}'. Valid types are: local, external."`
4. Delegate the read to `user_service.list_users()`. When multiple
   `--role` values are provided, return users with at least one of the
   specified roles (OR semantics per `docs/conventions.md`, Repeatable
   filter semantics)
   The command iterates pages until `UserPage.total` is reached; it never
   silently truncates the operator-visible result
5. Sort results alphabetically by username
6. Print a table to stdout with columns:

```
USERNAME        FULL NAME            EMAIL                    TYPE       STATUS    ROLES
jdoe            John Doe             jdoe@example.com         local      active    admin, vulnerability_analyst
bwilson         Bob Wilson           bob.wilson@suse.com      external   active    vulnerability_analyst
olduser         Old User             old@example.com          local      inactive  —
```

Column alignment uses fixed-width spaces. The ROLES column shows a
comma-separated list of roles, or `—` if the user has no roles. The FULL
NAME column shows `—` if `full_name` is NULL.

If no users match the filters, prints: `"No users found matching the
specified criteria."` and exits with code 0.

**Idempotency**: Idempotent. Read-only command, no state changes.

**Exit codes**: 0 on success (including empty results), 1 on validation
error (invalid role or type value), 2 on system error (database
unreachable).

**Output channels**: table to stdout. `"Error: ..."` messages to stderr.

### `sentinel manage-user show`

Displays detailed information about a single user.

```
sentinel manage-user show \
  --username <username>
```

**Parameters**:

| Parameter    | Required | Description                              |
|--------------|----------|------------------------------------------|
| `--username` | Yes      | Username of the user to display          |

**Behavior**:

1. Normalize the username (trim whitespace, lowercase)
2. Delegate the lookup to `user_service.get_user()` using the normalized
   username — if not found, exit with
   error: `"Error: User '{username}' not found."` (exit code 1)
3. Print detailed user information to stdout:

```
Username:     jdoe
Full name:    John Doe
Email:        jdoe@example.com
Type:         local
Status:       active
Roles:        admin (manual), vulnerability_analyst (O SUSE Security)
Created:      2025-03-15 10:30:00 UTC
Last login:   2025-06-01 14:22:00 UTC
Manager:      bwilson
```

The ROLES field shows each role with its origin in parentheses:
`manual` for roles assigned via CLI/API, or the external group name for roles
derived from external sync. If a role has both origins, show both:
`admin (manual, O SUSE Admins)`.

If `full_name` is NULL, show `—` for `Full name`. If `Last login` is
never, show `—`. If `Manager` is not set, show `—`.

**Idempotency**: Idempotent. Read-only command, no state changes.

**Exit codes**: 0 on success, 1 on validation error (user not found),
2 on system error (database unreachable).

**Output channels**: user detail to stdout. `"Error: ..."` messages to
stderr.

## Access Level Requirements

User listing and user detail are accessible to all authenticated and
unauthenticated users (read-only). Administrator API operations (create, edit,
deactivate, reactivate, reset password, unlock, role management) require the
`manage_users` capability. CLI commands are authorized by direct shell or
container access and pass `acting_user_id = None`; they do not evaluate an HTTP
caller capability.

### Public API endpoints

These endpoints are publicly accessible (read-only) and do not require
authentication.

#### List Users

```
GET /api/v1/users
```

**`Access: Public`**
**`Authentication: Optional`**

User search and autocomplete. Returns a paginated list of users.
The route delegates filtering, sorting, pagination, and relationship loading to
`user_service.list_users()` and performs no ORM query directly.

Query parameters:
- `search` (string, optional): searches across `username`, `email`, and
  `full_name`. Minimum 2 characters.
  Case-insensitive substring match (SQL `ILIKE '%query%'`)
- `type` (enum, optional): filter by authentication type. Values:
  `local`, `external`
- `active` (boolean, optional): filter by active status
- `role` (enum, repeatable, optional): filter by role (`admin`,
  `vulnerability_analyst`, `restricted_analyst`). Multiple values use
  OR semantics — returns users with at least one of the specified
  roles (e.g., `?role=admin&role=vulnerability_analyst`)
- `has_role` (boolean, optional): `true` to return only users with at
  least one role, `false` for users with no roles
- Standard pagination (`page`, `per_page`) and sorting (`sort_by`,
  `sort_order`). Valid `sort_by` fields: `username` (default),
  `full_name`, `email`, `created_at`

Default `sort_order` is `asc`, producing alphabetical username ordering.

Filters of different kinds combine with AND semantics (e.g., `type=local`
and `active=true` together return only active local users); repeated
values of the same filter combine with OR semantics as stated above.

`full_name` is nullable (see Field notes below). Sorting by `full_name`
follows `api-spec.md` (Nullable Sort Field Ordering).

Response uses the standard paginated envelope (`data` array + `meta`
object). Each user object follows the same schema as
`GET /api/v1/users/{user}` (see below).

#### Get User

```
GET /api/v1/users/{user}
```

**`Access: Public`**
**`Authentication: Optional`**

Returns full user profile. Response uses the standard single-resource
envelope:
The route delegates UUID-or-username resolution and relationship loading to
`user_service.get_user()` and performs no ORM query directly.

```json
{
  "data": {
    "id": "uuid",
    "username": "string",
    "email": "string",
    "full_name": "string | null",
    "active": true,
    "source": "external | local",
    "external_id": "uuid | null",
    "manager": {
      "id": "uuid",
      "username": "string",
      "full_name": "string | null",
      "active": true,
      "email": "string"
    } | null,
    "roles": [
      {
        "role": "admin",
        "group_name": "O SUSE Security",
        "assigned_by": "uuid | null",
        "created_at": "ISO8601"
      }
    ],
    "created_at": "ISO8601",
    "updated_at": "ISO8601"
  }
}
```

Field notes:
- `source`: derived field — `"external"` if `external_id IS NOT NULL`,
  otherwise `"local"`
- `external_id`: unique identifier from the external identity provider. NULL for local users
- `full_name`: nullable. A user record (local or external) may have no
  display name on file. The API returns `null` verbatim — it does not
  substitute `username` or any other fallback value. Consumers that need
  a display fallback (e.g., a UI showing `full_name ?? username`) apply
  it at presentation time
- `manager`: resolved manager object or `null`. `manager.full_name`
  follows the same nullability as above
- `roles`: array of all roles from both external group mappings and manual
  assignments. `group_name` is `'_manual'` for manually assigned roles.
  See `rbac.md` (Role Wire Format, Deterministic ordering) for the
  array's sort order

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | No user found matching the given UUID or username |

### Admin API endpoints

All user mutation endpoints are defined here. This is the single source
of truth for the user management API surface. Other specs define the
business rules and service-layer contracts that these endpoints invoke.

All endpoints below require the `manage_users` capability unless
otherwise stated.

For every endpoint with a `{user}` path parameter, the route resolves the
identifier through `user_service.resolve_user_identifier()` and passes the
resolved UUID to the owning service. `UserNotFoundError` maps to 404
`USER_NOT_FOUND`. Route handlers execute no ORM lookup directly.

#### Create User (Admin)

```
POST /api/v1/admin/users
```

Creates an ordinary local user through the authenticated administrator
surface. The CLI create command remains available for bootstrap and recovery
when no administrator can authenticate.

**`Capability: manage_users`**

This endpoint additionally requires JWT session authentication — it mints a
new credential (a password), so it must not be reachable with an API key.
API-key authentication returns `403 AUTH_SESSION_REQUIRED` with detail
`"This operation requires session authentication."` (see
`docs/features/identity/authentication.md`, Session-Only Authentication
Dependency).

**Request body**:

```json
{
  "username": "jdoe",
  "email": "john.doe@example.com",
  "full_name": "John Doe",
  "password": "a-fictional-password-value",
  "roles": ["admin"]
}
```

| Field | Type | Required | Null | Semantics |
|---|---|---|---|---|
| `username` | string | Yes | No | Trimmed, lowercased, and validated per Username Format |
| `email` | string | Yes | No | Trimmed and lowercased before format and uniqueness validation |
| `full_name` | string | No | Yes | Optional display name; omitted or NULL stores NULL |
| `password` | string | Yes | No | 16-128 characters; never logged or returned |
| `roles` | array of Role values | No | No | Initial manual roles; defaults to `[]`, and duplicates are rejected by request validation |

Missing required fields, explicit NULL for `username`, `email`, `password`, or
`roles`, malformed username/email, unknown role values, duplicate role values,
and wrong field types return the global HTTP 422 `VALIDATION_ERROR` response.
Password policy failure is domain validation and returns the error below.

**Behavior**:

1. Validate and normalize the request as specified above.
2. Delegate to `user_service.create_user()` with `active = true`,
   `external_id = None`, `manager_id = None`, each role represented as
   `(role, "_manual")`, and `acting_user_id` set to the authenticated user's
   UUID.
3. Within the caller-owned API transaction, persist the User, every initial
   UserRole, `user_created`, and one `role_added` event per role. The service
   flushes and the API transaction dependency commits once only after all
   records succeed. Any error rolls the entire set back.
4. Return HTTP 201 with the complete user profile in the standard data
   envelope. The response never contains `password` or `password_hash`.

**Response** (201 Created): the same user profile schema defined by Get User,
including the initial roles, wrapped in `{"data": {...}}`.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 403 | `AUTH_SESSION_REQUIRED` | Request is authenticated by API key instead of JWT session |
| 409 | `USER_ALREADY_EXISTS` | Normalized username or email is already used, including a concurrent uniqueness race |
| 422 | `USER_PASSWORD_POLICY_VIOLATION` | Password is outside the 16-128 character policy |

#### Update User (Admin)

```
PATCH /api/v1/admin/users/{user}
```

**`Capability: manage_users`**

Update a user's profile fields. Only local users (`external_id IS NULL`)
can be modified — external users have their identity fields managed by
external sync (see External User Data Ownership in
`docs/features/identity/user-service.md`). This endpoint operates on
both active and inactive users (see Inactive User Management Principle
in `docs/features/identity/user-service.md`).

**Request body** (all fields optional, at least one required):

```json
{
  "email": "new@example.com",
  "full_name": "New Display Name"
}
```

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. If no fields are provided in the body, return HTTP 422 with code
   `VALIDATION_ERROR`: `"At least one field must be provided."`
3. Malformed `email` returns the global HTTP 422 `VALIDATION_ERROR` response
   through request-schema validation. Explicit `email: null` also returns that
   response. Otherwise trim and lowercase the email before format and
   uniqueness validation
4. `full_name: null` is valid and explicitly clears the stored display name;
   omission leaves it unchanged
5. If the user is an external user (`external_id IS NOT NULL`), return HTTP 409
   with code `USER_EXTERNAL_FIELD_READONLY`:
   `"Cannot modify identity fields for external users. These fields are managed by the external identity provider."`
6. Delegate to `user_service.update_user()` with
   `acting_user_id = authenticated_admin.id`
7. If the service raises `UserConflictError` (duplicate email), return
   HTTP 409 with code `USER_ALREADY_EXISTS`:
   `"A user with this email already exists."`
8. Return HTTP 200 with `UserUpdateResult.user` — the updated user profile —
   in the standard `{"data": ...}` envelope

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `USER_NOT_FOUND` | User identifier does not resolve |
| 409 | `USER_EXTERNAL_FIELD_READONLY` | Authenticated administrator attempts to modify an external user's identity fields |
| 409 | `USER_ALREADY_EXISTS` | Normalized email is already used |

**Response**: user profile in `{"data": {...}}` envelope (see
`GET /api/v1/users/{user}` in Public API endpoints above for the full
response schema).

#### Set User Roles

```
POST /api/v1/admin/users/{user}/roles
```

**`Capability: manage_users`**

Add or remove manual roles for a user. This endpoint manages only the
`_manual` origin: it never inserts, deletes, or mutates a row whose
`group_name != '_manual'`. External role origins remain unchanged and
continue to participate in effective-role evaluation.

**Request body**:

```json
{
  "add": ["admin"],
  "remove": ["vulnerability_analyst"]
}
```

| Field | Type | Required | Null | Semantics |
|---|---|---|---|---|
| `add` | array of Role values | No | No | Manual roles to add; omitted means `[]` |
| `remove` | array of Role values | No | No | Manual roles to remove; omitted means `[]` |

Request validation is strict so client mistakes surface instead of being
silently normalized:

- an omitted field is equivalent to an empty array;
- an absent request body is equivalent to `{}` (both fields omitted) and is
  a valid no-op;
- an empty array is valid;
- explicit `null` for either field returns the global HTTP 422
  `VALIDATION_ERROR`;
- an unknown role value returns the global HTTP 422 `VALIDATION_ERROR`;
- a wrong field type or a wrong element type returns the global HTTP 422
  `VALIDATION_ERROR`;
- a role repeated within one list returns the global HTTP 422
  `VALIDATION_ERROR`;
- a role present in both `add` and `remove` returns the global HTTP 422
  `VALIDATION_ERROR`.

`user_service.update_roles()` keeps its own defensive set-based normalization
for non-HTTP callers; the API does not rely on it and rejects duplicate or
overlapping input first.

**Behavior**:

1. Verify the `manage_users` capability through the endpoint dependency
2. Resolve `{user}` through `user_service.resolve_user_identifier()`: UUID
   or username. An unresolved identifier returns HTTP 404 with code
   `USER_NOT_FOUND`. The route performs no ORM lookup directly
3. Delegate to `user_service.update_roles()` with only `Role` values — not
   `(role, '_manual')` pairs — and
   `acting_user_id = authenticated_admin.id`
4. `update_roles()` owns locking, the effective-change classification, the
   self-Admin guard, the `UserRole` mutations, and the Identity audit
   events, including any derived final-VA-loss Ticket unassignment (see
   `docs/features/identity/user-service.md`)
5. The API transaction dependency commits before the response is
   transmitted. Any error rolls the complete operation back atomically
6. Return HTTP 200 with the complete user profile — including all role
   origins — in the standard `{"data": ...}` envelope

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 404 | `USER_NOT_FOUND` | Identifier does not resolve to any user |
| 409 | `USER_SELF_ROLE_REMOVAL` | The effective deletion would remove the authenticated administrator's final Admin role origin |

**Idempotency**:

- adding a role whose `_manual` row is already present is a no-op;
- removing a role without a `_manual` row is a no-op;
- adding a role that the user already holds via external derivation creates a
  separate `_manual` record — both origins coexist independently;
- removing a `_manual` row while an external origin grants the same role
  deletes only the manual row and leaves the role effective;
- the response always contains the complete, deterministically ordered user
  profile, whether or not any row changed. See
  `docs/features/identity/rbac.md` (Role Origins and Coexistence) for the
  independent-origin semantics

**Response**: HTTP 200 with updated user profile including all roles,
wrapped in the standard `{"data": ...}` envelope (see
`GET /api/v1/users/{user}` in Public API endpoints above for the full
response schema).

#### Reset User Password

```
POST /api/v1/admin/users/{user}/password
```

**`Capability: manage_users`**

This endpoint additionally requires JWT session authentication — it mints a
new credential (a password), so it must not be reachable with an API key.
API-key authentication returns `403 AUTH_SESSION_REQUIRED` with detail
`"This operation requires session authentication."` (see
`docs/features/identity/authentication.md`, Session-Only Authentication
Dependency).

Reset the password for a local user. This endpoint operates on both
active and inactive local users (see Inactive User Management Principle
in `docs/features/identity/user-service.md`). Setting a password on an
inactive user prepares credentials for reactivation.

**Request body**:

```json
{
  "password": "string (required, see local-authentication.md § Password Validation)"
}
```

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. Delegate to `user_service.reset_password(user_id, password,
   acting_user_id=authenticated_admin.id)` — this handles external user
   check, validation, hashing, session invalidation, and audit event
   creation (see `docs/features/identity/user-service.md`)
3. After the API workflow commits, execute the session-cache purge and login
   lockout-counter clear from the returned `PasswordResetResult`
4. Return HTTP 200

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 403 | `AUTH_SESSION_REQUIRED` | Request is authenticated by API key instead of JWT session |
| 409 | `USER_EXTERNAL_PASSWORD_FORBIDDEN` | Cannot set password for external user |
| 422 | `USER_PASSWORD_POLICY_VIOLATION` | Password does not meet policy requirements (see `docs/features/identity/local-authentication.md` § Password Validation) |
| 404 | `USER_NOT_FOUND` | User not found |

**Response** (200):

```json
{
  "data": {
    "detail": "Password updated. All active sessions have been invalidated."
  }
}
```

#### Deactivate User

```
POST /api/v1/admin/users/{user}/deactivate
```

**`Capability: manage_users`**

Deactivate a user account. Triggers significant side effects (API key
revocation, session invalidation, ticket unassignment). Existing explicit
Ticket grants and package-maintainer associations are retained but cannot be
exercised while the user is inactive.

**Request body**: none (empty body or omitted). The endpoint defines no
application request schema.

**Behavior**:

1. Verify the `manage_users` capability through the endpoint dependency
2. Resolve `{user}` through `user_service.resolve_user_identifier()`: UUID
   or exact username. An unresolved identifier returns HTTP 404 with code
   `USER_NOT_FOUND`. The route performs no ORM lookup directly
3. Delegate to `user_service.deactivate_user()` with
   `acting_user_id = authenticated_admin.id` and
   `reason = "deactivated by admin via API"`
   as identity-audit lifecycle context. Any derived Ticket unassignment uses
   the canonical Ticket comment reason `user deactivated` instead. The
   service owns the guard ordering, the locked-current revalidation, and the
   complete side-effect sequence (see
   `docs/features/identity/user-service.md`)
4. The endpoint uses the shared scoped API transaction dependency
   (`scope="function"`). It commits exactly once after every database
   mutation and audit event succeeds, before the response is transmitted;
   any service or database error rolls back the complete workflow and
   transmits no success response
5. After the commit and before the response is transmitted, purge the
   session-liveness cache via
   `session_service.purge_session_cache(result.invalidated_session_ids)`.
   The helper's Redis-error contract is best-effort: a Redis failure cannot
   reclassify or roll back the committed deactivation and does not change
   the HTTP 200 response
6. Return HTTP 200 with the current complete user profile from
   `DeactivationResult.user` in the standard `{"data": ...}` envelope. An
   already-inactive target is an idempotent no-op that returns HTTP 200 with
   the unchanged profile; the response never includes the service-internal
   `deactivated` flag

**Guard ordering**: the service classifies the locked-current target in this
order — unknown user, already-inactive no-op, active external rejection,
active self-target rejection — so the error table below reflects the same
precedence.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | Identifier does not resolve to any user |
| 409 | `USER_EXTERNAL_STATUS_READONLY` | The target is an active external user; manual deactivation is reserved for external sync |
| 409 | `USER_SELF_DEACTIVATION` | The authenticated administrator targets their own account |

External deactivation renders `"Cannot deactivate external users."`;
self-deactivation renders `"Cannot deactivate your own account."`.

See `docs/features/identity/user-service.md` for the full side effect contract
(API key revocation, session invalidation, ticket unassignment on
deactivation). Deactivation creates no grant event and the impact response does
not count grants or maintainership rows because neither is mutated.

**Response**: user profile in `{"data": {...}}` envelope (see
`GET /api/v1/users/{user}` in Public API endpoints above for the full
response schema).

#### Reactivate User

```
POST /api/v1/admin/users/{user}/reactivate
```

**`Capability: manage_users`**

Reactivate a previously deactivated user account.

Retained explicit grants and package-maintainer associations become usable
again under their ordinary Ticket visibility conditions. Reactivation does not
recreate a grant deleted by a successful Ticket declassification and creates no
Ticket grant event.

**Request body**: none (empty body or omitted).

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. Delegate to `user_service.reactivate_user()` with
   `acting_user_id = authenticated_admin.id`
3. Return HTTP 200 with `ReactivationResult.user` in the standard
   `{"data": ...}` envelope; the profile is unchanged on a no-op

**Constraints**:
- External user reactivation is rejected by the service layer
  unconditionally — returns HTTP 409 with code
  `USER_EXTERNAL_STATUS_READONLY`: `"Cannot reactivate external users."`,
  even when the user is already active. Unlike Deactivate User above, this
  guard is evaluated before the idempotency check (see
  `docs/features/identity/user-service.md`, External Active Status
  Ownership, "Evaluation point differs by function")

**Response**: user profile in `{"data": {...}}` envelope (see
`GET /api/v1/users/{user}` in Public API endpoints above for the full
response schema).

#### Get Deactivation Impact

```
GET /api/v1/admin/users/{user}/deactivation-impact
```

**`Capability: manage_users`**

Returns a preview of the side effects that would occur if the user were
deactivated. Used by the frontend to display a confirmation dialog before
proceeding with deactivation.

**Behavior**:

1. Verify the `manage_users` capability through the endpoint dependency
2. Resolve `{user}` through `user_service.resolve_user_identifier()`: UUID
   or exact username. An unresolved identifier returns HTTP 404 with code
   `USER_NOT_FOUND`. The route performs no ORM lookup directly
3. Delegate the complete preview to
   `user_service.get_deactivation_impact(db, user.id,
   acting_user_id=authenticated_admin.id)`. The endpoint performs no
   API-key, Session, Ticket, or UserRole query of its own; the preview
   boundary owns every count and the last-active-Admin flag
4. Guard ordering: the service classifies the target in the same order as
   the action endpoint — unknown user, already-inactive no-op, active
   external rejection, active self-target rejection
5. An already-inactive target returns HTTP 200 with the zero-impact response
   below: all counts set to zero, `already_inactive` set to `true`, and
   `is_last_active_admin` set to `false`, for local and external targets
   alike. This mirrors `POST .../deactivate`, which is idempotent and
   returns HTTP 200 for already-inactive users; the preview must not be
   stricter than the action it previews, so returning 409 here while the
   action returns 200 would force clients to special-case a condition the
   action itself treats as a no-op
6. An active eligible target returns HTTP 200 with the observations below

**Response** (HTTP 200):

```json
{
  "data": {
    "already_inactive": false,
    "is_last_active_admin": false,
    "api_keys_count": 3,
    "sessions_count": 2,
    "tickets_count": 5
  }
}
```

When the user is already inactive, the response contains zeroed counts:

```json
{
  "data": {
    "already_inactive": true,
    "is_last_active_admin": false,
    "api_keys_count": 0,
    "sessions_count": 0,
    "tickets_count": 0
  }
}
```

| Field                  | Type          | Description                                      |
|------------------------|---------------|--------------------------------------------------|
| `already_inactive`     | `bool`        | `true` if the user is already inactive (no-op deactivation) |
| `is_last_active_admin` | `bool`        | `true` if the active target is the only active user with an effective Admin role |
| `api_keys_count`       | `int`         | Non-revoked API keys that will be revoked, including expired keys |
| `sessions_count`       | `int`         | Active sessions that will be invalidated         |
| `tickets_count`        | `int`         | Active tickets assigned to this user that will be unassigned |

Explicit Ticket grants and package-maintainer associations are intentionally
absent from this schema. Deactivation retains them, so they are not impact
mutations or counts.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | Identifier does not resolve to any user |
| 409 | `USER_EXTERNAL_STATUS_READONLY` | The target is an active external user; manual deactivation is reserved for external sync |
| 409 | `USER_SELF_DEACTIVATION` | The authenticated administrator targets their own account |

The self-target rejection renders
`"Cannot preview deactivation impact for your own account."` and keeps the
preview consistent with the action: if the administrator cannot deactivate
themselves, they cannot preview that deactivation either. The external
rejection renders `"Cannot deactivate external users."`.

**Advisory semantics**: the response reports independent point-in-time
observations of the user's current state, not one atomic snapshot. The four
observed values — `is_last_active_admin` and the three counts — are produced
by the preview read workflow and are not promised to share a PostgreSQL
transaction snapshot; concurrent changes may be reflected in some values but
not others. The preview acquires no lock, creates no reservation or preview
token, and does not constrain the subsequent `POST .../deactivate`:
resources created after the preview (sessions, API keys, or Ticket
assignments) are still affected when the action executes, which
independently revalidates locked-current state and affects every in-scope
resource present at that time. If another caller deactivates the target
first, the action is a successful no-op.

#### Unlock User

```
POST /api/v1/admin/users/{user}/unlock
```

**`Capability: manage_users`**

Clear the login lockout counter for a user.

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. Delegate to `user_service.unlock_user(user_id,
   acting_user_id=authenticated_admin.id)` — this handles Redis key
   deletion, logging, and idempotency (see
   `docs/features/identity/user-service.md`)
3. Return HTTP 200 with `{"data": {"detail": "Account unlocked successfully."}}`

The endpoint is idempotent: if the user is not locked, it returns 200
with the same response without error.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `USER_NOT_FOUND` | User not found |

## Interaction with External Provisioning

The external sync process operates exclusively on users with
`external_id IS NOT NULL`. Local users (`external_id = NULL`) are invisible to
the sync process:

- They are never deactivated by the sync
- They are never updated with data from the external provider
- They are never assigned externally-derived roles

This separation is inherent in the existing sync algorithm — no special
handling is required.

## Business Rules

1. **Local users are identified by `external_id = NULL`**: this is the
   canonical way to distinguish local users from externally-provisioned users. No
   additional flag or column is needed
2. **No "last admin" enforcement**: the system does not enforce a
   minimum admin count, and the self-removal guard is not a global
   minimum. The guard (see `docs/features/identity/rbac.md`, Business Rule 1)
   prevents an authenticated actor from effectively removing their own
   final Admin origin in their own operation, so that actor retains at
   least one Admin origin after their own request. It does not prevent
   another Admin from removing the first Admin's final origin, and
   crossing removals — including concurrent removals executed by two
   Admins on each other's accounts — can leave the platform with zero
   Admins. Via CLI or system operations (`acting_user_id = None`), the
   self-removal guard does not apply, and it is possible to remove or
   deactivate even the last admin. This is intentional and non-problematic:
   the platform continues to function normally without active admin users
   (all non-admin features remain operational). In these cases, a system
   administrator with shell access can restore admin access by either
   creating a new local administrator with `sentinel manage-user create
   --username <new-user> --email <email> --role admin` or promoting an
   existing user with `sentinel manage-user update --username <user>
   --add-role admin`.
3. **No duplicate usernames or emails**: enforced at creation and when
   changing the email
4. **Role origin is `_manual`**: all roles assigned via `manage-user`
   commands or admin UI have `group_name = '_manual'` and
   `assigned_by = NULL` (CLI) or `assigned_by = admin_user_id` (UI)
5. **Password required at creation**: local users must have a password
   set at creation time. There is no passwordless local user state.
   This invariant is enforced at the database level by a CHECK
   constraint (see `docs/data-model.md`, `chk_user_auth_exclusive`)

## Security Considerations

- **CLI access requires shell access**: the `manage-user` commands require
  direct access to the host or container and provide bootstrap/recovery. The
  ordinary create endpoint is authenticated and capability-protected; there
  are no unauthenticated user-management mutations
- **Passwords are never CLI arguments**: the `create` and `set-password`
  commands collect passwords via hidden interactive prompts. This
  prevents exposure in process listings (`ps aux`) and shell history
  files. A TTY is required — these commands cannot be scripted
- **Admin UI is authenticated and capability-protected**: only callers with
  `manage_users` can use administrator user-management operations
- **Password policy**: minimum 16 characters, no complexity rules.
  Length is the primary defense (see
  `docs/features/identity/local-authentication.md`)
- **Audit trail**: all identity operations produce `IdentityAuditEvent`
   records via `IdentityAuditLog.log_event()` (user creation, role
   changes, password resets, deactivation, reactivation, API key
   lifecycle). Deactivation additionally creates `TicketAuditEvent`
   records for ticket unassignment. Ordinary role changes create no
   `TicketAuditEvent`; an effective loss of the user's final
   `vulnerability_analyst` origin creates one `assignment` event per
   effectively unassigned active ticket, committed atomically with the
   identity events in the same transaction (see
   `docs/features/tickets/ticket-audit-log.md`). See
   `docs/features/identity/identity-audit-log.md` for the full event
   type contract and `docs/features/identity/user-service.md` for the
   service operations.
- **Admin password reset is audited**: every admin-initiated password
  reset produces a `password_reset` `IdentityAuditEvent`. No rate
  limiting or step-up authentication is applied
  — the admin role is the highest trust level in the system, and
  additional friction would not meaningfully improve security given that
  a compromised admin already has full system access
- **Admin password reset has no out-of-band alert (accepted risk)**: when
  an admin resets a user's password via
  `POST /api/v1/admin/users/{user}/password`, the target user receives no
  out-of-band alert. A compromised admin could covertly take over an
  account. This is accepted because: (1) the admin trust level already
  implies full system access; (2) the `IdentityAuditEvent`
  (`password_reset`) provides a forensic trail of acting admin and target
  user
- **Per-username lockout DoS vector (accepted risk)**: the per-username
  lockout mechanism (5 failed attempts → account locked for 10 minutes)
  allows anyone who knows a valid username to lock out that account by
  sending 5 failed login attempts. This is a known trade-off in internal
  tools: brute-force protection at the cost of a low-effort DoS vector.
  Mitigations: (1) the lockout is temporary (auto-expires via Redis
  TTL); (2) an admin can unlock immediately via CLI or API; (3) existing
  sessions are NOT invalidated by lockout (see
  `docs/features/identity/local-authentication.md`) — a logged-in user continues
  working normally even if their account is locked. Future mitigation:
  per-IP rate limiting could be added if the threat model changes

## Cross-references

- `docs/features/identity/authentication.md` — authentication framework, API
  keys, session management
- `docs/features/identity/local-authentication.md` — login endpoint, password
  hashing, rate limiting
- `docs/features/identity/user-service.md` — service contract for create,
  update, deactivate, reactivate
- `docs/features/identity/rbac.md` — role definitions and permission model
- `docs/features/identity/identity-provisioning.md` — external sync (manages external users)
- `docs/features/platform/cli-infrastructure.md` — CLI entry point, session
  management, interactive input helpers
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
