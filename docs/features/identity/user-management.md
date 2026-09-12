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

Updates an existing user account. Identity field modifications
(`--email`, `--full-name`) are only permitted on local users — external
users have their identity fields managed exclusively by external sync
(see External User Data Ownership in
`docs/features/identity/user-service.md`). Role changes are permitted on
both local and external users. Reactivation (`--reactivate`) is permitted on
local users only — external users have their active status managed
exclusively by external sync (see External Active Status Ownership in
`docs/features/identity/user-service.md`). The command works regardless
of whether the user is currently active or inactive (see Inactive User
Management Principle in `docs/features/identity/user-service.md`).

```
sentinel manage-user update \
  --username <username> \
  [--email <new_email>] \
  [--full-name <new_name>] \
  [--add-role <role>] ... \
  [--remove-role <role>] ... \
  [--reactivate]
```

**Parameters**:

| Parameter        | Required | Repeatable | Description                                |
|------------------|----------|------------|--------------------------------------------|
| `--username`     | Yes      | No         | Username of the user to update (identifier) |
| `--email`        | No       | No         | New email address                           |
| `--full-name`    | No       | No         | New display name                            |
| `--add-role`     | No       | Yes        | Role to add: `admin`, `vulnerability_analyst`, `restricted_analyst` |
| `--remove-role`  | No       | Yes        | Role to remove: `admin`, `vulnerability_analyst`, `restricted_analyst` |
| `--reactivate`   | No       | No         | Reactivate a previously deactivated user    |

**Behavior**:

1. Normalize the username (trim whitespace, lowercase)
2. Looks up the user by normalized username — if not found, exits with
   error: `"Error: User '{username}' not found."`
3. If the user is an external user (`external_id IS NOT NULL`) and `--email` or
   `--full-name` is provided, exits with error:
   `"Error: User '{username}' is managed by an external identity provider. Identity
   fields cannot be modified manually."` (exit code 1). Role changes
   are still permitted on external users.
4. If the user is an external user (`external_id IS NOT NULL`) and
   `--reactivate` is provided, exits with error:
   `"Error: Cannot reactivate external users."` (exit code 1).
   Active status of external users is managed exclusively by external sync.
5. If no modification flags are provided (`--email`, `--full-name`,
   `--add-role`, `--remove-role`, `--reactivate` are all absent), prints:
   `"No changes specified for user '{username}'."` and exits with code 0
6. For each role value in `--add-role` and `--remove-role`, validates that
   it is a recognized role. If not, exits with error:
   `"Error: Invalid role '{value}'. Valid roles are: {list}."`
   The list of valid roles is derived from the system's role definitions
   at runtime
7. If `--email` is provided, validates email format — if not
   syntactically valid, exits with error:
   `"Error: Invalid email format '{value}'."`
8. If `--email` or `--full-name` is provided, delegates to
    `user_service.update_user()` with `acting_user_id = None`. If the
    service raises `UserConflictError` (duplicate email), exits with
    error: `"Error: A user with email '{email}' already exists."`
9. For role changes, passes `--add-role` and `--remove-role` values
    verbatim to `user_service.update_roles()` with
    `acting_user_id = None` and roles as `(role, '_manual')` pairs. The
    CLI does not pre-process or validate conflicts between add and remove
    lists — the service handles input resolution (deduplication,
    cancellation of conflicting entries) and validation (externally-derived role
    protection). The service never rejects input due to add/remove
    conflicts; it resolves them silently. Since `acting_user_id = None`,
    the self-removal guard does not apply (CLI is a system action)
10. If `--reactivate` is provided: delegates to
    `user_service.reactivate_user()` with `acting_user_id = None`. If
    the user is already active, this is a no-op. See
    `docs/features/identity/user-service.md` for reactivation semantics.
    Reactivation is intentionally the LAST mutation step so that the
    account is fully configured (correct email, roles, etc.) before
    becoming active again
11. Prints summary of changes. The summary lists only changes that were
    actually applied (not no-ops). If all requested operations resulted
    in no-ops (e.g., reactivating an already-active user, adding a role
    the user already has, removing a role the user does not have), prints:
    `"No changes applied to user '{username}'."` and exits with code 0.
    Otherwise prints:
    `"Updated user '{username}': {list of actual changes}."`
    Role changes are reported in the summary as the net difference
    (before → after), for example `roles: added 'admin'; removed
    'vulnerability_analyst'`.
    If conflicting `--add-role` and `--remove-role` cancel out (no net
    change), no role line appears in the output (no-op, idempotent)

**Error handling (atomic fail-fast)**: steps 8–10 execute in one
caller-owned database transaction. Each service flushes but does not commit.
If any step fails, the workflow stops, rolls back every preceding mutation and
audit event, and reports the failed operation to stderr; no partial-success
step report is printed. After all steps succeed, the workflow commits exactly
once and prints the summary in step 11.

**Idempotency**: Idempotent. If all requested operations result in no-ops
(state already reached), the command prints an informational message and
exits with code 0.

**Exit codes**: 0 on success (including no-op), 1 on validation or
operational error, 2 on system error (database unreachable).

**Output channels**: success summary to stdout. All `"Error: ..."` messages to
stderr.

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

**Behavior**:

1. Normalize the username (trim whitespace, lowercase)
2. Looks up the user by normalized username — if not found, exits with
   error: `"Error: User '{username}' not found."`
3. If the user is an external user (`external_id IS NOT NULL`), exits with
   error: `"Error: Cannot deactivate external users."` (exit code 1).
   Active status of external users is managed exclusively by external sync.
4. If the user is already inactive, prints:
   `"User '{username}' is already inactive."` and exits with code 0
5. Queries the impact of deactivation:
   - Count of non-revoked API keys from
     `api_key_service.count_non_revoked_keys()` (including expired keys)
   - Count of active sessions, active assigned tickets, and whether this is the
     last active Admin from `user_service.get_deactivation_impact()`
6. Displays the impact summary:
   ```
   About to deactivate user '{username}':
     - {n} non-revoked API keys will be revoked
     - {n} active sessions will be invalidated
      - {n} active tickets will be unassigned
   ```
   If the user is the last active admin, appends a warning to stderr:
   ```
   Warning: this is the last active user with Admin role.
   After deactivation, assign Admin to another user via:
     sentinel manage-user update --username <user> --add-role admin
   ```
7. Prompts: `Proceed? [y/N]`
    - If the user answers anything other than `y` or `Y`, exits with
      code 0 without deactivating
    - If no TTY is detected, prints to stderr `Error: This command
      requires an interactive terminal (confirmation required).` and
      exits with code 1
8. Delegates to `user_service.deactivate_user()` with
   `acting_user_id = None` and
   `reason = "deactivated via CLI (manage-user deactivate)"`
   as identity-audit lifecycle context. Any derived Ticket unassignment uses
   the canonical Ticket comment reason `user deactivated` instead.
9. After the workflow commits, purges session cache using the returned
   `DeactivationResult.invalidated_session_ids`. Redis failure is best-effort
   and does not turn a committed deactivation into a command failure
10. Prints: `"Deactivated user '{username}'."`

This command does not permanently remove the user record from the
database. The User record is preserved to maintain referential integrity
with TicketAuditEvent, ticket assignments, and UserRole audit data. This is
consistent with external sync deactivation behavior. For full database
cleanup in development environments, reset the database directly.

**Inactive user management principle**: see
`docs/features/identity/user-service.md` (Inactive User Management Principle).

**Idempotency**: Idempotent. If the user is already inactive, the
command prints an informational message and exits with code 0.

**Exit codes**: 0 on success (including no-op and user-cancelled
confirmation), 1 on validation error, 2 on system error (database
unreachable).

**Output channels**: impact summary and confirmation to stdout.
`"Error: ..."` messages and `"Warning: ..."` (last admin) to stderr.

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
8. Return HTTP 200 with the updated user profile in the standard
   `{"data": ...}` envelope

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

Add or remove manual roles for a user.

**Request body**:

```json
{
  "add": ["admin"],
  "remove": ["vulnerability_analyst"]
}
```

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. Delegate to `user_service.update_roles()` with
   `acting_user_id = authenticated_admin.id` and roles as
   `(role, '_manual')` pairs

**Validation rules**:
- Cannot remove roles with `group_name != '_manual'` — returns HTTP 409
  with code `USER_EXTERNAL_ROLE_PROTECTED`:
  `"Cannot remove externally-derived role '{role}'. This role is managed by the
  external group '{group_name}'."`
- Cannot remove your own Admin role — returns HTTP 409 with code
  `USER_SELF_ROLE_REMOVAL`:
  `"Cannot remove your own Admin role."` (enforced by
  `user_service.update_roles()` — see `docs/features/identity/user-service.md`)
- If both `add` and `remove` are empty arrays (or missing), the
  operation is a no-op — returns HTTP 200 with the unchanged user
  profile in the standard `{"data": ...}` envelope
- Adding a role that the user already has as a manual assignment is a
   no-op (idempotent)
- Removing a role the user does not have is a no-op (idempotent)
- Adding a role that the user already holds via external derivation creates a
  separate `_manual` record — both origins coexist independently. See
  `docs/features/identity/rbac.md` (Role Origins and Coexistence) for full
  semantics
- Creates a `UserRole` record with `group_name = '_manual'` and
  `assigned_by` set to the authenticated admin's user ID for each added
  role

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
revocation, session invalidation, ticket unassignment).

**Request body**: none (empty body or omitted).

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. Delegate to `user_service.deactivate_user()` with
   `acting_user_id = authenticated_admin.id` and
   `reason = "deactivated by admin via API"`
   as identity-audit lifecycle context. Any derived Ticket unassignment uses
   the canonical Ticket comment reason `user deactivated` instead.
3. After the API workflow commits, purge session cache using the
   `DeactivationResult.invalidated_session_ids` returned by the service
4. Return HTTP 200 with the updated or unchanged user profile in the standard
   `{"data": ...}` envelope

**Constraints**:
- Self-deactivation is rejected by the service layer — returns HTTP 409
  with code `USER_SELF_DEACTIVATION`:
  `"Cannot deactivate your own account."`
- External user deactivation is rejected by the service layer for a
  currently-active user — returns HTTP 409 with code
  `USER_EXTERNAL_STATUS_READONLY`: `"Cannot deactivate external users."` An
  already-inactive external user is a no-op (see Reactivate User below for
  why this ordering differs from reactivation)

See `docs/features/identity/user-service.md` for the full side effect contract
(API key revocation, session invalidation, ticket unassignment on
deactivation).

**Response**: user profile in `{"data": {...}}` envelope (see
`GET /api/v1/users/{user}` in Public API endpoints above for the full
response schema).

#### Reactivate User

```
POST /api/v1/admin/users/{user}/reactivate
```

**`Capability: manage_users`**

Reactivate a previously deactivated user account.

**Request body**: none (empty body or omitted).

**Behavior**:

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. Delegate to `user_service.reactivate_user()` with
   `acting_user_id = authenticated_admin.id`
3. Return HTTP 200 with the updated or unchanged user profile in the standard
   `{"data": ...}` envelope

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

1. Look up the user by `user_id` — if not found, return HTTP 404 with
   code `USER_NOT_FOUND`
2. If the resolved user is the requesting admin themselves, return
   HTTP 409 with code `USER_SELF_DEACTIVATION`:
   `"Cannot preview deactivation impact for your own account."`
   Rationale: the actual deactivation endpoint rejects self-deactivation
   with the same code. Rejecting the preview as well keeps the API
   consistent — if you cannot deactivate yourself, you cannot preview
   the impact either. This prevents a confusing UX where the preview
   succeeds but the subsequent action is rejected.
3. If the user is already inactive, return HTTP 200 with a no-impact response:
   all counts set to zero and `already_inactive` set to `true`
4. If the user is an external user (`external_id IS NOT NULL`), return HTTP 409
   with code `USER_EXTERNAL_STATUS_READONLY`:
   `"Cannot deactivate external users."`
   Rationale: same consistency principle as self-deactivation — if the
   deactivation endpoint rejects external users, the preview should too.
   This check applies only to active external users
5. For an inactive user, the no-impact response mirrors the actual
   `POST .../deactivate` endpoint, which is idempotent and
   returns HTTP 200 for already-inactive users. The preview must not be
   stricter than the action it previews — returning 409 here while the
   action returns 200 creates an asymmetry that forces clients to
   special-case the preview error path for a condition that the action
   itself treats as a no-op.
6. Query and return the impact summary. Obtain `api_keys_count` through
   `api_key_service.count_non_revoked_keys()`; the endpoint performs no direct
   `ApiKey` query. Obtain `sessions_count`, `tickets_count`, and the
   last-active-admin flag through `user_service.get_deactivation_impact()`;
   neither the endpoint nor the CLI performs direct Session, Ticket, or
   UserRole queries. The API key count includes expired keys because
   deactivation revokes every row whose `revoked_at` is NULL.

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

**Semantics**: this endpoint returns a point-in-time snapshot of the
user's current state. The response is purely informational — the
subsequent `POST .../deactivate` call does not verify whether the impact has
changed since the preview was fetched. Between viewing the preview and
confirming the deactivation, new resources may have been assigned to the
user (tickets, API keys, sessions). The deactivation proceeds regardless
and affects all resources at execution time, not only those shown in the
preview.

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
   minimum admin count. However, via UI/API it is practically impossible
   for administrators to accidentally eliminate all admins — the
   self-removal guard (see `docs/features/identity/rbac.md`, Business Rule 1)
   prevents any admin from removing their own Admin role, so at least
   the acting admin always retains the role. Via CLI or system
   operations (`acting_user_id = None`), the self-removal guard does
   not apply, and it is possible to remove or deactivate even the last
   admin. This is intentional and non-problematic: the platform
   continues to function normally without active admin users (all
   non-admin features remain operational). In these rare cases, a
   system administrator with shell access can restore admin access by either
   creating a new local administrator with `sentinel manage-user create
   --username <new-user> --email <email> --role admin` or promoting an existing
   user with `sentinel manage-user update --username <user> --add-role admin`.
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
   records for ticket unassignment. Role changes do not produce
   `TicketAuditEvent` records. See
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
