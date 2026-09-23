# Local Authentication

**Parent spec**: `docs/features/identity/authentication.md`
**Sibling specs**: `docs/features/identity/sso-authentication.md`
**Inherited concerns**: token storage (HttpOnly cookie), session
lifecycle, logout, error code namespace (`AUTH_*`)

---

## Purpose

Provide a credential-based login mechanism for local user accounts.
Local authentication allows users who do not have access to the SUSE SSO
(`id.suse.com`) to log in with a username and password. This covers
three primary use cases:

1. **Development and staging environments** where the SUSE internal
   network is not reachable
2. **AI agents and bots** that need to log in once to create an API key
   for ongoing programmatic access
3. **Environments without SSO** where Sentinel is deployed outside the
   SUSE corporate network

Local authentication is only available to users with `external_id = NULL`
(local users). Users managed by external provisioning (`external_id IS NOT NULL`)
authenticate exclusively via SSO — see
`docs/features/identity/sso-authentication.md`.

## Login Endpoint

### Login

Authenticates a local user with username and password, creates a
session, and returns a JWT.

**`Access: Public`**

**Request body**:

```json
{
  "username": "string (required)",
  "password": "string (required)"
}
```

**Behavior**:

1. If the provided password exceeds 128 characters, return HTTP 401 with
   generic message immediately (reasonable UX limit — no database lookup
   needed, no lockout counter created)
2. Normalize the username: strip leading and trailing whitespace, then
   convert to lowercase. If the normalized username exceeds 64 characters
   (the Username Format limit in `docs/conventions.md`), return HTTP 401
   with generic message immediately — no database lookup or Redis counter
   creation. All subsequent steps use the normalized value.
3. If the normalized username is empty, return HTTP 401 with generic
   message (same as user not found — no lockout counter is created for
   empty usernames)
4. Atomically execute the lockout guard-and-increment on the Redis
   counter `login_attempts:{normalized_username}` (see Rate Limiting for
   the atomicity contract). The operation returns one of two outcomes:
   - **Blocked**: the counter was already at or above
     `LOGIN_MAX_ATTEMPTS`. The remaining TTL is returned in the same
     atomic operation. Return HTTP 429 with message: `"Account
     temporarily locked. Try again later."` and include a `Retry-After`
     header with the remaining TTL in seconds. No password verification,
     no counter increment, no TTL renewal.
   - **Admitted**: the counter was below `LOGIN_MAX_ATTEMPTS`. The
     counter has been incremented and its TTL set/renewed to
     `LOGIN_LOCKOUT_MINUTES`. The new counter value is returned.
     Proceed to step 5.
5. Look up the user by normalized `username`
6. If user not found: perform dummy bcrypt verification (equivalent cost
   to a real password check) — go to step 10 (failure)
7. If user is inactive (`active = false`), has `external_id IS NOT NULL`
   (external user), or has no `password_hash` set: perform dummy bcrypt
   verification — go to step 10 (failure)
8. Verify the provided password against the stored `password_hash`
9. If verification fails, go to step 10 (failure)
10. On failure (any of steps 6, 7, 9): return HTTP 401 with generic
    message. The counter was already incremented at step 4. If the
    counter has reached `LOGIN_MAX_ATTEMPTS` (transition from unlocked to
    locked), emit the lockout transition event (see Rate Limiting,
    Lockout transition logging) — `user_id` is available from step 5
    when the username resolved to an existing user.
11. On success, in one caller-owned database transaction, call
    `session_service.create_session(db, user, reason=local_login,
    expected_password_hash=<the hash verified at step 8>)`. The service
    acquires the User root lock and revalidates, before creating anything,
    both the locked-current active status and the locked-current credential
    state against the verified hash (see
    `docs/features/identity/authentication.md`, Session creation). If the
    locked-current target is inactive — a deactivation that committed after
    the step-7 pre-check — or its `password_hash` has been replaced by a
    password reset that committed after the step-8 verification, the service
    returns no Session and the endpoint returns the same HTTP 401
    `AUTH_INVALID_CREDENTIALS` generic response as every other failure. This
    outcome is a login failure for lockout purposes: if the counter value
    returned by step 4 equals exactly `LOGIN_MAX_ATTEMPTS`, emit the lockout
    transition event exactly as step 10 does. Otherwise commit the new
    session and `user.last_login_at` once or roll both back on failure.
    After commit, delete the failed-attempt counter as a best-effort
    post-commit effect; Redis failure does not fail the completed login.
    Return the JWT and its `token_expires_at` from the service result as
    `access_token` and `expires_at` (see
    `docs/features/identity/authentication.md`, Session creation). A failed
    counter delete may leave a residual counter that locks the account until
    TTL expiry; admin unlock and natural TTL expiry are the recovery paths.

Steps 1-10 (input normalization, Redis lockout handling, user lookup, and
bcrypt or dummy-bcrypt verification) execute before and outside the locked
database phase; the User lock covers only the short session-creation
transaction.

**Success response** (200):

```json
{
  "data": {
    "access_token": "eyJhbG...",
    "token_type": "bearer",
    "expires_at": "ISO8601"
  }
}
```

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 401 | `AUTH_INVALID_CREDENTIALS` | Invalid username or password (also covers: user not found, inactive user, external user, no password set) |
| 429 | `AUTH_ACCOUNT_LOCKED` | Account temporarily locked due to too many failed attempts. Includes `Retry-After` header |

Error response format:

```json
{
  "code": "AUTH_INVALID_CREDENTIALS",
  "detail": "Invalid username or password."
}
```

The 401 error message is intentionally generic and identical for all failure
cases (user not found, wrong password, inactive user, external user) to
prevent username enumeration.

## Password Management

### Storage

Passwords are stored as bcrypt hashes (with SHA-256 pre-hash) in the
`password_hash` column of the `User` table. This column is nullable — it
is `NULL` for external users (who authenticate via SSO and never have
a local password). Local users always have a `password_hash` set
(required at creation). This mutual exclusivity is enforced by a database
CHECK constraint (`chk_user_auth_exclusive`) — see `docs/data-model.md`.

### Hashing configuration

| Parameter       | Value                                              |
|-----------------|----------------------------------------------------|
| Algorithm       | bcrypt with SHA-256 pre-hash                       |
| Pre-hash step   | `base64(SHA-256(UTF-8(password)))` — 44 chars      |
| Cost factor     | 12 (OWASP 2024 recommendation)                    |
| Salt            | 16 bytes (auto-generated by bcrypt)                |
| Output format   | 60 chars (`$2b$12$...`)                            |

The hashing pipeline is:

1. Encode the password as UTF-8 bytes
2. Compute SHA-256 of the bytes (32 bytes raw output)
3. Encode the SHA-256 output as base64 (44 ASCII characters)
4. Hash the base64 string with bcrypt at cost factor 12

The SHA-256 pre-hash normalizes any password length to a fixed 44-byte
input for bcrypt, avoiding bcrypt's native 72-byte input limit. This
pattern is an industry standard (used by Dropbox, 1Password, and
others).

**Why bcrypt**: local passwords in Sentinel serve secondary use cases
(development environments, bot accounts, deployments without SSO). The
primary authentication path for SUSE employees is SSO. bcrypt provides
adequate resistance to offline brute-force attacks for this threat model
while using negligible memory (~4 KB per operation), eliminating the risk
of OOM under concurrent login attempts. Memory-hard algorithms
(Argon2id, scrypt) offer stronger GPU resistance but are unnecessary
given the limited role of local passwords and the existing rate limiting.

### Setting a password

Passwords are set in two scenarios:

1. **At user creation** (CLI or admin UI): the admin provides the
   initial password for the local user
2. **Password reset** (CLI or admin UI): an admin sets a new password
   for an existing local user

There is no self-service password reset or password change in the
initial implementation (v1 scoping decision). Users who need a password
change must request it from an admin. This is acceptable given the
primary use cases (development environments, bot accounts, deployments
without SSO) and will be revisited as a follow-up if local user adoption
grows beyond these scenarios.

### Password validation

- Minimum 16 characters
- Maximum 128 characters (reasonable UX limit; the SHA-256 pre-hash
  normalizes any length to a fixed 44-byte input for bcrypt, so there
  is no resource exhaustion risk from long passwords)
- No complexity rules (uppercase, numbers, symbols) — length is the
  primary defense
- No breach database check (e.g., HaveIBeenPwned k-anonymity API or
  local bloom filter) in v1. Rationale: passwords are set by admins (not
  self-service), the tool is internal, and integrating with external
  breach services or maintaining a local bloom filter adds complexity
  disproportionate to the threat model. May be reconsidered if
  self-service password change is added in the future.

### CLI commands

Passwords are managed via `sentinel manage-user create` (at user
creation) and `sentinel manage-user set-password` (reset). Both
commands collect the password interactively via a hidden prompt —
passwords are never passed as CLI arguments (arguments are visible in
process listings and shell history). See
`docs/features/identity/user-management.md` for full CLI behavior
(parameters, confirmation prompt, error handling, exit codes).

### Admin UI: password reset

The user management page in the administration panel includes a "Reset
password" action for local users. The admin enters the new password
(same validation: 16–128 characters). The behavior delegates to
`user_service.reset_password()` with `acting_user_id` set to the admin's
user ID. See `docs/features/identity/user-management.md` for the full
admin UI specification.

For external users, the "Reset password" action is not available (greyed out
or hidden).

### Admin Password Reset

API endpoint for admin password reset (used by the admin UI). The full
endpoint specification (request/response schema, error codes) is defined
in `docs/features/identity/user-management.md` (Admin API endpoints).

**`Capability: manage_users`**

Delegates to `user_service.reset_password()` which handles external user
check, password validation, hashing, and session invalidation. See
`docs/features/identity/user-service.md` for the service contract.

## Rate Limiting / Brute-Force Protection

### Account lockout

To protect against brute-force attacks, Sentinel tracks failed login
attempts per username using a Redis counter.

| Setting                   | Type | Default | Env var                     |
|---------------------------|------|---------|-----------------------------|
| `login_max_attempts`      | int  | `5`     | `LOGIN_MAX_ATTEMPTS`        |
| `login_lockout_minutes`   | int  | `10`    | `LOGIN_LOCKOUT_MINUTES`     |

**Behavior**:

1. On each login attempt that passes the lockout gate (login step 4,
   "Admitted" outcome), the counter
   `login_attempts:{normalized_username}` is atomically incremented and
   its TTL is set/renewed to `LOGIN_LOCKOUT_MINUTES`. This extends the
   counting window under active attack — an attacker cannot bypass
   lockout by spacing attempts just under the TTL. Note: attempts
   rejected at steps 1 and 3 (overlong password, empty username) do not
   create or modify a counter.
2. If the counter is already at or above `LOGIN_MAX_ATTEMPTS` when a new
   attempt arrives (login step 4, "Blocked" outcome), the attempt is
   rejected immediately with HTTP 429 (with `Retry-After` header).
   Attempts rejected at this step do **not** verify a password, increment
   the counter, or reset the TTL — the lockout window expires naturally
   from the last admitted attempt
3. On successful login, delete the counter (best-effort — Redis failure
   does not fail the login)

**Concurrency contract**:

The lockout gate and the counter increment are a single atomic operation
(login step 4). Concurrent requests collectively permit exactly
`LOGIN_MAX_ATTEMPTS` password verifications before subsequent requests
are treated as blocked. Specifically:

- The guard-and-increment is indivisible: atomically, if the counter is
  at or above `LOGIN_MAX_ATTEMPTS`, return the "Blocked" outcome without
  modifying the counter or TTL; otherwise increment the counter, set or
  renew the TTL to `LOGIN_LOCKOUT_MINUTES`, and return the "Admitted"
  outcome with the new counter value. No intermediate state is
  observable by other clients.
- A request that receives the "Blocked" outcome MUST NOT verify a
  password, increment the counter, or reset/renew the TTL. The lockout
  window expires naturally from the last admitted attempt.
- The transition from unlocked to locked (counter reaching
  `LOGIN_MAX_ATTEMPTS`) happens exactly once — it is not possible for
  two concurrent requests to both "be the Nth attempt" and both perform
  a password verification that crosses the threshold.
- A verification in progress (between step 4 "Admitted" and step 11
  success/failure resolution) occupies a counter slot. A concurrent
  request may receive the "Blocked" outcome while a valid verification
  is in flight — this is accepted and self-clears within one bcrypt
  duration when the successful login deletes the counter at step 11.

This contract does not prescribe the internal mechanism (e.g., a Lua
script) — only the observable behavior under concurrency.

**Lockout transition logging**:

The lockout transition event is emitted on the **failure path** (login
step 10, including the locked-current-ineligible failure outcomes of step 11
— an inactive target or a credential superseded by a password reset) when
the counter value returned by step 4 equals exactly
`LOGIN_MAX_ATTEMPTS`. It is NOT emitted on successful logins (which
delete the counter at step 11). The log message follows the PII
discipline in `docs/features/platform/logging.md` — it includes
`user_id` (UUID) from the step-5 lookup when the username resolved to
an existing user, and omits it when the username does not exist:

```json
{"event": "login_lockout_triggered", "attempt_count": 5, "user_id": "550e8400-..."}
{"event": "login_lockout_triggered", "attempt_count": 5}
```

Lockout events are tracked via application logging only (not the
identity audit trail) because lockout is a transient Redis-only state,
not a persistent identity mutation.

**Notes**:

- Lockout is per-username, not per-IP. This is simpler and sufficient
  for an internal tool.
- **Per-username lockout DoS (accepted risk)**: an unauthenticated
  attacker who knows a username can lock out that account with
  `LOGIN_MAX_ATTEMPTS` invalid attempts. This is mitigated by: (a) lockout
  does not invalidate existing sessions (the legitimate user already
  logged in continues working), (b) admin unlock is available via CLI or
  admin UI, (c) the lockout expires automatically after the TTL. For
  environments where this is unacceptable, a per-IP rate limit at the
  reverse proxy layer provides secondary defense.
- The lockout does not affect API key authentication (API keys bypass
  the login endpoint entirely).
- **Lockout does NOT invalidate existing sessions**. This is intentional:
  lockout is a temporary brute-force mitigation, not a security
  compromise indicator. A user who is already authenticated (has a valid
  JWT session) continues working normally even if their account is
  locked due to failed login attempts from another source. Revoking
  sessions on lockout would amplify the DoS vector — an attacker could
  not only block new logins but also disconnect the legitimate user from
  active work. This contrasts with deactivation and password reset,
  which DO invalidate sessions because they indicate a deliberate
  administrative action or credential compromise.
- An admin can unlock a locked account via `sentinel manage-user unlock
  --username <name>` (CLI) or the "Unlock" action in the admin user
  management page. Alternatively, the lockout expires automatically
  after the TTL. See `docs/features/identity/user-management.md`.
- **Permanent lockout is not possible**: once the account is locked,
  subsequent rejected attempts (step 4) do not increment the counter or
  reset the TTL. The lockout expires naturally after
  `LOGIN_LOCKOUT_MINUTES` from the last actual failed password
  verification, even under sustained attack.
- **Redis unavailability**: if Redis is unreachable (any `RedisError` —
  including connection failures and OOM rejections), the login endpoint
  operates in **fail-open** mode — login proceeds without rate limiting.
  This prioritizes availability over brute-force protection. The
  rationale: Sentinel is an internal tool on a trusted network; a
  Redis outage should not lock all users out of the system. The Redis
  connection failure should be logged as a warning for operators.
- **Configuration bounds**: `LOGIN_MAX_ATTEMPTS` must be >= 1.
  `LOGIN_LOCKOUT_MINUTES` must be >= 1. Values of 0 or negative cause
  the application to refuse to start with an explicit error message
  indicating which variable has an invalid value.
- **Redis key namespace safety**: the key format
  `login_attempts:{normalized_username}` is safe from namespace
  collisions because the `login_attempts:` prefix isolates it from
  other application-owned Redis keys. On the login path, the
  normalized username is bounded at 64 characters (step 2) before the
  Redis key is created, preventing unbounded key growth from
  attacker-controlled input. For paths that derive the key from an
  existing `User` row (e.g., `unlock_user()`), the stored username is
  additionally restricted to `[a-z0-9._-]` at creation time (see
  `docs/conventions.md`, Username Format).
- **Non-existent username counters (accepted risk)**: Redis counters are
  created for every non-existent username attempted (to prevent timing
  side-channels). A high-volume attack could create many short-lived
  keys. This is accepted because: (a) keys are TTL-bounded and expire
  after `LOGIN_LOCKOUT_MINUTES`, (b) each key is small (a few bytes),
  (c) per-IP rate limiting at the reverse proxy layer (recommended for
  exposed deployments) limits key creation rate.

## Login Page

The local login form does not check whether local users exist — it
simply returns an authentication error if the credentials are invalid.

### Frontend behavior

Post-login redirect and session expiration handling follow the shared
behavior defined in `docs/features/identity/authentication.md` § Frontend
session behavior.

## Security Considerations

- **Generic error messages**: the login endpoint never reveals whether a
  username exists. All failure cases return the same 401 message.
- **bcrypt with SHA-256 pre-hash**: provides adequate resistance to
  offline brute-force attacks for the local password threat model.
  Negligible memory usage (~4 KB/op) eliminates OOM risk under
  concurrent login attempts. The SHA-256 pre-hash avoids bcrypt's
  72-byte input limit while adding no meaningful computational cost.
- **No password complexity rules**: research shows that length is more
  effective than complexity requirements. The 16-character minimum
  provides adequate entropy.
- **Session invalidation on password change**: prevents continued access
  through sessions authenticated with old credentials after a password reset.
  A login that verified the old password before the reset but has not yet
  created its Session is also rejected: session creation revalidates the
  locked-current `password_hash` against the verified credential under the
  User lock, so no Session is created for a superseded credential (see
  `docs/features/identity/authentication.md`, Session creation). All sessions
  are invalidated, including the caller's own session — no exception for
  admin self-password-reset. The admin receives the success response,
  then the next API call returns 401. The frontend handles this via its
  standard session expiration behavior (see
  `docs/features/identity/authentication.md` § Frontend session behavior).
- **Password reset does not revoke API keys**: API keys are independent
  credentials and remain valid until revoked or expired. Response to suspected
  credential compromise therefore requires both a password reset and
  administrator revocation of the user's API keys, or user deactivation (which
  revokes them automatically).
- **Redis-based lockout**: survives application restarts, shared across
  all API server instances.
- **Fail-open rate limiting (accepted risk)**: when Redis is unreachable,
  the login endpoint operates without rate limiting to preserve
  availability. This is accepted for an internal tool on a trusted
  network. For deployments in untrusted environments (external networks,
  public-facing instances), operators should configure a global
  per-IP rate limit at the reverse proxy layer (e.g., nginx `limit_req`)
  as an infrastructure-level backstop against brute-force during Redis
  outages.
- **Per-IP rate limiting delegated to reverse proxy**: Sentinel
  intentionally does not implement per-IP rate limiting at the
  application level. The reverse proxy (nginx, ingress controller) is
  the appropriate layer for IP-based throttling because it sees the
  client's real IP address without relying on `X-Forwarded-For` headers
  (which can be spoofed by upstream hops). This covers both the
  fail-open scenario (Redis outage) and distributed attacks using many
  usernames from a single IP.
- **No self-service password change (v1 accepted risk)**: local users
  cannot change their own password. If a user suspects credential
  compromise, they must contact an admin who performs a password reset
  (CLI or admin UI). During the window between compromise detection and
  admin intervention, the old credential remains valid. This is accepted
  for v1 given the limited use cases (dev environments, bots, no-SSO
  deployments). A `POST /api/v1/auth/change-password` endpoint (requiring
  active session + old password) is a planned follow-up.
- **No password in JWT**: the JWT contains only user ID (`sub`), session
  ID, and timing claims (`iat`, `exp`, `session_deadline`). Roles are
  loaded from the database on each request, not embedded in the token.
  The password hash is never included in tokens or API responses.
- **Password not returned by API**: no endpoint returns the
  `password_hash` field. Pydantic response schemas must explicitly
  exclude it.

## Cross-references

- `docs/features/identity/authentication.md` — shared authentication framework
  (JWT format, session model, credential validation, middleware)
- `docs/features/identity/api-key-management.md` — API key lifecycle and
  management surfaces
- `docs/features/identity/sso-authentication.md` — SSO login flow (alternative
  provider)
- `docs/features/identity/user-management.md` — creating and managing
  local user accounts
- `docs/features/identity/user-service.md` — deactivation side effects
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
