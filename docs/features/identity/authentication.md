# Authentication

## Purpose

Define the authentication framework for Sentinel: how users prove their
identity and how the system verifies that identity on every request.

Sentinel supports two authentication providers — SSO via `id.suse.com`
(see `docs/features/identity/sso-authentication.md`) and local credentials (see
`docs/features/identity/local-authentication.md`). Both providers produce the
same artifact: a signed JWT that the client presents on subsequent
requests. Programmatic clients may instead present API keys managed under
`docs/features/identity/api-key-management.md`.

This specification defines the shared infrastructure consumed by both
providers: token format, session management, credential validation,
middleware behavior, and session UI surfaces.

## Architecture

```
   SSO Provider                        Local Provider
   (OIDC flow)                     (POST /api/v1/auth/login)
           │                                    │
           └──────────┐            ┌────────────┘
                      ▼            ▼
              ┌──────────────────────────┐
              │   Session + JWT issued   │
              └────────────┬─────────────┘
                           │
                           ▼
              ┌───────────────────────────────┐
              │ get_current_user()            │◄─── API Key (no session)
              │ get_optional_current_user()   │
              └───────────────────────────────┘
```

The middleware accepts two credential types on every request:

- **JWT** (session-backed): validated by signature + session liveness
- **API key**: validated by hash lookup + revocation check

## Token Format (JWT)

Sentinel issues JSON Web Tokens signed with a symmetric key.

### Configuration

| Setting               | Type   | Default | Env var               |
|-----------------------|--------|---------|-----------------------|
| `jwt_secret_key`      | string | —       | `JWT_SECRET_KEY`      |
| `jwt_expiry_hours`    | int    | `72`    | `JWT_EXPIRY_HOURS`    |
| `session_max_lifetime_days` | int | `30` | `SESSION_MAX_LIFETIME_DAYS` |

`JWT_SECRET_KEY` is required. The application must refuse to start if it
is not set.

### Configuration bounds

- `JWT_EXPIRY_HOURS` must be >= 1. Values of 0 or negative cause the
  application to refuse to start with error:
  `"Invalid JWT_EXPIRY_HOURS: must be >= 1 (got: {value})"`
- `JWT_EXPIRY_HOURS` values above 720 (30 days) are accepted but log a
  WARNING at startup:
  `"JWT_EXPIRY_HOURS is set to {value} (>720 hours). Long-lived tokens
  increase the window of exposure if a token is compromised."`
- `JWT_SECRET_KEY` must be at least 32 characters. If the value is shorter,
  the application refuses to start with error:
  `"Invalid JWT_SECRET_KEY: must be at least 32 characters (got: {length})"`
- `SESSION_MAX_LIFETIME_DAYS` must be >= 1. Values of 0 or negative cause
  the application to refuse to start with error:
  `"Invalid SESSION_MAX_LIFETIME_DAYS: must be >= 1 (got: {value})"`
- `SESSION_MAX_LIFETIME_DAYS` values above 365 are accepted but log a
  WARNING at startup:
  `"SESSION_MAX_LIFETIME_DAYS is set to {value} (>365 days). Long-lived
  sessions increase exposure if a session is compromised."`

### Claims

| Claim              | Type   | Description                                   |
|--------------------|--------|-----------------------------------------------|
| `sub`              | string | User UUID (primary key of the `User` row)     |
| `session_id`       | string | UUID of the associated `Session` row          |
| `iat`              | int    | Issued-at timestamp (Unix epoch)              |
| `exp`              | int    | Expiration timestamp (Unix epoch)             |
| `session_deadline` | int    | Maximum session lifetime (Unix epoch). Set at login per `SESSION_MAX_LIFETIME_DAYS`, never refreshed |
| `iss`              | string | `"sentinel"` (constant)                       |

Issued Sentinel JWTs contain exactly these six claims and no others. The
identifier claims are canonical UUID strings. The three time claims are
integer Unix timestamps; JSON booleans are not accepted as integers. All six
claims are required when decoding a Sentinel JWT.

### JWT validation contract

Normal JWT validation verifies all of the following with no clock-skew leeway:

1. The token is signed with `HS256` and its signature is valid under
   `JWT_SECRET_KEY`. No other algorithm is accepted.
2. The payload contains exactly the six claims listed above, with the listed
   types; `sub` and `session_id` parse as UUIDs; and `iss` is `"sentinel"`.
3. `iat <= now < exp <= session_deadline`. Equality with `exp` or
   `session_deadline` is expired: validation rejects when `exp <= now` or
   `session_deadline <= now`.

`now` is one UTC timestamp snapshot converted to an integer Unix timestamp
for all checks in one validation. Validation never recalculates
`session_deadline` from the current `SESSION_MAX_LIFETIME_DAYS` setting.
Malformed input or failure of any check produces one generic authentication
failure; callers do not receive the failed condition.

### Token lifecycle

- A token is issued at login with:
  - `session_deadline = now + SESSION_MAX_LIFETIME_DAYS * 86400` (default 30 days, never refreshed)
  - `exp = min(now + JWT_EXPIRY_HOURS * 3600, session_deadline)` — capped
    at `session_deadline` so the advertised `expires_at` never exceeds
    the session's actual maximum lifetime (same rule as token refresh)
- A change to `SESSION_MAX_LIFETIME_DAYS` applies only to sessions
  created by subsequent successful logins. Each session's
  `session_deadline` is calculated and persisted at login time and
  remains fixed for the lifetime of that session — it is never
  recomputed from the current setting.
- The server transparently refreshes the token via **sliding session**
  (see Token refresh below) whenever a request processes a valid JWT through
  mandatory or optional authentication. For browser sessions that retain the
  refreshed cookie, continued use of endpoints that process authentication
  prevents expiration at the shorter JWT `exp` boundary, but never extends the
  immutable `session_deadline`. Bearer-only behavior is defined under Token
  refresh.
- An inactive user whose token expires without renewal (no requests for
  longer than `JWT_EXPIRY_HOURS`) is redirected to the login page.
- After `SESSION_MAX_LIFETIME_DAYS` from login (`session_deadline`), the
  session expires unconditionally — the user must re-authenticate
  regardless of activity. This provides a hard cap on session lifetime.
- A token becomes invalid immediately if its associated session is
  deactivated (see Session Management below).

### Token refresh

The authentication middleware implements a sliding session mechanism
that transparently extends the token lifetime for active users:

1. After successful JWT validation and session liveness check, compute:
   `token_age = now - iat`
   `refresh_threshold = JWT_EXPIRY_HOURS * 3600 * 0.5`
2. If `session_deadline <= now`: do not refresh. The session has exceeded
   its maximum lifetime and normal validation rejects it. The explicit guard
   also prevents a restricted or independently tested refresh call from
   issuing a token with no remaining lifetime.
3. If `token_age >= refresh_threshold` and `session_deadline > now`:
   a. Verify `now + JWT_EXPIRY_HOURS * 3600` does not exceed
      `session_deadline`. If it does, set the new `exp` to
      `session_deadline` instead (final token before forced re-login)
   b. If the capped expiration is not later than `now`, do not refresh.
      Otherwise, generate a new JWT with the same `sub`, `session_id`, and
      `session_deadline`, but new `iat = now` and new `exp`
   c. Set the new JWT in the response `Set-Cookie` header (same cookie
      attributes: `HttpOnly`, `SameSite=Strict`, `Secure`, `Path=/api`)
4. If `token_age < refresh_threshold`: do nothing (normal request flow)

The refresh is completely server-side and transparent to the client. No
client-side logic or dedicated refresh endpoint is required.

**Notes**:

- The refresh threshold is a percentage (50%) of `JWT_EXPIRY_HOURS`, not
  an absolute value. If the expiry is changed, the threshold adjusts
  automatically
- If the `Set-Cookie` header cannot be set for any reason, the old JWT
  remains valid — the user experiences no error and the refresh is
  retried on the next eligible request
- No database write is required for token refresh (the Session record is
  not modified)
- Refresh delivery is identical whether the validated JWT came from the
  session cookie or a Bearer header: the renewed JWT is emitted as the
  `sentinel_session` cookie. A Bearer client that does not retain and send that
  cookie continues presenting its original token and must re-authenticate when
  that token reaches `exp`; programmatic clients that need non-session
  credentials should use API keys
- When multiple requests arrive simultaneously after the refresh
  threshold, each independently issues a new JWT. This is intentionally
  accepted: all resulting tokens reference the same valid session, no
  database write is involved, and the browser naturally adopts the last
  `Set-Cookie` received. No serialization or deduplication mechanism is
  required

## Session Management

Every login (SSO or local) creates a **Session** record. The JWT
references this session via the `session_id` claim. On every
authenticated request, the middleware verifies that the session is still
active. This allows immediate invalidation on logout or user
deactivation, without waiting for JWT expiry.

### Data model: `Session`

| Column             | Type         | Nullable | Description                         |
|--------------------|--------------|----------|-------------------------------------|
| `id`               | UUID         | No       | Primary key                         |
| `user_id`          | UUID (FK)    | No       | References `User.id`                |
| `created_at`       | timestamptz  | No       | When the session was created        |
| `updated_at`       | timestamptz  | No       | Last modification timestamp         |
| `expires_at`       | timestamptz  | No       | Immutable maximum lifetime, calculated at login as `now() + SESSION_MAX_LIFETIME_DAYS * 86400`. Maps to the JWT `session_deadline` claim. |
| `is_active`        | boolean      | No       | `false` after logout or revocation  |

### Session creation

The shared operation is:

```python
create_session(
    db: AsyncSession,
    user: User,
    reason: SessionCreationReason,
) -> CreatedSession | None
```

`SessionCreationReason` has exactly two values: `local_login` and
`sso_login`. `CreatedSession` contains the persisted `Session`, its signed JWT
string, and `token_expires_at`, the UTC datetime represented by the JWT `exp`
claim. This is distinct from `Session.expires_at`, which represents the later
immutable session deadline. The operation uses one UTC `login_at` snapshot for
`User.last_login_at`, the JWT `iat`, and calculation of both
`Session.expires_at` and the JWT `session_deadline`. It behaves as follows:

1. As the first database operation, acquire `FOR NO KEY UPDATE` on the
   target `User` row and reload the locked-current active status. The passed
   `user` identifies the target only; its pre-lock `active` value is never
   authoritative. If no row exists or `active = false`, do not create a
   Session, do not update `last_login_at`, and return `None` without issuing
   a token. Each provider workflow maps that outcome to its own documented
   login failure — `AUTH_INVALID_CREDENTIALS` for local login and
   `AUTH_SSO_USER_INACTIVE` for SSO.
2. Create a distinct active `Session` for the locked `user.id` without
   reading, invalidating, or otherwise changing any existing session.
3. Set `Session.expires_at = login_at + SESSION_MAX_LIFETIME_DAYS` and
   `user.last_login_at = login_at`.
4. Flush both writes, then issue a JWT whose `sub`, `session_id`,
   `session_deadline`, and timing claims match the flushed session and the
   same `login_at` snapshot.
5. Emit `session_created` at INFO with `user_id` and `reason`. The JWT and
   session ID are never logged.
6. Return the created session, token, and token expiration, or `None` per
   step 1.

The caller supplies and owns the transaction. The operation flushes but never
commits or rolls back. It catches no database or token-encoding exception;
any such exception propagates so the caller rolls back both the new session
and `last_login_at`. `None` is an in-process ineligibility outcome, not an
API error: the authentication endpoints own their failure vocabulary and
response codes, so session creation introduces no shared API-facing
exception for this condition.

**Deactivation serialization**: the User lock is the serialization point
between successful login and deactivation. If Session creation commits first,
a later `deactivate_user()` observes and invalidates the new Session; if
deactivation commits first, Session creation observes the committed inactive
state and returns `None` without creating anything. No Session can commit for
an inactive User. Concurrent logins for the same target serialize on the same
lock; each still creates its own independent Session, and `last_login_at`
ends at the last committed login. The lock covers only the short database
phase: password verification, bcrypt/dummy-bcrypt work, Redis lockout
handling, and every external IdP/network operation occur outside it (see the
provider specs and `docs/conventions.md`, Transaction Hygiene Rules).

Re-invocation intentionally creates another independent session and token.
Provider workflows establish every other eligibility condition — credential
validity, local-versus-external provider match, `external_id` presence, and
lockout state — before calling it. Session creation produces no
`IdentityAuditEvent`.

### Session liveness check

The shared read operation is:

```python
is_session_active(db: AsyncSession, session_id: UUID) -> bool
```

It returns `true` only for the positive cache or database outcomes below and
returns `false` for an inactive or absent row. It catches `RedisError` only to
apply the specified PostgreSQL fallback; database exceptions propagate to the
caller. It performs no database writes and never commits or rolls back.

On every authenticated request, the middleware checks:

```
session.is_active = true
```

If the session is inactive, the request is rejected with HTTP 401.
The `session_deadline` claim in the JWT provides the maximum lifetime
check (verified during JWT validation, before the liveness check).

To avoid a database round-trip on every request, the session liveness
result is cached in Redis with a TTL of 60 seconds. The explicit cache
purge after logout, deactivation, and password reset makes invalidation
near-instantaneous. A positive entry can nonetheless survive beyond the
invalidation through either of two interleavings: the post-commit purge is
lost (process crash or `RedisError`), or an in-flight request read an
active row before the invalidation committed and writes its positive value
after the purge completed. The TTL is the safety net in both cases. The
residual exposure differs by cause:

- **Logout and password reset**: the target User may remain active, so a
  positive cache entry that survives the purge keeps the invalidated
  Session passing the liveness check for at most the remaining TTL (60
  seconds maximum). This tradeoff is acceptable for an internal tool.
- **Deactivation while the target remains inactive**: deactivation
  additionally sets `User.active = false`, and Shared Credential Resolution
  loads the `User` record on every authenticated request and rejects an
  inactive user regardless of the session-liveness cache. A stale positive
  entry therefore cannot extend access while the target stays inactive;
  purging it remains important to remove stale positive state promptly, but
  Redis is never the authorization authority. If the account is reactivated
  before a surviving entry's TTL elapses, reactivation restores
  `User.active` and performs no session-cache operation, so a
  deactivation-invalidated Session can pass the cached liveness check for
  at most the entry's remaining TTL (60 seconds maximum).

**Cache value contract**: the Redis key `session_liveness:{session_id}` stores
the string `"1"` to represent an active session. Inactive sessions are never
cached. The lookup semantics are:

- **Cache hit** (key exists with value `"1"`): the session is active — no
  database query is needed. Proceed to user loading.
- **Cache miss** (key does not exist): query the database for the `Session`
  record and check `is_active`:
  - If `is_active = true`: write `"1"` to Redis with key
    `session_liveness:{session_id}` and TTL 60 seconds, then proceed. If this
    positive-cache write raises `RedisError`, still return `true` from the
    authoritative database result and apply the outage-episode warning rule
    below.
  - If `is_active = false`: do NOT write to cache, reject the request
    (HTTP 401).
  - If no `Session` row exists (deleted by `cleanup_sessions`): do NOT
    write to cache, reject the request (HTTP 401).
- **Unexpected value** (the key exists with any value other than `"1"`):
  never authorize from that value. Treat it as a cache miss and apply the
  same database verification and positive-cache rules above. No additional
  cache state or value is defined.

This ensures that only positive (active) state is ever cached, a cache miss
always triggers a database verification, and a revoked session never pollutes
the cache.

**Redis unavailability**: if Redis is unreachable (any `RedisError` —
including connection failures and OOM rejections), the session liveness
check falls back to a direct database query. This is functionally
correct but increases database load (one extra query per authenticated
request). The Redis connection failure is logged as a WARNING on first
occurrence (not per-request, to avoid log flooding). Normal caching
resumes automatically when Redis becomes available again.

The warning suppression state is per server process and shared by session
liveness reads, positive-cache writes, and invalidation purges. The first
`RedisError` in a continuous failure episode emits
`session_redis_unavailable` at WARNING without a user ID, session ID, cache
key, JWT, username, email address, or secret. Further Redis errors are
suppressed until any session-cache Redis operation succeeds; that success
ends the episode and makes a later failure eligible to emit a new warning.
Concurrent first failures in one process still produce at most one warning.

### Session invalidation

Session invalidation is handled by `session_service`
(`backend/app/services/session_service.py`), which provides the database and
Redis operations documented in this section.
Each method separates database mutations (transactional) from Redis
cache cleanup (post-commit, best-effort) per `docs/conventions.md`
(Transaction Hygiene Rules).

Every database method accepts a caller-supplied `AsyncSession`, flushes when
required, and never commits or rolls back. The API transaction dependency or
complete CLI/task workflow owns transaction completion. Redis-only
`purge_session_cache()` has no database transaction.

#### `invalidate_session(db, session_id) -> UUID`

Invalidates a single session (used by the logout endpoint).

**Database phase** (executes within the caller's transaction):

1. Set `Session.is_active = false` and `Session.updated_at = now()` only
   when the row for the given `session_id` is currently active. If no row
   exists (already deleted by `cleanup_sessions`) or the row is already
   inactive, this is a no-op — no exception is raised and `updated_at` is
   unchanged. An actual invalidation emits `session_invalidated` at INFO
   with the row's `user_id` and `reason = "logout"`.
2. Return the `session_id` (for post-commit cache purge)

**Post-commit phase** (best-effort, caller executes after commit via
`purge_session_cache([session_id])`):

3. Delete the Redis cache entry `session_liveness:{session_id}`
4. Apply the `purge_session_cache()` Redis-error contract below.

#### `invalidate_user_sessions(db, user_id, reason) -> list[UUID]`

Invalidates all active sessions for a user (used by deactivation and
password reset).

**Database phase** (executes within the caller's transaction):

1. `UPDATE session SET is_active = false, updated_at = now() WHERE
   user_id = :user_id AND is_active = true` — collect the list of
   invalidated `session_id`s
2. `reason` is required and is either `deactivation` or `password_reset`.
   Emit `sessions_invalidated` at INFO with `user_id`, the number of changed
   rows, and `reason`. An empty result is logged with count zero.
3. Return the list of invalidated `session_id`s (for post-commit cache
   purge)

**Post-commit phase** (best-effort, caller executes after commit via
`purge_session_cache(session_ids)`):

4. For each invalidated session, delete the Redis cache entry
   `session_liveness:{session_id}`
5. Apply the `purge_session_cache()` Redis-error contract below.

**Caller contract**: the caller is responsible for executing the
post-commit phase after its transaction commits. If the post-commit
phase is omitted (e.g., due to process crash between commit and cache
purge), the cache entries self-heal via TTL expiry. The database is
always the authoritative source for session validity — Redis is a
performance optimization.

**Database-phase callers**:

| Caller | Context |
|--------|---------|
| Logout endpoint (`POST /api/v1/auth/logout`) | Calls `invalidate_session()` for the current session |
| `user_service.deactivate_user()` | Calls `invalidate_user_sessions()` as part of deactivation side effects |
| `user_service.reset_password()` | Calls `invalidate_user_sessions()` after updating `password_hash` |

#### `purge_session_cache(session_ids: list[UUID]) -> None`

Executes the post-commit cache purge for previously invalidated
sessions. This is the named helper that callers invoke after their
transaction commits — it encapsulates the Redis key format and error
handling so that callers do not restate them.

1. For each `session_id` in the list, delete
   `session_liveness:{session_id}`
2. If a delete raises `RedisError`, apply the shared outage-episode warning
   rule in Session liveness check and continue attempting every remaining
   `session_id`. After all IDs have been attempted, return normally. Cache
   entries not deleted expire naturally within 60 seconds.

This function has no database dependency; it operates exclusively on
Redis. It is safe to call multiple times with the same input
(idempotent — deleting a non-existent key is a no-op). An empty input performs
no Redis operation.

### Concurrent sessions

Multiple concurrent sessions per user are allowed by design. A new login
(SSO or local) creates a new `Session` record without invalidating
existing ones. This supports legitimate multi-device usage (e.g., desktop
and laptop).

Sessions are only invalidated explicitly by:
- Logout (current session only)
- User deactivation (all sessions)
- Password reset (all sessions)

Orphaned sessions (e.g., from a browser where the user never explicitly
logged out) are cleaned up by the weekly session cleanup task. All
sessions expire unconditionally when their `session_deadline` is reached,
regardless of activity.

### Deactivation ordering

When a user is deactivated (via `user_service.deactivate_user()`), the
database-phase operations execute atomically in this order:

1. Revoke every non-revoked API key, including expired keys, via
   `api_key_service.revoke_all_user_keys(session, user_id,
   acting_user_id=acting_user_id)`. Authenticated API deactivation preserves
   the admin actor; CLI and external-sync workflows pass NULL. See
   `docs/features/identity/api-key-service.md`
2. Invalidate all active sessions via
   `session_service.invalidate_user_sessions()` (DB only — cache purge
   is post-commit; see Session invalidation above)
3. Mark the user as inactive
4. Unassign active tickets in deterministic Ticket UUID order (see
   `docs/features/identity/user-service.md`, Private Helpers, and
   `docs/features/tickets/ticket-audit-log.md`)

After the transaction commits, the post-commit phase purges the session
liveness cache entries (best-effort) and the caller reports the committed
`deactivated = true` result. See
`docs/features/identity/user-service.md` (`deactivate_user()`) for the
full two-phase specification. An already-inactive or concurrent-loser
invocation creates no database mutation, performs no cache purge, and
returns `deactivated = false`.

### Session cleanup

A Celery Beat task (`cleanup_sessions`) runs every **Sunday at 03:00 UTC**
(fixed schedule, not configurable) and deletes session rows matching either
of these conditions:

- `is_active = false` — invalidated sessions. A request in flight that
  encounters a missing row receives HTTP 401 (see Session liveness
  check, cache-miss branch), which is the correct outcome for an
  already-invalidated session.
- `expires_at < now()` — sessions whose immutable deadline has
  passed, regardless of active status. Because the `Session.expires_at`
  column and the JWT `session_deadline` claim originate from the same
  login operation, no clock-skew buffer is needed.

No session history is retained — invalidated and expired sessions are
deleted without trace.

The asynchronous cleanup operation is
`cleanup_sessions(db: AsyncSession, now: datetime) -> int`. It deletes both
predicates relative to the supplied UTC `now` snapshot in one caller-owned
database transaction, flushes, and returns the total number of deleted rows
without committing or rolling back. Database exceptions propagate.
Re-invocation is idempotent:
rows already deleted are absent and no additional state changes. The Celery
workflow logs `session_cleanup_started` at INFO before the transaction and
`session_cleanup_completed` at INFO after commit with `deleted_count`; neither
event contains user or session identifiers. Cleanup creates no
`IdentityAuditEvent`.

The Celery task is registered with the task name `cleanup_sessions`. Its thin
synchronous wrapper calls `asyncio.run()` exactly once to execute one named
async workflow. That workflow opens one async session, calls
`cleanup_sessions(db, now)` with one UTC snapshot, commits once on success,
and rolls back once when an exception escapes; failures propagate to Celery.
Because this task is repeatedly invoked within the same long-lived Celery
worker child, the workflow awaits `engine.dispose()` after the session-scoped
work completes — on both success and failure — before returning control to
`asyncio.run()`, per `docs/conventions.md` (Cross-loop pooled connection
lifecycle). The independently testable database operation never calls
`asyncio.run()`.

This is a maintenance task, not a `BaseFetcher` subclass (it does not
fetch data from external sources). It is registered as a static
`beat_schedule` entry; the Beat registration mechanism is fully
specified in `docs/features/platform/fetcher-infrastructure.md`
("Non-Fetcher Periodic Tasks").

### Session operational logging

Session lifecycle events are logged at **INFO** level for operational
visibility. Log messages follow the PII discipline in
`docs/features/platform/logging.md` — they use `user_id` (UUID) as a
pseudonymous correlation identifier, never usernames or session IDs:

- Session created: structured event with `user_id` and login reason
- Session invalidated (logout): structured event with `user_id` and
  reason
- Sessions invalidated (bulk): structured event with `user_id`, count,
  and reason (deactivation or password reset)

These are **operational diagnostic logs**, not a persistent audit trail.
Session lifecycle events do not produce `IdentityAuditEvent` records —
sessions are excluded from the identity audit trail scope (see
`docs/features/identity/identity-audit-log.md`). The `last_login_at`
field on the `User` table provides the queryable answer to "when did
this user last log in?" without depending on log retention.

### `last_login_at` field

The `User` table includes a `last_login_at` field (timestamptz,
nullable) that is updated to `now()` every time a session is created
(both SSO and local login). This provides a queryable answer to "when
did user X last log in?" without depending on session row retention or
log searches.

`last_login_at` is operational authentication metadata, not a lifecycle audit
field. Session creation and the matching `last_login_at` update use the same
caller-owned database transaction and commit together; failure rolls both
back. Neither write creates an `IdentityAuditEvent`. Any Redis cleanup or cache
population remains outside that transaction.

### Frontend session behavior

This section defines the frontend behavior shared by both login providers
(SSO and local). Provider-specific frontend flows are documented in their
respective specs.

#### Post-login redirect

After a successful login (regardless of provider):

1. The backend sets the session cookie (`sentinel_session`, HttpOnly) —
   the frontend does not handle the token directly
2. The frontend checks `sessionStorage` for `sentinel_return_url`:
   - If present: redirect to that URL and remove the key
   - If absent: redirect to the dashboard
3. Each provider is responsible for saving `sentinel_return_url` to
   `sessionStorage` before initiating the login flow (to preserve the
   user's intended destination across redirects)

#### Session expiration handling

When any API call returns HTTP 401 and the user previously had an active
session (the browser was sending the `sentinel_session` cookie):

1. Redirect to the login page
2. Display an informational message: "Your session has expired. Please
   log in again."

This applies regardless of the expiration cause (token expired, session
deadline reached, session invalidated by admin).

## Authenticated Principal

The authentication layer returns a minimal value object that carries the
resolved user and the kind of credential that authenticated the request.
This allows downstream dependencies — `require_capability()`, the
session-only guard, and future session-scoped checks — to distinguish the
authentication mechanism without re-parsing the request.

### `CredentialKind`

An enumeration with exactly two values:

| Value | Meaning |
|-------|---------|
| `jwt` | Request authenticated via a JWT session token |
| `api_key` | Request authenticated via an API key |

### `AuthenticatedPrincipal`

An immutable value object with exactly two fields:

| Field | Type | Description |
|-------|------|-------------|
| `user` | `User` | The active user record loaded from the database |
| `credential_kind` | `CredentialKind` | How the request was authenticated |

The principal MUST NOT retain any raw credential material: no JWT, cookie
value, API key plaintext, digest, prefix, or API key name. It is the
single return type of `get_current_user` and the input to all
authorization dependencies.

## Authentication Dependencies

`get_current_user` and `get_optional_current_user` share one credential
selection and validation path. They differ only when no credential is
selected; validation behavior and successful-authentication side effects MUST
NOT diverge between them.

### Shared Credential Resolution

Both dependencies receive the incoming FastAPI `Request`, outgoing `Response`,
and request `DatabaseSession`. They apply this credential selection and
validation contract:

1. Check the `Authorization` header:
   - Match the authentication scheme case-insensitively. If it is `Bearer`,
     extract the token value. If the extracted value is empty or
     whitespace-only, treat as header absent and proceed to step 2.
     Otherwise, go to step 3.
   - If the value uses any other scheme or has no parseable scheme, treat it
     as header absent and proceed to step 2.
2. If the `Authorization` header is absent, check for the session cookie
   (`sentinel_session`):
   - If the cookie has a non-empty value: extract its value as the token and go
     to step 3. A whitespace-only value is non-empty and therefore selects an
     invalid credential rather than anonymous access.
   - If the cookie is absent or empty: no credential is selected. The
     dependency-specific behavior below applies.
3. Determine credential type:
   - If the token starts with `stl_ak_`: treat as **API key**
   - Otherwise: treat as **JWT**
4. Validate according to the credential type (see below). Any credential
   validation failure results in HTTP 401 with the standard generic body
   (described below). Optional authentication does not convert a selected but
   rejected credential into anonymous access. Only the success path is
   described in the sub-flows.
5. Load the `User` record by the `user_id` returned from the credential
   sub-flow. If the user does not exist or is inactive (`active = false`),
   return HTTP 401.
6. **JWT only — sliding refresh**: if the credential is a JWT, evaluate
   the sliding refresh (see Token refresh above). The refresh occurs here
   — after the user-active check — so that a refreshed cookie is never
   emitted alongside a 401 for an inactive user. API-key requests skip
   this step entirely.
7. Return an `AuthenticatedPrincipal` with `user` set to the loaded
   `User` record and `credential_kind` set to `CredentialKind.JWT` or
   `CredentialKind.API_KEY` according to the sub-flow that succeeded.

A non-empty Bearer value is final once selected. If it fails validation, the
request returns 401 and MUST NOT fall back to a valid session cookie. A
non-Bearer, unparseable, empty, or whitespace-only Authorization value does not
select a credential and therefore retains the cookie fallback in steps 1-2.

Only the documented credential rejection conditions are mapped to 401.
Database failures and other infrastructure or unexpected exceptions propagate
through normal error handling; neither dependency converts them to anonymous
access or reports them as invalid credentials.

All HTTP 401 responses return a generic body `{"code":
"AUTH_NOT_AUTHENTICATED", "detail": "Authentication required"}` regardless
of the specific failure reason (expired token, invalidated session, session
deadline reached, inactive user). No information about the failure cause is
disclosed. See also `docs/api-spec.md`, "Global Responses".

The dual-source approach supports both programmatic clients (which send
`Authorization: Bearer <token>`) and browser sessions (where the JWT is
stored in an `HttpOnly` cookie attached automatically by the browser).

### `get_current_user`

`get_current_user` applies Shared Credential Resolution to endpoints that
require authentication.

**Return type**: `AuthenticatedPrincipal`.

If no credential is selected at shared step 2, return the standard generic
HTTP 401. Every other outcome is defined by the shared flow.

### `get_optional_current_user`

`get_optional_current_user` applies Shared Credential Resolution to Public
endpoints that explicitly declare `Authentication: Optional` per
`docs/api-spec.md`.

**Return type**: `AuthenticatedPrincipal | None`. The FastAPI type alias is
`OptionalCurrentUser`. No separate anonymous-principal type exists.

If no credential is selected at shared step 2, return `None` without loading a
user, checking a session, refreshing a JWT, looking up an API key, touching
`last_used_at`, or emitting `api_key_validation_failed`. The endpoint proceeds
as an anonymous request.

If a credential is selected, execute shared steps 3-7 without modification:

- a valid JWT returns an `AuthenticatedPrincipal` and performs sliding refresh
  when eligible;
- a valid API key returns an `AuthenticatedPrincipal` and performs the same
  debounced `last_used_at` touch;
- an unknown API key executes the same rate-limited
  `api_key_validation_failed` WARNING path before returning 401;
- malformed, invalid, expired, revoked, or otherwise rejected credentials,
  and credentials whose user is missing or inactive, return the same generic
  401 as mandatory authentication.

The optional dependency creates no audit event. Its successful JWT and API-key
effects retain the audit boundaries specified by their shared sub-flows.

Public endpoints without the `Authentication: Optional` declaration do not
invoke this dependency and ignore request credentials. In particular,
`/health`, `/ready`, local login, SSO authorization and callback, and
authentication-provider discovery remain independent of credential validation;
stale credentials cannot block those probe, bootstrap, or recovery paths.

### JWT validation

1. Apply the complete JWT validation contract above (signature, exact
   algorithm and claims, issuer, claim types, UUIDs, temporal ordering, and
   expiration boundaries).
2. Look up the session by `session_id` claim.
3. Verify the session passes the liveness check: the `Session` row must
   exist **and** have `is_active = true`. A missing row or
   `is_active = false` rejects the request (HTTP 401). Use Redis cache
   when available (see Session liveness check).
4. On success, return the `user_id` from the `sub` claim.

### API key validation

1. Compute `SHA-256(presented_key)` and encode the result as a lowercase
   hex digest.
2. Call `api_key_service.get_key_by_hash()` with the computed digest. If no
   record is found, emit the rate-limited WARNING described below and fail.
   The authentication boundary performs no direct `ApiKey` query. The log
   MUST NOT include the key prefix, key name, presented key, computed hash,
   username, or other credential material.

   **PII exception**: the source IP is included in this log message as a
   documented exception to the PII discipline in
   `docs/features/platform/logging.md`. The IP identifies an attack
   source (not a legitimate authenticated user), the log serves an
   active defense purpose (brute-force detection and response), and
   `request_id` correlation alone is insufficient because the rate
   limiter aggregates hundreds of requests into a single log message.
   The source IP is the ASGI peer address (`request.client.host`) — the
   application does not trust forwarded headers (`X-Forwarded-For`,
   `Forwarded`). Per-real-client-IP rate limiting behind a reverse proxy
   is delegated to the proxy layer (see
   `docs/features/identity/local-authentication.md`, Security
   Considerations). If `request.client` is `None` (e.g., connections
   over a Unix domain socket), the limiter uses the sentinel string
   `"unknown"` as the key and the log field value; all such requests
   share a single rate-limit bucket.

   **Log rate limiting**: the WARNING emission is rate-limited to prevent
   log flooding from brute-force attacks. The HTTP 401 response is
   ALWAYS returned regardless of rate limiting — only the log emission
   is suppressed. Details:

   - **Granularity**: per ASGI peer address. An attacker trying 1000
     different keys from the same peer generates a single WARNING per
     period.
   - **Rate**: at most 1 WARNING every 60 seconds per ASGI peer address
     per server instance.
   - **Aggregated log record**: `event="api_key_validation_failed"`,
     `source_ip=<ASGI peer address>`, and `suppressed_count=<integer>`.
     `suppressed_count` is zero for an unsuppressed first failure and the
     number of additional failures suppressed in the previous 60 seconds
     for the next emitted record. No value derived from the presented
     credential is emitted.
   - **Storage**: per-instance in-memory dictionary (no Redis). Same
     philosophy as the `last_used_at` debounce — no coordination
     between instances is needed.
   - **Eviction**: entries expire after 5 minutes of inactivity (no
     failed attempt from that IP). Maximum 10,000 entries; if the limit
     is reached, the least recently used entry is evicted (LRU). This
     prevents memory growth from IP spoofing or large botnets.
   - **Multi-instance**: with N instances, the worst case is N WARNINGs
     per minute per IP (one per instance) — acceptable for an internal
     tool.
3. Verify `revoked_at` is `NULL`.
4. If `expires_at` is set, reject when `expires_at <= now`.
5. Update `last_used_at` to the current timestamp through
   `api_key_service.update_last_used_at()` (debounced: update at
   most once per minute **per server instance** to reduce write
   pressure). The debounce uses a per-instance in-memory cache of
   `key_id → last_write_timestamp`. If less than 60 seconds have elapsed
   since the last DB write for this key on this instance, the update is
   skipped. With N API server instances, the worst case is N writes per
   minute per key — acceptable for an internal tool. The authentication
   boundary owns a transaction dedicated to this best-effort operational
   write: commit before recording the debounce timestamp; on failure, roll
   back, leave the debounce timestamp unchanged, and continue authentication
   with the otherwise valid credential. This metadata creates no
   `IdentityAuditEvent`; see `docs/features/identity/identity-audit-log.md`.
6. On success, return the `user_id` from the `ApiKey` record.

API keys do **not** use sessions. They are validated through
`api_key_service` against the `ApiKey` table on every request.

## API Key Management Boundary

API key lifecycle, status, retention, REST endpoints, CLI commands, and
consumer use cases are defined in
`docs/features/identity/api-key-management.md`. This specification owns
only use of an API key as an authentication credential.

## Session-Only Authentication Dependency

The `require_session_authentication()` dependency is a thin guard that
enforces JWT-session authentication for endpoints that must not be
accessible via API key credentials — endpoints that mint new
credentials (API key creation — see
`docs/features/identity/api-key-management.md` — and the admin Create
User and Reset User Password endpoints — see
`docs/features/identity/user-management.md`, Admin API endpoints).

**Input**: the `AuthenticatedPrincipal` returned by `get_current_user`.

**Behavior**:

1. If `principal.credential_kind` is `CredentialKind.JWT`: return the
   principal unchanged. The endpoint proceeds normally.
2. If `principal.credential_kind` is `CredentialKind.API_KEY`: return
   HTTP 403 with code `AUTH_SESSION_REQUIRED` and detail
   `"This operation requires session authentication."`.

The dependency does not re-parse the request, duplicate the `stl_ak_`
recognition rule, or perform any additional validation — it relies
entirely on the credential kind already resolved by `get_current_user`.

This dependency is owned by the authentication boundary and is the
single mechanism for session-only enforcement. Endpoint handlers must
not implement their own credential-kind checks. An endpoint that also
requires a capability (e.g., `manage_users`) composes both dependencies
independently — `require_session_authentication()` does not check
capabilities, and `require_capability()` does not check credential
kind.

## API Endpoints

### Get Current User

Returns the currently authenticated user's profile.

```text
GET /api/v1/users/me
```

**`Access: Authenticated`**

**Response** (200):

```json
{
  "data": {
    "id": "uuid",
    "username": "string",
    "email": "string",
    "full_name": "string | null",
    "roles": ["string"],
    "active": true
  }
}
```

`roles` contains the distinct current role values held by the
authenticated user (a role held from multiple origins — manual and one
or more external groups — appears once), rendered in the wire format
defined in `rbac.md` (Role Wire Format) and ordered alphabetically by
that wire value. The route obtains the deduplicated `Role` set from
`user_service.get_user_roles()` (see
`docs/features/identity/user-service.md`) and performs no ORM query
directly; converting to wire format and sorting is response formatting,
not a database operation.

### Logout

Invalidates the current session.

```text
POST /api/v1/auth/logout
```

**`Access: Authenticated`**

Global responses per `api-spec.md` do not apply (custom authentication handling — see below).

**Authentication**: this endpoint does NOT use the standard
`get_current_user` middleware (which would reject requests with an
already-invalidated session). Instead, it uses a lightweight dependency
that only verifies the JWT signature and extracts claims — it does not
check session liveness. This makes the endpoint fully idempotent:
calling it multiple times (e.g., retry or double-click) always succeeds.

The lightweight dependency uses the same credential-source precedence as
`get_current_user`: a non-empty `Authorization: Bearer` value takes precedence
over the `sentinel_session` cookie; an absent or whitespace-only bearer value
falls back to the cookie. It does not fall back to a valid cookie after a
non-empty bearer credential fails. A selected credential beginning with
`stl_ak_` produces the API-key-specific 400 response below.

If the token is not a valid JWT (invalid signature, malformed), return
HTTP 401 with code `AUTH_NOT_AUTHENTICATED` and body
`{"code": "AUTH_NOT_AUTHENTICATED", "detail": "Authentication required"}`.
This endpoint does not use `get_current_user` and therefore handles
authentication failure directly (same response format for client
consistency).

If called with an API key instead of a JWT, return HTTP 400 with
code `AUTH_LOGOUT_NOT_APPLICABLE` and message:
`"Logout is not applicable to API key authentication."`

**Behavior**:

1. Decode the JWT using the normal contract for `HS256`, signature, exact
   claim set, issuer, claim types, temporal ordering, and UUID parsing. The
   restricted logout path intentionally does not compare either `exp` or
   `session_deadline` with `now`; a correctly signed token remains usable for
   logout after either boundary. It still requires
   `iat <= exp <= session_deadline`. This allows users to explicitly log out
   even after their token has expired (e.g., returning to a stale tab after
   73+ hours). The security impact is negligible:
   the token is bound to a specific `session_id`, so an attacker with a
   stolen expired token can only invalidate that one session (a single
   forced re-login)
2. Extract `session_id` from the JWT claims
3. Call `session_service.invalidate_session(db, session_id)` — this is
   idempotent: if the session is already inactive, no change is made
4. After the transaction commits, execute the post-commit phase:
   `session_service.purge_session_cache([session_id])` (best-effort
   cache purge — see Session invalidation above)
5. Set a `Set-Cookie` header that clears the `sentinel_session` cookie:
   `Set-Cookie: sentinel_session=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
6. Return HTTP 204

## Security Considerations

- **JWT_SECRET_KEY** must be a cryptographically random string of at
  least 32 characters. It must never be committed to the repository or
  logged.
- **API key hashing uses plain SHA-256**, not a slow hash like bcrypt
  and not a keyed HMAC. API keys have ~190 bits of entropy (32
  alphanumeric characters generated server-side by a CSPRNG) and are
  not vulnerable to offline brute-force — the search space is
  computationally infeasible regardless of hash speed. A plain hash
  avoids the operational burden of a server-side secret: there is no
  key to rotate and no risk of permanently invalidating all API keys
  through a configuration change. Using a slow hash for high-entropy
  tokens would create unnecessary CPU pressure — at 100
  requests/second with bcrypt (cost 12, ~300ms/op), the server would
  need 30 CPU-seconds per second solely for key validation, creating a
  denial-of-service vector.
- **API key lifecycle security** (secret visibility, expiration, and
  revocation) is defined in `api-key-management.md`.
- **Session liveness check**: logout and password reset take effect through
  the liveness check within the cache TTL window (60 seconds maximum when
  the post-commit purge is lost or an in-flight positive-cache write
  survives it). Deactivation additionally sets `User.active = false`, which
  is checked on every authenticated request, so deactivation does not depend
  on the cache purge for enforcement while the account remains inactive; a
  reactivation inside a surviving entry's TTL can leave an invalidated
  Session accepted for at most the entry's remaining TTL.
- **No single logout (SLO)**: logging out of `id.suse.com` does not
  invalidate the Sentinel session. This is a known limitation,
  acceptable for an internal tool. Users can log out of Sentinel
  explicitly.
- **Token in browser storage**: the JWT is stored in an `HttpOnly`
  cookie named `sentinel_session` with `SameSite=Strict`, `Secure`
  (HTTPS only), and `Path=/api`. This makes the token immune to XSS
  attacks (JavaScript cannot access HttpOnly cookies). The frontend
  does not handle the token directly — the browser attaches it
  automatically to every request to the same origin. `SameSite=Strict`
  prevents the cookie from being sent on cross-origin requests,
  eliminating the need for a separate CSRF token mechanism.
- **No concurrent session limit**: there is no enforced maximum number
  of active sessions per user. Users may have sessions on multiple
  devices simultaneously. This is a deliberate choice for an internal
  tool — a limit would create friction without meaningful security gain.
  If a user's sessions need to be terminated, an admin can deactivate
  the user (which invalidates all sessions).
- **Key rotation**: rotating `JWT_SECRET_KEY` immediately invalidates
  all existing JWTs (the signature verification will fail). This
  effectively triggers a mass logout — all users must re-authenticate.
  Additionally, any in-flight SSO flows (state parameter signed with the
  old key) will fail at callback — max 10 minutes of disruption (see
  `docs/features/identity/sso-authentication.md`, Operational note).
  Operators should plan key rotation during low-traffic windows and
  communicate the expected impact. There is no graceful dual-key
  transition mechanism; this simplicity is acceptable for an internal
  tool where mass re-login is a minor inconvenience.
- **API key last_used_at debouncing**: updating `last_used_at` on every
  request would create write amplification. Updates are debounced to at
  most once per minute per key.
- **No client fingerprint binding on session cookies**: the session cookie
  is not bound to any client fingerprint (IP address, User-Agent, or TLS
  channel binding). A stolen cookie can be replayed from any network
  location without server-side detection. This is an **accepted risk** for
  the following reasons:
  - Binding to IP would break usability for users on VPNs, roaming
    networks, or dynamic IPs — common in an internal enterprise
    environment where employees switch between office, home, and travel
    networks
  - Binding to User-Agent provides negligible security (trivially spoofed)
  - TLS channel binding (RFC 5929) is not widely supported by browsers
  - The tool operates on a trusted internal network, reducing the attack
    surface for cookie theft
  - Existing compensating controls: `Secure` flag (HTTPS only), `HttpOnly`
    (no XSS access), `SameSite=Strict` (no cross-origin leakage),
    maximum session lifetime (`SESSION_MAX_LIFETIME_DAYS`), admin
    deactivation (invalidates all sessions immediately)
  - Detection of session theft is not a goal for this tool; prevention
    via the cookie flags above is the primary defense
- **OIDC state parameter not single-use (accepted risk)**: the OIDC
  `state` parameter is HMAC-signed with a timestamp for CSRF protection,
  but it is not stored server-side or tracked as consumed. Replay
  protection relies on the IdP's single-use authorization code. If the
  IdP has a code-replay vulnerability, Sentinel has no independent
  defense. This is accepted given enterprise IdP reliability (id.suse.com
  / Azure AD) and the operational cost of maintaining a consumed-states
  cache for a low-probability attack vector.

## Cross-references

- `docs/api-spec.md` — API conventions, global responses, scoped responses
- `docs/features/identity/api-key-management.md` — API key lifecycle,
  endpoints, CLI commands, status, and retention
- `docs/features/identity/api-key-service.md` — centralized API key
  persistence service, including the `last_used_at` operational touch
- `docs/features/identity/local-authentication.md` — local login endpoint and
  password management
- `docs/features/identity/sso-authentication.md` — SSO login flow with
  id.suse.com
- `docs/features/identity/user-service.md` — deactivation side effects
  (API key revocation, session invalidation)
- `docs/features/identity/user-management.md` — creating local user
  accounts (including for AI agents)
- `docs/features/identity/rbac.md` — role-based access control and permission
  model
