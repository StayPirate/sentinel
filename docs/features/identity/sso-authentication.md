# SSO Authentication

**Parent spec**: `docs/features/identity/authentication.md`
**Sibling specs**: `docs/features/identity/local-authentication.md`
**Inherited concerns**: token storage (HttpOnly cookie), session
lifecycle, logout, error code namespace (`AUTH_*`)

---

## Purpose

Provide single sign-on authentication for Sentinel using the SUSE
corporate identity provider (`id.suse.com`) via the OpenID Connect
(OIDC) protocol. This is the primary authentication method for SUSE
employees whose accounts are managed by the external identity provider and
provisioned in Sentinel by an external identity provider (see `docs/features/identity/identity-provisioning.md`).

SSO authentication is available only to users with `external_id IS NOT NULL`
(externally-provisioned users). Local users (`external_id = NULL`) authenticate via
the local login endpoint — see `docs/features/identity/local-authentication.md`.

## Configuration

| Setting             | Type   | Default | Env var               |
|---------------------|--------|---------|-----------------------|
| `sso_issuer_url`    | string | —       | `SSO_ISSUER_URL`      |
| `sso_client_id`     | string | —       | `SSO_CLIENT_ID`       |
| `sso_client_secret` | string | —       | `SSO_CLIENT_SECRET`   |
| `sso_redirect_uri`  | string | —       | `SSO_REDIRECT_URI`    |
| `sso_user_claim`    | string | `sub`   | `SSO_USER_CLAIM`      |

All settings except `sso_user_claim` are required for SSO to function.
If any required setting is empty or unset, **SSO is disabled entirely**:

- SSO authentication is unavailable to the user
- The SSO endpoints (`/api/v1/auth/sso/authorize`,
  `/api/v1/auth/sso/callback`) return HTTP 404
- At startup, the application logs: `"SSO authentication disabled —
  missing settings: {list of missing setting names}"` (secret values
  are never logged; only setting names appear)

When all required settings are present, the application logs at startup:
`"SSO authentication enabled (issuer: {SSO_ISSUER_URL})"`

This allows the same application build to be deployed in both
SSO-capable and SSO-less environments without any code changes.

`SSO_USER_CLAIM` specifies which claim from the OIDC ID token is used
to identify the user (matched against the `username` field in the User
table, with a guard that the user must be externally-provisioned). Defaults to `sub`.

`SSO_REDIRECT_URI` is the full URL (scheme + host + path) where the IdP
redirects the browser after authentication. It MUST point to the
canonical frontend callback route `/auth/callback` (e.g.,
`https://sentinel.suse.de/auth/callback`). This value MUST be registered
in the IdP's client configuration — the IdP rejects requests with a
`redirect_uri` that does not match any registered URI. Multiple URIs can
be registered in the IdP for the same client (one per environment), and
each Sentinel instance sets `SSO_REDIRECT_URI` to the value matching its
environment:

- Production: `https://sentinel.suse.de/auth/callback`
- Staging: `https://sentinel-staging.suse.de/auth/callback`
- Local dev: `http://localhost:5173/auth/callback`

At startup, Sentinel validates that `SSO_REDIRECT_URI` is a well-formed
URL with HTTPS scheme (the HTTP scheme is allowed only when the host is
`localhost` or `127.0.0.1`, for local development). If validation fails,
the application logs a WARNING and disables SSO (same behavior as a
missing required setting).

### Operational note: `JWT_SECRET_KEY` rotation

The SSO state parameter is signed with `JWT_SECRET_KEY`. Rotating this
key immediately invalidates all in-flight SSO flows (users who have been
redirected to the IdP but have not yet completed the callback). Affected
users see "Invalid or expired SSO state" and must restart the login.
Maximum disruption window: 10 minutes (the state TTL). Recommendation:
rotate the key during low-traffic periods.

### Discovery

Sentinel uses OIDC Discovery to resolve the authorization endpoint,
token endpoint, and JWKS URI automatically from:

```
{SSO_ISSUER_URL}/.well-known/openid-configuration
```

This avoids hardcoding endpoint URLs and allows seamless migration if
the IdP changes its URL structure.

#### Discovery document caching

The discovery document is cached **in-memory** (not in Redis — it is
small, public, and each application instance fetches its own copy).

| Behavior | Detail |
|----------|--------|
| First fetch | At application startup (SSO service initialization) |
| Refresh | Lazy with 1-hour TTL: the first request after the TTL expires triggers a synchronous re-fetch (HTTP timeout: 5 seconds; typically <100ms to the IdP). Subsequent requests within the TTL use the cache. Each API server process maintains an independent cache. |
| Refresh fails | Use cached version. Log WARNING with the failure reason. |
| No cache available (startup + IdP unreachable) | The application starts successfully, but `/authorize` returns HTTP 503: `"SSO service temporarily unavailable. Please try again later."` |
| Validation | The document MUST contain `authorization_endpoint`, `token_endpoint`, and `jwks_uri`. If any required field is missing, treat as a failed fetch. |

The application does NOT fail to start if the discovery document is
unreachable. SSO is degraded (503) until the next successful refresh.

### JWKS (JSON Web Key Set) caching

The IdP's public keys (used to verify ID token signatures) are cached
**in-memory** with the same graceful degradation pattern as discovery.

| Behavior | Detail |
|----------|--------|
| First fetch | Lazy — on the first ID token verification attempt, using the `jwks_uri` from the discovery document |
| Refresh | Lazy with 1-hour TTL: the first token verification after the TTL expires triggers a synchronous re-fetch (HTTP timeout: 5 seconds). Each API server process maintains an independent cache. |
| Unknown `kid` | If an ID token contains a `kid` not present in the cached JWKS, force-refresh the JWKS once (HTTP timeout: 5 seconds). If the `kid` is still absent after refresh, reject the token with HTTP 401. |
| Refresh fails | Use cached version. Log WARNING with the failure reason. |
| No cache available (first token + JWKS unreachable) | Reject the token with HTTP 401. Log ERROR. |

The unknown-`kid`-triggers-refresh mechanism handles key rotation by the
IdP without requiring a restart or manual intervention.

## OIDC Flow: Authorization Code

Sentinel uses the Authorization Code flow (not Implicit) as recommended
by OAuth 2.1 and OIDC best practices. PKCE (Proof Key for Code Exchange)
is always used, regardless of whether the IdP advertises support via
`code_challenge_methods_supported` in its discovery document. This
follows OAuth 2.1 which mandates PKCE for all authorization code grants.
If the IdP does not support PKCE, it ignores the `code_challenge`
parameter in the authorization request — the flow still succeeds, but
without the additional code interception protection.

### Step 1: Login initiation

When the user clicks "Login with SUSE SSO" on the login page, the
frontend calls:

#### SSO Authorize

**`Access: Public`**

**Behavior**:

1. Generate a cryptographically random `nonce` (16 bytes)
2. Capture the current Unix timestamp as a 4-byte big-endian integer
3. Construct the state payload: `payload = timestamp_4bytes || nonce_16bytes`
4. Generate `code_verifier` (43-128 chars, URL-safe random) and compute
   `code_challenge = BASE64URL(SHA256(code_verifier))`. Append the
   `code_verifier` (UTF-8 bytes) to the payload before signing:
   `payload = timestamp_4bytes || nonce_16bytes || code_verifier_bytes`
5. Compute the signature:
   `signature = HMAC-SHA256(JWT_SECRET_KEY, payload)`
6. Encode the state parameter:
   `state = base64url(payload) || "." || base64url(signature)`
7. Construct the authorization URL:
   ```
   {authorization_endpoint}?
     response_type=code&
     client_id={SSO_CLIENT_ID}&
     redirect_uri={SSO_REDIRECT_URI}&
     scope=openid profile email&
     state={state}&
     code_challenge={code_challenge}&
     code_challenge_method=S256
   ```
8. Return the URL to the frontend

No server-side storage (Redis or database) is required. The state is
self-contained and its authenticity is verified by the HMAC signature.
In a multi-instance deployment, all instances must have synchronized
clocks (NTP) for the 10-minute TTL window to be enforced correctly —
see `docs/deployment.md`, Clock Synchronization.

**Response** (200):

```json
{
  "data": {
    "authorization_url": "https://id.suse.com/authorize?..."
  }
}
```

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `AUTH_SSO_DISABLED` | SSO is not configured (all SSO endpoints return this when SSO settings are empty or unset) |
| 503 | `SSO_UNAVAILABLE` | OIDC discovery document unreachable and no cached version available |

The frontend then redirects the browser to this URL.

### Step 2: IdP authentication

The user authenticates at `id.suse.com` (credentials managed by the
identity provider). On success, the IdP redirects the browser back to Sentinel's
callback URL with an authorization `code` and `state` parameter.

### Step 3: Callback processing

#### SSO Callback

**`Access: Public`**

**Request body**:

```json
{
  "code": "string (required)",
  "state": "string (required)"
}
```

**Behavior**:

1. Validate the `state` parameter:
   a. Split on `"."` into `encoded_payload` and `encoded_signature`
   b. Decode both from base64url
   c. Recompute `expected = HMAC-SHA256(JWT_SECRET_KEY, payload)` and
      verify it equals the received signature (constant-time comparison).
      If invalid, return HTTP 400:
      `"Invalid or expired SSO state. Please try again."`
   d. Extract the timestamp (first 4 bytes of the payload, big-endian
      uint32). If `now - timestamp > 600 seconds` (10 minutes), return
      HTTP 400 with the same message
   e. Extract `code_verifier` from bytes 20 onward of the payload
      (bytes 0-3 = timestamp, bytes 4-19 = nonce, remainder =
      code_verifier UTF-8).
2. Exchange the `code` for tokens at the IdP's token endpoint (HTTP
   timeout: 10 seconds):
   ```
   POST {token_endpoint}
   grant_type=authorization_code&
   code={code}&
   redirect_uri={SSO_REDIRECT_URI}&
   client_id={SSO_CLIENT_ID}&
   client_secret={SSO_CLIENT_SECRET}&
   code_verifier={code_verifier}
   ```
3. If the token exchange fails (non-2xx HTTP response, network error,
   or 2xx response whose body does not contain an `id_token` field),
   return HTTP 401 with code `AUTH_SSO_FAILED`:
   `"SSO authentication failed. Please try again."`
   Log at WARNING level: `"SSO token exchange failed: {reason}"` where
   reason is `"HTTP {status}"` for non-2xx, `"no id_token in response"`
   for missing field, or `"network error: {detail}"` for connectivity
   failures.
4. Validate the ID token:
   - Verify signature against the IdP's JWKS (using the cached key set;
     if the token's `kid` is not in the cache, force-refresh once — see
     JWKS caching above)
   - Verify `iss` matches `SSO_ISSUER_URL`
   - Verify `aud` contains `SSO_CLIENT_ID`
   - Verify `exp` has not passed
   - Verify `iat` (issued-at) is not more than 10 minutes in the past
     (consistent with the state TTL). Reject tokens issued before this
     threshold with HTTP 401 and code `AUTH_SSO_FAILED`
   - Clock skew tolerance: allow up to 30 seconds of difference for all
     time-based claims (`exp`, `iat`) to accommodate minor clock
     drift between Sentinel and the IdP
5. Extract the user identifier from the ID token: read the claim
   specified by `SSO_USER_CLAIM` (default: `sub`). If the claim is
   absent from the ID token, or its value is `null` or an empty string,
   return HTTP 401 with code `AUTH_SSO_FAILED`:
   `"SSO authentication failed. Please try again."`
   Log at WARNING level: `"SSO callback: expected claim
   '{claim_name}' not found in ID token from {issuer}. Available
   claims: {list_of_claim_names}."` (claim values are never logged —
   only names, to aid debugging without leaking PII)
6. Look up the user by matching `username` to the extracted claim value
   (lowercased — see Matching rules). Additionally verify that
   `external_id IS NOT NULL` (i.e., the matched user is an
   externally-provisioned user, not a local user)
7. If user not found, return HTTP 401 with code `AUTH_SSO_USER_NOT_FOUND`:
   `"No Sentinel account found for this identity. Contact your
   administrator."`
8. If user is inactive (`active = false`), return HTTP 401 with code
   `AUTH_SSO_USER_INACTIVE`:
   `"Your account has been deactivated. Contact your administrator."`
9. In one caller-owned database transaction, call
   `session_service.create_session(db, user, reason=sso_login)`. The service
   acquires the User root lock and revalidates the locked-current active
   status before creating anything (see
   `docs/features/identity/authentication.md`, Session creation). If the
   locked-current target is inactive — a deactivation that committed after
   step 8 — the service returns no Session and the endpoint returns the same
   HTTP 401 `AUTH_SSO_USER_INACTIVE` response as step 8. Otherwise commit the
   new session and `user.last_login_at` once or roll both back on failure
10. Return the JWT and its `token_expires_at` from the service result as
    `access_token` and `expires_at`

Steps 1-8 (state validation, token exchange, ID token verification, and user
resolution) execute before and outside the locked database phase; every
network operation toward the IdP occurs outside the User lock.

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
| 400 | `AUTH_SSO_STATE_INVALID` | Invalid or expired SSO state parameter |
| 401 | `AUTH_SSO_FAILED` | Token exchange failed or ID token validation failed (transient/infrastructure) |
| 401 | `AUTH_SSO_USER_NOT_FOUND` | User authenticated by IdP does not exist in the Sentinel User table |
| 401 | `AUTH_SSO_USER_INACTIVE` | User exists but has been deactivated, including a deactivation that commits between the step-8 pre-check and Session creation |
| 404 | `AUTH_SSO_DISABLED` | SSO is not configured (all SSO endpoints return this when SSO settings are empty or unset) |
| 503 | `SSO_UNAVAILABLE` | SSO service temporarily unavailable (IdP discovery unreachable) |

Error response format:

```json
{
  "code": "AUTH_SSO_FAILED",
  "detail": "error message"
}
```

Unlike the local login endpoint, SSO error messages can be specific
(not generic) because:
- The username is not provided by the user (it comes from the IdP)
- There is no brute-force vector (the IdP handles credential
  verification)

### Frontend flow

0. **Session guard**: if the user already has a valid session (JWT
   cookie present and not expired), navigating to the login page
   redirects automatically to the dashboard — the login form is not
   rendered. If the user bypasses this frontend guard (e.g., direct API
   call) and completes a full SSO flow while already authenticated, a
   new session is created without invalidating existing ones — see
   `docs/features/identity/authentication.md`, Concurrent Sessions.
1. User clicks "Login with SUSE SSO"
2. Frontend saves the current URL to `sessionStorage` (key:
   `sentinel_return_url`) to preserve the user's intended destination
   across the SSO redirect
3. Frontend calls `GET /api/v1/auth/sso/authorize`
   - On HTTP 404 (`AUTH_SSO_DISABLED`): SSO is not available. This
     should not normally happen since availability is checked via
     `/auth/providers`, but handles race conditions (e.g., SSO disabled
     between page load and click)
   - On HTTP 503 (`SSO_UNAVAILABLE`): display an inline error
     message on the login page: "SSO is temporarily unavailable, please
     try later." Do not redirect the browser away
   - On success: proceed to step 4
4. Frontend redirects browser to the returned `authorization_url`
5. User authenticates at id.suse.com
6. Browser is redirected back to Sentinel at the canonical callback
   route: `/auth/callback`
7. Frontend checks URL parameters for `error`:
   - If `error` parameter is present (IdP denied consent or encountered
     an error): display an appropriate error message on the login page
     using `error_description` if available (e.g., "Authentication was
     denied or failed at the identity provider: {error_description}").
     Do NOT call the backend callback endpoint
   - If `error` parameter is absent: proceed to step 8
8. Frontend extracts `code` and `state` from URL parameters
9. Frontend calls `POST /api/v1/auth/sso/callback` with code and state
10. On success: the backend sets the session cookie (`sentinel_session`,
    HttpOnly — see `docs/features/identity/authentication.md`, Token
    Storage). The frontend then applies the post-login redirect logic
    (see `docs/features/identity/authentication.md` § Frontend session
    behavior)
11. On error: display error message on login page

## Identity Mapping

The claim specified by `SSO_USER_CLAIM` (default: `sub`) from the IdP's
ID token is matched against the `username` field in the `User` table,
with the additional guard that the matched user must have
`external_id IS NOT NULL` (i.e., be an externally-provisioned user).

With the default configuration (`sub`), this works because:

- The external sync process imports users and stores their provider username as `username`
- `id.suse.com` uses the same identity source, so its `sub`
  claim corresponds to the provider username

If the IdP changes its `sub` format (e.g., from bare username to
a UUID or email-decorated form), the operator can update `SSO_USER_CLAIM`
to point to a different claim (e.g., `preferred_username`) without code
changes.

### Matching rules

1. The matching is **case-insensitive**: the claim value is normalized
   to lowercase before comparison with `username`. This ensures
   consistency with the external sync process, which stores
   usernames normalized to lowercase (as required by the CLI
   conventions). Since provider usernames may be case-insensitive,
   this normalization prevents silent login failures
   if the IdP returns a differently-cased value (e.g., `JDoe` vs
   `jdoe`).
2. Log the match outcome (matched/unmatched) at DEBUG level on every SSO
   login attempt, with `request_id` for correlation. The claim value
   itself is never logged — it is a username and therefore personal
   data per `docs/features/platform/logging.md`.
3. Log a WARNING when the claim value does not match any `username`
   (for external users). The log message includes the `request_id` for
   correlation but omits the unmatched claim value (it is a username
   and therefore personal data per `docs/features/platform/logging.md`)

### No auto-provisioning

If the `sub` claim does not match any `username` (with
`external_id IS NOT NULL`) in the database, the login **fails**.
Sentinel does not auto-create user records during SSO login. The user
must already exist in the database (created by the external sync process).

This is a deliberate design choice:

- It prevents orphan accounts from users who are not in Sentinel's
  external groups
- It ensures that role mappings (based on external group membership) are
  applied before the user can access the system
- It keeps the external provisioning as the single source of truth for external user
  accounts

## Logout

### Sentinel logout

The standard logout endpoint (`POST /api/v1/auth/logout`) invalidates
the Sentinel session. This is the same endpoint used by local users (see
`docs/features/identity/authentication.md`).

### No Single Logout (SLO)

Logging out of Sentinel does **not** log the user out of `id.suse.com`,
and logging out of `id.suse.com` does **not** invalidate the Sentinel
session.

This is a deliberate design decision:

- SLO (Single Logout) adds significant complexity (backchannel logout
  endpoints, session tracking at the IdP)
- For an internal tool, the risk is minimal: if a user's session is
  compromised, an admin can deactivate the user, which immediately
  invalidates all sessions
- The Sentinel JWT is refreshed transparently via sliding session for
  active users. Inactive sessions expire after the configured duration
  (default 72 hours). All sessions expire unconditionally after `SESSION_MAX_LIFETIME_DAYS` (default 30 days)
  (see `docs/features/identity/authentication.md`, Token lifecycle).

## Authentication Providers Endpoint

#### List Auth Providers

**`Access: Public`**

**Purpose**: allows the frontend to discover which authentication methods
are available before rendering the login page.

**Response** (HTTP 200):

```json
{
  "data": {
    "local": true,
    "sso": true
  }
}
```

- `local` is always `true` (local authentication cannot be disabled)
- `sso` is `true` when all required SSO settings are configured, `false`
  otherwise

The frontend calls this endpoint once when loading the login page and
uses the response to decide whether to render the SSO button.

No application-level error responses. This endpoint reads internal
configuration only and has no failure modes beyond standard server
errors (500).

## Security Considerations

- **Local lockout does not apply to SSO**: the login lockout mechanism
  defined in `local-authentication.md` (Redis counter after failed
  password attempts) applies only to the local login endpoint. SSO login
  bypasses this counter because credentials are verified by the IdP, not
  by Sentinel — brute-force protection is the IdP's responsibility. The
  only access control that applies to external users is the `is_active` flag
  (deactivated users cannot log in via any method).
- **Authorization Code flow**: the client secret is never exposed to
  the browser. Token exchange happens server-side.
- **PKCE**: provides additional protection against authorization code
  interception, even for confidential clients.
- **State parameter (HMAC-based, stateless)**: prevents CSRF attacks on
  the callback endpoint. The state is signed with `JWT_SECRET_KEY` and
  contains a timestamp for TTL enforcement (10 minutes). No server-side
  storage is needed — the HMAC signature guarantees authenticity and the
  timestamp prevents stale states. The state is **not single-use** —
  replay protection relies entirely on the IdP's single-use authorization
  code: a replayed state with an already-consumed code will fail at the
  token exchange step. **Accepted risk**: if the IdP has a code-replay
  vulnerability (i.e., allows the same authorization code to be exchanged
  more than once), Sentinel's state parameter offers no additional
  protection. This is acceptable for an internal tool using enterprise
  IdPs (Keycloak, Azure AD) with well-tested OAuth implementations.
  Making the state single-use would require server-side storage
  (reintroducing the Redis dependency eliminated by design).
- **No Redis dependency for SSO login**: the SSO flow is fully stateless
  and operates correctly even if Redis is unavailable. Redis is only
  used for session caching (post-login), not for the login process
  itself.
- **OIDC `nonce` is intentionally omitted**: the `nonce` parameter
  prevents replay of the ID token. In Sentinel's flow, this risk is
  already mitigated by two mechanisms: (1) the authorization `code` is
  single-use at the IdP — replaying it fails at the token exchange step,
  and (2) the HMAC-signed `state` parameter binds the flow to a
  specific browser session. Adding a `nonce` would require either
  server-side storage (reintroducing Redis dependency) or embedding it
  in the signed state (increasing payload size). The residual risk
  without `nonce` is negligible for an internal tool.
- **ID token signature verification**: prevents token forgery. JWKS are
  cached in-memory with 1-hour refresh and unknown-`kid` force-refresh
  (see JWKS caching section above).
- **SSO_CLIENT_SECRET**: must be stored securely (environment variable,
  never in code or logs).
- **SSO_USER_CLAIM**: must point to a claim that is stable and unique
  per user. Avoid mutable claims like `email` (which users can change).
  Recommended values: `sub` (default, guaranteed stable by OIDC spec)
  or `preferred_username`.
- **No auto-provisioning**: limits the blast radius of an IdP
  compromise — only pre-existing users in Sentinel's database can
  obtain access.
- **Specific error messages**: SSO errors can be descriptive (unlike
  local login) because the identity comes from the IdP, not from user
  input.

## Cross-references

- `docs/features/identity/authentication.md` — shared authentication framework
  (JWT format, session model, credential validation, middleware)
- `docs/features/identity/api-key-management.md` — API key lifecycle and
  management surfaces
- `docs/features/identity/local-authentication.md` — local login (alternative
  provider)
- `docs/features/identity/identity-provisioning.md` — External provisioning
  (deferred) for SSO user accounts
- `docs/features/identity/user-service.md` — deactivation side effects
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
