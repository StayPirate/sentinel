# Review: authentication

**Spec**: `docs/features/identity/authentication.md`
**Last reviewed**: 2026-05-18
**Reviewers**: Gap Analysis, Coherence, Design, Security, API Conventions


---

## Gap Analysis

### AUTH-GAP-12 — API key creation during deactivation race (Medium)

**Status**: RESOLVED — Accepted risk — the race window is negligible in practice for an internal tool with low concurrent admin operations. (2026-05-07)

### AUTH-GAP-07 — JWT_SECRET_KEY minimum length not enforced at startup (Medium)

**Status**: RESOLVED — Added startup validation in "Configuration bounds" section — the application refuses to start if `JWT_SECRET_KEY` is shorter than 32 characters, with explicit error message. (2026-05-05)

### AUTH-GAP-08 — API key creation via API key authentication not restricted (Medium)

**Status**: RESOLVED — `POST /api/v1/api-keys` now requires JWT session authentication. API-key-authenticated requests receive HTTP 403, preventing a compromised key from self-replicating. (2026-05-05)

### AUTH-GAP-09 — User reactivation does not address revoked API keys (Medium)

**Status**: RESOLVED — Added explicit statement in the "Automatic revocation" section that revocation during deactivation is permanent — keys cannot be restored on reactivation because only the hash is stored. Users must create new keys. (2026-05-05)

### AUTH-GAP-10 — Session cookie not cleared on logout response (Medium)

**Status**: RESOLVED — Added step 4 to the logout endpoint behavior that sets a `Set-Cookie` header clearing the `sentinel_session` cookie (`Max-Age=0`). (2026-05-05)

### AUTH-GAP-01 — Concurrent API key creation race condition (Medium)

**Status**: RESOLVED — The per-user key count limit has been removed from the specification. Without a limit, the race condition is moot. A WARNING log is emitted when a user exceeds 20 active keys as an anomaly indicator. (2026-05-05)

### AUTH-GAP-02 — Expired token presented to logout endpoint leaves session active (Medium)

**Status**: RESOLVED — The logout endpoint now uses a lightweight JWT-signature-only dependency instead of the standard `get_current_user` middleware. It does not check session liveness or token expiration, making the operation fully idempotent. (2026-05-05)

### AUTH-GAP-13 — Session cleanup threshold hardcoded instead of referencing configured value (Low)

**Status**: RESOLVED — Changed session cleanup threshold from hardcoded `30 days` to `SESSION_MAX_LIFETIME_DAYS + 1 day` in `docs/features/identity/authentication.md`. (2026-05-07)

**Superseded**: Sessions now persist an immutable `Session.expires_at` set at
login, and cleanup uses `expires_at < now()` without a one-day buffer. Current
configuration changes affect only subsequently created sessions. (2026-08-09)

### AUTH-GAP-14 — Existing sessions not invalidated when SESSION_MAX_LIFETIME_DAYS is reduced (Low)

**Status**: RESOLVED — Added step 4 in JWT validation (`docs/features/identity/authentication.md`) that verifies `iat + current SESSION_MAX_LIFETIME_DAYS * 86400 >= now`, ensuring config reductions take immediate effect on existing tokens. (2026-05-07)

**Superseded**: JWT validation now uses the signed immutable
`session_deadline`; it never recalculates an existing deadline from the
current setting. (2026-08-09)

### AUTH-GAP-15 — Empty Bearer token value handling unspecified (Low)

**Status**: RESOLVED — Added explicit handling in credential resolution step 1 (`docs/features/identity/authentication.md`): empty or whitespace-only token value after extraction is treated as header absent, proceeding to cookie check. (2026-05-07)

### AUTH-GAP-16 — Admin revoking their own API key used for the current request (Low)

**Status**: RESOLVED — Added explicit note in `POST /api/v1/admin/api-keys/{key_id}/revoke` section (`docs/features/identity/authentication.md`): self-revocation of the authenticating key is allowed; authentication validation occurs before handler execution. (2026-05-07)

### AUTH-GAP-17 — Multiple status filter values on admin endpoint (Low)

**Status**: RESOLVED — Clarified in `docs/features/identity/authentication.md` that `status` parameter accepts a single value only ("single value only" added to parameter description). (2026-05-07)

### AUTH-GAP-18 — JWT refresh not explicitly denied when session_deadline already passed (Low)

**Status**: RESOLVED — Added explicit step 2 guard in token refresh logic (`docs/features/identity/authentication.md`): if `session_deadline < now`, do not refresh — prevents issuing tokens with `exp` in the past. (2026-05-07)

### AUTH-GAP-11 — Logout endpoint contradicts on expired token handling (Low)

**Status**: RESOLVED — Clarified in `docs/features/identity/authentication.md` that the logout endpoint does NOT check `exp` — expired tokens with valid signatures are accepted. Added rationale explaining the user scenario and security impact analysis. (2026-05-06)

### AUTH-GAP-03 — API key name uniqueness not specified (Low)

**Status**: RESOLVED — Duplicate names per user are not allowed among non-revoked keys. A partial unique index `UNIQUE(user_id, name) WHERE revoked_at IS NULL` enforces the constraint. `POST /api/v1/api-keys` returns HTTP 409 if conflict exists. (2026-05-05)

### AUTH-GAP-04 — `expires_at` evaluation method for active key count not explicit (Low)

**Status**: RESOLVED — No per-user key count limit exists (removed from spec). Evaluation is at query time: `WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. No background task marks keys as expired. (2026-05-05)

### AUTH-GAP-05 — No distinct error message for session_deadline expiration (Low)

**Status**: RESOLVED — All token validation failures return the same generic HTTP 401 with `{"detail": "Authentication required"}`. The frontend handles all 401 responses uniformly with redirect to login page. (2026-05-05)

### AUTH-GAP-06 — Token refresh failure when role DB query fails (Low)

**Status**: RESOLVED — If the role-loading DB query fails during token refresh, the refresh is silently skipped: the old JWT remains valid and a WARNING log is emitted. Token refresh is a transparent side-effect that must never block the user's actual request. (2026-05-05)

**Superseded**: JWTs no longer contain role claims, and refresh preserves only
the existing JWT identity and deadline claims. No role-loading query occurs
during refresh. (2026-08-09)

### AUTH-GAP-34 — Session cleanup task schedule and configuration not fully specified (Low)

**Status**: RESOLVED — Specified exact schedule (Sundays 03:00 UTC), task name (`cleanup_sessions`), and fixed (non-configurable) schedule in authentication.md (2026-05-18)

### AUTH-GAP-35 — Redis cache key format for session liveness not specified as contract (Low)

**Status**: RESOLVED — Added Redis cache value contract to session liveness section: only active sessions cached as "1", cache miss triggers DB verification, inactive sessions never cached (2026-05-18)

### AUTH-GAP-36 — API key `name` validation rules not fully specified (Low)

**Status**: RESOLVED — Added API key name validation rules: trim, lowercase normalization, charset [a-z0-9._-], 1-128 chars, uniqueness on normalized value (2026-05-18)

### AUTH-GAP-37 — `GET /api/v1/admin/api-keys` filter by `user_id` does not specify behavior for non-existent user (Low)

**Status**: RESOLVED — Covered by AUTH-API-08 fix: `owner` parameter explicitly specifies empty result set for non-existent user (2026-05-18)

### AUTH-GAP-38 — Token refresh and concurrent requests may issue multiple refreshed tokens (Low)

**Status**: RESOLVED — Added explicit note acknowledging concurrent token refresh behavior as intentional and benign (2026-05-18)

### AUTH-GAP-39 — CLI `api-key` commands missing exit code and output format specification (Low)

**Status**: RESOLVED — Added exit codes, output format, and idempotency declarations to CLI api-key commands (2026-05-18)

### AUTH-GAP-40 — CLI `api-key list` behavior for non-existent username unspecified (Low)

**Status**: RESOLVED — Specified Error + exit 1 for non-existent username in CLI api-key commands (2026-05-18)

---

## Coherence

### AUTH-COH-04 — SSO button "always visible" in rbac.md contradicts conditional rendering (Medium)

**Status**: RESOLVED — Corrected `docs/features/identity/rbac.md` — SSO button is now documented as conditionally rendered based on SSO configuration (via `GET /api/v1/auth/providers`), not "always visible". (2026-05-07)

### AUTH-COH-05 — local-authentication.md shows --password as CLI argument (Medium)

**Status**: RESOLVED — Removed `--password` from CLI examples and parameter table in `docs/features/identity/local-authentication.md` (both `create` and `set-password` commands). Replaced with interactive prompt description, aligning with `user-management.md`. (2026-05-07)

### AUTH-COH-06 — HTTP method mismatch for password reset in user-management.md (Low)

**Status**: RESOLVED — Corrected `docs/features/identity/user-management.md` Security Considerations section — changed `PUT` to `POST` for `/api/v1/admin/users/{user}/password`, matching the endpoint definition and `rbac.md`. (2026-05-07)

### AUTH-COH-01 — api-spec.md contains stale "TBD" markers for authentication (Low)

**Status**: RESOLVED — Stale TBD markers in `api-spec.md` replaced with references to the three authentication specs (`authentication.md`, `sso-authentication.md`, `local-authentication.md`). (2026-05-05)

### AUTH-COH-02 — Pagination envelope differs from api-spec.md standard (Low)

**Status**: RESOLVED — The `authentication.md` spec updated to use the standard pagination envelope from `api-spec.md`: `{"data": [...], "meta": {"total": ..., "page": ..., "per_page": ...}}`. (2026-05-05)

### AUTH-COH-03 — api-spec.md states "no manual user creation endpoint" (Low)

**Status**: RESOLVED — Misleading wording in `api-spec.md` replaced with "There is no public user self-registration endpoint. Local users are created by admins via CLI or admin UI." and references to `local-authentication.md`. (2026-05-05)

### AUTH-COH-07 — User-loading redundancy between credential sub-flows and get_current_user top-level (Low)

**Status**: RESOLVED — Credential sub-flows now return only user_id; user loading consolidated in get_current_user step 5; role loading removed from middleware (2026-05-18)

### AUTH-COH-08 — Session cleanup references `updated_at` column not present in data model (Medium)

**Status**: RESOLVED — Added `updated_at` column to Session table in data-model.md and explicit `updated_at = now()` step in invalidation operations in authentication.md (2026-05-18)

### AUTH-COH-09 — data-model.md session cleanup threshold still hardcoded to "30 days" (Low)

**Status**: RESOLVED — Replaced hardcoded "30 days" with SESSION_MAX_LIFETIME_DAYS reference in data-model.md (2026-05-18)

### AUTH-COH-10 — local-authentication.md states JWT contains "roles" claim (Low)

**Status**: RESOLVED — Corrected JWT claims description in local-authentication.md: removed incorrect "roles" claim, added actual timing claims (2026-05-18)

### AUTH-COH-11 — sso-authentication.md hardcodes "30 days" session lifetime (Low)

**Status**: RESOLVED — Replaced hardcoded "30 days" with SESSION_MAX_LIFETIME_DAYS reference in sso-authentication.md (2026-05-18)

### AUT-COH-012 — API key states terminology inconsistency (Low)

**Status**: RESOLVED — Fixed terminology: description now includes all three states (active, revoked, expired) matching the output format (2026-07-28)

---

## Design

### AUTH-DES-05 — `session_deadline` hardcoded with no configuration (Medium)

**Status**: RESOLVED — Added `SESSION_MAX_LIFETIME_DAYS` env var (default 30) to the Configuration table, Configuration bounds (>= 1, WARNING > 365), Token lifecycle formula, and Claims description. Also added to `docs/configuration.md`. (2026-05-05)

### AUTH-DES-01 — No graceful JWT secret key rotation mechanism (Medium)

**Status**: RESOLVED — Accepted as-is. Mass logout on key rotation is documented in Security Considerations of `authentication.md` and is an acceptable tradeoff for an internal tool. Dual-key mechanism deferred as future hardening. (2026-05-05)

### AUTH-DES-02 — Session cleanup may delete evidence during security investigation (Medium)

**Status**: RESOLVED — Session creation and invalidation are logged at INFO level. A `last_login_at` column was added to the User table. These compensating controls are sufficient for an internal tool at this scale. (2026-05-05)

### AUTH-DES-06 — Session cleanup has no grace period for in-flight requests (Low)

**Status**: RESOLVED — Added 1-hour grace period to the session cleanup clause in `docs/features/identity/authentication.md` — invalidated sessions are now deleted only after `updated_at < now() - 1 hour`. (2026-05-06)

**Superseded**: Inactive sessions are immediately eligible for cleanup. A
request encountering a missing session receives the correct HTTP 401 outcome,
so no grace period is required. (2026-08-09)

### AUTH-DES-07 — Per-instance debounce behavior misleading under horizontal scaling (Low)

**Status**: RESOLVED — Added "per server instance" qualifier to the first mention of the debounce rate in `docs/features/identity/authentication.md`, making it immediately clear the guarantee is per-instance, not global. (2026-05-06)

### AUTH-DES-03 — Roles claim in JWT adds complexity without authoritative use (Low)

**Status**: RESOLVED — The `roles` claim has been removed from the JWT payload. Roles are always loaded from the database on every authenticated request. (2026-05-05)

### AUTH-DES-04 — Cookie Path=/api restricts future non-API authenticated routes (Low)

**Status**: RESOLVED — `Path=/api` is a deliberate security choice. All authenticated backend routes are under `/api` by architectural convention. No routing constraint exists in practice. (2026-05-05)

### AUTH-DES-08 — Session model missing `updated_at` column referenced by cleanup logic (Low)

**Status**: RESOLVED — Cross-agent duplicate of AUTH-COH-08 (2026-05-18)

### AUT-DES-009 — No CLI command for API key creation — headless bootstrapping gap (Medium)

**Status**: RESOLVED — Won't fix: CLI reserved for bootstrap and emergency operations; API key creation does not qualify (routine operation achievable via two API calls) (2026-07-28)

---

## Security

### AUTH-SEC-01 — Rate limiting fails open on Redis outage (Medium)

**Status**: RESOLVED — Accepted as-is. Rate limiting fail-open during Redis outage is an acceptable tradeoff for an internal tool on a trusted network. Failed login attempts are logged at WARNING level regardless. (2026-05-05)

**Superseded**: The premise "Failed login attempts are logged at WARNING level
regardless" was never specified or implemented. Every failed local login now
emits `login_failed` at INFO, including on the Redis fail-open path, where
`attempt_count` is omitted and the lockout transition cannot fire; see
`docs/features/identity/local-authentication.md` (Login outcome logging). The
fail-open tradeoff itself is unchanged. (2026-10-18)

### AUTH-SEC-02 — HS256 symmetric key — any reader can forge tokens (Medium)

**Status**: RESOLVED — HS256 accepted as a conscious tradeoff for an internal tool with a small deployment surface. All processes sharing `JWT_SECRET_KEY` are within the same trust boundary. (2026-05-05)

### AUTH-SEC-03 — No key rotation grace period amplifies incident impact (Medium)

**Status**: RESOLVED — Accepted as-is (same resolution as AUTH-DES-01). Mass logout on key rotation is an acceptable tradeoff. Dual-key verification deferred as future hardening. (2026-05-05)

### AUTH-SEC-11 — SSO state parameter is not single-use (Low)

**Status**: RESOLVED — Documented as accepted risk in Security Considerations section of `docs/features/identity/authentication.md`. Replay protection relies on IdP's single-use authorization code; maintaining consumed-states cache unjustified for enterprise IdP reliability. (2026-05-07)

### AUTH-SEC-08 — Logout endpoint expired token handling ambiguity (Low)

**Status**: RESOLVED — Clarified in `docs/features/identity/authentication.md` that the logout endpoint accepts expired tokens (only signature is verified). Documented security rationale: token is bound to a specific `session_id`, so an attacker can only invalidate that one session. (2026-05-06)

### AUTH-SEC-09 — No rate limiting on API key validation failure logging (Low)

**Status**: RESOLVED — Added detailed log rate limiting specification to `docs/features/identity/authentication.md` in the API key validation section. Per-IP granularity, 60s suppression window, LRU eviction (5min TTL, 10k max entries). (2026-05-06)

### AUTH-SEC-10 — Session cookie not bound to client fingerprint (Low)

**Status**: RESOLVED — Documented as accepted risk in `docs/features/identity/authentication.md` Security Considerations section. Listed compensating controls (Secure, HttpOnly, SameSite=Strict, 30-day max lifetime, admin deactivation). (2026-05-06)

### AUTH-SEC-04 — Per-username lockout does not defend against credential stuffing (Low)

**Status**: RESOLVED — Per-username lockout without per-IP throttling is an acceptable tradeoff for an internal tool on a trusted network. Credential stuffing is impractical: most users authenticate via SSO. (2026-05-05)

### AUTH-SEC-05 — No concurrent session limit enables undetected compromise (Low)

**Status**: RESOLVED — Documented as an explicit design choice in Security Considerations of `authentication.md`. No session limit enforced for an internal tool — deactivation covers the revocation use case. (2026-05-05)

### AUTH-SEC-06 — No mandatory API key expiration allows indefinite credential exposure (Low)

**Status**: RESOLVED — Accepted as-is. API keys without expiration are permitted by design. Mitigation mechanisms exist: users can revoke their own keys, admin deactivation automatically revokes all keys. (2026-05-05)

### AUTH-SEC-07 — Admin API keys endpoint per_page not explicitly bounded (Low)

**Status**: RESOLVED — `per_page` is explicitly capped at 100, consistent with the `api-spec.md` standard pagination convention. Values above 100 are silently clamped. (2026-05-05)

---

## API Conventions

### AUTH-API-07 — VALIDATION_ERROR used with HTTP 400 for semantic validation (Low)

**Status**: RESOLVED — Changed error code from `VALIDATION_ERROR` to `AUTH_API_KEY_INVALID_EXPIRY` for past `expires_at` validation in `docs/features/identity/authentication.md`. Uses domain-specific code per `AUTH_*` prefix convention. (2026-05-07)

### AUTH-API-01 — DELETE for API key revocation uses wrong HTTP method semantics (Medium)

**Status**: RESOLVED — Changed both endpoints from `DELETE` to `POST /api/v1/api-keys/{key_id}/revoke` and `POST /api/v1/admin/api-keys/{key_id}/revoke` in `docs/features/identity/authentication.md` and updated `docs/api-spec.md`. (2026-05-06)

### AUTH-API-02 — DELETE API key endpoints missing response body specification (Medium)

**Status**: RESOLVED — The new `POST /revoke` endpoints define explicit response schemas (200 OK with `{"data": {...}}` envelope containing key metadata). (2026-05-06)

### AUTH-API-03 — Non-standard error code prefix API_KEY_* (Medium)

**Status**: RESOLVED — Renamed `API_KEY_NAME_CONFLICT` to `AUTH_API_KEY_NAME_CONFLICT` and `API_KEY_NOT_FOUND` to `AUTH_API_KEY_NOT_FOUND` throughout `docs/features/identity/authentication.md`. Consistent with `AUTH_*` prefix convention. (2026-05-06)

### AUTH-API-04 — GET /api/v1/api-keys missing sorting specification (Low)

**Status**: RESOLVED — Added explicit sorting declaration to endpoint definition in `docs/features/identity/authentication.md`: "Sorting: not supported (small bounded dataset per user; results returned in creation order, newest first)." (2026-05-06)

### AUTH-API-05 — GET /api/v1/admin/api-keys missing sorting specification (Low)

**Status**: RESOLVED — Added `sort_by` and `sort_order` query parameters to the admin api-keys endpoint definition in `docs/features/identity/authentication.md`. Supports sorting by `created_at` (default) and `last_used_at`. (2026-05-06)

### AUTH-API-06 — Logout endpoint 401 case missing error code (Low)

**Status**: RESOLVED — Introduced "Global Responses" section in `api-spec.md` documenting 401/422/500 as middleware-level responses with machine-readable codes. Replaced `AUTH_TOKEN_EXPIRED` with `AUTH_NOT_AUTHENTICATED` across all specs. (2026-05-06)

### AUTH-API-08 — Admin API keys endpoint `user_id` filter should accept username (Medium)

**Status**: RESOLVED — Renamed parameter from `user_id` to `owner` (string type, accepts UUID or username) with explicit empty-result-set behavior for non-existent users (2026-05-18)

### AUTH-API-09 — Admin API keys endpoint missing behavior for invalid `status` value (Low)

**Status**: RESOLVED — Auto-resolved: api-spec.md enum filter convention explicitly covers single-value parameters; no per-endpoint clarification needed (2026-05-18)
