# Review: sso-authentication

**Spec**: `docs/features/identity/sso-authentication.md`
**Last reviewed**: 2026-05-07
**Reviewers**: Gap Analysis, Coherence, Design, Security, API Conventions

---

## Gap Analysis

### SSO-GAP-01 — IdP error redirect to callback URL unhandled (Medium)

**Status**: RESOLVED — Added step 7 to Frontend Flow: frontend checks for `error` param before extracting code/state, displays error message from `error_description` without calling the backend callback (2026-05-07)

### SSO-GAP-02 — Case-sensitive claim matching vs LDAP sync lowercase normalization (Medium)

**Status**: RESOLVED — Changed Identity Mapping matching rules to case-insensitive (claim value lowercased before comparison with `ldap_uid`), with explicit justification referencing LDAP sync normalization and AD case-insensitivity (2026-05-07)

### SSO-GAP-03 — Locked-out user bypasses lockout via SSO (Low)

**Status**: RESOLVED — Added explicit note in Security Considerations: local lockout does NOT apply to SSO, with rationale (IdP handles credential verification and brute-force protection) (2026-05-07)

### SSO-GAP-04 — ID token `iat` validation not specified (Low)

**Status**: RESOLVED — Added `iat` validation (reject tokens issued >10 minutes ago) and 30-second clock skew tolerance for all time-based claims to callback processing step 4 (2026-05-07)

### SSO-GAP-05 — `SSO_REDIRECT_URI` mismatch handling unspecified (Low)

**Status**: RESOLVED — Documented `SSO_REDIRECT_URI` requirements in Configuration section: canonical route `/auth/callback`, multi-environment registration (production/staging/localhost), startup validation (HTTPS required except localhost), and mismatch error handling (2026-05-07)

### SSO-GAP-06 — Clock skew between Sentinel instances for state timestamp (Low)

**Status**: RESOLVED — Added "Clock Synchronization" section to `docs/architecture.md` (Deployment Portability) documenting the NTP requirement for all time-based mechanisms. Added cross-reference in `docs/features/identity/sso-authentication.md` state parameter section. (2026-05-07)

### SSO-GAP-07 — No return URL preservation across SSO redirect (Medium)

**Status**: RESOLVED — Added `sessionStorage` return URL preservation to Frontend Flow: step 2 saves current URL before SSO redirect, step 10 restores it after successful login (redirects to saved URL or dashboard as fallback) (2026-05-07)

### SSO-GAP-08 — Frontend error handling for /authorize endpoint failure unspecified (Medium)

**Status**: RESOLVED — Added error handling to Frontend Flow step 3: HTTP 404 shows only local login form, HTTP 503 shows inline message "SSO is temporarily unavailable, please try later" (2026-05-07)

### SSO-GAP-09 — Frontend callback route not concretely defined (Low)

**Status**: RESOLVED — Defined `/auth/callback` as the canonical frontend callback route in Frontend Flow step 6, and documented the relationship with `SSO_REDIRECT_URI` in the Configuration section (2026-05-07)

### SSO-GAP-10 — Already-authenticated user initiating new SSO flow behavior unspecified (Low)

**Status**: RESOLVED — Added session guard (step 0) to SSO Frontend Flow in `sso-authentication.md` — authenticated users are redirected to dashboard. Added "Concurrent sessions" subsection to `authentication.md` Session Management — documents that multiple sessions are allowed by design and a re-login does not invalidate existing sessions. Cross-reference added in the session guard note. (2026-05-07)

### SSO-GAP-11 — No HTTP timeout specified for IdP token exchange (Low)

**Status**: RESOLVED — Added "HTTP timeout: 10 seconds" to callback processing step 2 (token exchange). Timeout errors are already covered by step 3 error handling (network error → HTTP 401 with `AUTH_SSO_FAILED` and WARNING log) (2026-05-07)

---

## Coherence

_No findings. The spec is well-aligned with all referenced specifications (`authentication.md`, `local-authentication.md`, `ad-integration.md`, `user-service.md`), with consistent definitions, compatible data flows, and matching terminology._

---

## Design

### SSO-DES-01 — Case-sensitive matching without normalization risks silent login failures (Medium)

**Status**: RESOLVED — Same fix as SSO-GAP-02 — matching rules changed to case-insensitive with lowercase normalization (2026-05-07)

### SSO-DES-02 — Synchronous discovery re-fetch blocks request path (Low)

**Status**: RESOLVED — Added explicit HTTP timeout (5 seconds) to Discovery document caching and JWKS caching tables in `sso-authentication.md` (2026-05-07)

### SSO-DES-03 — JWT_SECRET_KEY rotation invalidates in-flight SSO states (Low)

**Status**: RESOLVED — Added "Operational note: JWT_SECRET_KEY rotation" subsection to `sso-authentication.md` Configuration section. Added cross-reference in `authentication.md` key rotation bullet. (2026-05-07)

---

## Security

### SSO-SEC-01 — Claim value logged at WARNING level risks PII leakage (Medium)

**Status**: RESOLVED — Accepted risk. For an internal tool with controlled log access, logging the claim value at WARNING level is acceptable for diagnostic purposes. No spec change. (2026-05-07)

### SSO-SEC-02 — No rate limiting on SSO callback endpoint (Medium)

**Status**: RESOLVED — Deferred to dedicated reverse proxy (see issue #682). Rate limiting is a cross-cutting infrastructure concern; recommended limits documented for future proxy configuration. No spec change. (2026-05-07)

### SSO-SEC-03 — Frontend JWT storage mechanism unspecified (Medium)

**Status**: RESOLVED — Corrected Frontend Flow step 10: backend sets `sentinel_session` HttpOnly cookie (per `authentication.md`), frontend does not handle the token directly. Added Spec Hierarchy header declaring `authentication.md` as parent spec with inherited concerns including token storage. (2026-05-07)

### SSO-SEC-04 — No `iat` validation on ID token (Low)

**Status**: RESOLVED — Same fix as SSO-GAP-04 — added `iat` validation (reject tokens >10 min old) and 30s clock skew tolerance to callback processing step 4 (2026-05-07)

### SSO-SEC-05 — SSRF via SSO_ISSUER_URL discovery fetch (Low)

**Status**: RESOLVED — Accepted risk. Exploitation requires admin compromise (env var access). For an internal tool where admin is already a trusted role, this does not warrant additional validation complexity. (2026-05-07)

### SSO-SEC-06 — State parameter not single-use (Low)

**Status**: RESOLVED — Risk already explicitly documented in spec (Security Considerations, "Accepted risk" paragraph). No further action needed. (2026-05-07)

### SSO-SEC-07 — OIDC nonce omitted removes defense-in-depth layer (Low)

**Status**: RESOLVED — Risk already explicitly documented in spec (Security Considerations, "OIDC nonce is intentionally omitted" paragraph). No further action needed. (2026-05-07)

---

## API Conventions

### SSO-API-01 — GET /api/v1/auth/providers not cataloged in api-spec.md (Medium)

**Status**: RESOLVED — Added `GET /api/v1/auth/providers` to the Authentication endpoints list in `docs/api-spec.md` (2026-05-06)

### SSO-API-02 — Single AUTH_SSO_FAILED code covers four distinct 401 conditions (Medium)

**Status**: RESOLVED — Split `AUTH_SSO_FAILED` into three codes: `AUTH_SSO_FAILED` (transient infrastructure failures), `AUTH_SSO_USER_NOT_FOUND` (user not in DB), `AUTH_SSO_USER_INACTIVE` (user deactivated). Updated error table, inline step descriptions, and `docs/api-spec.md` error code examples. (2026-05-06)

### SSO-API-03 — Error response inline descriptions omit error code references (Low)

**Status**: RESOLVED — Updated inline step descriptions (steps 3, 5, 7, 8) in `docs/features/identity/sso-authentication.md` to explicitly reference their error codes (`AUTH_SSO_FAILED`, `AUTH_SSO_USER_NOT_FOUND`, `AUTH_SSO_USER_INACTIVE`) (2026-05-06)

### SSO-API-04 — GET /api/v1/auth/providers does not specify error codes (Low)

**Status**: RESOLVED — Added explicit statement in `docs/features/identity/sso-authentication.md` that this endpoint has no application-level error responses (reads internal configuration only, no failure modes beyond standard 500) (2026-05-06)
