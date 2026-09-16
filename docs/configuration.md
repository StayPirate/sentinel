# Configuration Reference

Centralized index of all environment variables and runtime settings
required to deploy and operate Sentinel. Each setting is defined
authoritatively in the feature specification linked in the "Defined in"
column — this document is an aggregated reference, not the source of
truth. Exception: core infrastructure variables with no owning feature
spec (connection strings, application identity, CORS) are
authoritatively defined in this document directly — their "Defined in"
column shows `—`.

## Required Secrets

These must be provided in every environment. The application refuses to
start if any is missing.

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `JWT_SECRET_KEY` | string (>=32 chars) | — (required) | Symmetric key for signing JWTs | `docs/features/identity/authentication.md` |

## Required Connection Settings

These have sensible local-development defaults but must be configured
explicitly in staging/production.

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `DATABASE_URL` | string | `postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel` | PostgreSQL async connection string | — |
| `REDIS_URL` | string | `redis://localhost:6379/0` | Redis URL for application-owned ephemeral state, including session cache, rate limiting, locks, and the best-effort IBS consumer heartbeat | — |
| `CELERY_BROKER_URL` | string | `redis://localhost:6379/1` | Celery task broker URL | — |

All application-level Redis operations (session caching, login lockout,
deduplication, distributed locking, and the IBS consumer heartbeat) use
`REDIS_URL`. The Celery broker
is configured separately and managed by the Celery framework —
application code never accesses this database directly. Sentinel does
not configure a Celery result backend (see Celery Worker Configuration
below). Different database numbers (`/0`, `/1`) ensure namespace
isolation within a single Redis instance; in production, these URLs may
point to separate instances without code changes.

**Persistence and memory**: Redis persistence (RDB/AOF) is disabled by
design — all Redis state is volatile and reconstructible. See
`docs/deployment.md` (Redis Durability, Memory, and Persistence) for
the full operational requirements including `maxmemory`, `noeviction`
policy, and container resource limits.

## Application

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `APP_NAME` | string | `sentinel` | Application name (used in logs, health endpoint) | — |
| `DEBUG` | bool | `false` | Enable verbose error responses (stack traces in API errors). Does not affect logging — see `docs/features/platform/logging.md` | — |
| `CORS_ORIGINS` | list (comma-separated) | `http://localhost:5173` | Allowed CORS origins for API consumers | — |

CORS is configured with `allow_credentials=True`, restricted methods
(`GET`, `POST`, `PATCH`, `DELETE`), and restricted headers
(`Authorization`, `Content-Type`, `X-Request-ID`). These values are
application constants, not configurable via environment variables.

## Logging

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `LOG_LEVEL` | enum | `INFO` | Log verbosity (`DEBUG`\|`INFO`\|`WARNING`\|`ERROR`\|`CRITICAL`), applies to all loggers uniformly | `docs/features/platform/logging.md` |
| `LOG_FORMAT` | enum | `auto` | Log output format (`auto`\|`json`\|`console`) | `docs/features/platform/logging.md` |

`LOG_LEVEL` controls all logging and is independent of `DEBUG` — see
`docs/features/platform/logging.md`.

## Authentication

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `JWT_EXPIRY_HOURS` | int | `72` | JWT token lifetime in hours (3 days). Tokens are refreshed transparently via sliding session for active users. Must be >= 1; values > 720 log a warning | `docs/features/identity/authentication.md` |
| `SESSION_MAX_LIFETIME_DAYS` | int | `30` | Maximum session lifetime in days. Each session's deadline is calculated at login and remains fixed for the life of that session. Changes to this setting affect only sessions created by subsequent logins — existing sessions retain their original deadline. Must be >= 1; values > 365 log a warning | `docs/features/identity/authentication.md` |
| `LOGIN_MAX_ATTEMPTS` | int | `5` | Failed login attempts before account lockout. Must be >= 1; the application refuses to start if the value is below 1 | `docs/features/identity/local-authentication.md` |
| `LOGIN_LOCKOUT_MINUTES` | int | `10` | Lockout duration in minutes. Must be >= 1; the application refuses to start if the value is below 1 | `docs/features/identity/local-authentication.md` |

## SSO Configuration

All SSO settings are **optional**. If any of the required SSO settings
(`SSO_ISSUER_URL`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`,
`SSO_REDIRECT_URI`) is empty or unset, the application starts with **SSO
disabled**: the login page shows only the local credentials form (the
"Login with SUSE SSO" button is not rendered), and the SSO endpoints
(`/api/v1/auth/sso/authorize`, `/api/v1/auth/sso/callback`) return
HTTP 404.

At startup, the application logs an INFO message indicating SSO status:

- All SSO settings present: `"SSO authentication enabled
  (issuer: {SSO_ISSUER_URL})"`
- One or more settings empty or unset: `"SSO authentication disabled — missing
  settings: {list of missing setting names}"` (secret values are never
  logged; only the setting names appear)

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `SSO_ISSUER_URL` | string | — | OIDC issuer URL (e.g. `https://id.suse.com`). Required for SSO. | `docs/features/identity/sso-authentication.md` |
| `SSO_CLIENT_ID` | string | — | OIDC client ID. Required for SSO. | `docs/features/identity/sso-authentication.md` |
| `SSO_CLIENT_SECRET` | string | — | OIDC client secret. Required for SSO. | `docs/features/identity/sso-authentication.md` |
| `SSO_REDIRECT_URI` | string | — | OAuth2 callback URL. Required for SSO. | `docs/features/identity/sso-authentication.md` |
| `SSO_USER_CLAIM` | string | `sub` | OIDC ID token claim used to identify the user (matched against `username` for externally-provisioned users). Only relevant when SSO is enabled. | `docs/features/identity/sso-authentication.md` |

## Celery Worker Configuration

These settings control the Celery worker and Beat scheduler behavior.
The timezone settings are **fixed** — they MUST NOT be overridden.

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `CELERY_TIMEZONE` | string | `UTC` | Timezone for Celery Beat cron interpretation. MUST remain `UTC` — all fetcher schedules are expressed in UTC. Overriding this value causes all scheduled fetchers to run at incorrect times | `docs/features/platform/fetcher-infrastructure.md` |
| `CELERY_ENABLE_UTC` | bool | `true` | Forces Celery internal message timestamps to UTC. MUST remain `true` | `docs/features/platform/fetcher-infrastructure.md` |

### Timezone Enforcement

The Celery app factory validates these values at import time and refuses
to start if either is overridden — see
`docs/features/platform/fetcher-infrastructure.md` (Startup Validation)
for the exact validation logic.

Every Celery-based process (worker and Beat) imports the app object, so this
validation covers those processes automatically. The standalone IBS RabbitMQ
consumer does not import the Celery application and does not perform Celery
timezone validation; its process and container timezone still follow the
cross-cutting UTC requirement in `docs/deployment.md`.

### Result Handling

`task_ignore_result = True` is a fixed Celery application setting — task
return values are never stored. `FetcherRun` tracks executions of
`BaseFetcher` subclasses. Non-fetcher sub-operations create no `FetcherRun` and
rely on durable domain state plus the structured logs defined by their owning
specifications. See
`docs/features/platform/fetcher-infrastructure.md` (Result handling).

### Redbeat Scheduler

`celery-redbeat` (the dynamic Beat scheduler) uses the same Redis
instance as the Celery broker (`CELERY_BROKER_URL`) by default. No
separate `redbeat_redis_url` environment variable is needed or
supported. The scheduler class is configured in the Celery application
settings (`beat_scheduler = 'redbeat.RedBeatScheduler'`). Redbeat stores
schedule entries under the `redbeat:` key prefix in the broker database.
See `docs/features/platform/fetcher-infrastructure.md` (Celery Beat
Schedule Synchronization) for the full synchronization mechanism between
PostgreSQL (source of truth for fetcher schedules) and redbeat
(execution layer).

### Beat Tick Interval

`beat_max_loop_interval = 60` is a fixed application-level setting (not
an environment variable). It controls the maximum time Beat sleeps
between scheduler ticks. The worst-case latency for detecting Redis data
loss is ≤60s. This value also determines the derived `lock_timeout` for
the redbeat distributed lock — see
`docs/features/platform/fetcher-infrastructure.md` (Redbeat
Configuration) for the derivation and crash-recovery rationale.

This setting MUST NOT be exposed as an environment variable. It is a
system-level tuning constant with no deployment-specific variance.

### retry_period (redbeat)

NOT configured. When unset (the default), Redis operations raise
immediately on failure without internal retries. This preserves the
fail-fast behavior that enables automatic recovery via the lock sentinel
mechanism. Setting `retry_period` to any value would allow Beat to
silently reconnect to empty Redis after a restart, bypassing the lock
sentinel detection. See
`docs/features/platform/fetcher-infrastructure.md` (Runtime: Redis Data
Loss).

### Redbeat Socket Timeouts

`redbeat_redis_options` is a fixed application-level setting (not an
environment variable) configuring `socket_connect_timeout` and
`socket_timeout` at 2 seconds each on Redbeat's internal Redis client.
This bounds how long any Redbeat read or write can block on a hung
(blackholed/firewalled) connection, converting it into a `RedisError`
within a predictable time instead of blocking indefinitely. The value
mirrors the 2-second timeout already used by the application's own
Redis clients (`local_auth_service`, `session_service`). See
`docs/features/platform/fetcher-infrastructure.md` (Redbeat
Configuration).

## IBS (Internal Build Service)

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `IBS_API_URL` | string | `https://api.suse.de` | IBS API base URL | `docs/features/integrations/ibs-integration.md` |
| `IBS_USERNAME` | string | `""` | IBS HTTP Basic Auth username. Empty or unset: app starts without IBS credentials; IBS-dependent fetchers will fail at runtime | `docs/features/integrations/ibs-integration.md` |
| `IBS_PASSWORD` | string | `""` | IBS HTTP Basic Auth password. Same rationale as `IBS_USERNAME` | `docs/features/integrations/ibs-integration.md` |
| `IBS_DOWNLOAD_BASE_URL` | HTTPS URL | `https://download.suse.de/ibs` | Anonymous IBS Product-repository MirrorCache front door. Must be absolute HTTPS with a hostname and contain no user information, query, fragment, unsafe/empty path segment, percent encoding, backslash, or control character; one trailing slash is accepted and removed. Invalid values fail startup. Product downloads never send IBS API credentials | `docs/features/packages/ibs-product-release-detection.md` |

## IBS RabbitMQ Consumer

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `IBS_RABBITMQ_URL` | string | `amqps://suse:suse@rabbit.suse.de` | Credential-bearing RabbitMQ connection URL. May embed credentials; excluded from settings representations and never logged | `docs/features/integrations/ibs-rabbitmq-integration.md` |
| `IBS_RABBITMQ_ENABLED` | bool | `true` | Enables the standalone consumer process and controls the status API's synthesized `disabled` state | `docs/features/integrations/ibs-rabbitmq-integration.md` |
| `IBS_RABBITMQ_RECONNECT_INITIAL` | positive int | `5` | Initial transient reconnect delay in seconds | `docs/features/integrations/ibs-rabbitmq-integration.md` |
| `IBS_RABBITMQ_RECONNECT_MAX` | positive int | `300` | Transient reconnect delay cap in seconds; must be greater than or equal to `IBS_RABBITMQ_RECONNECT_INITIAL` | `docs/features/integrations/ibs-rabbitmq-integration.md` |

The exchange, queue properties, bindings, AMQP heartbeat, QoS, and shutdown
deadline are fixed integration constants. The consumer binds exactly
`suse.obs.package.commit`, `suse.obs.request.create`, and
`suse.obs.request.state_change`; there is no routing-key environment variable.
It requires `DATABASE_URL` for authoritative domain work, uses `REDIS_URL` only
for best-effort heartbeat publication, and does not read or depend on
`CELERY_BROKER_URL`.

## TLS / Security

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `SUSE_CA_CERT_PATH` | string | `certs/SUSE_Trust_Root.crt` | Path to SUSE internal CA certificate for TLS validation of all connections to *.suse.de services (HTTP, AMQP). Relative to working directory (`backend/` locally, `/app` in containers). Combined with system CA bundle at runtime. | `docs/features/platform/networking.md` |

## SMELT / AIMAAS

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `SMELT_API_URL` | string | `https://smelt.suse.de/api` | SMELT API prefix for product catalog sync and package resolution; must use HTTPS and contain no user information, query, or fragment; invalid values fail startup | `docs/features/packages/product-catalog.md` |
| `AIMAAS_API_URL` | string | `https://aimaas.suse.de/api` | AIMAAS HTTPS API prefix for product lifecycle and CVSS threshold sync; must use HTTPS and contain no user information, query, or fragment; invalid values fail startup | `docs/features/packages/product-catalog.md` |

Both SMELT and AIMAAS use anonymous HTTPS requests (no authentication). A
future upstream authentication requirement for either service is a contract
change requiring specification review; credential environment variables will
be added if an approved contract requires them.

## External APIs

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `NVD_API_KEY` | string | `""` (optional) | NVD API key for higher rate limits on CVE fetching. When non-empty, consider reducing the `sync_nvd_cves` fetcher's `request_delay` from 6.0s to ~0.6s via the fetcher admin dashboard | `docs/features/tickets/cve-sync-nvd.md` |
| `GITHUB_TOKEN` | string | `""` (required for `sync_ghsa_advisories`) | GitHub personal access token for GHSA advisory sync. Required for production rate limits (see `docs/data-sources.md`). The fetcher refuses to execute if this is empty or unset | `docs/features/tickets/cve-sync-ghsa.md` |

## Git-Based Fetchers

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `GIT_CLONE_BASE_DIR` | string (path) | `/var/lib/sentinel/git` | Base directory for persistent bare clones used by git-based fetchers (`sync_mitre_cves`, `sync_kernel_cves`). Must be backed by persistent storage in containerized deployments | `docs/features/platform/git-fetcher-infrastructure.md` |

## Standard Environment Variables (Non-Sentinel)

These are standard system-level variables respected by the HTTP client
library (httpx). They are NOT Sentinel-specific and are typically set at
the container or system level.

| Env Var | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `HTTPS_PROXY` | string | (none) | Proxy URL for outgoing HTTPS connections. Respected by all HTTP clients | `docs/features/platform/networking.md` |
| `HTTP_PROXY` | string | (none) | Proxy URL for outgoing HTTP connections | `docs/features/platform/networking.md` |
| `NO_PROXY` | string | (none) | Comma-separated hosts that bypass the proxy | `docs/features/platform/networking.md` |
| `LC_ALL` | string | (none) | Locale override. Set to `C` in `git_operations.py` subprocess calls (code-level guarantee). Recommended as `C` at container level for defense-in-depth | `docs/features/platform/git-fetcher-infrastructure.md` |
| `GIT_TERMINAL_PROMPT` | string | (none) | Git prompt control. Set to `0` in `git_operations.py` subprocess calls (code-level guarantee). Prevents interactive prompts that would block async workers | `docs/features/platform/git-fetcher-infrastructure.md` |
| `TZ` | string | (none) | Timezone. Set to `UTC` in `git_operations.py` subprocess calls and recommended at container level (see `docs/deployment.md`, Timezone and Locale Requirements) | `docs/features/platform/git-fetcher-infrastructure.md`, `docs/deployment.md` |

## Runtime Database Settings

These are not environment variables. They are stored in the database and
managed via the Admin API (`PATCH /api/v1/admin/settings`).

| Setting | Type | Default | Description | Defined in |
|---------|------|---------|-------------|------------|
| `default_cvss_version` | string | `"3.1"` | System-wide CVSS version for severity and eligibility. Allowed: `"3.1"`, `"4.0"` | `docs/features/platform/system-settings.md` |

## Notes for Operators

1. **Secrets must never be committed** to the repository or baked into
   container images. Use `.env` files for local development,
   ConfigMaps/Secrets for Kubernetes.

2. **`JWT_SECRET_KEY` must not be reused** for other purposes (e.g.,
   external integrations, webhook signing). Rotate it only during
   planned maintenance windows — rotation invalidates all active JWTs
   (mass logout).

3. **Startup validation**: the application validates all required settings
   at boot and fails fast with a clear error message indicating which
   variable is missing or invalid.

4. **Naming convention**: environment variables use `UPPER_SNAKE_CASE`.
   The corresponding Python setting uses `lower_snake_case`. The mapping
   is 1:1 (e.g., `JWT_SECRET_KEY` → `jwt_secret_key`).
