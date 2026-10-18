# Networking Infrastructure

## Purpose

Cross-cutting HTTP client and TLS trust store infrastructure used by
all Sentinel components that make outgoing network connections: fetchers
(via BaseFetcher), IBSClient, the SMELT requests of package addition and
of the package tasks, and IBSEventConsumer (AMQP).

Scope boundary: this spec covers the shared HTTP client factory and TLS
trust store configuration. Protocol-level reconnection logic, connection
pooling, and application retry policies belong to their respective
integration specs.

## Shared HTTP Client

All outgoing HTTP requests from fetchers and service-level clients use
a shared HTTP client infrastructure based on httpx `AsyncClient`. The
infrastructure provides two layers:

1. **Standalone factory module** (`backend/app/services/http_client.py`):
   creates a pre-configured httpx `AsyncClient` with all cross-cutting
   defaults. Any component can call this factory; the callers outside
   `BaseFetcher` are listed in Non-Fetcher Components.

2. **BaseFetcher integration**: `BaseFetcher` exposes a `self.http_client`
   lazy property that internally calls the standalone factory. Fetcher
   authors use `self.http_client` directly — zero configuration, zero
   boilerplate. See `docs/features/platform/fetcher-infrastructure.md`
   (BaseFetcher HTTP Client Integration) for the lazy property, override
   mechanism, and lifecycle details.

No other application module creates an httpx client or network transport,
calls an httpx top-level request function, or uses another HTTP client
library, so every outgoing HTTP request receives the shared behavior below.
A structural test enforces this boundary
(`docs/features/platform/testing-strategy.md`, Structural Tests).

### Factory Module

Location: `backend/app/services/http_client.py`

```python
def create_http_client(name: str, **overrides) -> httpx.AsyncClient:
    """Create a pre-configured httpx AsyncClient.

    Args:
        name: Identifies the calling component (fetcher name or client
              name). Used to build the User-Agent header and included
              in WARNING-level logs for TLS override traceability.

    Applies all cross-cutting defaults (User-Agent, timeouts, TLS,
    compression, Accept header, transport-level retry, proxies from the
    environment). Keyword arguments override individual defaults.
    """
```

#### Override Safety

Five settings receive special protection in the factory:

- **User-Agent**: always built from the standard template using the
  `name` parameter. Not overridable via `http_client_options` or
  `**overrides` — any `user-agent` key in headers or top-level
  `headers` override is silently dropped and replaced with the
  template-generated value.
- **Accept-Encoding**: the client default is always `gzip, deflate`, the
  content codings the shared response policy permits (see "HTTP Response
  Compression"). Any `accept-encoding` key in a `headers` override is
  replaced.
- **TLS verify / ssl_context**: overridable via `**overrides` or
  `http_client_options`, but every override that sets `verify=False`
  or provides a custom `ssl_context` emits a WARNING-level log at
  client creation time, including the caller's `name` for
  traceability. Example log: `"TLS verify overridden by
  'sync_nvd_cves' — verify=False"`.
- **Redirect following**: overridable via `http_client_options`, but
  every override that sets `follow_redirects=True` emits a
  WARNING-level log at client creation time, including the caller's
  `name` for traceability. Example log: `"Redirect following enabled
  by 'sync_example' — credentials may be forwarded to redirect
  targets"`. Rationale: outbound requests may carry credentials (IBS
  API request signatures and session cookies, NVD API key, GitHub
  token) in request headers; automatic redirect following could
  forward these to untrusted hosts.
- **Routing**: not overridable. A `transport`, `mounts`, `proxy`, or
  `trust_env` override raises `TypeError` at client creation. Every request
  uses the factory's own transport stack, which carries the transport-level
  retry and the response content-coding policy, and proxies come only from
  the environment (see "Proxy Configuration").

### Default Configuration

| Setting | Default | Override mechanism |
|---------|---------|-------------------|
| User-Agent | `Sentinel/{version} ({name}; +https://github.com/StayPirate/sentinel)` | Not overridable |
| Connect timeout | 10 seconds | `http_client_options` |
| Read timeout | 30 seconds | `http_client_options` |
| Write timeout | 10 seconds | `http_client_options` |
| Pool timeout | 10 seconds | `http_client_options` |
| Max connections | 100 | `http_client_options` (limits) |
| Max keepalive connections | 20 | `http_client_options` (limits) |
| Accept | `application/json` | `http_client_options` (headers) |
| Accept-Encoding | `gzip, deflate`; see "HTTP Response Compression" | Not overridable (see "Override Safety") |
| TLS | Combined trust store (system CAs + SUSE CA), verify enabled | `http_client_options` / `**overrides` (emits WARNING — see "Override Safety") |
| Transport retry | See "Transport-Level Retry" below | `http_client_options` |
| Redirect following | False (no redirects followed) | `http_client_options` (emits WARNING — see "Override Safety") |
| Proxy | Standard env vars (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`); see "Proxy Configuration" | Environment only; not overridable (see "Override Safety") |

Connection pool note: every consumer makes sequential requests (one HTTP
request at a time per client instance).
The pool exists for keepalive connection reuse between sequential
requests to the same host, not for managing parallelism. These limits
match httpx defaults and provide ample headroom for future consumers
with higher concurrency needs.

#### User-Agent

Format: `Sentinel/{version} ({fetcher.name}; +https://github.com/StayPirate/sentinel)`

- Platform version from `importlib.metadata.version("sentinel")`. If
  `PackageNotFoundError` (running from source without installation),
  defaults to `"dev"`
- Fetcher name automatic from `BaseFetcher.name` (mandatory, unique)
- Project URL hardcoded — not configurable
- Example: `Sentinel/1.0 (sync_nvd_cves; +https://github.com/StayPirate/sentinel)`
- Example (dev): `Sentinel/dev (sync_nvd_cves; +https://github.com/StayPirate/sentinel)`

For non-fetcher components (e.g., `IBSClient`), the `name` parameter
is passed explicitly to the factory.

#### Timeouts

- Connect: 10 seconds (TCP + TLS handshake)
- Read: 30 seconds (time to receive response body)
- Write: 10 seconds (time to send request body)
- Pool: 10 seconds (time waiting for a connection from the pool)

Not configurable via env var or admin panel — these are engineering
decisions. Fetchers that need different values override via
`http_client_options`.

Timeout hierarchy (independent concerns):

```
┌─────────────────────────────────────────────────────┐
│ FetcherConfig.run_timeout (default: 3600s)          │  ← Celery task level
│ Hard ceiling: task killed at this limit             │     (per entire run)
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ Per-HTTP-request timeout                      │  │  ← HTTP transport level
│  │ connect: 10s, read: 30s                       │  │     (per single request)
│  │                                               │  │
│  │ A single execute() run may make hundreds of   │  │
│  │ HTTP requests, each with its own timeout.     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

#### Transport-Level Retry

The shared client automatically retries transient errors before the
fetcher sees them. If all retries fail, the error propagates to the
fetcher, which applies its own logic (abort, skip-and-continue, etc.).

**Dispatch rule**: when a response matches multiple rows (e.g., 503 is
both a 5xx and may carry `Retry-After`), the most specific row wins. If
`Retry-After` is present and parseable, the guided path is selected;
otherwise, the generic status-code row applies.

| Condition | Retry | Backoff |
|-----------|-------|---------|
| 5xx (any method) | 4 attempts (1 original + 3 retries) | 1s / 2s / 4s (fixed) |
| Connection error, timeout, proxy error, remote protocol error (idempotent methods only†) | 4 attempts (1 original + 3 retries) | 1s / 2s / 4s (fixed) |
| 429/503 with `Retry-After` ≤ 120s | 1 retry | Wait the indicated value |
| 429/503 with `Retry-After` > 120s | No retry | Error propagated immediately |
| 429 without `Retry-After` | No retry at transport | Fetcher decides |
| 4xx (non-429) | No retry | Client error — retrying is pointless |

**Proxy and protocol errors**: `ProxyError` (proxy rejected the
CONNECT tunnel — request never reached the target) and
`RemoteProtocolError` (server sent unparseable HTTP — no usable
response available) are retried with the same policy as connection
errors. Both represent inability to obtain a usable HTTP response
from the target server.

**Path exclusivity**: if a response enters the Retry-After guided path,
the guided retry is the final attempt. The two retry paths are mutually
exclusive within a single request sequence. Consequence: a server that
sends `Retry-After` receives one guided retry, whereas the same status
without the header receives three fixed-backoff retries. This is
intentional — the server's explicit guidance replaces blind attempts.
If the server-guided retry fails, a more persistent issue is likely.

**Retry-After parsing**: integer (seconds) or HTTP-date (RFC 7231).
Malformed values (unparseable strings, negative integers) are treated as
absent — the response falls through to the "Retry-After absent" row.
For HTTP-date values, the wait is computed as `parsed_date - now()`; if
the result is ≤ 0 (date already elapsed or server clock ahead of client),
the value is treated as absent (same fallthrough). This prevents
zero-delay retries caused by server clock skew or stale dates and ensures
consistent behavior with the negative-integer rule.

**Shutdown**: all retry sleeps (both fixed-backoff and Retry-After waits)
use `asyncio.sleep()`, cancelled automatically on `SoftTimeLimitExceeded`
or task revocation. No special handling needed.

##### Method Safety

Per RFC 9110 Section 9.2.2, a client SHOULD NOT automatically retry a
request with a non-idempotent method unless it has means to know that
the request semantics are actually idempotent.

Default retry eligibility by method:

- **Idempotent methods** (GET, HEAD, OPTIONS, PUT, DELETE): retry on
  connection error, timeout (read/write), and 5xx with readable response
- **Non-idempotent methods** (POST, PATCH): retry on 5xx with readable
  response only. No retry on timeout or connection error by default —
  these conditions can occur after the server has received and begun
  processing the request, risking duplicate writes

The `†` marker in the retry condition table above indicates the
idempotent-method restriction.

**Opt-in for non-idempotent methods**: the factory accepts a
`retry_non_idempotent` parameter (boolean, default `False`). When
`True`, retry applies to all methods uniformly (connection error and
timeout are retried regardless of HTTP method). The caller is
responsible for ensuring their operations are semantically safe to
retry (e.g., IBS `cmd=diff` POST endpoints are read-only despite
using POST).

##### httpx Built-In Retry Exclusion

httpx's built-in transport retry (`retries` parameter on
`AsyncHTTPTransport`) is not used. The custom transport-level retry
described above replaces it entirely, providing unified backoff,
Retry-After support, method safety enforcement, and observability. Do
not enable `retries` on the transport — this would cause multiplicative
retry behavior (N httpx retries x M custom retries per attempt).

#### Infrastructure Failure Classification

The `is_infrastructure_failure()` function classifies post-transport
exceptions as either infrastructure failures (API unreachable) or
data-quality errors (API responded but data is unusable). It is used
by stateless per-CVE fetchers to drive the consecutive failure abort
counter (see `cve-fetcher-infrastructure.md`, session lifecycle
template 1).

**Location**: `backend/app/services/http_client.py`

**Signature**: `is_infrastructure_failure(exception: Exception) → bool`

**Implementation** (whitelist approach):

```python
INFRA_FAILURE_TYPES = (
    httpx.NetworkError,         # ConnectError, ReadError, WriteError, CloseError
    httpx.TimeoutException,     # ConnectTimeout, ReadTimeout, WriteTimeout, PoolTimeout
    httpx.ProxyError,           # Proxy tunnel establishment failed
    httpx.RemoteProtocolError,  # Server sent malformed HTTP response
)

def is_infrastructure_failure(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return isinstance(exc, INFRA_FAILURE_TYPES)
```

**Design choice — whitelist over blacklist**: the function enumerates
exception types that ARE infrastructure failures, rather than catching
all `TransportError` and excluding non-infra subclasses. This means
unknown future httpx exception types default to `False` (conservative
— does not abort), with `BaseFetcher` terminal outcome accounting as the
fallback when no selected unit succeeds.
Using parent classes (`NetworkError`, `TimeoutException`) ensures that
new subclasses within those families are automatically covered.

**Classification table** (exhaustive for httpx 0.28+):

| Exception class | Returns | Rationale |
|---|---|---|
| `httpx.NetworkError` (and subclasses: `ConnectError`, `ReadError`, `WriteError`, `CloseError`) | `True` | No usable HTTP response received — connection failed or dropped |
| `httpx.TimeoutException` (and subclasses: `ConnectTimeout`, `ReadTimeout`, `WriteTimeout`, `PoolTimeout`) | `True` | No usable HTTP response received within time budget |
| `httpx.ProxyError` | `True` | Proxy tunnel failed — request never reached target server |
| `httpx.RemoteProtocolError` | `True` | Server sent malformed HTTP — no parseable response available |
| `httpx.HTTPStatusError` with `status_code >= 500` | `True` | Server in persistent fault state (post-transport-retry exhaustion) |
| `httpx.HTTPStatusError` with `status_code < 500` | `False` | Server responded with client error (4xx) — proves reachability |
| `httpx.DecodingError` | `False` | HTTP response received (headers and status parsed), body encoding corrupted or outside the content-coding policy (see "HTTP Response Compression") — data-quality |
| `httpx.TooManyRedirects` | `False` | Server responded with 3xx redirects — redirect loop proves reachability |
| `httpx.LocalProtocolError` | `False` | Client-side programming error — not an external API issue |
| `httpx.UnsupportedProtocol` | `False` | Programming error (invalid URL scheme) — not a runtime issue |
| `JSONDecodeError` | `False` | HTTP 200 received — body corruption is data-quality |
| `ValidationError` (Pydantic) | `False` | HTTP 200 received — schema mismatch is data-quality |
| Any other non-httpx exception | `False` | Not related to external API communication |

**Post-transport context**: this function operates on exceptions that
have already exhausted transport-level retry. A `True` result means
the transport layer attempted up to 4 requests (with 1s/2s/4s backoff)
and all failed — the target API is unreachable or persistently failing.

**Consumers**: stateless per-CVE fetchers (`sync_epss_scores`,
`sync_redhat_cves`, `sync_osv_advisories`). Not used by paginated,
git-based, or catalog fetchers.

#### Celery Retry Classification

The `is_retryable_condition()` function classifies post-transport
exceptions to decide whether a Celery task wrapper should retry or fail
immediately. It is used by task wrappers that invoke fetcher operations
as standalone Celery tasks (not inside `execute()` batch loops).

**Location**: `backend/app/services/http_client.py`

**Signature**: `is_retryable_condition(exception: Exception) → bool`

**Implementation**:

```python
def is_retryable_condition(exc: Exception) -> bool:
    """Classify whether a post-transport exception is worth retrying.

    Used by Celery task wrappers (fetch_single_cve and run_catch_up) to
    decide self.retry() vs immediate failure.

    Returns True for transient conditions where a subsequent attempt
    may succeed: infrastructure failures (network, timeout, proxy,
    protocol errors, HTTP 5xx) and rate limiting (HTTP 429).

    Returns False for permanent conditions where retrying would hit
    the same error: HTTP 4xx (except 429), parsing errors on HTTP 200,
    and any non-httpx exception.

    Post-transport context: exceptions reaching this function have
    already exhausted transport-level retry (4 attempts with
    1s/2s/4s backoff). A True result means the transport layer
    attempted up to 4 requests and all failed — the condition is
    persistent at the transport level but may be transient at the
    Celery task level (minutes/hours timescale vs seconds timescale).
    """
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status == 429
    return isinstance(exc, INFRA_FAILURE_TYPES)
```

**Relationship with `is_infrastructure_failure()`**:

`is_retryable_condition()` is a **superset** of
`is_infrastructure_failure()`:

```
is_infrastructure_failure(e) == True  →  is_retryable_condition(e) == True  (always)
is_retryable_condition(e) == True  →  is_infrastructure_failure(e) == True  (EXCEPT HTTP 429)
```

| Condition | `is_infrastructure_failure()` | `is_retryable_condition()` |
|---|---|---|
| Network error / timeout / proxy | `True` (API unreachable) | `True` (transient) |
| HTTP 5xx | `True` (API error) | `True` (transient) |
| HTTP 429 | **`False`** (API reachable, rate-limited) | **`True`** (transient — will clear after backoff) |
| HTTP 403 / other 4xx | `False` | `False` |
| `JSONDecodeError` / `ValidationError` | `False` | `False` |
| Any non-httpx exception | `False` | `False` |

The two functions answer different questions:

- `is_infrastructure_failure()`: "Is the external API unreachable?" —
  drives the consecutive failure abort counter in `execute()` batch
  loops
- `is_retryable_condition()`: "Is there a reasonable chance the next
  attempt will succeed?" — drives Celery task retry decisions

Neither function is implemented in terms of the other. They share the
`INFRA_FAILURE_TYPES` tuple but apply independent logic for HTTP status
codes.

**Consumers**: `fetch_single_cve` and `run_catch_up` (Celery task
wrappers for on-demand and catch-up operations).

#### HTTP Response Compression

The shared client's default `Accept-Encoding` request header is
`gzip, deflate`. The factory sets this value itself instead of inheriting the
httpx default, which changes with the optional compression packages installed,
and a factory `headers` override cannot replace it (see "Override Safety"). A
single request may still set its own value, as the consumers described at the
end of this section do; the response policy below applies whatever the request
asked. Responses are decompressed transparently with Python standard-library
codecs. No per-fetcher configuration is needed.

A response may apply at most one content coding, and only `gzip` or
`deflate`. Its codings are taken from every `Content-Encoding` field and
comma-separated element, compared case-insensitively after trimming
whitespace; `identity` and empty elements are not codings. A final response
that declares more than one coding, or any other coding — for example `br`,
`zstd`, `x-gzip`, `compress`, or an unknown value — keeps its status and
headers, but reading its body, decoded or raw, raises `httpx.DecodingError`
before any body byte is received or decoded. Closing the response releases its
connection. A streamed response whose body the caller does not read, such as an
error response checked by status alone, keeps its HTTP status outcome. A
non-streaming request reads the body before it returns, so its caller observes
the `DecodingError` whatever the status, as for a corrupt compressed body. In
both reading cases the error is a data-quality failure (see Infrastructure
Failure Classification), and the caller applies the outcome its owning
specification defines for an undecodable response.

The policy bounds decoding, not transfer. One standard-library layer expands
the received bytes by at most about 1,032:1, the limit of the deflate format
that both codings use, so the decoded size grows only linearly with the bytes
received; stacked codings, which multiply that factor for every layer, are what
the policy excludes. The number of bytes received is not limited.

A consumer that decodes a compressed payload itself requests
`Accept-Encoding: identity` and rejects any declared coding before reading the
body, as its owning specification defines (for example the IBS Product release
detector, `docs/features/packages/ibs-product-release-detection.md`).

#### Proxy Configuration

The shared HTTP client sends requests through a forward proxy configured by
the standard `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment
variables. No application-level proxy settings exist, and no factory
override configures a proxy (see "Override Safety"). These are system-level
variables, set at the container or host level for every process role that
makes outgoing HTTP requests: the Celery workers (fetchers, `IBSClient`,
and the SMELT requests of package tasks), the IBS RabbitMQ consumer
(`IBSClient`), and the API server (SMELT requests during package addition).

**Reading**: the factory reads the variables each time it creates a
client, so a changed value applies to the next client. For each variable
the lowercase name (`https_proxy`, `http_proxy`, `no_proxy`) is read first,
then the uppercase one; an empty value counts as unset. `ALL_PROXY` and
other proxy variables are not read.

**Routing**: a request to an `https` URL uses the `HTTPS_PROXY` proxy, and a
request to an `http` URL the `HTTP_PROXY` proxy. A request is sent directly
when no proxy is configured for its scheme or when `NO_PROXY` exempts its
host. Every route keeps the shared behavior: TLS verification of the origin
with the shared trust store, the connection limits (applied to each route's
own connection pool), the transport-level retry, and the response
content-coding policy. A request to an `https` origin is tunneled through
the proxy with `CONNECT`, and the certificate presented inside the tunnel
is verified as for a direct request, which a TLS-intercepting proxy
satisfies only with a trusted CA (see below); a request to an `http` origin
is forwarded by the proxy.

**Proxy URL**: `http://` or `https://`, with a host and an optional port; a
value without a scheme means `http://`. Userinfo in the URL is sent to the
proxy as HTTP Basic authentication. The TLS connection to an `https://`
proxy is verified with the shared trust store, whatever the caller's
`verify` override: the client's own `build_tls_context()` context, or,
when the caller overrides `verify`, one the factory builds for the proxy,
so a missing or corrupt `SUSE_CA_CERT_PATH` then has the effects described
in TLS Trust Store Configuration as well. Any other value — another scheme
such as `socks5://`, a URL without a host, or an unparseable value — makes
client creation raise `ValueError` that names the variable but never its
value, which may contain credentials. The client never falls back to a
direct connection. Like a corrupt `SUSE_CA_CERT_PATH`, this is a
configuration error, not a transient condition; no caller handles it
specifically, so it follows each caller's handling of an unexpected
exception.

**`NO_PROXY`**: a comma-separated list; each entry is trimmed and compared
case-insensitively.

| Entry | Exempts |
|-------|---------|
| `*`, alone or as any entry | Every host: no request uses a proxy |
| Domain name, e.g. `example.com` | That host and its subdomains |
| Domain name with a leading `.` or `*.`, e.g. `.example.com` | Its subdomains only |
| IP address or CIDR network, e.g. `192.0.2.10`, `198.51.100.0/24`, `2001:db8::/32`; an IPv6 address may be in brackets | A host written as an IP address within it |

Domain entries match only host names, and IP entries only hosts written as
IP addresses; no name is resolved to decide. Any other entry, including
one with a port or a scheme, is ignored, so the requests it may have meant
to exempt use the proxy.

**TLS-intercepting proxy**: the proxy's CA certificate must be in the
system CA bundle, which `build_tls_context()` loads as its base (Trust
Store Layering, layer 1); no Sentinel-specific configuration exists.

**Scope**: proxy support for the `git` subprocess (`BaseGitFetcher`) and
for the AMQP connections of `IBSEventConsumer` is outside this contract.

#### Redirect Policy

The shared HTTP client does not follow redirects by default
(`follow_redirects=False`). This is an explicit security decision, not
merely inherited from httpx defaults.

**Security rationale**: outbound requests from Sentinel frequently carry
sensitive credentials in request headers — IBS API request signatures and
session cookies, NVD API keys, GitHub tokens. If the client automatically
follows redirects (301, 302, 307, 308), these credentials would be forwarded to
the redirect target, which may be an untrusted host. A compromised or
misconfigured upstream service could redirect authenticated requests to an
attacker-controlled server, leaking credentials silently.

**Generic opt-in mechanism**: consumers that genuinely require automatic
redirect following must opt in explicitly via `http_client_options`:

```python
http_client_options = {"follow_redirects": True}
```

This override triggers a WARNING-level log at client creation time (see
"Override Safety" above) to ensure visibility in production logs.

Consumers enabling automatic redirect following must define credential
handling and permitted destinations in their owning specification. The default
remains fail-closed because same-origin and cross-origin redirects can both
change the request's security assumptions.

**IBS Product-repodata exception**: the Product release detector does not
enable automatic redirect following. It may manually inspect and follow at
most one HTTP 302 repository-artifact redirect from a request constructed from
the validated `IBS_DOWNLOAD_BASE_URL` when the target is HTTPS, has exact host
`dist.suse.de`, has no explicit port, preserves the complete expected path, and
contains no user information, query, fragment, or traversal. A second redirect,
downgrade, different host/port/path, or malformed location fails the repository.
These requests are anonymous; no `Authorization` header or IBS credential is
sent or forwarded. This narrow exception is owned by
`docs/features/packages/ibs-product-release-detection.md` and does not alter
redirect behavior for another integration.

### Non-Fetcher Components

Components outside `BaseFetcher` call the standalone factory directly,
passing their own `name`, and manage their own client lifecycle. A client
never crosses an event loop.

`IBSClient`:

- One client per workflow invocation: in Celery roles each task
  invocation runs its own event loop, creates the client on it, and closes
  it before returning; the IBS RabbitMQ consumer uses one client for its
  single-loop process
- Connection pooling within one client lifetime
- Uses `Accept: application/xml` override (from JSON default)
- TLS validated via the same combined trust store
- httpx idle connection management (~5s timeout) prevents stale
  connections without manual intervention
- A rotated CA is picked up by the next client: the next workflow
  invocation in Celery roles, a process restart for the consumer (see
  "Certificate rotation" below)

The SMELT requests of `add_package_to_ticket()`
(`docs/features/packages/package-service.md`) use the factory defaults:

- The API server creates one client per package-addition request
  (`POST /api/v1/tickets/{ticket_id}/packages`) and closes it before the
  response is sent
- The `resolve_ticket_packages`, `run_ticket_convergence`, and
  `backfill_product_catalog` tasks each create one client on the task's
  event loop, share it across the packages of the invocation, and close it
  before returning
- A rotated CA is picked up by the next client: the next request or task
  invocation

## TLS Trust Store Configuration

All outgoing TLS connections from Sentinel — HTTP (shared client) and
AMQP (`IBSEventConsumer`) — use a combined
trust store that includes both the system CA bundle and the SUSE
internal CA.

- **Env var**: `SUSE_CA_CERT_PATH` (default: `certs/SUSE_Trust_Root.crt`)
  - The SUSE Trust Root CA file is committed in the repository at
    `backend/certs/SUSE_Trust_Root.crt`. The default relative path
    works both in containers (workdir `/app`) and in local development
    (run from `backend/`). No configuration needed for standard
    deployments
  - The env var exists as an override for non-standard deployments
- **Combined trust store**: at runtime, Python builds an SSL context
  that includes system CAs (for public services: NVD, GitHub, CISA,
  Red Hat, OSV, FIRST.org) and the SUSE CA (for internal services: IBS,
  SMELT, AIMAAS, RabbitMQ). All connections use the same trust store —
  no host matching, no fallback, no host list to maintain
- **If file does not exist**: combined trust store contains only system
  CAs. A log warning is emitted when `build_tls_context()` is invoked
  (does not block startup). Whether this actually degrades connectivity
  to SUSE-internal services depends on the system CA bundle's own
  contents — see Trust Store Layering below. The file existence check
  runs inside `build_tls_context()` itself (called by `create_http_client()`
  for HTTP consumers, and directly by `IBSEventConsumer`) when
  constructing the SSL context — the SSL context is built fresh on every
  invocation (no module-level caching). Warning frequency per component
  type:
  - Fetchers in batch mode (`execute()` loop): once per run — the client
    is created lazily on first access and reused for all `fetch_single()`
    calls within the same run
  - Standalone `fetch_single_cve` tasks: once per task — a client is
    created lazily and closed by the task wrapper per call
  - Standalone `run_catch_up` tasks: once per task — same pattern as
    `fetch_single_cve`
  - Standalone `resolve_ticket_packages`, `run_ticket_convergence`, and
    `backfill_product_catalog` tasks: once per task — the client is created
    and closed by the task workflow per invocation
  - API package addition: once per `POST /api/v1/tickets/{ticket_id}/packages`
    request
  - `IBSClient`: once per workflow invocation in Celery roles; once per
    process lifetime in the IBS RabbitMQ consumer
  - `IBSEventConsumer` (AMQPS): once per connection attempt — it builds a
    fresh context for every attempt (see the rotation table below)
- **If file is corrupt or unparseable**: `build_tls_context()` raises
  `TLSConfigurationError` with the file path and parse error detail.
  The calling component handles this error according to its own
  lifecycle model (see each integration spec for component-specific
  behavior). This is a configuration error, not a transient condition
  — retrying without fixing the file is pointless
- **TLS verification**: enabled by default using the SUSE Trust Root CA
  bundle. Callers may override `verify` or provide a custom `ssl_context`
  via factory overrides; doing so causes a WARNING-level log at client
  creation (including the caller's `name`) to ensure visibility. Failed
  TLS handshake with verification enabled is an immediate error — never
  proceed with an unverified connection unless explicitly overridden
- **Certificate rotation**: since the SSL context is built fresh per
  `create_http_client()` invocation (not cached at module level), rotation
  behavior differs by trust store layer — see Trust Store Layering below
  for the full breakdown.

### Trust Store Layering

The SUSE CA is present at two independent layers in a standard deployment.
Understanding which layer a given consumer relies on is necessary to
reason correctly about missing-CA behavior and certificate rotation.

| Layer | Mechanism | Built | Consumers |
|-------|-----------|-------|-----------|
| 1 — System trust store | `update-ca-certificates` installs the SUSE CA into the OS-wide CA bundle (container image build step) | At image build time | Any component that resolves TLS verification via OpenSSL's default verify paths without receiving an explicit `ssl.SSLContext` — e.g., a future git subprocess cloning from a SUSE-internal host (`BaseGitFetcher`). Also the mechanism for a TLS-intercepting proxy's CA (see Proxy Configuration above). Sentinel's actual AMQP client, `IBSEventConsumer`, is a layer-2 consumer (see below) — it always receives an explicit context from `build_tls_context()` and never falls back to this layer |
| 2 — `build_tls_context()` | Explicit `load_verify_locations(cafile=SUSE_CA_CERT_PATH)` on top of `ssl.create_default_context()` | Fresh on every invocation (no caching) | All Sentinel-controlled Python code that performs TLS (the shared HTTP client, `IBSEventConsumer`) |

**Layer 2 is required regardless of layer 1.** httpx — the library behind
the shared HTTP client — does not consult the system trust store for its
default verification: `verify=True` (the default) builds its context from
the `certifi` bundle, which does not include the SUSE CA. Without layer 2,
every shared-client request to a SUSE-internal host would fail
TLS verification regardless of what is installed system-wide. Layer 2 is
also the only layer available outside containers (local development runs
from `backend/` with no system-wide install).

**The layers overlap by design inside the standard container image.**
`build_tls_context()`'s base (`ssl.create_default_context()`) already
reads the system trust store, so when layer 1 is present (the standard
image), the explicit `load_verify_locations()` call in layer 2 is
redundant for already-trusted hosts — but still required for consumers
that bypass `build_tls_context()`'s base and construct their own context
without it, and it remains the only layer present in non-container
deployments (local development, custom images that skip the
`update-ca-certificates` step).

**Consequence for the "if file does not exist" behavior above**: the
WARNING is always the reliable, observable signal. Whether the described
connection failure actually occurs depends on layer 1: in the standard
container image it does not (layer 1 already trusts the SUSE CA), so the
warning indicates a misconfiguration to investigate rather than a live
outage. In local development or a custom image without the
`update-ca-certificates` step, layer 1 is absent and the failure is real.

**Certificate rotation by layer**:

| Consumer | Layer | Picks up a rotated CA |
|----------|-------|------------------------|
| Fetchers (httpx via `create_http_client()`) | 2 | Next run, no restart |
| `IBSEventConsumer` (AMQPS) | 2 | Next reconnection attempt, no restart |
| `IBSClient` (httpx client, one per workflow invocation) | 2 | Next workflow invocation in Celery roles, no restart; process restart in the IBS RabbitMQ consumer |
| SMELT package clients (API package addition, package tasks) | 2 | Next request or task invocation, no restart |
| Git subprocess and other OpenSSL-default-verify clients | 1 | Image rebuild (`SUSE_CA_CERT_PATH` overrides only layer 2 — a mounted replacement file does not reach layer 1) |

No git-based fetcher currently clones from a SUSE-internal host (both
`sync_mitre_cves` and `sync_kernel_cves` clone public repositories), so
the layer-1 git row above does not yet apply to any running fetcher. It
is documented for the candidate SUSE-internal git sources already listed
in `docs/data-sources.md` (`gitlab.suse.de`, `src.suse.de`).

The layer-1 rebuild requirement is acceptable given CA rotations are
infrequent (years between rotations).

### Shared Trust Store Function

All protocols use `build_tls_context()` to construct their SSL context:

```python
def build_tls_context() -> ssl.SSLContext:
    """Build the combined TLS trust store (system CAs + SUSE CA).

    Returns an ssl.SSLContext suitable for any protocol (HTTPS, AMQPS).

    Behavior:
    - SUSE_CA_CERT_PATH missing: log WARNING, return system-only context
    - SUSE_CA_CERT_PATH corrupt/unparseable: raise TLSConfigurationError
    - SUSE_CA_CERT_PATH valid: return combined context (system + SUSE CA)
    """
```

`create_http_client()` calls `build_tls_context()` internally.
Non-HTTP components (`IBSEventConsumer`) call it
directly and pass the returned context to their respective protocol
libraries.

Responsibility boundary: `build_tls_context()` is responsible only for
constructing the context and signaling errors. The *handling* of
`TLSConfigurationError` (retry, termination, failure marking) is owned
by each component and documented in its respective spec.

### Protocol-Specific Integration

| Protocol | Component | Trust Store Source |
|----------|-----------|-------------------|
| HTTPS | Shared HTTP client (all fetchers, IBSClient, SMELT package clients) | `build_tls_context()` via `create_http_client()` |
| AMQPS | `IBSEventConsumer` | `build_tls_context()` passed to aio-pika/aiormq |
| Git over HTTPS | `git` subprocess (`BaseGitFetcher`) | Container system trust store (layer 1 — see Trust Store Layering). Not yet exercised: no current git-based fetcher clones from a SUSE-internal host |

## Cross-references

- `docs/features/platform/fetcher-infrastructure.md` — BaseFetcher HTTP
  integration (lazy property, overrides), `run_catch_up` retry policy
- `docs/features/platform/cve-fetcher-infrastructure.md` — `fetch_single`
  retry policy, batch error handling
- `docs/features/tickets/cve-service.md` — `fetch_single_cve` orchestrator
- `docs/features/integrations/ibs-integration.md` — IBSClient usage
- `docs/features/integrations/ibs-rabbitmq-integration.md` — AMQP TLS
  configuration
- `docs/features/platform/git-fetcher-infrastructure.md` — `BaseGitFetcher`
  git subprocess invocation (Trust Store Layering, layer 1 consumer)
- `docs/data-sources.md` — candidate SUSE-internal git sources
  (`gitlab.suse.de`, `src.suse.de`)
- `docs/configuration.md` — environment variable index
- RFC 9110 Section 9.2.2 — HTTP method idempotency semantics (normative
  basis for transport-level retry method safety)
