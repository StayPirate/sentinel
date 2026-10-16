# Review: networking

**Spec**: `docs/features/platform/networking.md`
**Last reviewed**: 2026-07-02
**Reviewers**: Gap Analysis, Coherence, Design, Security, API Conventions, Documentation

> Post-split review (fetcher-infrastructure split, Phase 4m). The document
> was created by extracting the shared HTTP client + TLS trust store
> content from the former monolithic `fetcher-infrastructure.md`. The split
> was content-preserving; the gap findings below are pre-existing
> ambiguities, not regressions introduced by the split, and are recorded
> here for future hardening rather than fixed as part of the split exercise.

---

## Gap Analysis

### NET-GAP-01 — Transport retry on non-idempotent requests may duplicate writes (High)

**Status**: RESOLVED — Method safety sub-section added to Transport-Level Retry; retry restricted to idempotent methods by default with opt-in for non-idempotent; httpx built-in retry explicitly excluded; IBSClient retry safety documented in ibs-integration.md (2026-06-26)

### NET-GAP-02 — Timing of the missing-CA-file warning is ambiguous (Medium)

**Status**: RESOLVED — SSL context lifecycle clarified: built fresh per create_http_client() invocation, not at startup; warning frequency documented per component type (2026-06-26)

### NET-GAP-03 — Corrupt-CA handling for non-HTTP protocols unspecified (Medium)

**Status**: RESOLVED — Introduced shared `build_tls_context()` function with uniform contract (missing→warning, corrupt→TLSConfigurationError); documented component-specific error handling in ibs-rabbitmq-integration.md (terminate process) and ad-integration.md (fail without retry) (2026-06-26)

### NET-GAP-04 — Connection pool size limits unspecified (Medium)

**Status**: RESOLVED — Explicit pool limits (100 max connections, 20 max keepalive) added to Default Configuration table with override mechanism; note clarifying sequential usage pattern added; pool override example added to fetcher-infrastructure.md Override Mechanism section (2026-06-26)

### NET-GAP-05 — TLS verification override safety not enforced (Medium)

**Status**: RESOLVED — TLS verify documented as overridable with WARNING log; UA remains template-protected (2026-06-26)

### NET-GAP-06 — SSL context caching / certificate rotation behavior unspecified (Medium)

**Status**: RESOLVED — Explicitly specified that SSL context is rebuilt per create_http_client() invocation (no module-level caching); fetchers pick up rotated CA on next run without restart (2026-06-26)

### NET-GAP-07 — Retry-After HTTP-date in the past / clock skew not addressed (Low)

**Status**: RESOLVED — HTTP-date ≤ now() treated as absent; clock skew addressed (2026-06-27)

### NET-GAP-08 — `name` parameter handling for non-fetcher callers unspecified (Low)

**Status**: RESOLVED — Factory signature changed to require name as formal parameter (2026-06-27)

### NET-GAP-09 — Valid-but-wrong CA file (silent failure) not covered (Low)

**Status**: RESOLVED — Auto-resolved: runtime TLS handshake errors provide sufficient diagnostic; no startup validation needed (2026-06-27)

### NET-GAP-10 — Which error propagates on retry exhaustion is unspecified (Low)

**Status**: RESOLVED — Auto-resolved: behavior is implicit (last-error-wins); no consumer relies on this distinction (2026-06-27)

---

## Coherence

No issues identified.

---

## Design

### NET-DES-01 — Cert file existence check in readiness probe (Medium)

**Status**: RESOLVED — Won't fix: the SUSE CA certificate is a dependency of Celery workers/consumers, not of the API server process. Blocking API readiness for a worker-only prerequisite creates excessive coupling. The existing fetcher dashboard already surfaces certificate-related failures with adequate visibility. (2026-07-03)

---

## Security

### NET-SEC-01 — Explicit follow_redirects=False as factory default (Medium)

**Status**: RESOLVED — Added explicit `follow_redirects=False` as factory default in Default Configuration table, WARNING-level log on override in "Override Safety" subsection, and dedicated "Redirect Policy" subsection documenting security rationale and opt-in mechanism (2026-07-03)

### NET-SEC-02 — Response body size limit (max_content_length) (Medium)

**Status**: RESOLVED — Won't fix: risk accepted. The threat model relies on developer-curated endpoints (NVD, GitHub, CISA, SMELT, IBS, AIMAAS) with low compromise likelihood. Implicit protections (30s read timeout, container memory limits, Celery run_timeout) provide sufficient defense-in-depth for this risk level. (2026-07-03)

**Re-evaluated** (2026-10-16, #994): the accepted risk does not extend to decoded size. Stacked content codings let a body of a few hundred bytes decode to tens of MiB, and each further layer multiplies that, so neither the read timeout nor container memory bounds it; the same exposure applies to the API process, which uses the shared client for SMELT during package addition. The shared client now permits at most one `gzip` or `deflate` coding and rejects any other before decoding (`networking.md`, HTTP Response Compression), so decoded size grows only linearly with the bytes received. A limit on the received body itself remains unnecessary on the original grounds.

---

## API Conventions

No API endpoints defined in this spec.

---

## Documentation

### NET-DOC-01 — Dangling reference to the moved "Shared HTTP Client" section (Medium)

**Status**: RESOLVED — `fetcher-infrastructure.md` (BaseFetcher Base Class, item 5) pointed to a "Shared HTTP Client" section that no longer exists in that document after the split. Updated to reference the local "BaseFetcher HTTP Client Integration" section and `networking.md` ("Shared HTTP Client") for the full factory spec (2026-06-25)

### NET-DOC-02 — Factory signature omits the required `name` parameter (Low)

**Status**: RESOLVED — Factory signature now declares name: str as required parameter (2026-06-27)
