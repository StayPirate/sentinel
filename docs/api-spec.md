# API Specification

## Fundamentals

### Base URL

All API endpoints are prefixed with `/api/v1/`.

### Versioning

The API uses URL-path versioning (`/api/v1/`). Only v1 exists at this time.

Rules:

- Additive changes (new fields in responses, new endpoints, new optional
  query parameters) are NOT breaking changes and are added to v1 directly
- Removal or renaming of fields, changes to response structure, changes to
  error codes, or semantic changes to existing behavior are breaking changes
- A v2 will only be considered after a stable production instance is
  confirmed — until then, all work happens on v1
- When a new version is eventually introduced, the previous version will
  include a `Sunset` response header indicating the deprecation date

## Authentication and Authorization

### Authentication

All endpoints require authentication unless explicitly marked as public.
Authentication uses JWT tokens in HttpOnly cookies (browser sessions) or
API keys (programmatic access). See `docs/features/identity/authentication.md`,
`docs/features/identity/sso-authentication.md`, and
`docs/features/identity/local-authentication.md` for credential validation,
and `docs/features/identity/api-key-management.md` for API key lifecycle and
management.

### Authorization

Every endpoint definition in a feature specification MUST declare its
authorization level using one of the following formats:

- **`Access: Public`** — no authentication required; the endpoint additionally
  declares `Authentication: Optional` when it processes a presented credential
- **`Access: Authenticated`** — any logged-in user regardless of role
- **`Capability: <capability_name>`** — requires the specified capability
  (e.g., `Capability: create_ticket`)
- **`Capability: <capability_a> OR <capability_b>`** — requires at least one
  listed capability; see Authorization Chain Evaluation Order

The intentional field name change between `Access` and `Capability`
serves as a visual indicator: `Access` means "authentication level
only", `Capability` means "specific authorization check required". See
`docs/features/identity/rbac.md` for the full list of capabilities and
which roles include them.

#### Optional Authentication on Public Endpoints

Every normal Public application endpoint under `/api/v1` MUST process optional
authentication, including reads whose response does not otherwise vary by
caller, so browser activity on those endpoints participates in sliding session
refresh. Place this declaration immediately after the endpoint's access
declaration:

```text
**`Authentication: Optional`**
```

The declaration invokes `get_optional_current_user` from
`docs/features/identity/authentication.md`. Its result is a fully validated
`AuthenticatedPrincipal` or `None`; a partially authenticated caller is never
exposed to endpoint or visibility logic.

- No selected credential is accepted as anonymous and produces no
  authentication side effect.
- A valid selected credential authenticates the caller and executes the same
  JWT refresh or API-key operational effects as mandatory authentication.
- A selected credential that fails validation returns the global `401
  AUTH_NOT_AUTHENTICATED`; it is not silently ignored.
- A selected non-empty Bearer credential never falls back to a cookie after
  validation failure.

A Public endpoint without this declaration ignores request credentials. This
form is reserved for exactly `/health`, `/ready`, local login, SSO authorization
and callback, and authentication-provider discovery, whose probe, bootstrap,
or recovery contracts must remain independent of stale credentials. Adding
another exception requires an explicit contract in its owning specification;
endpoint authors MUST NOT infer optional authentication from `Access: Public`.

**Scope** is an orthogonal visibility input, not an endpoint capability.
Consumer-facing services receive request-resolved caller information and apply
the canonical Ticket visibility predicate from `docs/features/identity/rbac.md`
to their model-aware queries. Thin API dependencies may delegate resource
selection to those services and map an inaccessible result to HTTP, but API and
Core do not construct the business ORM predicate.

The authorization declared in the owning feature specification is the
**authoritative source**. `docs/features/identity/rbac.md` maintains a
derived summary index (Endpoint Permission Map) for cross-referencing —
it is not the source of truth.

#### Authorization Chain Evaluation Order

Ticket- and CVE-derived consumer operations use exactly one of these four
flows. In every flow, authentication resolves caller information once for the
request. Services consume that information; they do not reload roles or
reconstruct the caller during later query or mutation phases.

1. **Optional-authentication public read**:
   1. Run `get_optional_current_user`. No selected credential yields the
      anonymous caller; a selected invalid credential returns 401 before any
      resource query.
   2. A service selects the requested Ticket-, CVE-, or nested resource with
      accessibility constraining the same database result that is returned.
      Missing and inaccessible resources have the resource-specific not-found
      outcome.
2. **Authenticated or capability-protected read**:
   1. Authenticate the caller.
   2. If the operation declares a capability, check it without loading the
      protected resource. Failure returns 403
      `AUTH_INSUFFICIENT_PERMISSION` regardless of resource existence.
   3. A service performs one visibility-constrained resource selection and
      returns that selected result. Authenticated operations without a
      capability begin with step 1 and continue directly to this step.
3. **Mutation without external pre-lock I/O**:
   1. Authenticate and check every declared resource-independent capability
      before resource lookup.
   2. The mutation service acquires the applicable roots in its owning lock
      order, including each protected Ticket, and evaluates canonical Ticket
      accessibility from locked-current Ticket and visibility-relationship
      state. A missing or inaccessible resource returns its path's not-found
      response (`TICKET_NOT_FOUND` for a Ticket path or `CVE_NOT_FOUND` for a
      CVE path) with no mutation effect. Multi-root operations retain their
      owning deterministic lock order.
   3. Only after locked-current accessibility succeeds may the service evaluate
      operability, nested-resource ownership, status or state guards, no-op
      classification, writes, audit, reconciliation, and post-commit effects.
4. **Mutation with permitted external pre-lock I/O**:
   1. Authenticate and check every declared resource-independent capability
      before resource lookup.
   2. Perform a preliminary service-owned accessibility selection before
      external I/O. Missing or inaccessible resources return the appropriate
      not-found response without external I/O.
   3. Complete the permitted external phase with no Ticket lock held. If this
      phase fails, return its documented external error. Do not perform another
      lookup solely to replace that failure with a concurrent 404.
   4. If external I/O succeeds, acquire the Ticket lock and perform the same
      authoritative locked-current accessibility and subsequent guard ordering
      as flow 3.

The locked-current check in mutation flows closes the stale-access window. If
another transaction removed visibility before lock acquisition, denial causes
zero writes, assignment, audit events, reconciliation, or post-commit effects.
If an authorized mutation itself removes the actor's final visibility path, it
still completes and returns its ordinary success response; later requests use
the committed post-state.

When an operation accepts alternative capabilities, the capability step checks the
documented capability union without loading the Ticket. A caller lacking every
alternative receives the same generic 403 regardless of whether the Ticket or
nested resource exists. Any mutation condition that requires current Ticket
state is then enforced only after locked-current accessibility under the Ticket
lock. For example,
`status = fixed` accepts `admin_ticket_ops OR manage_packages` before
accessibility; under lock, `manage_packages` alone is sufficient only when
`Ticket.cve_id IS NULL`. Ticket convergence rerun similarly accepts
`triage_ticket OR manage_fetchers`, then checks status eligibility under lock.

For a CVE operation, the selected CVE is accessible when it has no associated
Ticket or when its associated Ticket satisfies the canonical Ticket visibility
predicate. Capability-protected CVE operations check capability before this
selection. Every denial from missing or inaccessible CVE selection returns 404
`CVE_NOT_FOUND`, never a Ticket error code.

Non-Ticket, non-CVE endpoints follow their declared authentication and
capability requirements without a Ticket accessibility step.

## Request Conventions

### Query Parameter Length Limit

Every string query parameter has an individual maximum length of 500
characters, unless the endpoint specifies otherwise. Values exceeding the
limit return `422 VALIDATION_ERROR`.

### Undeclared Query Parameters

Query parameters not declared by an endpoint are ignored and are absent from
its OpenAPI contract. This preserves FastAPI's standard handling of undeclared
query input. A parameter name used by another endpoint does not become valid
globally; for example, an endpoint that declares fixed ordering but no
`sort_by` parameter ignores a supplied `sort_by` value.

### Pagination

List endpoints support pagination via query parameters:

- `page` (int, default: 1): Page number
- `per_page` (int, default: 20, max: 100): Items per page

Constraint enforcement: if `page < 1`, `per_page < 1`, or `per_page > 100`,
the endpoint returns `422 VALIDATION_ERROR`. Values are never silently
clamped. Requesting a `page` beyond the last available page returns an
empty `data` array with correct `meta.total` (not an error).

### Filtering

List endpoints support filtering via query parameters specific to each
resource. Common patterns:

- Exact match: `?status=active`
- Search: `?search=term` (searches relevant text fields)
- Date range: `?from_date=2024-01-01&to_date=2024-12-31`

Unless an endpoint explicitly specifies otherwise, simultaneously supplied
client-declared filter parameters on a list or search endpoint combine with
AND semantics. Matching rules internal to one parameter remain
endpoint-specific: for example, a `search` parameter may match any of several
resource fields. Pagination, sorting, authentication, authorization,
confidentiality or visibility rules, path or ownership scope, and other
mandatory resource constraints are not client-declared filters for this rule.
An endpoint may instead make filters mutually exclusive when their combined
meaning would be invalid; it must state that behavior and its validation
response explicitly.

#### Enum Filter Validation

Enum filter parameters accept a **single value** by default. Endpoints
that support multiple values MUST declare the parameter as `repeatable`
in the endpoint specification. If nothing is stated, the parameter
accepts only one value.

**Repeatable format**: multiple values are specified as separate query
parameters with the same name (e.g., `?status=new&status=analysis`).
The semantics are OR — the result includes resources matching **any** of
the provided values.

Comma-separated format is **not supported**. A value containing commas
(e.g., `?status=new,analysis`) is treated as a single literal value that
does not match any enum member and is silently ignored per the validation
rule below.

**Validation rules**: invalid enum values are silently ignored — they
are removed from the filter set without producing an error. If all
provided values are invalid (or the resulting filter set is empty after
removing invalid values), the endpoint returns an empty result set (not
an error). This applies to all endpoints that accept enum-based filter
parameters (e.g., `event_type`, `status`, `severity`).

#### Date Range Interpretation

When a date range filter (`from_date`, `to_date`) is applied against a
`datetime` column:

- **Date-only value** (e.g., `2025-01-15`):
  - `from_date` → interpreted as `2025-01-15T00:00:00Z` (start of day
    UTC, inclusive)
  - `to_date` → interpreted as `2025-01-15T23:59:59.999999Z` (end of day
    UTC, inclusive)
- **Full datetime value without offset** (e.g., `2025-01-15T14:30:00`):
  interpreted as UTC
- **Full datetime value with offset** (e.g., `2025-01-15T14:30:00+02:00`):
  accepted and converted to UTC before comparison (i.e.,
  `2025-01-15T12:30:00Z`)

**Inverted range validation**: when both `from_date` and `to_date` are
provided and `from_date` is strictly after `to_date` (after timezone
normalization), the endpoint returns **400 Bad Request** with error code
`DATE_RANGE_INVERTED`. This validation applies globally to all endpoints
that accept date range parameters.

`DATE_RANGE_INVERTED` is a shared response derived from an endpoint declaring
both date range parameters. Like global responses, it is not repeated in
per-endpoint error tables. Malformed date/datetime values remain schema
validation failures and produce the global `422 VALIDATION_ERROR` response.

**Maximum range constraint**: endpoints that return unbounded datasets
without pagination (e.g., chart/timeline data) SHOULD declare a maximum
allowed interval between `from_date` and `to_date`. When the interval
exceeds the declared limit, the endpoint returns **400 Bad Request** with
error code `DATE_RANGE_TOO_WIDE`. Paginated endpoints generally do not
need this constraint — pagination already bounds the response size.
Each endpoint that enforces this constraint MUST document its specific
limit in its own error table.

This ensures that "inclusive bounds" means inclusive of the full day when no
time component is specified. For the full timezone policy, see
`docs/conventions.md` (Timestamps & Timezones).

### Sorting

List endpoints support sorting:

- `sort_by` (string): Field name to sort by
- `sort_order` (string): `asc` or `desc` (default: `desc`)

**Default sort order**: when a paginated list endpoint does not document
specific sorting behavior, the implicit default is `sort_by=created_at`,
`sort_order=desc` (newest first). Endpoints with a different natural
ordering (e.g., alphabetical, severity-based) must state their default
explicitly.

Endpoints that intentionally do not support client-controlled sorting must
state so with justification (e.g., "fixed chronological order for timeline
display").

#### Semantic Sort Fields

When `sort_by` references a field with domain-defined ordinal semantics
(not alphabetical), the sort uses the semantic rank:

| Field | Ascending order (semantic rank) |
|-------|--------------------------------|
| `severity` | None (0) < Low (1) < Medium (2) < High (3) < Critical (4) |
| `status` | New (0) < Analysis (1) < Analyzed (2) < Resolved (3) < Ignored (4) < Duplicated (5) |

`None` is the resolved severity label for CVSS score 0.0 (rank 0 in the
semantic ordering). `NULL` (severity not yet resolved) is not part of the
ranking — NULL values sort last (see Nullable Sort Field Ordering below).

Endpoints that support sorting by semantic fields MUST note this in
their query parameter specification: "semantic ordering (see Sorting)".

#### Sort Parameter Validation

A `sort_by` value not present in the endpoint's documented list of valid
sort fields returns `422 VALIDATION_ERROR`. Similarly, a `sort_order`
value other than `asc` or `desc` returns `422 VALIDATION_ERROR`.

Rationale: sorting is a singular operation (one active field per
request). Unlike set-based enum filters — where removing an invalid
value still produces a valid narrower result — an invalid sort field
leaves the entire response ordering undefined. Silent fallback to the
default sort would mask client errors (e.g., typos in field names).

#### Deterministic Pagination Ordering

All paginated list endpoints MUST append a secondary sort by the
resource's primary key (`id`) when the primary `sort_by` field is not
guaranteed to be unique. This ensures deterministic pagination — clients
will never see duplicate items or miss items across pages due to
unstable ordering of rows with identical sort-key values.

If the primary `sort_by` field is the resource's primary key itself (or
another column with a UNIQUE constraint), the secondary sort is
redundant and MAY be omitted.

The secondary sort uses the same direction as `sort_order`. It is an
implementation-level concern — the `id` tiebreaker is NOT exposed as a
client-visible query parameter and is not documented in per-endpoint query
parameter tables. Per-endpoint specifications reference this cross-cutting rule
instead of repeating the secondary sort detail. A fixed-order paginated
endpoint applies the same requirement even without client-controlled sorting.

#### Nullable Sort Field Ordering

When `sort_by` references a nullable column, rows with `NULL` in that
column sort last regardless of `sort_order`. This ensures that missing
data never displaces meaningful values at the top of a result set,
independent of whether the client requested ascending or descending
order. Per-endpoint specifications reference this rule instead of
restating it.

### Request Tracing

Every API response includes an `X-Request-ID` header containing a UUID that
uniquely identifies the request. If the client sends an `X-Request-ID`
header, the server adopts it; otherwise the server generates one.

**Client-supplied value validation.** The server adopts the client-supplied
`X-Request-ID` value only if, after trimming leading/trailing whitespace, it
is non-empty, at most 128 characters long, and composed exclusively of
characters in `[A-Za-z0-9._-]`. If the value is absent, empty (or
whitespace-only), exceeds 128 characters, or contains any character outside
this set, the server discards it and generates a UUIDv7 instead — the
request is never rejected on account of an invalid `X-Request-ID` value. The
server does not truncate or sanitize an out-of-bounds value; it is either
adopted whole or discarded whole. If the client sends multiple
`X-Request-ID` headers, the server validates and considers only the first
occurrence; subsequent occurrences are ignored.

The request ID is propagated to all log entries produced during synchronous
request processing (see `docs/features/platform/logging.md` for scope
boundaries), enabling request-scoped debugging. Clients should log or
display the request ID when reporting errors to support staff.

See `docs/features/platform/logging.md` for the correlation ID mechanism
and log record schema.

### Rate Limiting

Rate limiting is not enforced at this time. When activated, the API will
communicate limits via standard headers:

- `X-RateLimit-Limit`: maximum requests allowed in the current window
- `X-RateLimit-Remaining`: requests remaining in the current window
- `X-RateLimit-Reset`: UTC epoch timestamp when the window resets

Clients that exceed the limit will receive `429 Too Many Requests`. Clients
SHOULD respect these headers proactively to avoid hitting limits.

## Response Conventions

### Response Format

All responses use JSON.

**Paginated list endpoints** return:

```json
{
  "data": [ ... ],
  "meta": {
    "total": 100,
    "page": 1,
    "per_page": 20
  }
}
```

**Single-resource and unpaginated list endpoints** return:

```json
{
  "data": { ... }
}
```

The `meta` object is present **only** on paginated list endpoints.
Unpaginated endpoints return the full dataset in `data` (clients can derive
the count from the array length). Endpoints that intentionally omit
pagination must state the justification (e.g., bounded dataset size).

Error responses follow this structure:

```json
{
  "code": "VALIDATION_ERROR",
  "detail": "Request validation failed",
  "errors": [
    {
      "loc": ["body", "field_name"],
      "msg": "Field required",
      "type": "missing"
    }
  ]
}
```

Fields:

- `code` (string, required): a stable machine-readable error identifier in
  UPPER_SNAKE_CASE. Clients MUST use this field (not `detail`) for
  programmatic error handling
- `detail` (string, required): a human-readable description of the error.
  May change without notice — do not match against this string
- `errors` (array, optional): field-level validation errors. Present only
  for `VALIDATION_ERROR` responses. This array uses Pydantic v2's native
  validation error format, produced automatically by FastAPI. Each
  element has the following schema:
  - `loc` (array of strings/integers, required): the path to the invalid
    field within the request payload, e.g. `["body", "field_name"]` or
    `["query", "per_page"]`
  - `msg` (string, required): a human-readable error message
  - `type` (string, required): a stable machine-readable error type
    identifier, e.g. `"missing"`, `"string_type"`

#### Error Code Categories

Error codes are grouped by prefix:

| Prefix | Domain | Examples |
|--------|--------|----------|
| `VALIDATION_*` | Input validation | `VALIDATION_ERROR`, `VALIDATION_FIELD_REQUIRED` |
| `AUTH_*` | Authentication and authorization | `AUTH_NOT_AUTHENTICATED`, `AUTH_INSUFFICIENT_PERMISSION`, `AUTH_API_KEY_INVALID`, `AUTH_API_KEY_NOT_FOUND`, `AUTH_API_KEY_NAME_CONFLICT`, `AUTH_API_KEY_NAME_INVALID`, `AUTH_API_KEY_INVALID_EXPIRY`, `AUTH_SSO_FAILED`, `AUTH_SSO_USER_NOT_FOUND`, `AUTH_SSO_USER_INACTIVE`, `AUTH_SESSION_REQUIRED`, `AUTH_INVALID_CREDENTIALS`, `AUTH_ACCOUNT_LOCKED`, `AUTH_SSO_STATE_INVALID`, `AUTH_SSO_DISABLED`, `AUTH_LOGOUT_NOT_APPLICABLE` |
| `TICKET_*` | Ticket operations | `TICKET_NOT_FOUND`, `TICKET_ALREADY_RESOLVED`, `TICKET_INVALID_TRANSITION`, `TICKET_NOT_MUTABLE`, `TICKET_NOT_CONFIDENTIAL`, `TICKET_DUPLICATE_TARGET_DUPLICATED`, `TICKET_DUPLICATE_CONCURRENT_MODIFICATION`, `TICKET_SELF_DUPLICATE`, `TICKET_CVE_CONFLICT`, `TICKET_CVE_ALREADY_SET`, `TICKET_SEVERITY_DERIVED`, `TICKET_ASSIGNEE_NOT_VA`, `TICKET_ASSIGNEE_INACTIVE` |
| `CVE_*` | CVE operations | `CVE_NOT_FOUND`, `CVE_FETCH_FAILED`, `CVE_INVALID_SOURCE`, `CVE_INVALID_FORMAT` |
| `CVSS_*` | CVSS assessment operations | `CVSS_INVALID_VECTOR`, `CVSS_ASSESSMENT_NOT_FOUND`, `CVSS_RECALC_ALREADY_IN_PROGRESS` |
| `RESOURCE_*` | Generic resource errors | `RESOURCE_NOT_FOUND`, `RESOURCE_CONFLICT`, `RESOURCE_GONE`, `RESOURCE_NOT_EDITABLE` |
| `PACKAGE_*` | Package operations | `PACKAGE_NOT_FOUND_IN_SMELT`, `PACKAGE_TARGETS_UNRESOLVED`, `PACKAGE_ALREADY_EXCLUDED`, `PACKAGE_NOT_EXCLUDED` |
| `PRODUCT_*` | Product catalog operations | `PRODUCT_CATALOG_NOT_READY` |
| `ROLE_MAPPING_*` | Role mapping operations | `ROLE_MAPPING_GROUP_NOT_FOUND`, `ROLE_MAPPING_INVALID_GROUP_NAME` |
| `FETCHER_*` | Fetcher operations | `FETCHER_NOT_FOUND`, `FETCHER_ALREADY_RUNNING`, `FETCHER_DEREGISTERED`, `FETCHER_DISABLED`, `FETCHER_SETTING_UNKNOWN`, `FETCHER_SETTING_INVALID` |
| `USER_*` | User operations | `USER_NOT_FOUND`, `USER_ALREADY_EXISTS`, `USER_INACTIVE`, `USER_ALREADY_INACTIVE`, `USER_EXTERNAL_STATUS_READONLY`, `USER_EXTERNAL_FIELD_READONLY`, `USER_EXTERNAL_PASSWORD_FORBIDDEN`, `USER_EXTERNAL_ROLE_PROTECTED`, `USER_SELF_ROLE_REMOVAL`, `USER_SELF_DEACTIVATION`, `USER_PASSWORD_POLICY_VIOLATION` |
| `DATE_RANGE_*` | Date range filter validation | `DATE_RANGE_INVERTED`, `DATE_RANGE_TOO_WIDE` |
| `INTERNAL_*` | Framework | `INTERNAL_ERROR` |
| `<DEPENDENCY>_UNAVAILABLE` | Infrastructure dependency availability (external service or broker unreachable) | `REDIS_UNAVAILABLE`, `SMELT_UNAVAILABLE`, `CELERY_UNAVAILABLE`, `PROVISIONING_UNAVAILABLE`, `SSO_UNAVAILABLE` |

Rules:

- Every new error introduced in the codebase MUST have a corresponding code
  with the appropriate prefix
- Codes are defined as a Python enum in the backend (`app/core/errors.py`)
  and are part of the API contract — removing or renaming a code is a
  breaking change
- When an error does not fit an existing category, use the `RESOURCE_*`
  prefix for generic cases or introduce a new prefix if a distinct domain
  emerges

#### Infrastructure Dependency Errors (HTTP 503)

When an endpoint fails because an external dependency is unreachable,
use a domain-specific error code that identifies the unavailable service.
Do not use a generic code — the client and operator need to know *which*
dependency failed.

Pattern: `<DEPENDENCY>_UNAVAILABLE` with HTTP 503.

**Status-reporting exception**: an endpoint whose defined purpose is to
report the operational state of a dependency or process may represent an
unavailable dependency as a successful status observation rather than a
request failure. The owning endpoint specification MUST define the response
status and body explicitly. This exception applies only when the endpoint can
still fulfill its monitoring contract without the dependency; it does not
apply to domain operations that require the dependency to complete their
work. For example, `GET /api/v1/ibs-consumer/status` returns `200` with
`status = "unreachable"` when Redis cannot be read, because the endpoint has
successfully reported that consumer liveness cannot be confirmed.

A status endpoint that combines durable state with a best-effort transient
overlay may likewise return the durable state when the overlay dependency is
unavailable, provided its owning specification explicitly identifies which
information may be stale or omitted. For example,
`GET /api/v1/cves/{cve_id}/sources` continues to return persisted source
status when Redis pending-key lookup fails; only the transient `pending`
overlay is unavailable.

Examples:

| Code | Dependency |
|------|------------|
| `REDIS_UNAVAILABLE` | Redis cache/session store |
| `PROVISIONING_UNAVAILABLE` | External identity provider |
| `SMELT_UNAVAILABLE` | SMELT API |
| `SSO_UNAVAILABLE` | SSO identity provider (OIDC discovery) |
| `CELERY_UNAVAILABLE` | Celery task broker (task dispatch failed) |

### Global Responses

The following responses may be returned by any endpoint that processes
authentication due to shared dependencies. Individual endpoint error tables
document only endpoint-specific errors; global responses are not repeated.

| Status | Code                     | Condition                                      | Source                         |
|--------|--------------------------|------------------------------------------------|--------------------------------|
| 401    | `AUTH_NOT_AUTHENTICATED` | Credential required but absent, or selected credential invalid | Authentication dependency |
| 403    | `AUTH_INSUFFICIENT_PERMISSION` | User authenticated but lacks required capability | `require_capability` dependency |
| 422    | `VALIDATION_ERROR`       | Request body/query/path fails schema validation | FastAPI automatic (Pydantic)   |
| 500    | `INTERNAL_ERROR`         | Unhandled server error                         | Framework                      |

Notes:

- **Public endpoints without optional authentication** are exempt from 401;
  Public endpoints with `Authentication: Optional` accept absence but return
  401 when a selected credential fails validation
- The 401 response body is always `{"code": "AUTH_NOT_AUTHENTICATED",
  "detail": "Authentication required"}` regardless of the specific failure
  reason — no information about the failure cause is disclosed
- The 422 response uses Pydantic's native format with the `errors` array
  populated with field-level details
- The 403 response detail is always `"Insufficient permissions"` — it
  MUST NOT disclose which capability was required

#### What belongs in an endpoint error table

An error row belongs in a per-endpoint table **if and only if** its
condition conveys information specific to that endpoint that is not
already stated by the Global Responses table above or the Scoped
Responses section below.

**Include**: errors with endpoint-specific codes (e.g., `TICKET_CVE_CONFLICT`),
errors from service exceptions with domain semantics (e.g.,
`PACKAGE_ALREADY_EXCLUDED`), and errors with a different error code from
the global one for the same status (e.g., `AUTH_SESSION_REQUIRED` instead
of generic `AUTH_INSUFFICIENT_PERMISSION`).

**Exclude**: generic `401 AUTH_NOT_AUTHENTICATED`, generic `403
AUTH_INSUFFICIENT_PERMISSION`, generic `422 VALIDATION_ERROR` (Pydantic
schema failures), `500 INTERNAL_ERROR`, and the shared
`DATE_RANGE_INVERTED` response for endpoints that declare both date range
parameters. These are derivable and provide no endpoint-specific information.

**Conditional authorization**: when an endpoint has authorization logic beyond
a fixed `require_capability()` guard, document the complete condition in the
**Behavior** section or capability declaration — not as a 403 row in the error
table. This includes both a secondary capability required for a specific field
and payload-dependent substitution where one capability replaces another.
The HTTP response is still the generic `AUTH_INSUFFICIENT_PERMISSION` (the
consumer cannot distinguish it).

**Pydantic-level validation**: constraints enforceable via Pydantic
schema definitions (type, enum membership, string length, regex, cross-field
exclusivity, required fields) produce the global `422 VALIDATION_ERROR`
automatically. Do not add a separate row for these. Only
domain-specific validation with a **dedicated error code** (e.g.,
`CVSS_INVALID_VECTOR`, `FETCHER_SETTING_INVALID`) warrants a table row.

**Reading contract**: if an endpoint section has no error table, it
produces only the responses derivable from its access level and path
(see Response Applicability Derivation below). If it has an error table,
the table lists only endpoint-specific errors — global and scoped
responses are always implicit and derivable from context. Per-endpoint
reference lines are not used.

### Scoped Responses

Some shared dependencies apply to a specific resource group rather than to
all endpoints. Like global responses, scoped responses are not repeated in
per-endpoint error tables.

#### Ticket Accessibility Check

All endpoints under `/api/v1/tickets/{ticket_id}/`, plus any operation whose
path identifies a Ticket by another prefix, use the Ticket accessibility
boundary role conventionally named `require_accessible_ticket`. The name
describes observable boundary behavior, not a Core ORM implementation or a
mandatory standalone preliminary query. A thin API dependency may perform the
role by delegating to a service; a service may satisfy it directly as part of
the read selection or locked mutation required by the flow above.

The path value follows Ticket Identifier Resolution below. The service applies
the single canonical predicate in `docs/features/identity/rbac.md`. A malformed
locator, a Ticket UUID supplied as the locator, a well-formed locator with no
matching Ticket, and an inaccessible Ticket all return the same `404
TICKET_NOT_FOUND` response. These outcomes are indistinguishable. Reads select
the returned Ticket or Ticket-derived resource under the predicate. Mutations
apply it to locked-current state as specified by their flow.

| Status | Code              | Condition                                            |
|--------|-------------------|------------------------------------------------------|
| 404    | `TICKET_NOT_FOUND`| Ticket locator is invalid, does not exist, or identifies a Ticket inaccessible to the caller |

#### CVE Accessibility Check

All endpoints under `/api/v1/cves/{cve_id}/` use the CVE accessibility boundary
role conventionally named `require_accessible_cve`. As with the Ticket role,
this is observable behavior delegated to a model-aware service, not a Core ORM
implementation or a required router-level preliminary query.

The service parses CVE-ID syntax through the pure Core parser, then resolves the
database resource and applies these semantics in the selected result:

1. A CVE with no associated Ticket is public.
2. A CVE with an associated Ticket is accessible exactly when that Ticket
   satisfies the canonical Ticket visibility predicate.
3. A malformed, missing, or inaccessible CVE returns `404 CVE_NOT_FOUND`.

| Status | Code              | Condition                                           |
|--------|-------------------|-----------------------------------------------------|
| 404    | `CVE_NOT_FOUND`   | CVE does not exist, or is associated with a confidential ticket and caller is not authorized |

All denial cases from this dependency return the same
`404 CVE_NOT_FOUND` response — never `TICKET_NOT_FOUND`.

**Post-accessibility service-layer errors**: mutation endpoints under
`/api/v1/cves/{cve_id}/` may still surface `409 TICKET_NOT_MUTABLE`
from `ensure_ticket_operable()` at the service layer. This applies
only when the CVE has an associated ticket in a manual-zone status
(see Manual-Zone Mutability Guard below)

Anonymous selection never performs grant or maintainer lookup and therefore
includes an associated CVE only when its Ticket is non-confidential. The CVE
boundary consumes the canonical Ticket predicate rather than implementing a
second semantic predicate. `GET /api/v1/cves` applies the same association rule
inside its service-owned list query.

#### Maintainer Ticket Accessibility Check

`GET /api/v1/my/packages/ticket/{ticket_id}` is not under the Ticket router, but
its path identifies one Ticket and therefore derives the same `404
TICKET_NOT_FOUND` scoped response. The service selects an accessible Ticket
before evaluating Ticket status, maintainer membership, `error_state`, or
`duplicate_of_ticket_id`. A missing or inaccessible Ticket is
indistinguishable; no
status-specific or `no_packages` projection may reveal it first.

#### Anti-Enumeration Boundary

The not-found rules above conceal protected Ticket-derived content and direct
resource reads: a caller cannot distinguish a missing Ticket/CVE from one made
inaccessible by an associated confidential Ticket. This guarantee does not make
`SNTL-{n}` identifiers or CVE IDs confidential data. A Ticket UUID is an
internal identifier and is not part of the API contract.

Existing identifier-only contracts remain unchanged:

- a visible Duplicated Ticket may return `duplicate_of_ticket_id = SNTL-{n}`
  even when following that target now returns `TICKET_NOT_FOUND`;
- `TICKET_CVE_CONFLICT` retains `existing_ticket_id`, including when that
  Ticket is otherwise inaccessible; the value is the conflicting Ticket's
  `SNTL-{n}` identifier; and
- the global CVE-source listing may return CVE IDs without applying Ticket
  visibility.

These bounded exceptions expose identifiers only. They do not expose protected
Ticket content, authorize a direct read, add a capability, or change any
resource-accessibility result.

#### Manual-Zone Mutability Guard

Tickets in the **manual zone** (status `Ignored` or `Duplicated`) reject
ordinary workflow and gate-relevant mutation endpoints with `409
TICKET_NOT_MUTABLE`. This is enforced at the service layer by
`ensure_ticket_operable()` (defined in `ticket_mutations`) after acquiring
`FOR UPDATE` on the Ticket row. An owning mutation contract may declare a
genuine exception when the operation is independent from Ticket workflow and
gate state.

| Status | Code                  | Condition                                          |
|--------|-----------------------|----------------------------------------------------|
| 409    | `TICKET_NOT_MUTABLE`  | Ticket is in Ignored or Duplicated status          |

**Exceptions** — the following service functions are excluded from this check:

- `reopen_from_ignored` and `revert_duplicate`, which manage the dedicated
  manual-zone exit lifecycle;
- `set_confidentiality`, `grant_access`, and `revoke_access`, which change only
  Ticket visibility state and neither assign nor reconcile or exit the manual
  zone; and
- `dispatch_ticket_convergence`, which validates its own eligible status set.

Read endpoints (GET) are never subject to this guard.

See `docs/features/tickets/tickets.md` ([Mutability Guard](features/tickets/tickets.md#mutability-guard))
for the full specification.

### Response Applicability Derivation

Global and scoped responses are mechanically derivable from the endpoint's
access level, path pattern, and declared query shape. Per-endpoint reference
lines are **not required** and MUST NOT be added to new or existing endpoints.
The derivation tables below are the single normative source of truth.

#### Global Response Derivation

| Access level | Applicable global responses |
|---|---|
| `Access: Public` | `422 VALIDATION_ERROR`, `500 INTERNAL_ERROR` |
| `Access: Public` + `Authentication: Optional` | `401 AUTH_NOT_AUTHENTICATED`, `422 VALIDATION_ERROR`, `500 INTERNAL_ERROR` |
| `Access: Authenticated` | `401 AUTH_NOT_AUTHENTICATED`, `422 VALIDATION_ERROR`, `500 INTERNAL_ERROR` |
| `Capability: <any>` | `401 AUTH_NOT_AUTHENTICATED`, `403 AUTH_INSUFFICIENT_PERMISSION`, `422 VALIDATION_ERROR`, `500 INTERNAL_ERROR` |

#### Scoped Response Derivation

| Path pattern | Scoped responses |
|---|---|
| `/api/v1/tickets/{ticket_id}/**` | `404 TICKET_NOT_FOUND` |
| `/api/v1/cves/{cve_id}/**` | `404 CVE_NOT_FOUND` |
| `/api/v1/my/packages/ticket/{ticket_id}` | `404 TICKET_NOT_FOUND` |
| Mutation (POST/PATCH/DELETE) under `/api/v1/tickets/{ticket_id}/**` | + `409 TICKET_NOT_MUTABLE`, except when the owning endpoint contract declares an opt-out from `ensure_ticket_operable()` |
| Mutation (POST/PATCH/DELETE) under `/api/v1/cves/{cve_id}/**` | + `409 TICKET_NOT_MUTABLE` (only when CVE has associated ticket) |
| Any other path | None |

#### Query-Shape Response Derivation

| Declared query parameters | Applicable shared responses |
|---|---|
| Both `from_date` and `to_date` | `400 DATE_RANGE_INVERTED` when the normalized range is inverted |

Note: `TICKET_NOT_MUTABLE` applies only to mutation endpoints
(POST/PATCH/DELETE) under the scoped routers listed above. GET endpoints
under the same routers receive only the `NOT_FOUND` scoped response.
The mechanism behind `TICKET_NOT_MUTABLE` is `ensure_ticket_operable()`
— see Manual-Zone Mutability Guard above. Endpoints excluded from
`ensure_ticket_operable()` (manual-zone exit, visibility-only, and async
dispatch endpoints) are annotated per-endpoint and do not produce
`TICKET_NOT_MUTABLE`.

#### Genuine Exceptions

If an endpoint **deviates** from the derivation rules above (e.g., an
authenticated endpoint that does not use the standard authentication
middleware, or an endpoint under a scoped router that bypasses the
router dependency), annotate the deviation directly in the endpoint
section. The annotation must explain HOW and WHY the endpoint deviates
— it is not a formulaic reference line but a substantive explanation
of non-standard behavior.

Section-level declarations (e.g., "Global responses per api-spec.md
apply to all endpoints in this section") are not necessary and MUST NOT
be used — the derivation rules apply uniformly by access level and path.

## Identifier Resolution

### Ticket Identifier Resolution

`SNTL-{n}` is the sole consumer-facing Ticket identity. Every `{ticket_id}`
path value and every Ticket reference in a request or response uses the
canonical uppercase form `SNTL-{n}`. `Ticket.id` remains the internal UUIDv7
primary key used by PostgreSQL relationships, service and task boundaries,
locking, and internal deterministic ordering. The API never accepts that UUID
as a Ticket locator and never serializes it as a Ticket identity.

The canonical grammar is `^SNTL-[1-9][0-9]*$`, with `n` no greater than the
positive PostgreSQL `INTEGER` maximum. Parsing performs no trimming, case
normalization, sign handling, or zero-padding normalization. Lowercase prefixes,
leading or trailing whitespace, `SNTL-0`, signed values, padded values such as
`SNTL-0042`, overflow, UUIDs, and every other shape are malformed.

For a Ticket path, syntax parsing and database resolution deliberately share
the scoped not-found contract: malformed, missing, and inaccessible values all
produce `404 TICKET_NOT_FOUND`. The pure grammar/range parser may live in Core;
lookup by the unique `Ticket.sequence_id` and application of Ticket visibility
belong to the Service layer. API dependencies may pass through or parse the
string and map the service outcome, but they perform no Ticket ORM query.

A request-body field that names another Ticket uses the same canonical value
grammar but ordinary Pydantic validation semantics. In particular,
`duplicate_of_ticket_id` with malformed syntax produces the global `422
VALIDATION_ERROR`; a well-formed target that is missing or inaccessible
produces `404 TICKET_NOT_FOUND`. Response fields use `ticket_id` for a root or
embedded Ticket reference, `duplicate_of_ticket_id` for a duplicate target, and
`existing_ticket_id` in `TICKET_CVE_CONFLICT`. Parallel Ticket fields named
`id`, `identifier`, or `ticket_sequence_id` are not exposed.

This rule is specific to Ticket identity. UUIDs that identify Users,
TicketPackage/Track/Product occurrences, Ticket references, audit events, IBS
request actions, tasks, and other non-Ticket resources retain their owning API
contracts. Structured operational logs and internal Celery/service payloads
also retain their owning internal Ticket UUID contracts.

### User Identifier Resolution

All parameters that identify a user — whether path parameters, query
parameters, or request body fields — accept either a UUID or a username.
Resolution is automatic:

- If the value is a valid UUID (RFC 4122 format), lookup is by primary key
  (`User.id`)
- Otherwise, lookup is by the `username` field (case-sensitive exact match)
- If no user matches either lookup, the endpoint returns 404 with error code
  `USER_NOT_FOUND`. This 404 convention applies to parameters that identify a
  **single target resource** (path parameters, request body fields). Optional
  filter parameters on list endpoints (e.g., `?actor=jdoe`) do NOT return
  404 — a non-matching value produces an empty result set instead

Response payloads always contain the user's UUID (never the username as
identifier). The database persists only UUIDs in foreign keys and
relationships.

#### User References in Responses

When a response payload includes a reference to a user (e.g., `actor`,
`assignee`, `target_user`, `created_by`), it is serialized as an object
with `id`, `username`, `full_name` (nullable), and `active` — populated
via JOIN to the **current** User record. These values reflect the
user's current profile data, not a historical snapshot at the time of
the event or action.

Historical values, where relevant, are preserved in dedicated fields of
the owning entity (e.g., `old_value` / `new_value` in audit events).
The `id` (UUID) is the stable, immutable identifier; `username`,
`full_name`, and `active` are display conveniences that may change over
time (e.g., via external sync or deactivation). The `full_name` field
is nullable — it is returned as `null` when the user has no display
name set, with no substitution of `username` or any other fallback
value.

Users are never physically deleted from the database — all foreign keys
referencing the User table use `ON DELETE RESTRICT`. Deactivated users
(`active=false`) are resolved normally, with all fields (`id`, `username`,
`full_name`, `active`) populated from current data. Consequently, a user
reference object is never null or partial when `user_id` is non-null — if
a `user_id` foreign key is present, the referenced user record is
guaranteed to exist and the serialized object will always be complete
(`full_name` may itself be `null`, but the object's presence and its
other fields are always populated).

This convention applies to:

- Path parameters (e.g., `/api/v1/users/{user}`)
- Query parameters (e.g., `?assignee=jdoe`)
- Request body fields (e.g., `{"user_id": "jdoe"}`)

The special filter value `none` (used in query parameters like `assignee`)
is not subject to user resolution — it is handled as a literal keyword
before resolution is attempted.

Implementation note: the owning domain service performs detection and lookup;
identity consumers use `user_service.resolve_user_identifier()`. API
dependencies may parse or pass through the path value but do not execute the
ORM query. See `docs/conventions.md` (FastAPI Conventions) and
`docs/features/identity/user-service.md`.

### CVE Identifier Resolution

The `{cve_id}` path parameter in `/api/v1/cves/` endpoints accepts
a CVE-ID string (e.g., `CVE-2024-1234`). The CVE's internal UUID is
never accepted as input and is not exposed in API responses.

- If the value matches the CVE-ID format (see `CVE_ID_PATTERN` below),
  lookup is by the `CVE.cve_id` column (UNIQUE indexed)
- Otherwise, return `404 CVE_NOT_FOUND`

The CVE-ID string is the natural, globally unique identifier used across all
security tooling (NVD, MITRE, advisories). Like the Sentinel-minted immutable
Ticket identifier, it provides the complete public identity while the internal
UUID serves no external purpose. User identity remains different because a
mutable username and stable UUID are both accepted under the User contract.

The CVE-ID format parser is pure and may live in Core. The canonical
`CVE_ID_PATTERN` in `backend/app/core/identifiers.py` (anchored regex
`^CVE-[0-9]{4}-[0-9]{4,}$`) is the single source of truth for syntax
validation. Database resolution and accessibility selection belong to a
service; API dependencies do not perform the ORM lookup.

### Product Identifier Resolution

Product API representations use the canonical Product CPE as their public
identity. The internal UUIDv7 `Product.id` is a database primary key and
foreign-key target only; it is not serialized in API responses and is not
accepted as an API input.

This rule does not apply to ticket-scoped package-tree resources. A
`TicketPackageProduct` is a mutable occurrence of one Product under one Ticket
package and track. Its UUID identifies that occurrence in package-tree
responses and mutation paths, while `product_cpe` identifies the related
catalog Product. `TicketPackage` and `TicketPackageTrack` UUIDs similarly remain
public mutation locators.

`ProductRepository` is an internal catalog association. Its UUID is never
serialized or accepted by the API; repository names are exposed only when an
owning endpoint explicitly requires them.

## Mutation Conventions

### Mutation Patterns

Two patterns exist for modifying resources:

**PATCH — field update on an identified resource:**

```
PATCH /api/v1/tickets/{ticket_id}/severity
Body: {"severity": "critical"}
```

Used when the client sets one or more fields on a resource clearly
identified by the URL and the field assumes the requested value
(predictable outcome). Side effects are permitted when they are **domain
cascading consequences** — that is, reactions intrinsic to the data model
such as:

- Status propagation to related entities
- Eligibility or threshold re-evaluation
- Audit event creation

These side effects are a consequence of the domain model, not additional
business workflows. The operation remains a PATCH because from the
client's perspective the semantics are "update this field on this
resource."

**POST with action verb — operation or command:**

```
POST /api/v1/tickets/{ticket_id}/ignore
Body: {"reason": "..."}
```

Used when the operation has characteristics that go beyond a field
update:

- **State machine guards** that may reject the operation (the field is
  not freely settable to any value)
- **Creation or destruction of separate entities** (not just cascading
  re-evaluation of existing records)
- **Irreversible operations** where the semantic weight is "execute a
  procedure" (revoke, delete, deactivate)
- **Lifecycle transitions** with cross-entity destructive mutations
  (session invalidation, key revocation, ticket reassignment)
- **Multi-entity commands** that affect multiple independent resources
  in a single operation

Rule of thumb: if the client perceives the operation as "set this field
to this value" and the field will reliably assume that value (barring
validation errors), use PATCH. If the client perceives the operation as
"perform this action" with guards, workflows, or irreversible
consequences beyond the target field, use POST with an action verb.

### Partial Update Semantics

All PATCH endpoints follow partial update semantics inspired by RFC 7396
(JSON Merge Patch). The request body includes only the fields the client
wants to change. Three cases are distinguished:

| Payload state              | Behavior                                        |
|----------------------------|-------------------------------------------------|
| Field **omitted**          | Current value is preserved (no change)           |
| Field present with **value** | Field is updated to the provided value          |
| Field present with **`null`** | Field is set to NULL in the database            |

Sending `null` is only meaningful for fields that are nullable in the
data model. Sending `null` for a non-nullable field results in a `422
VALIDATION_ERROR`.

When all fields in a PATCH request body are optional, the endpoint MUST
reject an empty body (no fields provided) with `422 VALIDATION_ERROR`
and the message `"At least one field must be provided."`. This does not
apply to single-field PATCH endpoints where the field is required.

Individual endpoint specifications document any domain-specific
semantics that `null` may carry beyond "clear the value" (e.g.,
resetting a computed value to automatic calculation, reverting to a
system default). The partial update semantics defined here are the
baseline; domain-specific meaning is additive.

Implementation note: in Pydantic v2, distinguishing "field omitted" from
"field explicitly set to `null`" requires a sentinel pattern (e.g., an
`UNSET` constant as the field default) or inspecting `model_fields_set`
after parsing. Standard `Optional[X] = None` conflates the two cases and
MUST NOT be used for PATCH request schemas with nullable fields.

## Naming Conventions

### Audit Trail Endpoint Naming

Every audit trail retrieval endpoint MUST use the `/audit-log` suffix.
The general pattern is `/{resource-scope}/audit-log`:

- Entity-scoped: `GET /api/v1/tickets/{ticket_id}/audit-log`
- Admin-scoped: `GET /api/v1/admin/identity/audit-log`
- Nested: `GET /api/v1/admin/settings/audit-log`
- Named resource: `GET /api/v1/fetchers/{fetcher_name}/audit-log`

See `docs/features/platform/audit-trail-infrastructure.md` for the full
audit trail specification.

## Endpoint Index

Each feature specification in `docs/features/` authoritatively defines its
own API endpoints with full request/response schemas, error codes, and
behavioral details.

For a complete cross-cutting index of all API endpoints — with HTTP
methods, paths, access levels, and links to the owning feature
specifications — see the
[Endpoint Permission Map](features/identity/rbac.md#endpoint-permission-map)
in the RBAC specification.
