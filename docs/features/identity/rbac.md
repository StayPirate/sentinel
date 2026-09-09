# Role-Based Access Control (RBAC)

## Purpose

Control access to platform features using a capability-based authorization
model. Each predefined role grants a set of **capabilities** (what operations
a user can perform) and a **scope** (what resources a user can see). Users can
hold zero, one, or multiple roles. Capabilities and scopes are resolved at
request time from the user's roles.

## Authorization Model

### Capabilities

Capabilities are static enums defined in code. Each capability covers a
cohesive set of operations that are logically granted or denied together.
Endpoints are protected by capability checks applied according to their owning
endpoint contract.

#### Vulnerability Analyst Capabilities

| Capability | Operations Covered |
|---|---|
| `create_ticket` | Create ticket manually |
| `triage_ticket` | Assign/reassign ticket, change ticket status (all transitions: ignore, reopen, duplicate, revert-duplicate), associate CVE with ticket, set/update manual severity |
| `manage_packages` | Add/remove packages from tickets, exclude/restore (package, track, product), change track affectedness to any non-`FIXED` status, override product eligibility |
| `manage_cvss` | Add/edit/delete SUSE CVSS assessments |
| `manage_references` | Add/edit/delete ticket references |
| `manage_confidentiality` | Set ticket confidentiality flag, list/grant/revoke access grants |

#### Admin Capabilities

| Capability | Operations Covered |
|---|---|
| `manage_users` | Create local users, update user fields, manage user roles, reset password, deactivate/reactivate, unlock, view deactivation impact, view/revoke all API keys, view admin-scoped identity audit log |
| `manage_role_mappings` | Group-to-role mapping CRUD, preview role mapping |
| `manage_settings` | View/update system settings, trigger CVSS recalculation, view settings audit log |
| `manage_fetchers` | Trigger manual fetcher run, enable/disable fetchers, view/modify fetcher config, view fetcher audit log, view error details, view error tracebacks, view triggered_by_user identity, view disabled_by/enabled_by actors |
| `admin_ticket_ops` | Set track affectedness to `FIXED` from any status |

> **Design note — capability granularity**: capabilities are intentionally
> coarse (~11 total). The current three roles are well served by grouped
> capabilities. There is no foreseeable use case for partial grants within
> a group (e.g., "can assign but not change status"). Splitting a coarse
> capability later is a bounded, mechanical refactor (~12 endpoint
> decorators + tests for the two largest groups), not an architectural
> change. The capability groupings may be refined in the future if a new
> role requires a subset of operations within an existing group.

### Scope

Scope determines the default visibility of confidential tickets. It is
orthogonal to capabilities — scope controls *what you can see*, while
capabilities control *what you can do*.

| Scope | Meaning |
|---|---|
| `all` | Unrestricted — all tickets visible including confidential |
| `non_confidential` | Confidential tickets are invisible by default (see Scope and Confidential Ticket Visibility) |

**Scope resolution**: if any of the user's roles has scope `all`, the
effective scope is `all`. Otherwise, the effective scope is
`non_confidential`. Authenticated users with no roles have an effective
scope of `non_confidential`. Unauthenticated users have no scope (treated
as `None` — only non-confidential tickets visible, no grant/maintainership
checks).

> **Design note — scope is API-layer only**: scope is enforced at the API
> layer via `confidential_ticket_filter()` in query endpoints and
> `require_accessible_ticket` in single-ticket endpoints. It does not
> apply to the service layer or background tasks. Celery workers,
> fetchers, and event consumers process all tickets (including
> confidential ones) without scope restrictions. Scope is an
> access-control concept, not a data-partitioning concept.

### Predefined Roles

Roles are static definitions mapping to a set of capabilities and a scope.
Adding a new access profile requires a code change (PR + deploy) — there
is no runtime role management by admins beyond assigning existing roles to
users.

| Role | Capabilities | Scope |
|---|---|---|
| `admin` | `manage_users`, `manage_role_mappings`, `manage_settings`, `manage_fetchers`, `admin_ticket_ops` | `all` |
| `vulnerability_analyst` | `create_ticket`, `triage_ticket`, `manage_packages`, `manage_cvss`, `manage_references`, `manage_confidentiality` | `all` |
| `restricted_analyst` | `create_ticket`, `triage_ticket`, `manage_packages`, `manage_cvss`, `manage_references` | `non_confidential` |

Design notes:

- `admin` does NOT inherit VA capabilities. A user needing both must hold
  both roles (unchanged from current design)
- `restricted_analyst` shares all VA capabilities except
  `manage_confidentiality` — this role cannot set the confidentiality
  flag or manage access grants
- A user holding multiple roles receives the **union** of all capabilities
  and the **least restrictive** scope (i.e., if any role has `all`, the
  effective scope is `all`). The admin is responsible for role assignments
  — the system does not enforce mutual exclusivity between roles
- A user with no roles has an effective scope of `non_confidential` and no
  capabilities. They can still access specific confidential tickets via
  `TicketAccessGrant` or package maintainership — these per-ticket mechanisms
  are independent of scope

> **Design note — VA role granularity**: the VA role intentionally bundles
> triage, assessment, and package management into a single role. Sentinel
> targets a small security team where all analysts perform the full
> triage-to-resolution workflow. Introducing sub-roles would increase
> complexity for a scenario that has no current demand. The role can be
> split by adding new roles and redistributing capabilities — no
> architectural change is required.

## Access Levels

Access levels describe authentication state, not authorization. They do
not carry capabilities or scope.

### Public

No authentication required. Public endpoints that declare optional
authentication resolve a caller when a valid credential is selected and
otherwise apply their anonymous behavior. Read-only access to platform data:
- View users (list and detail)
- View tickets, CVEs, products, packages, and ticket package trees
- View ticket references, CVSS assessments, and submission/release requests
- View fetcher dashboard (list, detail, charts, run history, error messages)

### Authenticated

Any logged-in user, regardless of role. Includes all Public access plus:
- Logout (terminate own session)
- View own profile (`/api/v1/users/me`)
- Manage own API keys (list, create, revoke)
- View own identity audit log (`/api/v1/users/me/audit-log`)
- View maintainer dashboard (own pending, in-progress, and completed packages)
- View ticket audit logs

## Permission Matrix

### Capability-Protected Operations

| Action | Required Capability |
|---|---|
| Create ticket manually | `create_ticket` |
| Assign/reassign ticket | `triage_ticket` |
| Change ticket status (ignore, reopen, duplicate, revert-duplicate) | `triage_ticket` |
| Associate CVE with ticket | `triage_ticket` |
| Set/update manual severity | `triage_ticket` |
| Add/remove packages from tickets | `manage_packages` |
| Exclude/restore package, track, or product | `manage_packages` |
| Change track affectedness to any non-`FIXED` status | `manage_packages` |
| Override product eligibility | `manage_packages` |
| Add/edit/delete SUSE CVSS assessments | `manage_cvss` |
| Add/edit/delete ticket references | `manage_references` |
| Set ticket confidentiality | `manage_confidentiality` |
| Manage access grants on confidential tickets | `manage_confidentiality` |
| Set track affectedness to `FIXED` from any status | `admin_ticket_ops` |
| Create local user | `manage_users` |
| Update user fields | `manage_users` |
| Manage user roles | `manage_users` |
| Reset user password | `manage_users` |
| Deactivate/reactivate user | `manage_users` |
| Unlock user | `manage_users` |
| View deactivation impact | `manage_users` |
| View/revoke all API keys | `manage_users` |
| View admin-scoped identity audit log | `manage_users` |
| Group-to-role mapping CRUD | `manage_role_mappings` |
| Preview role mapping | `manage_role_mappings` |
| View/update system settings | `manage_settings` |
| Trigger CVSS recalculation | `manage_settings` |
| View settings audit log | `manage_settings` |
| Trigger manual fetcher run | `manage_fetchers` |
| Enable/disable fetchers | `manage_fetchers` |
| View fetcher config | `manage_fetchers` |
| Modify fetcher config | `manage_fetchers` |
| View fetcher audit log | `manage_fetchers` |
| View fetcher error details | `manage_fetchers` |
| View fetcher error tracebacks | `manage_fetchers` |
| View triggered_by_user identity | `manage_fetchers` |
| View disabled_by/enabled_by actors | `manage_fetchers` |

> **Assignment target constraint**: the `triage_ticket` capability allows
> performing assignment operations, but the target user MUST hold the
> `vulnerability_analyst` role **and be active**. Assigning to a user
> without this role or to an inactive user is rejected with 400 Bad
> Request. This is a business rule (who can own a ticket), not a
> capability check (who can invoke the endpoint). See Business Rule 10.

### Authenticated Operations

| Action | Access |
|---|---|
| Logout | Authenticated |
| View own profile | Authenticated |
| Manage own API keys | Authenticated |
| View own identity audit log | Authenticated |
| View maintainer dashboard | Authenticated |
| View ticket audit log | Authenticated |

### Public Operations

| Action | Access |
|---|---|
| View users (list and detail) | Public |
| View tickets / CVEs | Public |
| View packages and ticket package trees | Public |
| View products | Public |
| View ticket references | Public |
| View CVSS assessments | Public |
| View submission/release requests | Public |
| View fetcher dashboard | Public |

These application read operations use optional authentication. Authentication
bootstrap/recovery endpoints and infrastructure probes remain Public without
optional authentication.

## Scope and Confidential Ticket Visibility

Scope determines the **default** visibility of confidential tickets. It
does NOT override explicit per-ticket access mechanisms.

A ticket is visible to a user if ANY of the following is true:

1. The ticket is not confidential (always visible to everyone)
2. The user's effective scope is `all`
3. The user has an explicit `TicketAccessGrant` for this ticket
4. The user's ID matches a `TicketPackageMaintainer.user_id` whose parent
   `TicketPackage` belongs to this Ticket and has `deleted_at IS NULL`

The persisted user-ID association is package-wide. Track/Product exclusion,
Product lifecycle, and Ticket resolution do not revoke it; package exclusion
disables it until restore. Maintainership creates no `TicketAccessGrant`.
Like an explicit grant, maintainership changes visibility only. It grants no
capability; the caller can perform only operations already permitted by their
roles.

This means a user with `manage_confidentiality` capability can grant
explicit access to a confidential ticket to a user with
`non_confidential` scope. The grant overrides the scope restriction for
that specific ticket only. The grant provides full access (read and
write) — the user can perform any operation their capabilities allow on
the granted ticket. There is no read-only vs read-write distinction in access
grants; this is consistent with how grants work for all users.

Note that visibility alone does not imply write access. An authenticated
user with no roles who receives a `TicketAccessGrant` can see the ticket
but cannot modify it — they have no capabilities. A `restricted_analyst`
with a grant can both see and modify the ticket because they have
capabilities like `triage_ticket` and `manage_packages`. The two checks
are independent:

- **Scope** (+ grant/maintainership) determines: *can you see this ticket?*
- **Capability** determines: *can you perform this operation?*

Both checks must pass for a write operation to succeed.

The `confidential_ticket_filter()` function uses `caller_scope` instead
of `caller_is_privileged`:

```python
def confidential_ticket_filter(
    ...,
    caller_scope: Scope | None,     # None for unauthenticated
    caller_user_id: UUID | None,
    ...
)
```

When `caller_scope` is `None` (unauthenticated), the function
short-circuits: only non-confidential tickets are returned, and
grant/maintainership checks are skipped (no user identity to match against).

### Optional Principal to Caller Context

Public endpoints that depend on caller identity obtain
`AuthenticatedPrincipal | None` from `get_optional_current_user` before
building visibility or field-level authorization rules.

- For `None`, pass `caller_scope=None` and `caller_user_id=None`. No roles are
  loaded and grant/maintainership checks remain
  disabled as described above.
- For an `AuthenticatedPrincipal`, load the user's current roles, resolve the
  effective scope using the normal Scope resolution rule, and pass that scope
  together with `principal.user.id`.

Only a completely validated principal reaches this mapping. A selected invalid
credential returns 401 at the authentication boundary before confidentiality,
resource accessibility, or optional field-level capability checks execute.

## Endpoint Authorization

### `require_capability()` Dependency

Capability-protected endpoints use the `require_capability()` dependency:

```python
@router.post("/tickets")
async def create_ticket(
    ...,
    principal: AuthenticatedPrincipal = Depends(
        require_capability(Capability.CREATE_TICKET)
    ),
):
```

The dependency:

1. Obtains the `AuthenticatedPrincipal` from `get_current_user`
2. Loads the user's current roles from the `UserRole` table
3. Checks if any of the user's roles includes the required capability
   (using the static role definition map)
4. If yes, returns the `AuthenticatedPrincipal`; if no, returns 403 with
   error code `AUTH_INSUFFICIENT_PERMISSION` and detail
   `"Insufficient permissions"`

The 403 response MUST NOT disclose which capability was required. The
generic message prevents information leakage about the internal
authorization model.

**Assumption**: this dependency assumes that the request has already
passed the authentication layer, which verifies `User.active` (step 5
of the authentication middleware). `require_capability()` does not
independently verify user active status. Any future authentication
mechanism that bypasses the standard middleware MUST replicate the
active-user check before the request reaches capability-protected
endpoints.

The return type is `AuthenticatedPrincipal` (defined in
`docs/features/identity/authentication.md`), preserving both the active
user and the credential kind for downstream dependencies that need to
distinguish JWT from API key authentication (e.g., the session-only
guard).

### Authorization Chain Evaluation Order

For ticket endpoints that are capability-protected and operate on a
specific ticket, the authorization chain evaluates in this order:

1. **Authentication** (`get_current_user`) — resolve the authenticated
   principal. Returns 401 if not authenticated.
2. **Capability** (`require_capability`) — check the principal's user has
   the required capability. Returns 403 `AUTH_INSUFFICIENT_PERMISSION` if
   not. This check is user-level (does not depend on the specific
   ticket), so it does not leak information about ticket existence.
3. **Ticket accessibility** (`require_accessible_ticket`) — check that
   the ticket exists and is visible to the caller (scope + grant + package
   maintainership). Returns 404 for invisible tickets.

For mutation endpoints, a fourth check occurs at the **service layer**
(not as an API dependency):

4. **Operability guard** (`ensure_ticket_operable`) — rejects mutations
   on tickets in a manual-zone status (409 `TICKET_NOT_MUTABLE`). This
   check executes under the `FOR UPDATE` lock and is the authoritative
   enforcement.

This ordering is security-significant: the capability check (step 2)
fires before the accessibility check (step 3). A user without the
required capability receives 403 regardless of whether the ticket
exists — this prevents probing for ticket existence via differentiated
error codes.

For the track affectedness PATCH endpoint, `status = fixed` requires
`admin_ticket_ops`; every other valid status requires `manage_packages`. This
payload-dependent check occurs at step 2 before Ticket accessibility, and
neither capability implies or supplements the other for that request.

For CVE endpoints that are capability-protected and operate on a
specific CVE, the same pattern applies with `require_accessible_cve`
as step 3 — returning `404 CVE_NOT_FOUND` for non-existent or
inaccessible CVEs (see `docs/api-spec.md`, CVE Accessibility Check).
For the exact ordering on Public CVE endpoints with optional authentication,
see `docs/api-spec.md` (Authorization Chain Evaluation Order).

For non-ticket, non-CVE endpoints (user management, settings,
fetchers), only steps 1 and 2 apply.

## Endpoint Permission Map

This section is a **derived summary index** of access control rules. The
authoritative source for each endpoint's authorization is the owning
specification linked in the last column. This table does NOT define
endpoint behavior, parameters, response schemas, or error codes.

When adding a new endpoint to any feature spec, add a corresponding row
here with the required authorization level and a link to the owning spec.

### Authentication

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| POST | `/api/v1/auth/login` | Public | [local-authentication](local-authentication.md#login) |
| GET | `/api/v1/auth/sso/authorize` | Public | [sso-authentication](sso-authentication.md#sso-authorize) |
| POST | `/api/v1/auth/sso/callback` | Public | [sso-authentication](sso-authentication.md#sso-callback) |
| GET | `/api/v1/auth/providers` | Public | [sso-authentication](sso-authentication.md#list-auth-providers) |
| POST | `/api/v1/auth/logout` | Authenticated | [authentication](authentication.md#logout) |

### Users

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/users/me` | Authenticated | [authentication](authentication.md#get-current-user) |
| GET | `/api/v1/users/me/audit-log` | Authenticated | [identity-audit-log](identity-audit-log.md#list-my-identity-audit-events) |
| GET | `/api/v1/users` | Public (optional auth) | [user-management](user-management.md#list-users) |
| GET | `/api/v1/users/{user}` | Public (optional auth) | [user-management](user-management.md#get-user) |

### API Keys

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/api-keys` | Authenticated | [api-key-management](api-key-management.md#list-my-api-keys) |
| POST | `/api/v1/api-keys` | Authenticated (JWT session only) | [api-key-management](api-key-management.md#create-api-key) |
| POST | `/api/v1/api-keys/{key_id}/revoke` | Authenticated | [api-key-management](api-key-management.md#revoke-my-api-key) |

### Tickets

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/tickets` | Public (optional auth) | [tickets](../tickets/tickets.md#list-tickets) |
| GET | `/api/v1/tickets/{ticket_id}` | Public (optional auth) | [tickets](../tickets/tickets.md#get-ticket) |
| POST | `/api/v1/tickets` | `create_ticket` †manage_confidentiality | [tickets](../tickets/tickets.md#create-ticket) |
| POST | `/api/v1/tickets/{ticket_id}/associate-cve` | `triage_ticket` | [tickets](../tickets/tickets.md#associate-cve) |
| PATCH | `/api/v1/tickets/{ticket_id}/severity` | `triage_ticket` | [tickets](../tickets/tickets.md#set-severity-manual) |
| PATCH | `/api/v1/tickets/{ticket_id}/assignee` | `triage_ticket` | [tickets](../tickets/tickets.md#assign-ticket) |
| POST | `/api/v1/tickets/{ticket_id}/ignore` | `triage_ticket` | [tickets](../tickets/tickets.md#ignore-ticket) |
| POST | `/api/v1/tickets/{ticket_id}/reopen` | `triage_ticket` | [tickets](../tickets/tickets.md#reopen-ticket) |
| POST | `/api/v1/tickets/{ticket_id}/duplicate` | `triage_ticket` | [tickets](../tickets/tickets.md#mark-ticket-as-duplicate) |
| POST | `/api/v1/tickets/{ticket_id}/revert-duplicate` | `triage_ticket` | [tickets](../tickets/tickets.md#revert-duplicate-status) |
| PATCH | `/api/v1/tickets/{ticket_id}/confidentiality` | `manage_confidentiality` | [tickets](../tickets/tickets.md#set-confidentiality) |
| GET | `/api/v1/tickets/{ticket_id}/access` | `manage_confidentiality` | [tickets](../tickets/tickets.md#list-access-grants) |
| POST | `/api/v1/tickets/{ticket_id}/access` | `manage_confidentiality` | [tickets](../tickets/tickets.md#grant-access) |
| DELETE | `/api/v1/tickets/{ticket_id}/access/{user}` | `manage_confidentiality` | [tickets](../tickets/tickets.md#revoke-access) |

### Ticket Packages

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/packages` | Public (optional auth) | [package-model](../packages/package-model.md#search-packages-across-tickets) |
| GET | `/api/v1/tickets/{ticket_id}/packages` | Public (optional auth) | [package-model](../packages/package-model.md#list-ticket-packages) |
| POST | `/api/v1/tickets/{ticket_id}/packages` | `manage_packages` | [package-model](../packages/package-model.md#add-package-to-ticket) |
| POST | `/api/v1/tickets/{ticket_id}/packages/{package_id}/exclude` | `manage_packages` | [package-model](../packages/package-model.md#soft-delete-package-from-ticket) |
| POST | `/api/v1/tickets/{ticket_id}/packages/{package_id}/restore` | `manage_packages` | [package-model](../packages/package-model.md#restore-package) |
| POST | `/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/exclude` | `manage_packages` | [package-model](../packages/package-model.md#soft-delete-track) |
| POST | `/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/restore` | `manage_packages` | [package-model](../packages/package-model.md#restore-track) |
| PATCH | `/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}` | `manage_packages` for non-`fixed`; `admin_ticket_ops` for `fixed` | [package-model](../packages/package-model.md#change-track-status) |
| POST | `/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/products/{ticket_package_product_id}/exclude` | `manage_packages` | [package-model](../packages/package-model.md#soft-delete-product) |
| POST | `/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/products/{ticket_package_product_id}/restore` | `manage_packages` | [package-model](../packages/package-model.md#restore-product) |
| PATCH | `/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/products/{ticket_package_product_id}` | `manage_packages` | [package-model](../packages/package-model.md#override-product-eligibility) |

### Products

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/products` | Public (optional auth) | [product-catalog](../packages/product-catalog.md#list-products) |

### Ticket References

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/tickets/{ticket_id}/references` | Public (optional auth) | [references](../tickets/ticket-references.md#list-references) |
| POST | `/api/v1/tickets/{ticket_id}/references` | `manage_references` | [references](../tickets/ticket-references.md#add-reference) |
| PATCH | `/api/v1/tickets/{ticket_id}/references/{reference_id}` | `manage_references` | [references](../tickets/ticket-references.md#update-reference) |
| DELETE | `/api/v1/tickets/{ticket_id}/references/{reference_id}` | `manage_references` | [references](../tickets/ticket-references.md#delete-reference) |

### CVEs

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/cves` | Public (optional auth) | [cve-tracking](../tickets/cve-tracking.md#list-cves) |
| GET | `/api/v1/cves/{cve_id}/cvss` | Public (optional auth) | [cvss-scoring](../tickets/cvss-scoring.md#get-cvss-assessments-for-a-cve) |
| GET | `/api/v1/cves/{cve_id}/sources` | Public (optional auth) | [cve-service](../tickets/cve-service.md#cve-source-status) |
| POST | `/api/v1/cves/{cve_id}/cvss/suse` | `manage_cvss` | [cvss-scoring](../tickets/cvss-scoring.md#set-or-update-suse-cvss-assessment) |
| DELETE | `/api/v1/cves/{cve_id}/cvss/suse/{cvss_version}` | `manage_cvss` | [cvss-scoring](../tickets/cvss-scoring.md#delete-suse-cvss-assessment) |
| POST | `/api/v1/cves/{cve_id}/refetch` | `triage_ticket` | [cve-tracking](../tickets/cve-tracking.md#re-fetch-cve-data) |
| GET | `/api/v1/cve-sources` | Public (optional auth) | [cve-service](../tickets/cve-service.md#global-cve-source-listing) |

### Ticket Events

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/tickets/{ticket_id}/audit-log` | Authenticated | [ticket-audit-log](../tickets/ticket-audit-log.md#list-ticket-events) |

### Submission Tracking

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/tickets/{ticket_id}/submission-requests` | Public (optional auth) | [ibs-submission-tracking](../packages/ibs-submission-tracking.md#list-submission-requests) |
| GET | `/api/v1/tickets/{ticket_id}/release-requests` | Public (optional auth) | [ibs-submission-tracking](../packages/ibs-submission-tracking.md#list-release-requests) |

### Fetchers

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/fetchers` | Public (optional auth) | [fetcher-operations](../platform/fetcher-operations.md#list-fetchers) |
| GET | `/api/v1/fetchers/{fetcher_name}/runs` | Public (optional auth) | [fetcher-operations](../platform/fetcher-operations.md#list-fetcher-runs) |
| GET | `/api/v1/fetchers/{fetcher_name}/runs/{run_id}` | Public (optional auth) | [fetcher-operations](../platform/fetcher-operations.md#get-fetcher-run-detail) |
| GET | `/api/v1/fetchers/{fetcher_name}/timeline` | Public (optional auth) | [fetcher-operations](../platform/fetcher-operations.md#get-fetcher-run-timeline-data) |
| POST | `/api/v1/fetchers/{fetcher_name}/trigger` | `manage_fetchers` | [fetcher-operations](../platform/fetcher-operations.md#trigger-fetcher) |
| GET | `/api/v1/fetchers/{fetcher_name}/config` | `manage_fetchers` | [fetcher-operations](../platform/fetcher-operations.md#get-fetcher-config) |
| PATCH | `/api/v1/fetchers/{fetcher_name}/config` | `manage_fetchers` | [fetcher-operations](../platform/fetcher-operations.md#update-fetcher-config) |
| GET | `/api/v1/fetchers/{fetcher_name}/audit-log` | `manage_fetchers` | [fetcher-operations](../platform/fetcher-operations.md#get-fetcher-audit-log) |

### IBS Consumer

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/ibs-consumer/status` | Public (optional auth) | [ibs-rabbitmq-integration](../integrations/ibs-rabbitmq-integration.md#get-ibs-consumer-status) |

### Maintainer Operations

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/my/packages/pending` | Authenticated | [maintainer](../packages/maintainer.md#pending-packages) |
| GET | `/api/v1/my/packages/in-progress` | Authenticated | [maintainer](../packages/maintainer.md#in-progress-packages) |
| GET | `/api/v1/my/packages/completed` | Authenticated | [maintainer](../packages/maintainer.md#completed-packages) |
| GET | `/api/v1/my/packages/ticket/{ticket_id}` | Authenticated | [maintainer](../packages/maintainer.md#package-details-for-ticket) |

### Administration

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/api/v1/admin/settings` | `manage_settings` | [system-settings](../platform/system-settings.md#get-system-settings) |
| PATCH | `/api/v1/admin/settings` | `manage_settings` | [system-settings](../platform/system-settings.md#update-system-settings) |
| GET | `/api/v1/admin/settings/audit-log` | `manage_settings` | [system-settings](../platform/system-settings.md#list-settings-audit-events) |
| POST | `/api/v1/admin/settings/default-cvss-version/recalculate` | `manage_settings` | [system-settings](../platform/system-settings.md#trigger-cvss-recalculation) |
| GET | `/api/v1/admin/identity/audit-log` | `manage_users` | [identity-audit-log](identity-audit-log.md#list-identity-audit-events) |
| GET | `/api/v1/admin/api-keys` | `manage_users` | [api-key-management](api-key-management.md#list-all-api-keys) |
| POST | `/api/v1/admin/api-keys/{key_id}/revoke` | `manage_users` | [api-key-management](api-key-management.md#revoke-api-key) |
| POST | `/api/v1/admin/users` | `manage_users` (JWT session only) | [user-management](user-management.md#create-user-admin) |
| PATCH | `/api/v1/admin/users/{user}` | `manage_users` | [user-management](user-management.md#update-user-admin) |
| POST | `/api/v1/admin/users/{user}/roles` | `manage_users` | [user-management](user-management.md#set-user-roles) |
| POST | `/api/v1/admin/users/{user}/password` | `manage_users` (JWT session only) | [user-management](user-management.md#reset-user-password) |
| POST | `/api/v1/admin/users/{user}/deactivate` | `manage_users` | [user-management](user-management.md#deactivate-user) |
| POST | `/api/v1/admin/users/{user}/reactivate` | `manage_users` | [user-management](user-management.md#reactivate-user) |
| GET | `/api/v1/admin/users/{user}/deactivation-impact` | `manage_users` | [user-management](user-management.md#get-deactivation-impact) |
| POST | `/api/v1/admin/users/{user}/unlock` | `manage_users` | [user-management](user-management.md#unlock-user) |
| GET | `/api/v1/admin/role-mappings` | `manage_role_mappings` | [identity-provisioning](identity-provisioning.md#list-role-mappings) |
| POST | `/api/v1/admin/role-mappings` | `manage_role_mappings` | [identity-provisioning](identity-provisioning.md#create-role-mapping) |
| POST | `/api/v1/admin/role-mappings/preview` | `manage_role_mappings` | [identity-provisioning](identity-provisioning.md#preview-role-mapping) |
| DELETE | `/api/v1/admin/role-mappings/{id}` | `manage_role_mappings` | [identity-provisioning](identity-provisioning.md#delete-role-mapping) |

### Infrastructure

| Method | Endpoint | Authorization | Owning Spec |
|--------|----------|---------------|-------------|
| GET | `/health` | Public | [health-endpoints](../platform/health-endpoints.md#liveness--get-health) |
| GET | `/ready` | Public | [health-endpoints](../platform/health-endpoints.md#readiness--get-ready) |

**Notes**:
- "Public" = no authentication required; "Public (optional auth)" additionally
  processes a selected credential per `docs/api-spec.md`
- "Authenticated" = any logged-in user regardless of role
- Capability names (e.g., `create_ticket`, `manage_users`) = requires the
  specified capability; see Predefined Roles for which roles include each
  capability
- User creation: external users are created by the external sync process (see
  [identity-provisioning](identity-provisioning.md)); local users are created
  through the authenticated administrator API or the bootstrap/recovery CLI
  (see [user-management](user-management.md#create-user-admin))

† Field-level capability — the endpoint has a base access level, but
  this specific request body field requires an additional capability.
  If the field is present and the caller lacks the capability, the
  endpoint returns 403 (AUTH_INSUFFICIENT_PERMISSION). If the field is
  absent, the capability is not checked.

## Business Rules

1. An admin cannot remove their own Admin role. This is enforced by
   `user_service.update_roles()` for any entry point where
   `acting_user_id` is set. System actions (external sync, CLI) pass
   `acting_user_id = None` and are exempt. See
   `docs/features/identity/user-service.md`. This guard ensures that via
   UI/API, admins cannot accidentally eliminate all admin users — the
   acting admin always retains the role. For the full "zero admins"
   scenario (possible only via CLI/system operations) and recovery
   procedure, see `docs/features/identity/user-management.md`, Business Rule 2
2. Only users with the `manage_users` capability can manage roles. They
   can manage any user's roles, including their own (subject to the
   self-removal guard in Business Rule 1)
3. Users cannot deactivate their own account (enforced by
   `user_service.deactivate_user()` — see
   `docs/features/identity/user-service.md`)
4. External users cannot be manually deactivated or reactivated — their
   active status is controlled exclusively by the external identity
   provider via sync (enforced by `user_service.deactivate_user()` and
   `user_service.reactivate_user()` — see
   `docs/features/identity/user-service.md`, External Active Status Ownership)
5. Deactivated users cannot authenticate. On deactivation, all API keys
   are revoked and all active sessions are invalidated (proactively,
   before marking the user inactive). Additionally, the middleware
   checks `User.active` on every request as a defense-in-depth measure.
   See `docs/features/identity/authentication.md` (Deactivation ordering) and
   `docs/features/identity/user-service.md`
6. All authentication events are logged (login, logout, failed attempts)
7. Session duration: JWT expires after 72 hours without a request that
   processes authentication. Valid JWT requests using mandatory or optional
   authentication refresh it transparently when eligible. Maximum session
   lifetime is `SESSION_MAX_LIFETIME_DAYS` (default 30 days) regardless of
   activity. See `docs/features/identity/authentication.md`
8. Authenticated users with no roles have an effective scope of
   `non_confidential` and no capabilities. They can access specific
   confidential tickets via `TicketAccessGrant` or package maintainership —
   unlike unauthenticated users, who see only non-confidential tickets
   with no per-ticket override mechanisms
9. Admin bootstrap:
   - **Local-only phase** (current): create a local admin via
     `sentinel manage-user create --username bootstrap-admin
     --email bootstrap@example.com --role admin`. This is the only
     bootstrap mechanism available when external provisioning is
     not active.
   - **With external provisioning** (future): after the initial
     local admin is created, trigger the external provisioning
     sync (see `docs/features/identity/identity-provisioning.md`,
     Bootstrap Sequence), then optionally promote an external user
     to admin via `sentinel manage-user update --username
     <username> --add-role admin` and deactivate the bootstrap
     account.
   For restricted analyst accounts, see Business Rule 14
10. **Assignment target constraint**: only users holding the
    `vulnerability_analyst` role can be assigned as ticket owners. The
    `triage_ticket` capability controls who can *perform* the assignment;
    the VA role controls who can *be the target*. This constraint is
    enforced at two levels:
    - **Prospective** (assignment time): attempting to assign a ticket to
      a user without the VA role, or to an inactive user, is rejected
      with 400 Bad Request
    - **Retroactive** (role removal): if a user loses the
      `vulnerability_analyst` role entirely (no remaining `UserRole`
      records from any origin), all their active ticket assignments (New,
      Analysis, Analyzed) are automatically unassigned, with
      corresponding `TicketAuditEvent` records and status reconciliation
      — identical to the behavior on user deactivation. See
      `docs/features/identity/user-service.md`,
      `_unassign_tickets_on_va_role_loss()`
11. **Auto-assignment**: when a user modifies an unassigned ticket, the
    ticket is auto-assigned to the acting user **only if** the acting user
    holds the `vulnerability_analyst` role. If the acting user holds only
    `restricted_analyst` (or any other non-VA role), auto-assignment is
    skipped — the operation proceeds but the ticket remains unassigned
    for a vulnerability analyst to claim
12. **Status transitions with embedded assignment**: the reopen,
    revert-duplicate, and mark-as-duplicate flows embed a reassignment
    step. When a user without the `vulnerability_analyst` role performs
    these operations (they have `triage_ticket` capability to do so), the
    reassignment step is skipped — the ticket retains its current assignee.
    If the ticket was unassigned, it remains unassigned. Non-VA users can
    trigger status transitions but are never assigned as ticket owners
13. **Confidential ticket creation**: the `is_confidential` field in
    `POST /api/v1/tickets` requires the `manage_confidentiality` capability
    in addition to `create_ticket`. A user with only `create_ticket` (e.g.,
    `restricted_analyst`) can create tickets but cannot set
    `is_confidential: true`. If the field is present and the caller lacks
    `manage_confidentiality`, the endpoint returns 403 with error code
    `AUTH_INSUFFICIENT_PERMISSION`. This prevents users without
    `manage_confidentiality` from creating confidential tickets they
    cannot subsequently access.
    (This is a _hard conditional check_ — see Conditional Capability Checks
    above for the pattern definition.)
14. **Restricted analyst account setup**: restricted analyst accounts
    are local users created via CLI with the `restricted_analyst` role:

    ```
    sentinel manage-user create --username mybot --email mybot@example.com --role restricted_analyst
    ```

    The `create` command prompts for a password interactively. After
    creation, authenticate with the account credentials to create an API
    key via `POST /api/v1/api-keys`. Non-interactive accounts should use
    API keys exclusively for ongoing operations. Rotation means creating a
    replacement key and revoking the old key; see
    `docs/features/identity/api-key-management.md`.

## Implementation Details

### Authentication Mechanism

JWT with session-backed liveness checks plus API key credential validation.
See `docs/features/identity/authentication.md` for token, session, and
middleware behavior and `docs/features/identity/api-key-management.md` for
API key lifecycle behavior.

### Permission Checking

- Permissions are checked at the API endpoint level using FastAPI
  dependencies
- A `require_capability()` dependency factory returns a dependency that
  checks whether the current user holds the required capability through
  any of their roles
- Example: `Depends(require_capability(Capability.CREATE_TICKET))`
- Public endpoints (ticket list, CVE list, product list, fetcher dashboard)
  do not require authentication
- The `require_capability()` check loads the user's roles from the
  `UserRole` junction table, then checks each role's static capability set
- **Scope filtering** is applied separately by
  `confidential_ticket_filter()` and `require_accessible_ticket`, not at
  the endpoint decorator level
- Role changes take effect on the user's next request. A request already
  in progress continues with the permissions loaded at its start. This is
  the expected behavior and requires no additional synchronization

### Password Security

Sentinel stores bcrypt password hashes (with SHA-256 pre-hash) for local
users only. External users do not have local passwords. See
`docs/features/identity/local-authentication.md` for password policy and
hashing parameters.

## Data Model

See `docs/data-model.md`. Key tables:

- **User**: username, email, active status, external identity fields (external_id,
  manager_id, synced_at)
- **UserRole**: junction table linking users to roles with `group_name`
  (external group name or `_manual` for manual assignments)
- **RoleMapping**: maps external group names to Sentinel roles
- **Role** enum: `Admin`, `Vulnerability Analyst`, `Restricted Analyst`

The capability-to-role mapping and scope-to-role mapping are static
definitions in code (not stored in the database). No new tables are
required. The Role enum uses VARCHAR(30) columns protected by CHECK
constraints (`chk_user_role_role_valid`, `chk_role_mapping_role_valid`)
— Category A (state-machine, security-critical). Adding a new role
requires an Alembic migration (DROP + ADD constraints — reversible).
Values are never removed from the CHECK if existing records reference
them. Deprecated roles (if ever needed) would be handled via a
migration that reassigns affected users and then removes the value
from the constraints.

### Role Wire Format

All role values in API requests and responses use lowercase with
underscores:

- `admin`
- `vulnerability_analyst`
- `restricted_analyst`

This applies to all endpoints that accept or return role values:
`POST /api/v1/admin/users/{user}/roles`, `GET /api/v1/users/{user}`,
CLI `--role` parameter, and `RoleMapping` API payloads.

**Deterministic ordering**: any response array of role values (e.g.,
`GET /api/v1/users/me`'s `roles`) is ordered alphabetically by the
wire-format string. Any response array of role *assignment* objects
that additionally carries an origin (e.g., `GET /api/v1/users/{user}`'s
`roles`, each with `role`, `group_name`, `assigned_by`, `created_at`) is
ordered alphabetically by the wire-format role value, then by
`group_name`, then by `id` — deterministic regardless of assignment
order or database physical order.

## Role Origins and Coexistence

A user can acquire a role from two independent sources (origins):

- **Manual** (`group_name = '_manual'`): assigned by an admin via CLI
  or API. Can be removed by an admin at any time.
- **Externally-derived** (`group_name = <group name>`): derived from external group
  membership during external sync. Managed exclusively by the sync process
  — cannot be removed **per-user** via UI or API (only via role mapping deletion or external sync reconciliation). See `docs/features/identity/identity-provisioning.md`.

External groups can be mapped to `restricted_analyst` via `RoleMapping`. This
is a valid use case — for example, users who should perform ticket
operations but must not access embargoed (confidential) data. The admin
is responsible for ensuring the mapping is intentional.

### Coexistence Rules

1. The same role can be held by a user from multiple origins
   simultaneously. Each origin creates a distinct `UserRole` record
   (unique constraint: `user_id, role, group_name`).
2. **Manual assignment when role already exists via external sync**: creates a new
   `UserRole` record with `group_name = '_manual'`. The user now holds
   the role from both sources. If the external group is later revoked, only
    the externally-derived record (identified by its `group_name` value) is removed — the manual assignment persists.
3. **External derivation when role already exists manually**: the external sync
   creates a new `UserRole` record with the external group's `group_name`.
   The user now holds the role from both sources. If the admin later
   removes the manual assignment, only the `_manual` record is removed
   — the externally-derived assignment persists.
4. A role is effectively held as long as **at least one** `UserRole`
   record exists for that `(user_id, role)` pair, regardless of origin.
5. Removing a manual role never affects externally-derived records; removing an
   externally-derived role (via sync) never affects manual records. The two
   lifecycles are fully independent.

## Cross-references

- `docs/features/tickets/tickets.md` — confidentiality rules, status transitions
- `docs/features/tickets/ticket-mutations.md` — service-layer mutation contracts
- `docs/features/identity/authentication.md` — authenticated principal and
  mandatory/optional authentication dependencies
- `docs/features/identity/identity-provisioning.md` — external sync, role mappings
- `docs/features/identity/user-service.md` — centralized user lifecycle operations
- `docs/data-model.md` — Role enum, UserRole table
- `docs/api-spec.md` — API authorization conventions
- `docs/conventions.md` — FastAPI implementation conventions
