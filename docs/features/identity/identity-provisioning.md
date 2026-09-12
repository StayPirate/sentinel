# External Identity Provisioning

## Status

**Deferred**. This specification is not yet active. External user
provisioning will be implemented after the local-only phase, once the
SCIM integration with SUSEID is finalized.

## Purpose

Define the external identity provisioning mechanism: how Sentinel
receives user identity data from an external provider, maps external
group memberships to Sentinel roles, and manages the lifecycle of
externally-provisioned users.

This specification owns:
- The provisioning mechanism (push-based, future SCIM)
- The role-mapping management API endpoints
- The bootstrap sequence for external provisioning
- The reconciliation strategy

## Background

The LDAP endpoint at `pan.suse.de` (OpenLDAP proxy to SUSE Active
Directory) is being decommissioned. The replacement provisioning
mechanism will be SCIM push from SUSEID (Authentik), with hourly full
sync and near-real-time event delivery. The SCIM specification is not
yet finalized (authentication, scope, retry semantics, and group naming
are still in negotiation with the infrastructure team).

Sentinel will proceed to implementation using only local users initially.
External user provisioning (via SCIM or equivalent) will be specified
and implemented when this specification is activated.

## Provider Data Requirements

| Sentinel field | External provider field | Notes |
|---|---|---|
| `external_id` | Provider's stable UUID | Immutable matching key |
| `username` | Provider's username/uid | Updated on every sync if changed |
| `full_name` | Display name | — |
| `email` | Primary email | Normalized to lowercase |
| `active` | Active/inactive status | Drives deactivation side effects |
| `manager_id` | Manager's username/uid | Resolved to User FK |
| Group memberships | Group names/displayNames | Used for role mapping derivation |

## Role Mapping Management Endpoints

These endpoints are part of the deferred external provisioning feature.
They will be implemented when this specification is activated.

### List Role Mappings

```
GET /api/v1/admin/role-mappings
```

**Capability**: `manage_role_mappings`. Returns all configured
role mappings.

**Pagination**: not paginated. The number of role mappings is naturally
bounded (one per external group x role combination, expected <30
entries). The full list is always returned.

**Sorting**: results are returned in insertion order (`created_at`
ascending). No client-side sorting parameters are supported (bounded
dataset).

Response:
```json
{
  "data": [
    {
      "id": "uuid",
      "group_name": "SecurityTeam",
      "role": "vulnerability_analyst",
      "created_by": { "id": "uuid", "username": "admin1", "full_name": "...", "active": true },
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Preview Role Mapping

```
POST /api/v1/admin/role-mappings/preview
```

**Capability**: `manage_role_mappings`. Queries the external provider to show which users would be
affected by a proposed mapping. Does not persist anything. The query
mechanism depends on the provider (SCIM read API or locally-cached
data from the last reconciliation sync — see Open Questions).

Request body:
```json
{
  "group_name": "SecurityTeam",
  "role": "vulnerability_analyst"
}
```

Response:
```json
{
  "data": {
    "group_name": "SecurityTeam",
    "role": "vulnerability_analyst",
    "affected_users": [
      { "id": "uuid", "username": "jdoe", "full_name": "John Doe", "active": true, "email": "..." },
      { "id": "uuid", "username": "asmith", "full_name": "Alice Smith", "active": true, "email": "..." }
    ],
    "affected_count": 22,
    "unknown_users": ["newemployee"]
  }
}
```

The `unknown_users` field lists provider usernames found in the group
but not yet present in the User table (e.g., users provisioned after
the last sync). These users will receive the role at the next sync.

**Zero-member group**: if the group exists at the provider but
currently has zero members, the response is valid with
`affected_users: []`, `unknown_users: []`, and `affected_count: 0`.
This is not an error — an admin may create a role mapping for a group
that is not yet populated, in preparation for future members.

**Validation**: `group_name` MUST conform to the provider's group name
character rules (to be defined when this spec is activated). The
character set from the AD era (letters, numbers, spaces, hyphens,
underscores, dots; 256-char max) serves as a reference starting point.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 422 | `ROLE_MAPPING_INVALID_GROUP_NAME` | `group_name` contains characters invalid for the provider |
| 503 | `PROVISIONING_UNAVAILABLE` | External provider is unreachable or timed out |

### Create Role Mapping

```
POST /api/v1/admin/role-mappings
```

**Capability**: `manage_role_mappings`. Creates a new role mapping. **Roles are applied
immediately** to all matching users (not deferred to the next sync).

Request body:
```json
{
  "group_name": "SecurityTeam",
  "role": "vulnerability_analyst"
}
```

**Validation**:
- 422 / `ROLE_MAPPING_INVALID_GROUP_NAME` if `group_name` contains
  characters invalid for the provider (character set TBD)
- 422 / `VALIDATION_ERROR` if `group_name` exceeds 256 characters
- 422 / `ROLE_MAPPING_GROUP_NOT_FOUND` if the group does not exist at
  the provider (queries provider live to verify)
- 409 / `RESOURCE_CONFLICT` if a mapping for the same (group_name,
  role) already exists
- 503 / `PROVISIONING_UNAVAILABLE` if the provider is unreachable

Response (`201 Created`):
```json
{
  "data": {
    "id": "uuid",
    "group_name": "SecurityTeam",
    "role": "vulnerability_analyst",
    "created_by": { "id": "uuid", "username": "admin1", "full_name": "Admin User", "active": true },
    "created_at": "2026-05-06T12:00:00Z",
    "affected_users_count": 22
  }
}
```

A single group may have multiple mappings (one per role). For example,
group "SecurityTeam" can be mapped to both `admin` and
`vulnerability_analyst` simultaneously. Each mapping operates
independently — creating or deleting one does not affect the other.

1. Before opening a database transaction, query the external provider for
   members of the specified group. If
   the provider is unreachable, return 503 /
   `PROVISIONING_UNAVAILABLE` — no records are created

**Processing** (steps 2-5 within a **single database transaction**):

2. Create the `RoleMapping` record
3. Call `user_service.sync_role_mapping(role, group_name,
   member_user_ids, acting_user_id=acting_admin.id)` where
   `member_user_ids` is the set of User IDs matching the group
   members. The service creates `UserRole` records for each member
   and returns `(added_count, removed_count)` (see
   `docs/features/identity/user-service.md`). For a new mapping,
   `removed_count` is always 0
4. Create `IdentityAuditEvent` with
   `event_type = role_mapping_created` via
   `IdentityAuditLog.log_event()` — `user_id` = admin,
   `target_user_id = NULL`,
   `new_value` = `"{group_name} -> {role}"`,
   `detail` = `{"group_name": "...", "role": "...", "affected_users": N}`
5. Return `affected_users_count = added_count` (only newly created UserRole
   records, not pre-existing ones). The API transaction dependency commits
   once after the handler and all delegated services succeed.

### Delete Role Mapping

```
DELETE /api/v1/admin/role-mappings/{id}
```

**Capability**: `manage_role_mappings`. Removes a role mapping and revokes the corresponding role
from all affected users. Identifies affected users from local
`UserRole` records matching the mapping's `group_name` and `role`.

Returns **200** (not 204) because the deletion has side effects (role
revocation from affected users) that the admin needs to confirm in the
response.

Response (**200**):
```json
{
  "data": {
    "mapping": { "group_name": "SecurityTeam", "role": "vulnerability_analyst" },
    "affected_users_count": 22,
    "message": "Removed the 'vulnerability_analyst' role from 22 users."
  }
}
```

**Processing** (steps 2-4 within a single database transaction):
1. Look up the `RoleMapping` record by ID — return 404 if not found
2. Call `user_service.delete_role_mapping_roles(role, group_name,
   acting_user_id=acting_admin.id)`. The service removes all
   `UserRole` records tagged with this mapping's `(role, group_name)`
   and returns `affected_users_count`. If the acting admin would lose
   their only source of admin role, the service raises
   `SelfRoleRemovalError`. If the deleted mapping removes a user's final
   `vulnerability_analyst` origin, the derived Ticket unassignment is
   system-attributed and uses exact reason
   `vulnerability_analyst role removed after role mapping deletion`
3. Delete the `RoleMapping` record
4. Create `IdentityAuditEvent` with
   `event_type = role_mapping_deleted` via
   `IdentityAuditLog.log_event()` — `user_id` = admin,
   `target_user_id = NULL`,
   `old_value` = `"{group_name} -> {role}"`,
   `detail` = `{"group_name": "...", "role": "...", "affected_users": N}`
5. Return 200 with impact summary

Note: users who also have the same role via a different group mapping
or with `group_name = '_manual'` will retain the role.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `RESOURCE_NOT_FOUND` | Role mapping not found |
| 409 | `USER_SELF_ROLE_REMOVAL` | Deleting this mapping would remove the acting user's only source of admin role (via `user_service.delete_role_mapping_roles()`) |

## Behavioral Rules

1. **Role mapping application is immediate**: when an admin creates or
   deletes a role mapping, the roles are applied/revoked immediately —
   not deferred to the next sync cycle
2. **No minimum admin count enforcement**: the system does NOT prevent
   role mapping deletions that would remove admin access from all
   users. This is a deliberate design decision — CLI recovery
   (`sentinel manage-user update --username <user> --add-role admin`)
   is always available and is a sufficient mitigation. Adding a minimum
   count enforcement was evaluated and rejected for simplicity
3. **Self-admin guard (Delete only)**: an admin cannot delete a role
   mapping if that would remove their own only source of admin role
   (enforced by `user_service.delete_role_mapping_roles()`)

## Concurrency

If an admin creates a role mapping while a provisioning sync is in
progress, the sync may not process the new mapping in its current
cycle. This does not cause inconsistency: the Create endpoint applies
roles immediately to all matching users. The next sync cycle will
reconcile any users missed (e.g., users provisioned between the Create
and the next sync).

No locking mechanism is needed between role mapping CRUD and the sync
process.

## Provisioning Mechanism (Placeholder)

No provisioning mechanism is active currently. Users are
created as local users through the authenticated administrator API or the
bootstrap/recovery CLI.

**Candidate mechanism**: SCIM 2.0 push from SUSEID (Authentik) with
hourly full reconciliation sync. The application would expose
`/scim/v2/Users` and `/scim/v2/Groups` endpoints as a SCIM Service
Provider.

**Open questions** (to be resolved before this spec is enabled):
- Authentication: static bearer token (confirmed) — rotation mechanism?
- Scope: all employees regardless of active status (requested, pending confirmation)
- Retry/delivery guarantee: dramatiq defaults + hourly full sync as catch-up
- Group naming: original Okta group names preserved (confirmed)
- Rate/concurrency: 2-4 workers, sequential-ish (low pressure)
- Testing: staging SCIM provider in dry-run mode (offered by infra team)
- Read API availability: is there a read API to query group membership
  and group existence at the provider? If not, Preview and
  group-existence validation must use locally-cached data from the last
  reconciliation sync
- DELETE semantics: how does a provider DELETE map to Sentinel's user
  lifecycle? Options: hard-delete (requires FK cascade analysis),
  soft-delete (= deactivate_user), or new lifecycle status. To be
  resolved when the SCIM contract is defined

## Bootstrap Sequence (External Provisioning)

When external provisioning is activated, the bootstrap sequence is:

1. Create local admin via CLI:
   `sentinel manage-user create --username bootstrap-admin --email bootstrap@example.com --role admin`
2. Configure external provisioning endpoint (SCIM Service Provider
   settings, bearer token)
3. Trigger initial full sync (or wait for hourly cycle) — external
   users are created in Sentinel
4. Promote an external user to admin:
   `sentinel manage-user update --username <username> --add-role admin`
5. Deactivate bootstrap account (recommended):
   `sentinel manage-user deactivate --username bootstrap-admin`

## Future Evolution

**Single-provider limitation**: the current data model supports exactly
one external identity provider at a time. `User.external_id` has a
single UNIQUE column, `RoleMapping.group_name` has no provider
discriminator, and `UserRole.group_name` cannot distinguish which
provider derived the role. Multi-provider support would require adding a
`provider` discriminator column to User, UserRole, and RoleMapping.

When this spec is enabled and finalized:
1. Define the SCIM Service Provider endpoint contract
2. Define reconciliation fetcher (if pull-based catch-up is needed)
3. Finalize group validation rules for the provider
4. Update SSO spec to remove "deferred" notes
5. Add fetcher source_type value if a reconciliation fetcher is added
6. Re-run the applicable reviewers for `sso-authentication.md`

## Cross-references

- `docs/features/identity/user-service.md` — external user data ownership,
  sync_role_mapping(), delete_role_mapping_roles()
- `docs/features/identity/rbac.md` — manage_role_mappings capability,
  Role Origins and Coexistence
- `docs/features/identity/sso-authentication.md` — SSO requires external
  provisioning
- `docs/data-model.md` — User, UserRole, RoleMapping tables
- `docs/api-spec.md` — PROVISIONING_UNAVAILABLE, ROLE_MAPPING_* error codes
