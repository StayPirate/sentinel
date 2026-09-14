---
name: new-api-endpoint
description: Guided workflow for adding or modifying an API endpoint in an existing Sentinel feature (schema, service, thin route, tests, reviews).
---

## Workflow: Adding or Modifying an API Endpoint

This skill assumes a topic branch already exists. Branch creation, push,
PR opening, and merge follow the global workflow defined in
`docs/conventions.md` (Git Conventions) and `AGENTS.md` (Guardrail 25).
This skill covers only the implementation sequence within an
already-active branch.

Follow these steps when adding or modifying an API endpoint for a feature
that already has a specification in `docs/features/`.

### When to use this skill

- The feature specification **already exists** and defines the endpoint
  (method, path, request/response schemas, error codes, authorization level)
- You are adding the endpoint implementation, or modifying an existing one

**Do NOT use this skill when:**

- The feature requires new database tables or models — follow the standard
  workflow: write the spec first (Guardrail 1), then implement models,
  services, and endpoints in sequence
- The endpoint is not yet defined in any specification — first complete the
  spec work (Guardrail 1: specs-first), then return here

This skill references guardrails and conventions by number/name instead of
restating them. See `AGENTS.md` and `docs/conventions.md` for the
authoritative definitions.

### Step 1: Verify the specification (Guardrail 1)

1. Locate the feature specification in `docs/features/<domain>/`
2. Confirm the endpoint is fully defined:
   - HTTP method and path
   - Authorization level (`Access: Public`, `Access: Authenticated`, or
     `Capability: <name>`)
   - Request body / query parameter schemas
   - Response schema
   - Error responses (endpoint-specific; global/scoped responses are
     derivable per `docs/api-spec.md`)
3. If the endpoint is **not specified** or is **underspecified** → STOP.
   Complete the specification work first. Do not proceed with
   implementation

### Step 2: Define the Pydantic schemas

1. Create or update schemas in `backend/app/schemas/`
2. Use separate schemas for Create, Update, and Response
   (`docs/conventions.md`, Pydantic Conventions)
3. Define query parameter schemas if the endpoint supports
   filtering/pagination/sorting
4. Validate at the schema level, not in endpoints or services

### Step 3: Implement the service layer

1. Create or update service functions in `backend/app/services/`
2. Business logic belongs here — NOT in the endpoint handler
3. Follow the service exception conventions (`docs/conventions.md`):
   all exceptions inherit from a `<Module>ServiceError` base class with
   1:1 HTTP/error-code mapping
4. For gate-relevant mutations, use the centralized modules
   (Guardrail 16): `package_service` for package/track/product,
   `ticket_mutations` for CVSS/severity
5. For identity mutations, go through `user_service` (Guardrail 19)
6. Create audit events in the same transaction as the mutation
   (Guardrail 11)

### Step 4: Create the endpoint handler

1. Add the endpoint in the appropriate router in `backend/app/api/v1/`
2. Keep the handler **thin**: validate input → call service → return
   response
3. Use dependency injection (`Depends()`) for DB session, auth, and
   permissions:
   - `require_capability(<Capability>)` for capability-protected
     endpoints (see `docs/conventions.md`, FastAPI Conventions)
   - `resolve_user_identifier` for endpoints that accept a user
     identifier (UUID or username)
4. Add OpenAPI documentation: `summary`, `description`, response models
5. Follow the response envelope format from `docs/api-spec.md`
   (`{"data": ...}` / `{"data": [...], "meta": {...}}`)

### Step 5: Update cross-cutting documentation

1. Endpoint details (schemas, errors, behavior) live in the **feature
   spec** — verify they are already there (Step 1)
2. Update `docs/api-spec.md` **only** if the endpoint introduces:
   - A new error code not yet registered in the Error Code Categories
     table
   - A new shared convention (e.g., a new mutation pattern)
3. **Update the Endpoint Permission Map** in
   `docs/features/identity/rbac.md` with the new endpoint's method,
   path, access level, and owning spec link (Guardrail 22)

### Step 6: Write tests (Guardrail 6)

1. Create tests in `backend/tests/test_api/`
2. Mark all endpoint tests with `@pytest.mark.e2e`
3. Use the `client` fixture (HTTP test client with DB override)
4. Required test cases:
   - Happy path with valid data
   - Validation errors (invalid input)
   - Authentication (unauthenticated request → 401)
   - Authorization (insufficient permissions → 403)
   - Edge cases (empty results, not found, etc.)
5. For endpoints accepting a **user identifier**: test with both UUID
   and username inputs (mandatory per `docs/conventions.md` and
   `docs/features/platform/testing-strategy.md`)
6. For **mutations**: assert audit event creation with correct field
   values (see `docs/features/platform/testing-strategy.md`, Audit
   Trail Testing)
7. Run `cd backend && uv run pytest` and verify all tests pass

### Step 7: Reviews

After tests pass, invoke the following reviewers:

1. `@test-reviewer` — test quality and coverage (Guardrail 6)
2. `@security-reviewer` — if the endpoint touches auth, input handling,
   or external integrations (Guardrail 10)
3. `@api-parity-reviewer` — verify the API exposes all operations
   defined in the spec (Guardrail 12)

Note: `@api-convention-reviewer` (Guardrail 20) applies at the
**specification stage**, not at implementation time. If the spec was
already reviewed, no additional convention review is needed here.
