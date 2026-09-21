# Testing Strategy

## Purpose

Define the testing methodology, infrastructure, and policies for the
Sentinel backend. This is the single canonical source for how tests are
structured, executed, and enforced. `docs/conventions.md` (Testing
Conventions) contains brief style rules and references this document for
the full strategy.

Scope boundary: this spec covers the backend test suite
(`backend/tests/`). CI pipeline configuration and local automation
(pre-commit hooks) are specified here at the requirements level; their
implementation is owned by `.github/workflows/ci.yml` and
`.githooks/` respectively.

---

## Test Pyramid and Suite Taxonomy

Sentinel uses a three-tier test pyramid. Each tier has distinct
characteristics and isolation rules.

The unit, integration, and end-to-end tiers form the **default in-process
suite**. `pytest` without a marker filter runs this suite; "default" describes
its normal invocation, not a claim that it includes every test boundary.

Two separately invoked suites sit outside the pyramid:

- the **system suite** starts real local application processes and verifies
  inter-process communication against test infrastructure; and
- the **image suite** verifies the final OCI artifact and acts as a blocking
  publication gate.

Neither separate suite contributes to coverage measured for the default
in-process suite. They complement the pyramid rather than forming fourth and
fifth functional tiers.

### Tier 1 — Unit Tests

Fast, isolated tests for pure logic. No external dependencies.

| Property | Value |
|----------|-------|
| Marker | `@pytest.mark.unit` |
| Isolation | In-process only. No database, no Redis, no network I/O |
| Speed target | Full unit suite < 10 seconds |
| Typical subjects | Resolution cascades, parsers, validators, status evaluators, enum logic, Pydantic schema validation, utility functions |

A test that requires a database session, Redis connection, or HTTP
client is NOT a unit test — even if it tests a single function. Use
the `integration` marker instead.

### Tier 2 — Integration Tests

Tests that exercise service-layer functions with real database state.

| Property | Value |
|----------|-------|
| Marker | `@pytest.mark.integration` |
| Isolation | Real PostgreSQL (per-test transaction rollback). Redis available through the shared fixture when needed. No external network I/O |
| Speed target | Full integration suite < 120 seconds |
| Typical subjects | Service functions, CRUD operations, audit event creation, status gate evaluation, query builders, authorization checks |

Integration tests are the **primary verification layer** for
business logic. They verify that service functions interact correctly
with the database, create the right audit events, enforce constraints,
and produce the expected state transitions.

### Tier 3 — End-to-End Tests

Tests that exercise the full HTTP request/response cycle through
FastAPI's test client.

| Property | Value |
|----------|-------|
| Marker | `@pytest.mark.e2e` |
| Isolation | Real PostgreSQL + FastAPI test client (ASGI transport). Redis available via the shared fixture when exercised by the request path. No external network I/O |
| Speed target | Full e2e suite < 60 seconds |
| Typical subjects | API endpoint handlers, request validation, response schemas, authentication/authorization enforcement, error envelope format, pagination |

E2e tests verify the API contract — correct status codes, response
shapes, error codes, and permission enforcement. Business logic
correctness is covered by integration tests; e2e tests focus on the
HTTP layer.

### Default Marker

Tests without an explicit marker are treated as **integration** tests.
This is the safe default — a test that accidentally omits its marker
gets the database fixture rather than failing mysteriously.

This is a classification convention, not a pytest enforcement
mechanism — `pytest -m integration` selects only tests explicitly
marked `@pytest.mark.integration`, not all unmarked tests. To run
integration tests plus unmarked tests, use `pytest` without a marker
filter (the default in-process suite includes them).

The `asyncio_mode = "auto"` setting in `pyproject.toml` applies to all
tiers (all async tests run without manual `@pytest.mark.asyncio`
decoration). The `asyncio_default_fixture_loop_scope = "session"` and
`asyncio_default_test_loop_scope = "session"` settings ensure all async
fixtures and tests share a single session-scoped event loop, which is
required for the session-scoped engine fixture to work correctly with
function-scoped test functions.

### Marker Registration

All custom markers (`unit`, `integration`, `e2e`, `image`, `system`)
MUST be registered in `pyproject.toml` under `[tool.pytest.ini_options]`
to avoid `PytestUnknownMarkWarning`:

```ini
markers = [
    "unit: Fast, isolated tests (no DB, no Redis, no network)",
    "integration: Tests with real PostgreSQL",
    "e2e: Full HTTP request/response cycle tests",
    "image: OCI artifact and publication-gate tests (require Docker Engine and Docker Compose; excluded from default run)",
    "system: Local process system tests (spawn worker/Beat; excluded from default run)",
]
```

An unregistered marker MUST fail the test run rather than emit a silent
warning — this is enforced by pytest's strict-markers mode. Likewise, an
unrecognized pytest configuration option MUST fail rather than be silently
ignored — this is enforced by pytest's strict-config mode. Both prevent a
typo (e.g., a mistyped marker name) from being accepted without effect.

Similarly, warnings raised during test execution (e.g.,
`DeprecationWarning`, `RuntimeWarning` from an unawaited coroutine) MUST be
treated as test failures, not silently logged. Any warning that is a known,
accepted condition (e.g., a warning raised by a third-party dependency that
cannot be fixed locally) MUST be filtered explicitly with an inline
justification for why it is safe to ignore.

---

## Database Strategy

### Engine: PostgreSQL Only

All tests run against a real PostgreSQL instance. SQLite is not used —
the data model relies on PostgreSQL-specific features (JSONB,
TIMESTAMPTZ, ARRAY types, partial indexes, `FOR UPDATE` locking) that
SQLite does not support or emulates differently. Testing against SQLite
would hide bugs.

The `aiosqlite` dependency MUST NOT be included in dev dependencies —
it would allow writing tests against SQLite, creating a divergence from
the PostgreSQL-only policy.

### Database Provisioning

Two provisioning modes, selected automatically:

1. **CI environment**: when the `TEST_DATABASE_URL` environment variable
   is set (the CI workflow sets it to the PostgreSQL service container),
   the test engine connects directly. No container management needed.

2. **Local development**: when `TEST_DATABASE_URL` is not set, the
   `conftest.py` fixture uses `testcontainers` to start an ephemeral
   PostgreSQL 18 container automatically. The container is created once
   per test session and destroyed at the end. Zero manual setup required
   — the developer just runs `pytest`.

   Prerequisite: Docker Engine or Docker Desktop must be available locally.
   Testcontainers uses the Docker daemon; Podman compatibility endpoints are
   not a supported test-provisioning path.

### Schema Setup

At the start of each test session, the test engine runs
`Base.metadata.create_all()` to create all tables from SQLAlchemy model
definitions. This is faster than running Alembic migrations and
sufficient for correctness — the Alembic drift check (see Execution
Model, CI) separately verifies that migrations stay in sync with models.

### Per-Test Isolation: Transaction Rollback

Each test runs inside a **nested transaction** (savepoint) that is
rolled back after the test completes. This provides:

- **Speed**: no table drops/recreates between tests.
- **Isolation**: each test sees a clean database state.
- **Correctness**: tests cannot pollute each other.

Pattern (in `conftest.py`):

1. A session-scoped async fixture (using `pytest_asyncio.fixture` with
   `loop_scope="session"`) creates the async engine and runs
   `create_all`. The global `asyncio_default_fixture_loop_scope` and
   `asyncio_default_test_loop_scope` settings in `pyproject.toml` ensure
   all fixtures and tests share this session-scoped event loop.
2. A function-scoped `db_session` fixture begins an external transaction and
   binds a session with `join_transaction_mode="create_savepoint"`. The
   session creates savepoints lazily as database work begins. Teardown closes
   the session and rolls back the external transaction, reverting every change
   made during the test, including changes released from earlier savepoints.
3. The `client` fixture overrides `get_db` to use the same
   `db_session`, so HTTP requests in e2e tests share the test
   transaction.

#### Rollback Within a Test

Most tests rely only on fixture teardown for isolation and do not call
`db_session.rollback()` themselves. A test that explicitly verifies caller
rollback must first decide whether its setup data is part of the operation
being rolled back.

**Discard the setup and operation together.** When the test verifies that all
work in the session disappears, create the setup and perform the operation in
the current savepoint, then call `rollback()` directly. The setup rows are
expected to disappear too:

```python
user = await user_factory()
result = await create_resource(db_session, user.id)

await db_session.rollback()

assert await db_session.get(Resource, result.id) is None
```

**Preserve a setup baseline.** When the test needs setup rows to survive so it
can verify that only a later mutation was undone, use
`rollback_test_scope()` from `tests.support.database`. The helper commits the
session's current savepoint on entry, establishing the setup as a baseline
inside the still-uncommitted external test transaction. The next database
operation lazily creates a new savepoint, and the helper rolls that savepoint
back on exit, including when the scoped operation raises:

```python
resource = await resource_factory(field=None)
resource_id = resource.id

async with rollback_test_scope(db_session):
    await update_resource(db_session, resource_id, field="changed")

refreshed = await db_session.get(
    Resource,
    resource_id,
    populate_existing=True,
)
assert refreshed is not None
assert refreshed.field is None
```

The code inside `rollback_test_scope()` MUST follow the caller-owned service
transaction contract and must not call `commit()`. A commit inside the scope
would release the mutation savepoint, leaving no current mutation transaction
for the helper to roll back.

Capture primary keys before entering the scope. `Session.rollback()` expires
persistent ORM state regardless of `expire_on_commit=False`, and rows inserted
after the active savepoint began no longer exist after rollback. In async code,
accessing an expired attribute can also attempt an implicit load outside an
awaitable context. For post-rollback ORM assertions, query by the captured
primary key and pass `populate_existing=True`; `Session.get()` may otherwise
return the existing identity-map instance without unconditionally repopulating
it from the database. `refresh()` is valid only when the instance's row existed
at the preserved baseline, but the explicit primary-key query makes the test's
database-reload intent clearer.

### Alembic Drift Check

A CI step verifies that no model changes exist without a corresponding
Alembic migration. The check runs `alembic check` (or equivalent
autogenerate dry-run) and fails the build if differences are detected.
This ensures that developers who add or modify models also create the
matching migration.

### Concurrency Testing

The standard `db_session` fixture provides a single connection with a
wrapping transaction that is rolled back after each test. Within a
single transaction, `SELECT ... FOR UPDATE` is a no-op — the lock is
already held by the same transaction, so it never blocks. This means
the per-test rollback pattern **cannot** verify that pessimistic row locks
serialize concurrent mutations correctly (see `docs/conventions.md`,
Transaction and Locking).

Tests that need to verify lock serialization MUST use the
`db_session_factory` fixture, which creates independent sessions with
independent connections and transactions. The canonical two-session
pattern is:

1. Create **session A** and **session B** from `db_session_factory`.
2. In **A**: insert test data, flush, then acquire the documented
   pessimistic row lock on the target row.
3. Launch **B** as an `asyncio.Task` that attempts the conflicting lock
   on the same row.
4. Verify that **B** blocks by using
   `asyncio.wait_for(asyncio.shield(task_B), timeout=0.5)` and catching
   `asyncio.TimeoutError`. `asyncio.shield()` prevents `wait_for` from
   cancelling the task on timeout. A timeout confirms that B is blocked
   on the lock held by A.
5. Release the lock in **A** (rollback or commit).
6. Await **B**'s completion — it should now acquire the lock
   successfully.
7. Both sessions are tracked by the factory; fixture teardown rolls
   back open transactions and closes all sessions and connections.

When a test requires **commit** (e.g., to verify post-commit
visibility), the committed data is not rolled back by the fixture.
The test MUST perform explicit `DELETE` cleanup before the factory
teardown runs. Session and connection closure is still handled by the
fixture.

### `server_default=func.now()` and `onupdate=func.now()` Testing

PostgreSQL's `now()` function returns
`transaction_timestamp()` — the time at which the **current
transaction** began — not the wall-clock time at each statement.
Because `db_session` wraps each test in a single transaction (see
Per-Test Isolation above), every `server_default=func.now()` and
`onupdate=func.now()` evaluation within one test returns the
**identical** value.

This has a concrete consequence: a naïve `updated_at` test that
reads the column before a mutation, performs the mutation, and
asserts `updated_at >= original` is **tautological** — it passes
even if `onupdate` is removed from the model, because both
evaluations of `now()` produce the same timestamp.

The correct pattern **backdates** the column explicitly before the
mutation. An explicit Python-side assignment takes precedence over
`onupdate`, so the column is set to a known past value. The
subsequent mutation triggers `onupdate=func.now()`, which overwrites
the backdated value with the (fixed) transaction timestamp. The
assertion then compares two genuinely different values:

```python
async def test_updated_at_advances_on_update(self, db_session, factory):
    row = await factory()

    # Backdate: explicit assignment overrides onupdate
    backdated = datetime.now(UTC) - timedelta(days=7)
    row.updated_at = backdated
    await db_session.flush()
    await db_session.refresh(row)
    assert row.updated_at == backdated

    # Mutate: onupdate=func.now() fires, replacing the backdated value
    row.some_field = new_value
    await db_session.flush()
    await db_session.refresh(row)

    assert row.updated_at > backdated
```

Every model test that verifies `onupdate` behavior MUST use this
backdating pattern instead of comparing two `now()` evaluations
within the same test transaction.

---

## Redis Strategy

Tier 2 tests and Tier 3 tests whose exercised request path uses Redis
use the Redis instance and worker database designated by the shared
`redis_client` fixture. Tests MUST NOT create ad-hoc connections to
application-configured Redis instances. Code under test MAY create additional
client objects when its production lifecycle requires them, provided every
client targets the same designated worker database.

### Provisioning

Redis 8 is provisioned at session scope beneath the function-scoped
fixture. The test harness selects one of two modes:

1. **Configured test server**: when `TEST_REDIS_URL` is set (notably in
   CI), the harness connects to that designated Redis 8 test server and
   database range.
2. **Local development**: when `TEST_REDIS_URL` is absent, the harness
   starts an ephemeral Redis 8 container with `testcontainers`. The
   container is shared for the test session and destroyed afterward.

`TEST_REDIS_URL` is test-harness-only configuration, not Sentinel
runtime configuration. Tests MUST never use `REDIS_URL` or
`CELERY_BROKER_URL` as fixture storage, even when either variable points
to a locally available server. When configured, `TEST_REDIS_URL` MUST
designate a logical-database range reserved exclusively for this test
harness; providing an exclusive range is the environment owner's
responsibility.

### Worker and Test Isolation

Each pytest worker receives a dedicated Redis logical database. The
database encoded in `TEST_REDIS_URL` is the start of the test harness's
designated range; additional workers use consecutive logical databases.
The harness MUST verify that each worker maps to a distinct database and
that the Redis server provides enough logical databases. It MUST fail
explicitly if the configured range is insufficient; it must not continue
with worker mappings that overlap one another. The harness cannot infer
ownership by unrelated processes, so it relies on the exclusive-range
contract of `TEST_REDIS_URL` above.

All Redis clients and application processes created within one test MUST
use that test's worker database. This intentionally preserves realistic
contention, locking, and key-collision behavior within the test. Pytest
workers are suite executors, not substitutes for application replicas;
concurrency tests create multiple clients or processes inside one test
against the same logical database.

The fixture runs `FLUSHDB` before and after every test. It MUST never run
`FLUSHALL`, because other workers use other logical databases. An
unreachable server, an unsafe database allocation, or failed cleanup is
a test failure rather than a skip.

Scenarios whose behavior is server-global and cannot safely share a
server use a Redis 8 container dedicated to that test. This includes
memory exhaustion or eviction, server restart or unavailability, and
Pub/Sub scenarios where server lifecycle affects the result. Tests of a
feature's `RedisError` handling do not stop a shared Redis service; they
replace the relevant Redis boundary with deterministic behavior that raises
`RedisError`. Connectivity-probe tests may instead substitute an unreachable
target because connectivity itself is the behavior under test.

Every application-owned Redis consumer MUST expose a replaceable boundary
appropriate to its execution context so tests can both route normal access to
the designated worker database and simulate `RedisError` without changing
shared infrastructure. The boundary may be a client, factory, dependency, URL
provider, or equivalent mechanism. A single universal override mechanism and
reuse of the fixture's exact Python client object are not required.

---

## Fixture Catalog

This catalog documents the contract of each shared, non-model-specific
fixture: its scope, the test tier(s) that use it, and the feature it is
tied to (if any). It defines what each fixture must do — not whether it
has been implemented yet; implementation status is tracked by GitHub,
not by this specification.

Model factory fixtures (`<model>_factory`) are not enumerated
individually here — they all follow the single generic contract in
Model Factory Fixtures below. One such fixture exists per model that
tests need to instantiate; consult that section for the pattern, not a
per-model row.

| Fixture | Scope | Tier | Feature dependency |
|---------|-------|------|---------------------|
| `db_session` | function | integration, e2e | Core infrastructure (no feature dependency) |
| `client` | function | e2e | Core infrastructure (no feature dependency) |
| `authenticated_client` | function | e2e | Authentication feature (`local-authentication.md`) |
| `admin_client` | function | e2e | RBAC feature (`rbac.md`) |
| `db_session_factory` | function | integration, e2e | First concurrency/locking test (pessimistic locking pattern) |
| `redis_client` | function | integration, e2e | First Redis-dependent feature; follows Redis Strategy |
| `real_session_factory` | function | integration, e2e | First feature needing a real `async_sessionmaker` rather than a single `AsyncSession` (readiness PostgreSQL check) |

The `redis_client` fixture yields an asynchronous `redis.asyncio.Redis`
client configured with decoded string responses. Its session-scoped
provisioning layer selects the worker database and verifies
connectivity with `PING`. Before yielding, it runs `FLUSHDB` and
overrides applicable Redis boundaries so application access targets the same
designated worker database. Code under test may use the fixture client or
create additional clients against that database. Teardown restores those
overrides, runs `FLUSHDB`, and closes the fixture client. Provisioning,
connectivity, isolation, or cleanup failures fail the test suite; they are
never converted to skips.

Once authentication session liveness uses Redis, `authenticated_client` and
`admin_client` compose this Redis isolation automatically; tests using either
client MUST NOT need to request `redis_client` separately merely to prevent
access to application-configured Redis.

`authenticated_client` creates a user with **no roles** — it represents
pure authentication without any capability. Tests that need specific
capabilities must either use `admin_client` or assign roles explicitly.
`admin_client` creates a user with only the **`admin`** role.

The `real_session_factory` fixture returns a real `async_sessionmaker`
bound to the shared, session-scoped `_engine` fixture — mirroring the
production shape in `app/database.py`. It is used by tests that need a
session *factory* (something that opens its own fresh session per
call) rather than a single shared `AsyncSession`, such as the
readiness PostgreSQL check, which is exercised against a real,
independently-connecting factory rather than the request-scoped
`db_session`. Unlike `db_session` and `db_session_factory`, sessions
opened through this factory are not covered by the per-test savepoint
rollback: this fixture is intended for read-only checks; a test that
commits writes through it would leak state into the shared test
database across tests.

The `db_session_factory` fixture is an async callable
(`async def () -> AsyncSession`) that creates a new `AsyncSession` with
an independent connection and transaction on each call. Internally, the
factory uses the session-scoped `_engine` fixture (tests MUST NOT
interact with the engine directly). The factory tracks all sessions it
creates. During teardown, it rolls back all open transactions and closes
all sessions and connections — even if the test did not clean up
explicitly. If the database is unreachable or cleanup fails, the test
fails (never skips). This fixture is used exclusively for concurrency
and locking tests; all other integration tests continue using
`db_session`.

### Model Factory Fixtures

A model factory fixture creates persisted model instances with sensible
defaults, so that each test specifies only the fields relevant to the
behavior under test.

**Canonical shape**: `<model>_factory` is a synchronous pytest fixture
that returns an **async callable**. The callable accepts keyword
overrides and returns a flushed model instance:

```python
# Fictional bcrypt-shaped value — never a real hash (see AGENTS.md Guardrail 23)
_FICTIONAL_PASSWORD_HASH = "$2b$12$" + "a" * 53


@pytest.fixture
def user_factory(db_session: AsyncSession):
    counter = itertools.count(1)

    async def _create(**overrides: Any) -> User:
        n = next(counter)
        defaults: dict[str, Any] = {
            "username": f"user{n}",
            "email": f"user{n}@example.com",
        }
        defaults.update(overrides)
        # chk_user_auth_exclusive: a local user has a password hash and no
        # external_id; an external user has the inverse.
        if not defaults.get("external_id"):
            defaults.setdefault("password_hash", _FICTIONAL_PASSWORD_HASH)
        instance = User(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create
```

Rules:

| Rule | Rationale |
|------|-----------|
| The fixture is `def`; the callable it returns is `async def` | pytest resolves the fixture synchronously; the test awaits each creation |
| Persist with `flush()`, never `commit()` | `flush()` emits the INSERT and populates the primary key while leaving transaction control to the test and to the code under test |
| Defaults for columns with a UNIQUE constraint derive from a per-fixture counter | multiple calls within one test must not collide |
| Keyword overrides always take precedence over defaults | the caller's intent is authoritative |
| Defaults MUST produce a row that satisfies every constraint on the model; when the valid default set depends on the overrides supplied (e.g. mutually exclusive columns governed by a CHECK constraint), the factory adjusts its defaults accordingly | avoids opaque `IntegrityError` failures that obscure the behavior under test |

**Composition**: a factory for an entity with required foreign keys
requests the factories of its dependencies as fixtures and calls them to
populate any foreign key the caller did not override:

```python
@pytest.fixture
def user_role_factory(db_session: AsyncSession, user_factory):
    async def _create(**overrides: Any) -> UserRole:
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        ...  # same defaults / add / flush shape as above

    return _create
```

This keeps each factory responsible for a single model while allowing
tests to create deep object graphs in one call.

The default values of an individual factory are documented in that
fixture's docstring, not in a feature specification.

### Fixture Location

All shared fixtures live in `backend/tests/conftest.py`. Domain-specific
fixtures that are only useful within a single test directory (e.g.,
`tests/test_services/conftest.py`) may be defined locally, but shared
fixtures must not be duplicated.

---

## Coverage Policy

### Two Independent Gates

The CI pipeline enforces **two independent quality gates**. Both must
pass; neither substitutes for the other:

1. **Test pass/fail**: if ANY test fails, the build fails immediately.
   A single broken test blocks the build regardless of coverage
   percentage. This is the primary correctness control.

2. **Coverage threshold**: the build fails if line coverage drops below
   **95%** (`--cov-fail-under=95`). This prevents untested code from
   entering the codebase silently.

### Why 95%, Not 100%

- Coverage measures **quantity** (lines executed), not **quality**
  (correctness of assertions). 100% coverage with weak assertions
  provides false confidence.
- A small remainder typically consists of defensive error handlers,
  platform-specific branches, and boilerplate that is expensive to
  test and yields diminishing returns (e.g., a CLI process entry-point
  guard, OS signal handler bodies, or a debug-only `__repr__`).
- An unrealistic target incentivizes low-value tests that game the
  metric (executing code without verifying behavior).
- 95% is a **floor, not a ceiling**. Teams should aim higher where
  practical; the threshold exists to catch regressions, not to define
  "good enough."

### Ratchet Mechanism

The coverage threshold only goes up, never down. When coverage
naturally exceeds the current threshold (e.g., reaches 99%), the
threshold SHOULD be raised to the new level (rounded down to nearest
5%) to prevent regression. This is a manual adjustment made when
updating the CI configuration — not an automatic mechanism. The
threshold was raised from 85% to 95% once coverage stabilized above
99%, following an explicit line-by-line review of the remaining
uncovered lines to confirm each one is genuinely low-value to test
(see Why 95%, Not 100% above) rather than an unaddressed gap.

### Coverage Configuration

Coverage is measured by `pytest-cov` with the following settings (in
`pyproject.toml`):

- Source: `app` (the application package)
- Omissions: `*/tests/*`, `*/alembic/*`, `app/database.py` (infrastructure,
  tested via integration)
- Report format: `term-missing` in CI (shows uncovered lines)
- Mode: **branch coverage**, not line-only. Line coverage can report a
  guard condition (e.g., an `if`/`else`) as covered when only one branch
  ever executed, which understates untested behavior. Branch coverage
  requires both outcomes of a conditional to be exercised, aligning the
  metric with the project's convention of testing every guard condition
  (see Mandatory Test Scenarios below). The coverage threshold applies to
  the combined line+branch metric.
- Concurrency: `concurrency = ["greenlet", "thread"]`. Two distinct
  execution contexts otherwise escape `coverage.py`'s tracer:
  - `greenlet`: Sentinel's async-only database layer (see
    `docs/architecture.md`, Async-only database layer) uses
    SQLAlchemy's async engine, which relies on `greenlet` internally to
    bridge every async ORM/Core call to the underlying sync driver.
  - `thread`: FastAPI/`anyio` run synchronous dependencies and endpoint
    functions in a real OS thread pool, and
    `local_auth_service.authenticate_local_user()` offloads bcrypt
    verification into a worker thread via `asyncio.to_thread()`.

  Without both entries, coverage silently loses track of statements
  executed after control passes through a greenlet switch or into a
  spawned thread, under-reporting coverage for ordinary endpoint and
  service code — not just edge cases. Per-file reports are the most
  visible symptom: a small file can show as low as 70% coverage while
  every line is demonstrably exercised by passing tests, because the
  project-wide aggregate is large enough to mask the gap.

---

## Audit Trail Testing

### General Rule

For every mutation covered by any audit trail registered in the Audit Trail
Index (`docs/features/platform/audit-trail-infrastructure.md`, section "Audit
Trail Index"), tests MUST verify the owning domain's exact event contract or
explicit no-event contract.

When an owning mutation contract explicitly requires no event in a registered
trail, tests MUST assert that absence as part of the boundary contract. For the
Ticket trail, the complete audited/no-event inventory is the canonical matrix in
`ticket-audit-log.md`; delivery is one of several intentional no-event
boundaries rather than a global exception.

The Audit Trail Index is the authoritative source for which audit
trails exist. As of this writing, four audit trails are registered:

| Audit Trail | Event Model | Owning Spec |
|---|---|---|
| Ticket | `TicketAuditEvent` | `docs/features/tickets/ticket-audit-log.md` |
| Identity | `IdentityAuditEvent` | `docs/features/identity/identity-audit-log.md` |
| Fetcher | `FetcherAuditEvent` | `docs/features/platform/fetcher-infrastructure.md` |
| Setting | `SettingAuditEvent` | `docs/features/platform/system-settings.md` |

This list is **not closed**. When a new audit trail is added to the
Index, the testing obligation extends automatically — no update to this
document is needed.

### What to Assert

For each audit-producing mutation, the test MUST assert:

1. **Existence**: exactly the expected number of audit events are
   created (no missing, no duplicates).
2. **Event type**: the `event_type` value matches the contract table in
   the owning spec.
3. **Actor**: `user_id` matches the semantic event actor, including `NULL` for
   system-attributed derived consequences inside a user-initiated workflow.
4. **Payload**: `old_value`, `new_value`, and any domain-specific fields
   (`comment`, `detail`, `target_user_id`, etc.) match the contract.
5. **Ordering**: direct, derived, and multi-record events appear in the exact
   deterministic order required by the owning contract.
6. **Atomicity**: the audit event and the mutation are visible within the
   same test transaction (i.e., no intermediate commit separates them).

For an explicit no-event mutation, assert zero matching events before and after
the operation and verify that rollback or retry cannot synthesize one.

Ticket audit coverage includes all rows in the canonical mutation/no-event
matrix. Multi-record tests assert Product events by
`TicketPackageProduct.id`, maintainer events by `User.id`, duplicate-dependent
events by locked Ticket UUID, identity-unassignment events by ascending Ticket
UUID after every applicable User lock, and reference PATCH events in
URL/type/title/description order.
Independent-session tests prove serialized winner/loser behavior without stale
old values. Ticket audit API tests include equal `created_at` values and prove
stable `created_at DESC, id DESC` pagination.
Architecture and service tests also prove that audit history is never queried
to determine current state, authorization, idempotency, restoration,
reactivation, provenance, or recovery.

### Immutability Testing

Audit event tables are append-only. No application-level UPDATE or
DELETE operations are permitted. This is enforced mechanically by a
structural test rather than per-function negative assertions — see
Structural Tests below ("Audit immutability").

---

## Structural Tests

### Purpose and Governing Principle

Some project rules require no judgement to verify — they are
mechanically checkable facts about the codebase (a table has a UUID
primary key, a module in `app/core/` does not import from
`app/services/`, a Markdown link points at a file that exists).
Rules of this kind are implemented as **structural tests**: deterministic
`@pytest.mark.unit` tests that inspect code (SQLAlchemy metadata, AST
import graphs, FastAPI route objects) or file contents (Markdown links)
directly, instead of relying on a reviewer agent to notice a violation
on every pull request.

Structural tests are a Tier 1 (unit) test, not a separate tier — they
run in-process, require no database or network I/O, and are part of the
unit suite executed by the pre-commit fast gate.

**Governing principle**: a structural test may read code; it must never
impose a format on a specification. If verifying a rule would require a
specification document to remain machine-parsable (fixed table columns,
a rigid heading structure, a parseable sub-language), the rule is not a
structural test candidate — it stays with the appropriate reviewer
agent, which can apply judgement to prose that legitimately varies in
shape.

### Location and Modules

| Module | Location | What it enforces |
|---|---|---|
| Model conventions | `backend/tests/test_architecture/test_model_conventions.py` | Over every table in `Base.metadata`: primary key column type is UUID (`docs/conventions.md`, SQLAlchemy Conventions), except the small, explicit per-table exception list documented in `docs/data-model.md` (Notes) for natural-key configuration tables (e.g. `SystemSetting.key`); every UUID primary key column declares both `default=uuid.uuid7` and `server_default=text("uuidv7()")` (`docs/conventions.md`, SQLAlchemy Conventions); every `DateTime` column is timezone-aware, i.e. `DateTime(timezone=True)` (`docs/conventions.md`, Timestamps & Timezones); no PostgreSQL ENUM type (`sa.Enum`/`postgresql.ENUM`) is used (`docs/conventions.md`, Enum Storage Strategy) |
| Audit immutability | `backend/tests/test_architecture/test_audit_immutability.py` | Over every service module in `app/services/`: no `sqlalchemy.update()` or `sqlalchemy.delete()` call targets a model whose class inherits `AuditEventMixin` (`docs/features/platform/audit-trail-infrastructure.md`, Immutability). Discovers audit event models dynamically via `AuditEventMixin.__subclasses__()`, so it starts enforcing automatically as each concrete audit trail (ticket, identity, setting, fetcher) is implemented — no update to this test is needed when a new trail is added |
| Layer dependencies | `backend/tests/test_architecture/test_layer_dependencies.py` | The dependency direction of the Backend Layer Architecture table in `docs/architecture.md` — a module in a given layer does not import a layer that is not listed as an allowed dependency for it. Both runtime and type-checking-only (`TYPE_CHECKING`-guarded) imports are checked, since either represents a coupling the architecture forbids |
| Ticket accessibility boundaries | `backend/tests/test_architecture/test_ticket_accessibility.py` | Core imports no Model or Service modules; API modules contain no business ORM query or Ticket-visibility predicate; every new or changed protected read delegates to a service-owned model-aware operation; and authorization or mutation code never queries Ticket audit history as current visibility state. Behavioral tests, rather than an attempted semantic static comparison, prove every consumer implements the complete canonical predicate |
| Workflow job timeouts | `backend/tests/test_architecture/test_workflow_timeouts.py` | Every job across all `.github/workflows/*.yml` (or `.yaml`) files declares a job-level `timeout-minutes` — GitHub's 360-minute default could otherwise occupy a runner and its `concurrency` group for up to six hours on a hung step |
| Documentation links | `backend/tests/test_docs_links.py` | Every relative Markdown link (`[text](path)` or `[text](path#anchor)`) in an existing tracked `.md` file resolves to an existing file or directory. Tracked files deleted in the candidate worktree are excluded. `http(s)://` and `mailto:` links and anchor-only links (`#section`) are out of scope. A link whose entire `[text](target)` construct is wrapped in inline code spans (`` `[text](target)` ``) is also out of scope — this is a literal, illustrative example of link syntax (e.g. in `AGENTS.md`, Endpoint Permission Map maintenance), not a real link, and is not meant to resolve to a file. The test only detects and reports broken links; resolving them (fixing the link, creating the missing file, or removing the reference) is a judgement call left to whoever introduced or is reviewing the change |
| CPE canonical data | `backend/tests/test_services/test_cpe_mapping.py` | The committed `app/data/cpe-package-mapping.json` is valid UTF-8 JSON with no textual or semantic duplicate keys; every key round-trips through the canonical grammar and is sorted; every package list satisfies the mapping contract. The same focused module tests the parser, package-relative loader, cache, resolvers, and resource packaging defined in `docs/features/packages/cpe-package-mapping.md`. The normal blocking pytest suite is the CI owner; no CPE-specific workflow or generic worker-startup check is required |
| API route conventions | `backend/tests/test_api_conventions.py` | Over every registered FastAPI route (excluding the documented `/health` and `/ready` exemption, `docs/features/platform/health-endpoints.md`): path starts with `/api/v1/` (`docs/api-spec.md`, Base URL); the HTTP method is one of `GET`/`POST`/`PATCH`/`DELETE` — the only methods the documented mutation patterns (`docs/api-spec.md`, Mutation Patterns) and the application's own CORS configuration allow; OpenAPI documentation (`summary` or `description`) is present (`docs/conventions.md`, FastAPI Conventions); a path referencing audit trails ends with the `/audit-log` suffix (`docs/api-spec.md`, Audit Trail Endpoint Naming); a `response_model` is declared, unless the route returns `204 No Content` (`docs/conventions.md`, FastAPI Conventions); the response schema has a top-level `data` property, i.e. the standard envelope, checked via the generated OpenAPI schema (`docs/api-spec.md`, Response Format) — the `/health`/`/ready` exemption also applies to this last check, since those endpoints are outside the envelope contract by design. Also walks every route's *effective* dependency graph (including dependencies nested at any depth, e.g. under authentication) and asserts every occurrence of the `get_db` dependency declares `scope="function"` with caching enabled (`docs/conventions.md`, API Transaction Dependency Scope) — this is the mechanism that guarantees a commit (or its failure) completes before the response is transmitted to the client. This test passes vacuously when no routes are registered yet — it starts enforcing automatically as soon as the first endpoint is added, with no further action required |
| API session ownership | `backend/tests/test_architecture/test_api_session_ownership.py` | Over every module in `app/api/` (excluding `app/api/health.py`, whose readiness probe never uses the `get_db` yield-dependency at all — it opens its own read-only, no-commit session directly for its `SELECT 1` check, so the `scope="function"` rule does not apply to it): no direct reference to `async_session_factory` and no direct `.commit()`/`.rollback()` call — both would bypass the `DatabaseSession` dependency and its `scope="function"` ordering guarantee (`docs/conventions.md`, API Transaction Dependency Scope) invisibly to the route-dependency-graph check above |
| `asyncio.run()` boundary inventory | `backend/tests/test_architecture/test_asyncio_run_inventory.py` | Every direct `asyncio.run(...)` call site in `backend/app/tasks/` (by module and enclosing function) is enumerated via AST and compared against a reviewed inventory maintained in the test module. A new, unclassified call site fails the test — not because direct `asyncio.run()` is forbidden, but because a long-lived Celery process repeating it needs an explicit lifecycle classification (disposes the shared pooled engine before returning; a documented one-shot or independently safe lifecycle) per `docs/conventions.md` (Cross-loop pooled connection lifecycle). Adding the new call site to the inventory with its classification is the required action, not a workaround |
| OpenCode command discovery | `backend/tests/test_opencode_agent_permissions.py` | Every project command definition is a direct child of `.opencode/commands/`. OpenCode recursively registers Markdown files below that directory, so nested reference documents would become unintended slash commands |

### Excluded Invariant

The `Settings` class (`backend/app/config.py`) ↔ `docs/configuration.md`
invariant (every settings field has a corresponding registry entry) is
deliberately **not** a structural test. Verifying it would require
`docs/configuration.md` to remain machine-parsable — turning an
operator-facing reference document into a disguised configuration file.
This invariant is verified by `@docs-reviewer` by explicit decision.

---

## Test Structure and Naming

### Directory Structure

Test files mirror the `backend/app/` directory structure:

```
backend/tests/
├── conftest.py                 # Shared fixtures
├── test_api_conventions.py     # Structural API convention tests
├── test_docs_links.py          # Structural documentation link tests
├── support/                    # Test-only helpers with no app/ counterpart
│   ├── audit_models.py         # Concrete AuditEventMixin subclass for mixin/base-class tests
│   └── database.py             # Shared database transaction test helpers
├── test_support/               # Tests for importable test support helpers
│   └── test_database.py
├── test_architecture/          # Structural model and layer tests
│   ├── test_model_conventions.py   # Invariants over Base.metadata
│   └── test_layer_dependencies.py  # Layer dependency direction (AST)
├── test_api/                   # E2e tests for API endpoints
│   ├── conftest.py             # API-specific fixtures (authenticated clients)
│   └── test_<resource>.py      # One file per API resource/router
├── test_services/              # Integration tests for service layer
│   └── test_<service>.py       # One file per service module
├── test_models/                # Integration tests for model constraints
│   └── test_<model>.py         # One file per model (constraints, relationships)
└── test_tasks/                 # Integration tests for Celery tasks
    └── test_<task>.py          # One file per task module
```

`tests/support/` holds importable test-only artifacts that have no
corresponding `app/` module — for example, a minimal concrete SQLAlchemy model
needed to exercise an abstract mixin (`AuditEventMixin`) that has no table of
its own, or a transaction helper shared across service tests. It is distinct
from `conftest.py`: fixtures live in `conftest.py`, while importable classes and
functions shared across multiple test modules live in `support/`.

### Naming Convention

Test functions follow the pattern:
`test_<what>_<condition>_<expected_result>`

Examples:
- `test_get_cve_not_found_returns_404`
- `test_set_track_status_affected_creates_audit_event`
- `test_resolve_severity_no_scores_returns_none`
- `test_create_user_duplicate_username_raises_conflict`

### Test Independence

Every test MUST be independent — it must not rely on execution order,
shared mutable state, or side effects from other tests. The per-test
transaction rollback enforces database isolation; tests must also avoid
module-level mutable state (global caches, singletons) that could leak
between tests.

When testing code that uses module-level mutable registries (e.g.,
`FETCHER_REGISTRY`, `_CVE_SOURCE_TYPE_MAP`), the test must snapshot and restore
each affected registry in a fixture or teardown. See
`docs/features/platform/cve-fetcher-infrastructure.md` for the CVE registry
isolation contract.

### Sync Entry-Point Tests

Test functions that exercise code containing `asyncio.run()` — such as
CLI commands (invoked via `CliRunner.invoke()`) or Celery task
functions called directly — MUST be synchronous (`def`, not
`async def`). With `asyncio_mode = "auto"` (see Marker Registration
above), an async test function runs inside an event loop managed by
pytest-asyncio; `asyncio.run()` in the code under test then raises
`RuntimeError: asyncio.run() cannot be called when another event loop
is running`. This applies to any synchronous entry point that bridges
into the project's async-only database layer via a single
`asyncio.run()` call (see `docs/conventions.md`, Sync-to-Async
Bridging). Fixtures for
these tests provide the async session factory itself (for the code
under test to wrap in its own `asyncio.run()` call), not a live
`AsyncSession` via an async fixture.

The factory MUST NOT reuse an asyncpg connection acquired on pytest-asyncio's
event loop. Synchronous CLI tests use a CLI-test engine with `NullPool`, or an
equivalent factory whose engine and connections are created, used, and
disposed on the event loop established by the production `asyncio.run()`
boundary. The factory targets the shared test PostgreSQL server; it does not
require a second server. A successful mutating command commits durable rows,
so its test performs explicit cleanup on its own event loop rather than
depending on the ordinary per-test rollback fixture.

When such an entry point uses application-owned Redis, synchronous test
fixtures obtain the designated worker-database URL from the provisioning
layer and install the consumer's replaceable boundary without passing a live
async Redis client into the test. The workflow under test creates or obtains
its own async client inside the event loop established by its single
`asyncio.run()` call. Redis arrangement and assertions happen outside that
invocation through the test harness; no client object is shared across event
loops. Setup and cleanup clients are created, used, and closed on the loop that
owns them. Cleanup uses `FLUSHDB` only on the designated worker database and
never `FLUSHALL`.

#### Cross-Loop Engine Lifecycle

Every generic task wrapper that is *repeatedly invoked within the same
long-lived process* and is therefore subject to the Cross-loop pooled
connection lifecycle rule (`docs/conventions.md`) — currently
`run_fetcher`, `cleanup_sessions`, and `resolve_ticket_packages` — MUST have a
regression test that
proves it does not leak a pooled connection across its own event-loop
boundary. The test invokes the real synchronous wrapper (or its
extracted async workflow via two separate `asyncio.run()` calls) twice
in the same test process against the shared pooled production-style
engine, with only the innermost domain operation replaced by a trivial
query (e.g. `SELECT 1`) or a minimal no-op domain object (e.g. a
test-only `BaseFetcher` subclass). Both invocations MUST succeed;
before the fix, the second invocation reproduces the
`RuntimeError`/`InterfaceError` cross-loop failure. Additional required
cases per wrapper:

- `engine.dispose()` is awaited exactly once per invocation, after the
  wrapped work completes, on both the success and the exception path
- the wrapper's return value (if any) and its propagated exception (if
  any) are unchanged by the addition of disposal

This is a Tier 2 (integration) test — it exercises a real pooled engine
against the shared test PostgreSQL server. It does not require a Celery
broker or worker process; the cross-loop failure is a SQLAlchemy/asyncio
event-loop invariant, reproducible directly.

**Beat's bootstrap handler is exempt from the two-invocation
reproduction above.** It is a one-shot startup handler: it runs at most
once per process (Beat startup), and any failure exits the process
(`sys.exit(1)`) rather than allowing a second invocation to reuse the
same engine — the "second invocation in the same process" scenario that
reproduces the cross-loop bug for
`run_fetcher`/`cleanup_sessions`/`resolve_ticket_packages` never
occurs for this handler in production. Its disposal-ordering contract
(dispose only after a successful commit, never on failure) is instead
verified with unit-level mock tests asserting call order — see
`backend/tests/test_tasks/test_beat_startup.py`.

---

## Execution Model

### Local Development

Developers (and OpenCode agents) run tests locally using:

```bash
# Default in-process suite
cd backend && pytest

# Unit tests only (fast feedback)
cd backend && pytest -m unit

# Integration tests only
cd backend && pytest -m integration

# Specific file or test
cd backend && pytest tests/test_services/test_ticket_mutations.py
cd backend && pytest -k "test_set_track_status"
```

When `TEST_DATABASE_URL` or `TEST_REDIS_URL` is not set, the corresponding
shared fixture automatically starts a PostgreSQL 18 or Redis 8 container
via testcontainers through the Docker daemon. Containers are reused for the
test session. Redis
tests require no application `REDIS_URL` or `CELERY_BROKER_URL`; leaving
`TEST_REDIS_URL` unset is the normal local setup.

### Pre-Commit Hooks (Local Automation)

Repository-level git hooks provide fast feedback before commits reach
CI. Configured as shell scripts in `.githooks/` and activated
per-repository via `core.hooksPath` (see activation steps below):

- **pre-commit**: ruff check + ruff format check + mypy strict type check +
  `pytest -m unit` (fast gate, < 15 seconds) + `gitleaks git --staged`
  (secret scan on staged changes). Tool invocations use `uv run --locked`,
  so the hook never mutates `backend/uv.lock` as a side effect of running
  a check.
- **pre-push**: full test suite (`pytest`) including integration and
  e2e tests, followed by the system suite (`pytest -m system
  tests/system/`) — see Local Process System Testing. Also uses
  `uv run --locked`, for the same reason.
- **post-checkout / post-merge / post-rewrite**: after switching
  branches, pulling, merging, or completing a rebase, the backend
  environment (`backend/.venv`) is automatically synchronized with
  `backend/uv.lock` on the resulting branch. This applies uniformly
  regardless of which branch is involved — there is no restriction to
  `master`. A file-level checkout (e.g. `git checkout -- <file>`) does
  not trigger this check. Synchronization never modifies
  `backend/uv.lock` itself, and it is exact — a package installed
  manually into `backend/.venv` outside the lockfile may be removed. If
  `uv` is not installed, or if synchronization fails (e.g. no network
  access when a new dependency needs downloading), the hook prints a
  warning to stderr and does not block the underlying git operation; the
  developer must then run `cd backend && uv sync` manually before
  relying on the environment.

These hooks are a supplementary safety net. The CI pipeline is the
authoritative enforcer — hooks can be bypassed in extraordinary
circumstances but CI cannot.

**Secret scanning (`gitleaks`)** is local-only by design: no CI job or
GitHub Action performs secret scanning. The pre-commit hook runs
`gitleaks git --staged` against staged changes only. Because
`gitleaks` is not part of the Python environment, the hook degrades
gracefully — if the binary is absent, it prints a warning and the
commit proceeds — the same treatment already applied to `shellcheck`
and `shfmt` (see `docs/conventions.md`, Shell Scripting). No specific
version is pinned locally; any recent release is expected to behave
consistently for this use case. `.gitleaks.toml` at the repository
root extends gitleaks' default rule set and defines no allowlist
today — verification during implementation confirmed the fictional
values already used in this repository (e.g., the fictional bcrypt
hash, `not-for-production` markers) do not trigger any default rule.
Should a real false positive be observed in the future, it must be
allowlisted by regex pattern — never by path — in that file.

To activate after cloning:

```bash
git config --local core.hooksPath .githooks
```

The `--local` scope writes to this repository's `.git/config`, so the
setting applies only to the Sentinel working tree. If you already have a
global `core.hooksPath` (`git config --global core.hooksPath ...`), this
local setting takes precedence inside Sentinel while leaving your global
hooks untouched in every other repository. Git uses a single hooks
directory at a time — it does not merge the two — so your global hooks do
not run inside Sentinel while the local setting is active. To revert and
fall back to your global hooks here, run:

```bash
git config --local --unset core.hooksPath
```

### CI Pipeline

The CI pipeline runs on every push to `master` and every pull request
targeting `master`. It provides the **non-bypassable enforcement layer**
through the following required gates:

1. **Python lint and format** — all application and test code MUST pass
   the configured linter and formatter without findings.
2. **Static type checking** — strict-mode type checking MUST pass over
   application code (`app/`), tests (`tests/`), and Alembic migration
   scripts (`alembic/`).
3. **Default in-process suite with coverage threshold** — the unit,
   integration, and e2e suite MUST pass with a minimum line-coverage
   percentage enforced as a blocking gate.
4. **Migration drift detection** — model definitions and migration
   scripts MUST remain in sync; the build fails if they diverge.
5. **OpenAPI schema verification** — the OpenAPI schema generation MUST
   complete without error.
6. **Static security analysis and dependency vulnerability scanning** —
   static analysis of application code for insecure patterns MUST pass,
   and all declared dependencies MUST be free of known vulnerabilities
   and known malware.
7. **Shell script lint/format and workflow validation** — all tracked
   shell scripts and git hooks MUST pass lint and format checks; all
   GitHub Actions workflow files MUST pass syntax validation.
8. **Container image artifact gate** — on pull requests, the final OCI
   candidate MUST pass the artifact-risk checks defined below. This gate is
   blocking on PRs only (not on pushes to `master`).
9. **Local process system test** — the system suite (`-m system`) MUST
   pass. This gate verifies the inter-process fetcher pipeline using
   real worker and Beat processes against the test infrastructure. It
   is a separate invocation from the coverage-measured suite.
10. **Release SBOM validation** — on pull requests, the final image built for
    the image smoke gate MUST also produce a valid CycloneDX SBOM with the
    required runtime-component coverage. The SBOM is retained as a short-lived
    workflow artifact for inspection but is not published as release metadata.
    This validation does not run in `ci.yml` on pushes to `master`;
    `build-images.yml` performs the equivalent check for `master` and tag builds.

The advisory `renovate-validation.yml` workflow is documented in
`docs/deployment.md` (Workflow Inventory and Workflow Conventions). It is
separate from the required `ci.yml` gates and is not a required merge check.

The test execution environment MUST provide PostgreSQL 18 and Redis 8
instances, exposed to the test harness via `TEST_DATABASE_URL` and
`TEST_REDIS_URL` respectively. When the suite runs with parallel
workers, the Redis instance MUST offer enough logical databases for one
dedicated database per worker (see Worker and Test Isolation, above).

---

## Image / Container Smoke Testing

The three-tier pyramid runs against the local installation and cannot prove
that the final OCI image has the right contents, metadata, permissions, or
runtime topology. The **image suite** fills that gap. It is an
artifact-verification and publication gate, not a second product/API test
suite and not another tier of the functional pyramid.

Assertions prefer an external observation through the candidate's normal
runtime boundary. A small gray-box probe through `compose exec` or an
equivalent one-shot container is permitted when it is the narrowest sound way
to inspect a physical artifact property such as a file, runtime user, installed
command or import, task registration, or certificate store. Large injected
programs that recreate service, API, schema, or algorithm tests are not
justified merely by running inside the container.

### Location and Marker

| Property | Value |
|----------|-------|
| Location | `backend/tests/image/` (one file per concern/role) |
| Marker | `@pytest.mark.image` |
| Isolation | Final-image containers and self-contained infrastructure. Does NOT use the in-process `db_session` / `client` fixtures |
| Default run | **Excluded** — `pyproject.toml` sets `addopts = "-m 'not image and not system'"` |

Because the marker is excluded from the default invocation, `cd backend
&& uv run pytest` never attempts to start containers, and — since
coverage is measured on that same default invocation — the image suite
**does not contribute to, and is not counted toward, the ≥95% coverage
gate**. This is intentional: it runs against a separately built artifact,
not the instrumented local installation.

### Artifact-Risk Rule

A change adds or extends image-suite coverage only when it introduces an
**artifact risk**: a plausible failure that focused tests against the local
installation would not detect because the final image or its real runtime
topology differs. Applicable risks include:

- OCI contents and omitted runtime assets, including Alembic files,
  certificates, package resources, required binaries, and exclusion of test
  code;
- image metadata and filesystem behavior, including the runtime user,
  non-root permissions, `PATH`, working directory, installed entry points,
  default command, and application importability;
- a documented process-role command and the runtime dependencies needed for
  that role to complete startup;
- real container networking or dependency topology;
- execution of migrations from the candidate image and external migration-job
  ordering before runtime startup; and
- behavior that genuinely changes across a real server or process boundary,
  including one representative broker-delivered path when needed to prove the
  packaged process topology.

The following normally remain at focused in-process or system boundaries, even
though they are observable over HTTP, CLI, or a process interface:

- API business semantics, envelopes, filtering, sorting, pagination, and
  authentication/authorization/error matrices;
- mutation, audit, transaction, idempotency, locking, and concurrency rules;
- exhaustive schema, index, and constraint assertions;
- detailed CLI option, rendering, interactive, and domain-error behavior;
- configuration validators, client defaults, and algorithms reproducible at a
  focused boundary; and
- reconciliation semantics whose only artifact-specific claim is that the
  packaged process starts and invokes already-tested logic.

When exact coverage exists at a focused integration, e2e, CLI, model,
migration, task, lifespan, or system boundary, it MAY replace an image
assertion if the behavior is not artifact-sensitive. The change that removes
the image assertion MUST record the exact parity first. Facts that exist only
in the OCI artifact, such as physical exclusion of test code, cannot be
replaced by source-level or system-suite coverage.

### Execution

The suite runs exclusively through this chain:

```text
scripts/image-smoke.sh -> Docker Compose -> pytest on the host
```

The same runner is used locally and in CI. The supported harness environment
is Docker Engine or Docker Desktop with the Docker Compose CLI plugin
(`docker compose`) version 2.32.2 or later. The runner validates the CLI,
server identity, daemon reachability, and Compose version before build or stack
operations. Podman compatibility endpoints, `podman-compose`, standalone
`docker-compose`, and command-selection overrides are not supported.

Compose version acceptance compares numeric major, minor, and patch components
against 2.32.2. This floor ensures `--pull never` is available for both `up`
and one-shot `run` operations, so every candidate-consuming path can reject
image substitution explicitly. An optional leading `v` and vendor or build
suffix do not alter the comparison; an unparseable version fails preflight.

Host pytest reaches the API through a daemon-allocated port bound explicitly
to the pytest host's loopback interface. A remote Docker context that cannot
provide that local reachability MUST fail during preflight rather than timing
out against host `localhost`. A daemon endpoint located on another host is
incompatible; local Docker Engine or Docker Desktop contexts that expose the
published port on the pytest host remain supported.

Each invocation owns a unique Compose project name and its corresponding
containers, network, volumes, and disposable projects. It MUST pass the
resolved project identity, candidate-image identity, and API endpoint to every
fixture and diagnostic command. No invocation may discover, address, or tear
down resources belonging to another invocation.

The runner:

1. resolves or builds the candidate image once;
2. records an immutable local image identity and requires every application
   role and one-shot probe to use that candidate without a rebuild or pull;
3. starts a fresh self-contained primary Compose stack;
4. waits for the role-readiness evidence below;
5. runs `uv run pytest -m image tests/image/` on the host;
6. captures diagnostics when any phase fails; and
7. removes every owned project and volume.

`--no-build` may use a pre-built image supplied through `SENTINEL_IMAGE`, but
the same identity requirements apply. A failure before pytest preserves the
failing phase as the primary result and receives the same project-aware
diagnostics as a pytest failure.

This Docker-only requirement applies to the repository's image-smoke harness,
not to the published OCI artifact; see Deployment-agnostic packaging in
`docs/architecture.md`. Repository-managed local development, testcontainers
provisioning, and the image-smoke suite all standardize on Docker, but remain
separate execution paths with distinct lifecycle contracts.

### Primary and Disposable Topologies

`docker-compose.smoke.yml` defines a self-contained primary stack with its own
PostgreSQL and Redis services, the one-shot migration job, and each implemented
and deployable application role. All application roles use the exact candidate
image. Infrastructure services publish no host ports; only the API is exposed,
on the invocation's loopback-bound dynamic port. A future process role gains an
image assertion when it becomes implemented and deployable, not while its
service remains speculative or commented out.

The primary stack starts from fresh volumes and is predominantly
observational. Tests MUST NOT drop and recreate its tables, corrupt and repair
its Redis state, or restart services merely to repeat service, lifespan, or
reconciliation contracts. Manual repair of primary PostgreSQL or Redis state
is forbidden because later assertions would depend on the repair succeeding.

Failed migration, deliberately failed process startup, destructive
infrastructure lifecycle, or another irreducibly mutable artifact scenario
runs in a dedicated disposable Compose project. Each disposable project owns
fresh resources, independent finite bounds, diagnostics, and cleanup. A full
Compose project per ordinary assertion is not required.

### Process Readiness

Container existence or process-running state alone is not readiness when
required initialization continues afterward. The gate uses bounded positive
evidence appropriate to each active role:

- **Migration:** the one-shot migration job exits successfully after upgrading
  fresh PostgreSQL. An incomplete or failed migration prevents application
  roles from starting.
- **API:** the server responds through the published loopback endpoint with
  readiness evidence that depends on both PostgreSQL and Redis. The gate also
  exercises the image's default API command instead of always replacing it in
  Compose.
- **Worker:** a Celery control round-trip succeeds and a representative set of
  application tasks is registered after startup bootstrap completes.
- **Beat:** bounded evidence shows startup bootstrap and schedule reconciliation
  completed; merely observing the Beat process still running is insufficient.

Readiness MUST NOT use arbitrary fixed sleeps, invent a fake Beat ping, enable
a Celery result backend, or make a Redis key the authoritative record that a
process is ready. Redis remains ephemeral and PostgreSQL remains the source of
persistent truth.

### Lifecycle Bounds, Diagnostics, and Failure Precedence

Preflight, image resolution/build, initial stack startup, per-role readiness,
pytest, every disposable project, diagnostics, and teardown each have an
explicit finite bound. The CI job timeout is only the final safety net. Polls
use monotonic deadlines and produce the last relevant observation on timeout.

For startup, readiness, pytest, or disposable-project failure, diagnostics are
captured before teardown and include, when available:

- the resolved candidate image identity;
- Compose project identity and complete container state, including stopped
  containers;
- bounded recent timestamped, color-free logs;
- migration exit evidence; and
- the phase, command, and captured output that failed.

Each diagnostic command is independently bounded. Diagnostic failure is
reported but never replaces the primary failure. Cleanup always runs and also
cannot hide the primary failure; however, a cleanup failure makes an otherwise
successful run fail. Passing phases do not perform diagnostic collection.

### CI Gate

`.github/workflows/build-images.yml` wraps the smoke suite as a
**blocking gate** between build and publish: the image is built once and
loaded locally (`push: false, load: true`), the smoke script runs
against that exact artifact, and only on success is the **same image
digest** re-tagged and pushed. A failing smoke test prevents `latest`
and semver tags from ever being published. The tested and published
artifacts are guaranteed identical — no second build is performed.

The SBOM gate runs only after artifact verification succeeds and scans that
same candidate identity. Image smoke, SBOM generation/validation, and
publication therefore form one ordered chain; none may silently substitute a
different tag resolution, pulled image, or rebuilt artifact.

### SBOM Gate

The pull-request `image-smoke` job reuses the image it already built and tested
to exercise release SBOM generation without publishing an image, GitHub
Release asset, or signed attestation. A shared repository script owns the gate
so CI and release workflows cannot acquire separate implementations. Pinned
tool versions live in one CI-consumed configuration file read by that script.
The gate MUST:

1. generate CycloneDX 1.7 JSON from the immutable candidate image ID produced
   by the successful smoke gate, using the same pinned Syft version as the
   release workflow;
2. validate it with the same pinned official CycloneDX validator image used by
   the release workflow;
3. run Sentinel's semantic validator, which checks the required CycloneDX
   fields, non-empty inventory, all direct runtime Python dependencies declared
   by `backend/pyproject.toml`, Debian runtime packages, and exclusion of direct
   development-only Python dependencies declared by that same file; and
4. upload the validated file as a seven-day workflow artifact so reviewers can
   inspect the exact candidate output.

The release workflow performs the same two validation mechanisms after its smoke
gate and before pushing the image. Structural unit tests verify workflow
permissions, release-only publication conditions, fixed artifact naming,
step ordering, digest consistency, and fail-fast behavior. These tests mock
publication commands; the first version-tag execution after implementation is
the end-to-end verification of GitHub OIDC signing, the Attestations API, GHCR
OCI attachment, and GitHub Release asset upload.

### Representative Gate Evidence

The gate keeps the smallest set of observations that localize the following
artifact facts without duplicating focused behavior tests:

- expected non-root execution, required runtime imports/assets, Alembic files,
  certificate file and system trust store, installed CLI entry points, and
  physical exclusion of test code;
- successful fresh migration and migration-gated application startup, plus a
  disposable failed-migration ordering scenario;
- external `/health`, `/ready`, and `/openapi.json` availability through the
  candidate's default API command;
- startup of each implemented API, worker, and Beat role from the same image,
  with representative worker task registration and Beat post-reconciliation
  readiness;
- one representative broker-delivered task producing a durable PostgreSQL
  outcome without a Celery result backend; and
- only the smallest justified process-command-specific startup failure, in a
  disposable project, when positive startup plus focused tests cannot establish
  the artifact risk.

One observation MAY establish multiple closely related facts when failure
localization remains clear. Detailed API responses, system-setting self-healing
and preservation, RedBeat reconciliation algorithms, CLI domain errors, and
Celery configuration validation remain in their focused suites. The image gate
does not restart the primary stack to repeat them. Database-unavailability
variants of worker and Beat startup failure remain in focused startup-handler
tests.

---

## Local Process System Testing

The three-tier pyramid and the image smoke suite share a limitation:
they never exercise real inter-process communication between the
pytest host, a Celery worker, Celery Beat, Redis as a broker, and
PostgreSQL as durable storage — all within the local development
environment. The **local process system suite** fills this gap by
spawning real worker and Beat processes against the test
infrastructure and verifying observable outcomes through the database
and the in-process ASGI API client.

This suite is distinct from the image smoke suite: it does NOT
exercise the built Docker image. It validates the scheduled pipeline
path (registration → config bootstrap → Beat schedule → broker
delivery → worker execution → FetcherRun finalization → Public API
visibility) using the local virtual environment and real
infrastructure.

### Location and Marker

| Property | Value |
|----------|-------|
| Location | `backend/tests/system/` |
| Marker | `@pytest.mark.system` |
| Isolation | Spawns real worker and Beat processes against test PostgreSQL and test Redis. Does NOT use the `db_session` rollback fixture for subprocess-committed rows |
| Default run | **Excluded** — `addopts` excludes both `image` and `system` markers |
| Coverage | Not counted toward the coverage gate — subprocess execution is not observable by the pytest-host tracer |

### Execution

The suite runs via a dedicated pytest invocation:

```bash
cd backend && uv run pytest -m system tests/system/
```

This invocation is included in the **pre-push hook** (after the
default in-process suite) and as a **separate blocking CI gate** on every
pull request and push to `master`. The CI environment provides the
same `TEST_DATABASE_URL` and `TEST_REDIS_URL` used by the default in-process
suite.

### Test-Only Fetcher

The suite exercises the generic fetcher pipeline using a concrete
`BaseFetcher` subclass that exists exclusively in test code. This
class:

- Lives under `backend/tests/support/` (never under `app/`).
- Is not imported by `app/services/fetcher_discovery.py`.
- Is not documented in `docs/data-sources.md` (Fetcher Registry).
- Cannot be discovered by normal production processes (API server,
  worker, Beat) unless explicitly imported by a test-owned process
  launcher.
- Has no production discovery import, environment flag, or runtime
  test mode that could expose it.
- Performs no database writes, network calls, metric-helper calls,
  cursor assignment, or domain mutations in its `execute()` method.

**Expected finalized run outcome:**

| Field | Expected value |
|-------|----------------|
| `status` | `success` |
| `items_succeeded` | `0` |
| `items_created` | `0` |
| `items_updated` | `0` |
| `items_failed` | `0` |
| `triggered_by` | `schedule` |
| `triggered_by_user_id` | `NULL` |
| `error_message` | `NULL` |
| `error_detail` | `NULL` |
| `error_traceback` | `NULL` |
| `cursor` | `NULL` |
| `started_at`, `finished_at` | Non-NULL, `finished_at >= started_at` |
| `FetcherAuditEvent` | None created |

### Registration Boundary

The test-only fetcher is registered in worker and Beat processes
through a test-owned launcher that imports the class before invoking
the normal Celery entrypoint. This ensures:

- Production entrypoints import only `fetcher_discovery`.
- The test class is registered process-locally in spawned test
  processes and in the pytest host (for API visibility assertions).
- Process exit removes subprocess registry state.
- Pytest teardown restores only the specific test entry without
  clearing the global registry.

The spawned worker and Beat subprocesses MUST receive an explicit
environment that sets `DATABASE_URL` and `CELERY_BROKER_URL` (and
`REDIS_URL` if consumed) to the test-harness infrastructure derived
from `TEST_DATABASE_URL` and `TEST_REDIS_URL`. The subprocess
environment MUST NOT inherit application-configured values from the
developer's shell or `.env` file. This prevents the spawned processes
from writing test rows into a real local development database or
broker.

### Behavioral Requirements

The system test MUST prove the following end-to-end path using real
infrastructure:

1. A real Celery worker starts, becomes reachable, and has the
   generic `run_fetcher` task registered.
2. A real Celery Beat starts, bootstraps the test fetcher's
   `FetcherConfig`, reconciles a RedBeat entry for it, and schedules
   it according to the normal mechanism.
3. Beat dispatches the task through the Redis broker without manual
   `send_task()` bypass.
4. The worker executes the fetcher and finalizes a `FetcherRun` record
   with the expected outcome. Exactly one finalized `FetcherRun` row
   MUST exist for the test fetcher after the assertion phase (no
   duplicates from concurrent dispatch).
5. The finalized run is visible through the Public fetcher observation
   API (exercised via the in-process ASGI client with independently
   connecting database sessions).
6. No domain tables are mutated (no rows created, modified, or
   deleted outside the fetcher infrastructure tables).

The test MAY use the RedBeat public API to make an existing
reconciliation-created entry become due without waiting for a real
cron boundary, provided Beat still performs the dispatch (the broker
path is not bypassed).

### Bounded Waiting and Diagnostics

- Every poll operation uses a monotonic deadline.
- Every subprocess operation has a finite timeout.
- Short intervals between poll attempts are acceptable; a fixed sleep
  followed by a single assertion is not.
- Early failure if the worker or Beat process exits unexpectedly.
- Timeout diagnostics MUST include: captured process output, return
  codes, current `FetcherConfig`/`FetcherRun` state, and RedBeat
  entry state (when readable).

### Deterministic Cleanup

Cleanup MUST succeed regardless of whether the test assertions passed
or failed. The required ordering:

1. Stop Beat first (prevents new task enqueues).
2. Allow the worker bounded time for graceful completion.
3. Escalate to forced termination after a deadline.
4. Delete the test RedBeat entry through the library's public API.
5. Clear only the designated Redis logical database (`FLUSHDB`).
6. Delete committed test rows from PostgreSQL in FK-safe order.
   This includes all `FetcherConfig` rows created by the spawned
   processes' bootstrap (which inserts rows for every fetcher in
   the subprocess registry), not only the test fetcher's own row.
7. Restore/remove the test registry entry in the pytest process.
8. Verify that processes are dead and test artifacts are absent.

A cleanup failure MUST fail the test — including when the primary
assertion already failed.

### Parallel Safety

- Uses the worker-specific Redis logical database (same isolation as
  the ordinary suite).
- `FLUSHALL` is forbidden.
- PostgreSQL cleanup predicates are restricted to test-fetcher-
  specific names and IDs (no table-wide deletions).
- Worker hostname, temporary files, and diagnostic paths are unique
  per test invocation.
- The suite remains safe if assigned to a pytest-xdist worker.

### Relationship to Other Test Suites

The local process system suite complements focused unit and integration tests;
it does not replace their lifecycle, bootstrap, acquisition, reconciliation,
or serialization assertions. It MAY replace image coverage for real-process or
broker behavior under the Artifact-Risk Rule above, which requires exact parity
and absence of artifact sensitivity before removal.

The image suite retains only the artifact-specific remainder, such as startup
of a packaged role or physical exclusion of the test-only fetcher source from
the shipped image. It does not retain detailed process behavior solely because
that behavior was once exercised in a container.

### Automation

The system suite MUST be executed automatically:

- **Pre-push hook**: invoked after the default in-process suite completes
  successfully.
- **CI pipeline**: a separate blocking invocation alongside the
  existing gates (not merged into the coverage-measured run).

No manual invocation is required for normal development workflow.

---

## Mandatory Test Scenarios

Beyond the general obligation to test every implemented function (see
Guardrail 6 in `AGENTS.md`), the following scenarios are always
required when their feature area is affected:

### API Endpoints

Every new or modified API endpoint MUST be tested for:

- Happy path with valid input
- Validation errors (invalid/missing fields) → correct error code
- Authentication enforcement when applicable to the declared access level
  (see `api-spec.md`, Response Applicability Derivation)
- Authorization enforcement when the declared capability can produce 403
- Resource not found → 404
- Edge cases: empty results, boundary values, concurrent modifications
  (for endpoints backed by `FOR UPDATE` locking: verify lock
  serialization using `db_session_factory` and the two-session pattern
  described in Database Strategy — Concurrency Testing)

### Fetcher Outcome and Effect Accounting

When `BaseFetcher`, `FetcherRun`, a concrete fetcher's metric mapping, or a
fetcher run response schema is implemented or changed, the following complete
contract is mandatory:

- **Helper validation**: exercise each of `record_succeeded`, `record_failed`,
  `record_created`, and `record_updated` with the default count, an integer
  greater than one, and zero. Zero is a no-op. For every helper, a negative
  integer raises `ValueError`; each non-integer representative, including
  `True`, `False`, a float, a numeric string, and `None`, raises `TypeError`.
  Every rejected call leaves all four counters unchanged.
- **Per-run reset**: reuse one fetcher instance across runs and prove all four
  counters reset to zero before the next execution, including after a prior
  success, per-item failure, and escaping exception. Cursor, settings, and HTTP
  lifecycle reset assertions remain under their existing contracts.
- **Finalization precedence**: an escaping settings, previous-cursor, execution,
  timeout, or other run-level exception produces `failure` regardless of any
  successful, failed, created, or updated counts and preserves those counts for
  diagnostics. On normal return, failed greater than zero with succeeded equal
  to zero produces `failure` and exactly `All {items_failed} items failed`;
  both succeeded and failed greater than zero produces `partial`; no failed
  items produces `success`, including an empty run. Created or updated counts
  never substitute for succeeded in any branch.
- **Regression combinations**: cover successful unchanged/no-op work plus one
  failure (`partial`), all selected units failed (`failure`), an empty run
  (`success`), successful terminal units with durable effects and no failures
  (`success`), and each of a committed create and a committed update followed
  by a required post-commit failure (the corresponding effect counter is `1`,
  `items_failed = 1`, `items_succeeded = 0`, normal-return `failure`). Cover a
  best-effort post-commit failure separately: it is logged, retains the durable
  effect, records the unit as succeeded, and records no failure.
- **Durability and exclusivity**: a create/update effect is absent before commit
  and after rollback or commit failure, and appears only after durability. No
  current work unit records both created and updated. Every selected terminal
  unit contributes exactly once to succeeded or failed, never both; pre-scope
  exclusions contribute to neither. Tests must fail counter-compensation or
  dispatch-as-updated implementations.
- **Diagnostics and persistence**: timeout diagnostics compute processed items
  as `items_succeeded + items_failed`. Finalization persists all four counters
  in one finalization transaction on success, partial, normal all-failed, and
  escaping-exception paths. A finalization database failure retains its existing
  exception precedence. Queued and running rows remain at database defaults and
  expose zero counters; tests must prove no live progress writes occur.
- **Model contract**: `items_succeeded` is `INTEGER NOT NULL DEFAULT 0` in
  SQLAlchemy metadata and the forward migration. No nullable compatibility
  state or data backfill is expected because no live or production database
  exists.
- **Public read shapes**: e2e and response-schema tests assert
  `items_succeeded` in fetcher-list `last_run`, run list, run detail, and every
  timeline point. Include terminal examples where success is not equal to
  created plus updated and queued/running examples with all counters zero.
  Existing paths, methods, filters, pagination, errors, optional authentication,
  field-level visibility, and authorization remain unchanged.
- **Concrete mappings**: tests cover the selected unit, all successful
  terminal outcomes, all failed terminal outcomes, pre-scope exclusions, and
  durable create/update effects documented by the owning specs for all 16
  registered fetchers: `sync_nvd_cves`, `sync_mitre_cves`,
  `sync_redhat_cves`, `sync_smelt_products`, `sync_aimaas_lifecycle`,
  `sync_aimaas_thresholds`, `detect_ibs_track_releases`,
  `detect_ibs_product_releases`, `evaluate_lifecycle_transitions`,
  `sync_ibs_requests`, `sync_cisa_kev`, `sync_epss_scores`,
  `sync_ghsa_advisories`, `sync_kernel_cves`, `sync_osv_advisories`, and
  `evaluate_failed_cve_sources`. Shared failures affecting several selected
  units count each unit exactly once, not each retry, parser stage, or log.

### User Identifier Resolution

Every endpoint that accepts a user identifier MUST be tested with both
UUID and username inputs. At minimum:

- Valid UUID → returns expected result
- Valid username → returns same expected result
- Non-existent UUID → 404
- Non-existent username → 404

### Service Functions

Every new or modified service function MUST be tested for:

- Expected behavior on valid input
- All guard conditions (Q2) and their error responses
- Audit event creation with correct field values (see Audit Trail
  Testing)
- Re-invocation behavior (Q5 — idempotency characteristics)
- Exception propagation to callers (Q6)
- Lock serialization: every service function that acquires `FOR UPDATE`
  (as documented in `docs/features/tickets/ticket-mutations.md`,
  `docs/features/tickets/ticket-service.md`,
  `docs/features/packages/package-service.md`) MUST have at least one
  test verifying lock serialization using `db_session_factory` and the
  two-session pattern described in Database Strategy — Concurrency
  Testing

Ticket gate and convergence changes additionally require:

- exhaustive status-transition coverage and highest-valid-status evaluation;
- Analyzed and Resolved formulas over empty sets, all-EOL trees, missing
  Products/lifecycle data, independently excluded descendants, eligibility
  overrides, CVE-less `FIXED`, CVE association after CVE-less resolution, and
  forward/reverse corrections;
- `REJECTED -> PUBLISHED` reopening the unique associated Ticket only when its
  locked-current status is `Ignored`, without consulting audit history.

The owning service specifications define detailed Ticket-convergence test
matrices: see `ticket-service.md` (Architectural Test Requirement, manual-zone
registration and operator dispatch) and `package-service.md` (Architectural
Test Requirement, affectedness authority and Ticket convergence workflow).
Those tests distinguish best-effort automatic publication failure after a
successful committed mutation from the explicit rerun endpoint's 503
publication failure.

### CVE Ingestion Persistence

When `CVEIngestPayload`, `upsert_cve()`, `ensure_cve_exists()`, child
persistence, or `record_source_status()` is implemented or changed, tests must
cover this complete matrix:

- Every nullable global field independently: omitted preserves, explicit null
  clears, a value sets/replaces, and an equal supplied value is a no-op.
  `cve_state` omission preserves, explicit null is rejected before writes, and
  both Enum values are accepted.
- `PUBLISHED` always leaves `date_rejected` null, including a
  `REJECTED -> PUBLISHED` merge that omits the date. Explicit
  `PUBLISHED + non-null date_rejected` rejects the complete payload before any
  CVE, child, source-status, Ticket, or audit write. For `REJECTED`, exercise
  omitted, explicit-null, and timestamp date inputs.
- For CVSS, CWE, external identifiers, SSVC, KEV, and EPSS, exercise omitted,
  explicit null, empty collection where applicable, create, effective update,
  equality, and retain behavior. Assert that rejection alone deletes none of
  them.
- For each child conflict key, identical normalized duplicates collapse and
  conflicting same-key content rejects the complete payload before writes.
  Include the affected-version safety-net key and fields outside that key.
- Affected-version scopes cover unobserved, non-empty replacement, observed
  empty replacement, explicit removal, equal replacement, repeated empty/remove
  no-op, and multiple scopes where one operation cannot change another. Empty
  and removed scopes leave no marker row.
- `UpsertResult.action` covers serialized insert winner `created`; every global
  and child effective change as `updated`; all-equal/retained input as
  `unchanged`; and exclusion of source-status timestamps, Ticket creation,
  references, delegated audit, and post-ingest work. Successful results always
  contain a Ticket.
- Concurrent create/create and create/ensure races use independent PostgreSQL
  sessions. Assert one insert winner, loser `updated` or `unchanged` as
  applicable, the loser's caller-owned transaction remains usable for an
  unrelated write, and a rolled-back apparent winner allows another caller to
  become the creator. Service calls never commit or roll back.
- Same-source status races cover every success/failure/missing ordering with
  independent sessions and deterministic synchronization. Assert the last
  successfully serialized write wins, `fetched_at` is the statement's database
  wall-clock instant rather than transaction start, a repeated failure preserves
  `first_failed_at`, success/missing clears it, a later failure starts a new
  streak, and rollback or failed writes preserve prior committed state.

Unit tests additionally prove that `BaseCVEFetcher` accepts only
`CVESourceType` members, rejects raw strings at import time, and converts to
`.value` only in persistent, registry, API/wire, and Redis-key outputs.

### CVE Fetcher Infrastructure

When the CVE registry, single-item interface, per-CVE finalization, isolated
status handling, default catch-up, or a concrete CVE fetcher is implemented or
changed, focused tests MUST cover this complete contract:

- **Atomic registration and isolation**: duplicate `cve_source_type`, duplicate
  generic `name`, and every other generic or CVE validation failure leave both
  `FETCHER_REGISTRY` and `_CVE_SOURCE_TYPE_MAP` unchanged. Tests snapshot and
  restore both dictionaries. `supports_fetch_single = True` rejects the base
  safety-net method and accepts a real implementation inherited from
  `BaseGitFetcher`. `participates_in_catch_up = True` with
  `supports_fetch_single = False` rejects the default CVE `catch_up()` and
  accepts a custom override. Both accessors return fresh plain dictionaries.
- **Discovery completeness**: one production discovery import populates both
  registries in the API, general-worker, Git-worker, and Beat startup paths;
  every `CVESourceType` maps to exactly one concrete production class; and no
  test-only class appears in production discovery.
- **Typed result**: all successful `fetch_single()` and Git `process_item()`
  cases return `CVEFetchResult` for `created`, `updated`, and `unchanged`, with
  both non-NULL and NULL `post_ingest` where applicable. `CVENotInSource`
  returns no token. The token contains no ORM/session state and is not accepted
  as a Celery payload or result.
- **One-shot finalization**: the first finalization attempt consumes the token;
  a second call raises `RuntimeError` before commit, publication, or metrics.
  Consumption persists after commit failure. Assert exactly one commit, no
  pre-commit publication/metric, convergence before optional package handoff,
  no handoff for `post_ingest = None`, ordinary publication failure consumed,
  and cancellation/whole-run signals propagated before and after commit with
  truthful post-durability metrics.
- **Periodic metrics**: automatic periodic context maps created/updated and
  always success immediately after commit; unchanged maps only success.
  On-demand and catch-up map no `FetcherRun` metric. Periodic handlers do not
  duplicate success/effect metrics. Isolated missing is terminal periodic
  success; an ordinary failed unit records one failure.
- **Isolated statuses**: only typed `FAILURE` and `MISSING` are accepted, and the
  write uses an independent transaction after caller rollback. Ordinary lookup,
  write, and commit failures are logged and suppressed while preserving the
  prior latest state and original exception. Cancellation,
  `SoftTimeLimitExceeded`, and `MemoryError` propagate. No convergence,
  package publication, or FetcherRun metric/effect occurs.
- **Default catch-up**: cover missing Ticket, CVE-less Ticket, unresolved
  referenced CVE, success, missing, every ordinary pre-commit failure on every
  retry attempt, later success/missing overwrite, disabled and unknown fetcher,
  malformed UUID structured failure, retry classification, cancellation and
  whole-run signals, HTTP teardown, one `asyncio.run()`, exactly one engine
  disposal per invocation, Git queue preservation, and absence of
  `FetcherRun` records and `fetch_pending` keys.
- **Git boundaries**: `process_item()` returns `CVEFetchResult`, only the
  template finalizes and records periodic metrics, `fetch_single()` performs no
  clone mutation, candidate read failures never call `record_failed()` without
  a run, `queue = "git"` is preserved, and concrete subclasses do not override
  `execute()`.
- **Concrete compliance**: all eight CVE sources comply with typed return,
  centralized finalization, metric, status, and capability contracts. NVD and
  GHSA inline paths construct the token; MITRE and Kernel return it from
  `process_item`; Red Hat, OSV, and EPSS preserve `UpsertResult.action`; KEV
  remains non-refetchable and preserves its documented isolated-status
  deviation. `CompletenessGuardError` remains in the OSV module.

### On-Demand CVE Refetch

When on-demand preparation, publication, task execution, source status, or the
refetch endpoint is implemented or changed, focused integration, synchronous
task-wrapper, and e2e tests MUST cover:

- capability failure before resource lookup; missing and inaccessible CVEs with
  identical `CVE_NOT_FOUND` bodies; and an independent-session accessibility
  race proving CVE-then-Ticket locked-current state wins before source or
  enabled-state validation;
- explicit unknown/non-refetchable and disabled sources, broadcast partial
  disabled results, no enabled refetchable sources, and an empty fetch-single
  registry, with the exact 422/409/503 matrix and standard error envelopes;
- service-owned preparation for manual create-with-CVE, associate-CVE, and
  refetch; placeholder-only-when-needed behavior; refresh preparation for an
  existing populated CVE; and atomic association, CVSS handover, Product,
  reconciliation, audit, and registration; automatic create/associate must
  preserve ordinary `201`/`200` and committed audit events when preparation
  finds an empty or all-disabled eligible-source roster, while an unexpected
  database, bootstrap-invariant, registration, or transaction error rolls back
  the mutation and its audit events;
- zero Redis/Celery I/O on capability or accessibility denial, validation
  failure, rollback, and commit failure; commit and CVE/Ticket lock release
  before publication; automatic create/associate preserving ordinary 201/200
  on publication failure; and the accepted commit-to-publication crash gap
  without an outbox, durable job/progress row, or result backend;
- all four `FetchDispatchResult` lists as disjoint, deterministic canonical
  source order; 202 only when enqueued or already pending is non-empty; partial
  failed/disabled 202 results; and every-attempt-unconfirmed 503 without
  treating an `apply_async()` exception as certain broker rejection;
- fixed token-valued `SET NX EX 600`, Redis fail-open publication, compare-and-
  expire at attempt start and before retry, no absent-key recreation, owner-only
  terminal compare-and-delete, an old task unable to delete a newer marker, and
  TTL recovery after crash or hard kill;
- `fetch_single_cve` payload validation and the complete terminal matrix:
  unknown/deregistered target, source mismatch, missing configuration, disabled
  meanwhile, missing CVE, successful `CVEFetchResult` finalization,
  `CVENotInSource`, retryable attempts and exhaustion, non-retryable failure,
  cancellation, soft time limit, memory exhaustion, and process-loss cleanup;
- one `asyncio.run()` per task attempt, one fresh session, wrapper-owned HTTP
  teardown, exactly one engine disposal on every return/exception path, no
  `FetcherRun`, and no Celery result storage;
- task identity from `fetcher_cls.name` and queue omission for `None`, plus Git
  queue preservation for both MITRE and Kernel;
- source response `enabled` independent from `refetchable`, deregistered values
  all false, missing-config effective enabled fallback, disabled-source overlay
  suppression, Redis failure durable fallback, and pending overriding prior
  success, failure, missing, or no status while retaining completed timestamps;
- `evaluate_failed_cve_sources` materializing candidates, using non-locking
  internal source/config revalidation, and closing each read transaction before
  Redis/Celery; excluding sources that revalidation finds unregistered,
  no longer fetch-single capable, or disabled from success and failure metrics;
  recording a failure for a selected pair whose required `FetcherConfig`
  invariant fails or whose publication is unconfirmed; counting a later
  accepted publication according to the existing dispatch-only metric while the
  task performs its disabled no-op; and
- cross-loop lifecycle regression coverage for repeated task attempts using the
  production pooled engine.

### CVE and Source Reads

When the CVE list, the per-CVE source-status read, or the global
persisted-source listing is implemented or changed, focused service, API, and
integration tests MUST cover this complete matrix.

**CVE list:**

- Anonymous and authenticated callers, with ticketless CVEs always visible and
  associated CVEs visible or invisible according to the canonical Ticket
  predicate; an independent-session race changes confidentiality, revokes the
  caller's grant, excludes the caller's last qualifying package, or creates the
  CVE-to-Ticket association so an initially visible CVE becomes inaccessible
  before the protected selection, and the response never exposes a row selected
  after access was lost.
- Single and combined `search`, `cve_state`, repeatable `severity`,
  `has_ticket`, `from_date`, and `to_date` filters, including AND across
  distinct filters and OR across valid severity values.
- Search normalization: outer trim, a whitespace-only value equivalent to
  omission, and literal percent, underscore, and backslash characters; CVE-ID
  case-insensitive prefix and title/description case-insensitive substring
  matches.
- Severity `none` (resolved score `0.0`) and `unresolved` (SQL `NULL`), and a
  supplied severity list whose values are all invalid returning an empty page.
- A supplied `cve_state` that is not the documented `published`/`rejected`
  wire value returning an empty page.
- Inclusive date bounds, an inverted range returning `400 DATE_RANGE_INVERTED`,
  and rows whose `published_date` is `NULL` excluded when a bound is present.
- Lexical `cve_id` sort, semantic `severity` sort, NULL-last behavior, and the
  same-direction internal tie-breaker across pages; a page beyond the last page
  returns an empty item list with the correct total.
- Fan-out from the associated-Ticket join and child joins collapsing to exactly
  one logical row per CVE, with no duplicate rows and no inflated `meta.total`.
- Items and `meta.total` deriving from one coherent observation, proven by
  failing an implementation that counts broadly and removes rows in Python or
  post-filters after pagination.

**Per-CVE source status:**

- Malformed, missing, and inaccessible CVE paths producing identical
  `404 CVE_NOT_FOUND` bodies; independent-session acquisition and loss of access
  before the protected selection.
- Registered sources with no `CVESource` row, persisted historical
  (deregistered) sources, `enabled` independent of `refetchable`, and the
  missing-`FetcherConfig` effective-enabled fallback.
- Every durable status (`success`, `failure`, `missing`) and `not_attempted`,
  and every durable status combined with an enabled-source pending marker;
  disabled-source overlay suppression; deterministic `source` ordering with
  current and historical identities interleaved.
- A pending marker preserving the last completed `fetched_at` and
  `first_failed_at` over a prior `success`/`failure`/`missing` row, and a
  pending marker with no persisted row yielding null timestamps.
- Aggregate Redis overlay success and failure, proving the failure path returns
  the complete durable status for every source with `200 OK` and never a mixed
  response assembled from observations taken before and after the failure.
- The durable observation completing and its transaction closing before any
  Redis I/O.

**KEV projection:**

- A `CVEKEVEntry` written through the dedicated `sync_cisa_kev` fetcher and a
  `CVEKEVEntry` written through the MITRE CISA-ADP container both yielding
  `success` with `fetched_at = CVEKEVEntry.updated_at` and null
  `first_failed_at`.
- No entry and no successful `sync_cisa_kev` run yielding `not_attempted`; a
  fully successful run whose `finished_at` precedes the CVE yielding
  `not_attempted`; a later fully successful run yielding `missing` with the run
  `finished_at`.
- `partial`, `failure`, `queued`, and `running` runs never proving absence, and
  the `finished_at DESC, id DESC` tie-breaker selecting the latest successful
  run.
- A retained historical entry continuing to yield `success` after catalog
  removal.

**Global persisted-source listing:**

- Current and historical source identities, and the `source`, `status`,
  `stalled`, and date filters, including an inverted `from_date`/`to_date`
  range returning `400 DATE_RANGE_INVERTED`.
- A malformed or overlength `source` value rejected as `422 VALIDATION_ERROR`
  and a well-formed absent value returning an empty page; a supplied `status`
  that is not a persisted status value returning an empty page.
- The 30-day boundary before, exactly at, and after the threshold, with the
  same observation instant used for the page and `meta.total`; `stalled=false`
  is not treated as retryable.
- Lexical `source`/`status` sort, nullable timestamp sort, coherent total, and
  the internal `CVESource.id` tie-breaker across pages.
- An anonymous request returning a source row whose CVE is associated with a
  confidential Ticket, proving the identifier-only exception is preserved and
  not over-restricted.
- `CVESource.id` absent from the response, and no Ticket UUID, protected CVE
  content, user identity, or raw error exposed.
- A latest-state result that can diverge from `FetcherRun.items_failed` without
  changing the authoritative run count.

### CVE Ingestion and Ticket Composition

When the complete source-neutral ingestion transaction is implemented or
changed, integration tests additionally cover:

- one exact phase order from pre-write validation through the sole commit and
  post-commit effects, with one shared UTC `evaluation_date`;
- brand-new published, brand-new already-rejected, existing-with-Ticket,
  published orphan, rejected orphan, unchanged rejected,
  `PUBLISHED -> REJECTED`, and `REJECTED -> PUBLISHED` paths;
- brand-new-already-rejected and rejected-orphan event order:
  `ticket_created`, `cve_associated`, canonical CVSS events, optional one
  severity/Product/final-gate sequence, then exact system `New -> Ignored` with
  `comment = "CVE rejected"`;
- the system-only rejection boundary across every Ticket status, idempotent
  retry, no audit-history query, and lock/association contract violations;
- one multi-assessment trusted-external CVSS batch with canonical version then
  provider order, mixed create/update/unchanged and individually invalid
  candidates, one setting read, at most one severity event, one Product pass,
  and one final reconciliation; an empty batch performs no setting read or
  CVSS-derived write/event, and a one-element external batch still uses the
  batch boundary rather than the manual single-assessment function;
- contradictory canonical CVSS duplicates rejecting before every CVE, Ticket,
  source-status, reference, and audit write, while standalone invalid candidates
  log safely and do not discard valid siblings;
- independent-session same-CVE races proving the CVE lock serializes unique
  Ticket creation/association, one commit winner, waiter-current behavior, and
  no catch-and-requery in an aborted transaction; race conflicting rejection
  and republication payloads in both commit orders and prove the waiter derives
  its lifecycle decision from locked-current state;
- republication with changed CVSS in the same payload proves the re-opened
  Ticket's Product and final gate state derive from the newly persisted complete
  assessment set, and that the Ticket reselect in `reopen_from_ignored()` is a
  same-transaction re-lock preserving the CVE-then-Ticket order;
- the accepted `REJECTED -> PUBLISHED -> REJECTED` oscillation sequence: once
  the intermediate republication moves the Ticket into an active status, the
  later rejection changes CVE state but creates no Ticket lifecycle event and
  leaves correction to a VA without consulting audit history;
- automatic references after all `upsert_cve()` database work but before the
  sole commit: invalid candidates continue, while an unexpected reference
  failure rolls back CVE/source status, Ticket, CVSS, Product, lifecycle, audit,
  and every reference write;
- rollback, commit failure, and cancellation publish neither registered Ticket
  convergence nor the package handoff; successful commit releases locks,
  attempts registered convergence publication first, and only then may publish
  the package handoff, even when the best-effort convergence publication fails;
- an ordinary package-handoff publication failure after successful commit logs
  exactly one sanitized `cve_package_handoff_publication_failed` ERROR, returns
  normally, preserves `CVESource.success` and the one terminal
  `record_succeeded()` outcome plus any committed created/updated effect,
  records no failure metric, and never enters API/Git per-item failure handling;
  the log excludes payload, package names, exception text, and upstream data;
- repeated `commit_and_dispatch()` calls for different CVEs on one reusable
  session prove each transaction's convergence registrations are detached and
  consumed exactly once, attempted failures do not replay, rollback/cancellation
  clear failed-transaction registrations, and later CVEs inherit none;
- pure `build_post_ingest_tasks()` extraction with no database, mapping, Redis,
  Celery, or network call; exact deduplication, deterministic ordering,
  serializable output, filtered invalid package-name candidates, and `None` for
  empty input;
- a structural/spy assertion that no HTTP, Redis, Celery, DNS, package mapping,
  or other external I/O occurs in Phase 1 or while CVE/Ticket locks are held;
  and
- manual creation with an already-`REJECTED` CVE and manual association of an
  already-`REJECTED` CVE retain their ordinary Ticket status/audit sequence,
  do not invoke `ignore_new_for_rejected_cve()`, and create no automatic
  `CVE rejected` event.

### Post-Ingest Package Resolution

When `resolve_ticket_packages` or its package-service async workflow is
implemented or changed, unit, integration, and synchronous task-wrapper tests
MUST cover this complete matrix:

- primitive task argument validation rejects malformed Ticket and match-criteria
  UUIDs, container shapes, CPE-match keys/types, vendor/product pair shapes, and
  individually overlength or otherwise invalid values before mapping, database,
  HTTP client creation, or SMELT I/O; the wrapper receives explicit primitives,
  not a `PostIngestTasks` dataclass;
- exact CPE and vendor/product deduplication occurs before resolver calls;
  NVD-selected metadata is not reinterpreted; resolver results and direct names
  preserve case, exact-deduplicate across sources, apply the package-name grammar
  before SMELT, and use ascending Unicode code-point processing order;
- malformed CPE values retain the resolver's per-value empty result, while
  `CPEMappingLoadError` and unexpected resolver failures terminate before any
  package session or mutation; invalid final names never reach SMELT;
- an empty final set succeeds without package session creation, SMELT call,
  database mutation, audit event, or post-commit effect;
- every final package receives a fresh independently closed `AsyncSession` and
  one caller-owned transaction with exact system attribution, audit comment,
  active-only mode, and excluded-package guard; successful no-op,
  maintainer-only, and package-tree outcomes commit independently;
- an isolated outcome rolls back and closes its package session before the next
  package. A failed session is never reused, and earlier successful commits
  remain after a later isolated failure, terminal exception, or simulated
  process loss;
- the locked-current active-status check has no unlocked authoritative precheck.
  `active_ticket_only_skipped` terminates normally without requesting remaining
  packages, mutation, audit, or post-commit effect;
- the outcome matrix covers `PackageAlreadyExcludedError` skip,
  `PackageNotFoundInSmeltError` no-match,
  `PackageTargetsUnresolvedError`, `ProductCatalogNotReadyError`, and
  `SmeltUnavailableError` isolated continuation, plus no-op, maintainer-only,
  and package-tree success. Unexpected database, commit, audit, delegated, and
  programming errors fail the task after current-unit rollback;
- cancellation, `SoftTimeLimitExceeded`, and `MemoryError` propagate
  immediately rather than entering package-level isolation or retry;
- any new-IBS-track catch-up is attempted only after its package commit and
  lock release, and publication failure cannot roll back or fail that committed
  package unit;
- the synchronous wrapper invokes exactly one `asyncio.run()`, configures no
  automatic task retry, returns `None`, creates no `FetcherRun`, and stores no
  Celery result or Redis progress/guard state;
- one HTTP-client lifetime is confined to the invocation's event loop; every
  HTTP resource and package session closes on success, empty, inactive,
  expected-error, terminal-error, and cancellation paths; the shared pooled
  engine is disposed exactly once after cleanup on every outcome before the
  loop closes. A two-invocation production-pool regression test applies the
  Cross-Loop Engine Lifecycle contract;
- structured logs distinguish completed, empty, expected no-match, excluded
  skip, inactive termination, isolated package failure, partial completion, and
  terminal failure. Tests prove that `empty`, `inactive`, `completed`,
  `partial`, and `failed` are mutually exclusive aggregate terminal events;
  `partial` means normal return after every applicable package was attempted
  with at least one isolated failure, while expected no-match or excluded
  outcomes alone still permit `completed`. Cancellation,
  `SoftTimeLimitExceeded`, and `MemoryError` require no feature-owned terminal
  event before propagation. Log assertions permit only canonical IDs, bounded
  counts, bounded reason categories or class names, and task correlation; an
  invalid `ticket_id` is omitted and correlated only by `celery_task_id`.
  Assertions reject candidate payloads, raw CPE/vendor-product data, package
  candidate collections, SMELT response bodies, maintainer identity data,
  URLs, raw exception text, credentials, and secrets;
- the workflow itself creates no Ticket audit event for any operational outcome;
  each committed effective delegated mutation creates only its ordinary atomic
  `package_added` and `package_maintainer_added` events, while rolled-back,
  empty, no-match, excluded, inactive, and failure outcomes create none; and
- duplicate, concurrent, and reordered full invocations converge through
  locking, uniqueness, and idempotency. Publication failure, a simulated
  commit-to-enqueue crash, worker loss, and an unprocessed suffix leave no
  invented durable progress or automatic retry guarantee; a later full
  invocation may recover without duplicating committed state.

### Ticket Accessibility

When Ticket accessibility or a Ticket-derived read or mutation is affected,
integration and e2e coverage MUST apply this canonical matrix. These tests use
real PostgreSQL. Every race uses `db_session_factory` sessions with independent
connections and transactions plus deterministic synchronization at the
relevant read, I/O, lock, commit, or publication boundary; two tasks sharing
`db_session` and timing-only sleeps are not concurrency evidence. Distribute
the matrix between service integration tests and endpoint e2e tests according
to the boundary under test; every case need not be repeated at both tiers.

This matrix owns the shared visibility, atomicity, and disclosure guarantees.
Feature-specific matrices continue to own response fields, package-policy
formulas, reference behavior, audit payloads, CVSS resolution, submission
projection, and workbench classification; they MUST NOT restate a different
visibility predicate.

**Canonical predicate:**

| Case | Required assertion |
|---|---|
| Non-confidential Ticket | Visible to anonymous and authenticated callers regardless of scope, grant, or maintainership |
| Anonymous caller | Confidential Ticket is invisible; no grant or maintainer lookup can authorize the caller |
| Invalid selected optional credential | Returns the global 401 before visibility evaluation; it never falls back to anonymous access |
| Effective scope `all` | Confidential Ticket is visible without a grant or maintainer association |
| Explicit grant | An authenticated `non_confidential`-scope caller can see only the granted confidential Ticket |
| Included-package maintainer | The persisted `TicketPackageMaintainer.user_id` association makes the confidential Ticket visible while its parent `TicketPackage.deleted_at IS NULL` |
| Package exclusion and restore | Excluding the caller's last qualifying package removes access; restoring it reactivates the retained association without external I/O |
| Track or Product exclusion | Does not remove package-wide maintainer visibility |
| Other package and Ticket state | Product EOL, affectedness, eligibility, delivery, Product release state, and Ticket status do not change visibility |
| Multiple qualifying packages | Excluding one package preserves access while another included maintained package remains; access is lost only after the last qualifying package is excluded |
| Authenticated user with no roles | Has effective `non_confidential` scope and can gain visibility through a grant or included-package maintainership, but gains no capability |
| Visibility without capability | Protected reads succeed, while a capability-protected mutation returns 403; conversely, a capability never makes an otherwise invisible Ticket visible |

**List and count reads:**

- Ticket lists, CVE lists, cross-Ticket package search, Ticket audit lists,
  submission/release lists, and maintainer workbench lists are exercised with
  mixed visible and invisible Tickets. No returned item may derive from an
  invisible Ticket, and every paginated `meta.total` excludes invisible rows.
  A scoped audit or submission/release request for an invisible Ticket returns
  the resource-appropriate 404 rather than an empty collection.
- Visibility is part of the database selection before sorting and pagination.
  Count and items derive from one coherent database view, not merely the same
  caller predicate evaluated by independently observed statements.
  Implementations MUST NOT count broadly and remove invisible rows in Python or
  apply a Python visibility post-filter after pagination.
- At least one independent-session race per query shape changes
  confidentiality, revokes the caller's grant, or excludes the caller's last
  qualifying package after a preliminary resolution point but before the
  protected selection. For a CVE list query, this also includes changing a
  CVE-to-Ticket association so an initially ticketless or otherwise visible CVE
  becomes inaccessible before protected selection. The response must not expose
  a row selected after access was lost. This race must fail an implementation
  that performs an unconstrained protected query after a stale split
  accessibility check.

**Single, nested, and assembled reads:**

- Parameterize Ticket detail, package tree, references, Ticket audit,
  submission requests, release requests, CVSS assessments, and per-CVE source
  status over missing, visible, and inaccessible resources and over concurrent
  confidentiality, grant, included-package, and CVE-to-Ticket association
  changes where the resource is CVE-derived. Maintainer per-Ticket detail is
  included and evaluates accessibility before status or package membership
  projection.
- A successful response's root and all PostgreSQL-backed nested or separately
  assembled content are bound to one coherent database view in which the
  caller can access the Ticket. A response must never combine a stale
  successful access decision with Ticket, CVE, package, reference, event,
  submission, CVSS, or durable source-status content selected after visibility
  was lost. A specified best-effort transient overlay, such as source-status
  Redis `pending`, runs only after that coherent protected selection and cannot
  expose another protected resource. An implementation may satisfy this with
  any database mechanism that preserves the contract; tests assert the
  observable result rather than a private SQL shape.
- The concurrency coverage includes both loss and acquisition of visibility.
  It accepts a complete response from a coherent pre-change view or the
  resource-appropriate not-found response, as allowed by the transaction view,
  but never a mixed response assembled across incompatible views.
- Resolve authenticated identity, roles, and effective scope once for a request.
  A deterministic concurrent role change proves that an in-flight read or
  mutation does not reconstruct that caller state midway through the request;
  the committed role change applies to the next request.

**Locked mutations:**

- For every user-facing Ticket, CVE, or nested-resource mutation family, use
  two sessions to prove the authoritative accessibility decision is made from
  locked-current state. Session A pauses after any preliminary API check, when
  one exists, or immediately before root-lock acquisition otherwise. Session B
  then commits, in separate cases, making the Ticket confidential, revoking
  A's grant, excluding A's last included maintained package, or changing the
  CVE-to-Ticket association for a CVE-scoped operation. A subsequently acquires
  the Ticket lock and must receive `404 TICKET_NOT_FOUND`, or `404
  CVE_NOT_FOUND` for a CVE-scoped operation.
- Each denied race asserts zero domain write, Ticket audit event, assignment,
  reconciliation, post-commit callback, and task dispatch. Nested-resource,
  operability, status, idempotency, and no-op decisions must not precede the
  locked-current accessibility denial.
- The converse self-loss case is explicit: a `restricted_analyst` authorized
  through the last included package may successfully exclude that package.
  Authorization uses the locked pre-mutation state, the ordinary mutation and
  response succeed, and a subsequent request after commit returns 404 unless
  another visibility rule applies.

**External I/O and post-commit effects:**

- An I/O-then-lock workflow such as package addition holds no Ticket lock while
  calling SMELT. An independent session must be able to acquire and commit the
  Ticket lock while the external boundary is deterministically paused.
- If preliminary accessibility passed, another session removes visibility,
  and the external operation then fails before the lock boundary, the
  documented external error retains precedence. The workflow does not perform
  an extra accessibility lookup solely to replace that failure with 404.
- If external I/O succeeds after the same visibility-loss race, the mutation
  boundary acquires the Ticket lock, revalidates accessibility, and returns the
  resource-appropriate 404 with zero local write, association, audit,
  assignment, reconciliation, or dispatch. A maintainer association discovered
  by that request cannot authorize the request that would create it.
- Broker publication and every other post-commit effect are absent on denied
  or rolled-back paths and are observed only after the owning database commit
  succeeds and the Ticket lock is released.

**Authentication, authorization, and anti-enumeration:**

- Missing or invalid mandatory credentials, and invalid selected optional
  credentials, produce the global 401 before capability or accessibility work.
  A capability-protected path returns the generic 403 before any Ticket, CVE,
  or nested-resource lookup when the caller lacks the required capability.
- For each direct protected read and mutation, a missing resource and an
  inaccessible resource have identical status, code, and complete response
  body. Ticket-scoped paths use `TICKET_NOT_FOUND`; CVE-scoped paths use
  `CVE_NOT_FOUND` and never substitute the other resource's code.
- The per-Ticket maintainer workbench returns 404 before inspecting or
  projecting Ticket status, maintainer ownership, or package data. Missing and
  inaccessible Tickets are therefore indistinguishable, while an accessible
  Ticket with no qualifying caller work returns the normal three empty
  collections rather than an alternate state.
- Tests preserve only the documented identifier-only exceptions: a visible
  Duplicated Ticket may retain `duplicate_of_ticket_id = SNTL-{n}` when its target later
  becomes inaccessible; `TICKET_CVE_CONFLICT` may include
  `existing_ticket_id` for an inaccessible conflicting Ticket; and the global
  CVE-source listing may expose public CVE IDs without Ticket visibility
  scoping. Following a protected Ticket/CVE identifier still applies ordinary
  accessibility, and none of these exceptions may expose Ticket-derived
  content or create another bypass.

**Ticket identifier and read-contract coverage:**

- Unit tests for the pure Ticket parser accept `SNTL-1` and the maximum
  positive PostgreSQL `INTEGER` value. They reject lowercase prefixes,
  whitespace, signs, zero, missing digits, leading-zero padding, overflow,
  UUIDs, and trailing content without trimming or normalization.
- E2E tests parameterize every `{ticket_id}` path family over malformed input,
  a Ticket UUID, a well-formed missing SNTL value, and an inaccessible Ticket.
  Each produces the same complete `404 TICKET_NOT_FOUND` response. A malformed
  body `duplicate_of_ticket_id` instead produces the global Pydantic `422
  VALIDATION_ERROR`; a well-formed missing or inaccessible target produces
  `TICKET_NOT_FOUND`.
- Generated OpenAPI and representative response-schema tests prove that a
  Ticket root or embedded reference exposes only `ticket_id: SNTL-{n}`, a
  duplicate target uses only `duplicate_of_ticket_id`, and CVE conflict metadata
  uses `existing_ticket_id: SNTL-{n}`. Ticket `id`, `identifier`, and
  `ticket_sequence_id` fields and Ticket UUID path alternatives are absent.
  User, package/track/Product occurrence, reference, event, IBS action, and task
  UUIDs remain present where their owning contracts require them.
- Ticket list integration tests cover every search branch, outer-whitespace
  normalization, whitespace-only omission, literal percent/underscore/backslash,
  AND across different filters, OR within repeatable enum filters, all-invalid
  enum filters, `assignee=none` before resolution, and unknown optional
  assignee/maintainer values producing an empty page. Package-name search and
  `package_names` exclude directly excluded package occurrences.
- Ticket list tests create one-to-many package, maintainer, and external-ID
  fan-out and prove one row per Ticket plus an uninflated filtered total. They
  cover equal primary sort keys, semantic severity/status ordering, nullable
  severity, exact package-name deduplication and Unicode code-point ordering,
  the internal UUID tie-breaker, and a page beyond the last.
- Ticket detail tests cover CVE-less and CVE-associated Tickets, nullable and
  complete current assignee projection, direct duplicate target sequence
  projection without target-content access or chain following, external-ID and
  package-tree ordering, and absence of inline CVSS assessments and maintainer
  identities.
- Independent-session detail races at the protected selection boundary accept
  an entirely pre-change response, an entirely post-change response, or the
  applicable not-found outcome, but reject a mixed root/CVE/assignee/duplicate/
  package tree. Mutation tests prove every endpoint declaring `TicketDetail`
  assembles the post-mutation state inside the caller-owned transaction and
  rolls the mutation and audit back if final assembly fails.
- Controlled-clock tests cross UTC midnight and prove one `evaluation_date` is
  reused by Ticket detail, package detail, package search candidate selection,
  track aggregates, mutation reconciliation, and mutation response assembly.
  A serializer never captures a second date.
- Package query tests cover SNTL-only parent resolution, complete tree marker/
  lifecycle/actionability/reason/delivery projection, canonical nested ordering,
  exact-name and normalized literal-substring search, actionable-only compact
  items, all Ticket status filters, coherent totals/aggregates, equal sort keys,
  and beyond-last pages. Query-count assertions prove bounded database work
  independent of page size and fail per-item/N+1 loading without prescribing a
  particular SQL statement.
- Ticket audit API and service tests cover SNTL-only parent resolution before
  every filter, all-invalid event types, unknown optional actors, `system`, UUID
  and exact-username actors, normalized literal search, inclusive date bounds,
  fixed `created_at DESC, id DESC` ordering, equal timestamps, beyond-last
  pages, and coherent filtered totals. Non-null actors are complete current User
  references including nullable `full_name` and current `active`; system events
  use `null`. Tests also prove the parent-scope query can use the required
  `TicketAuditEvent.ticket_id` index and never derives current state from audit
  history.

**Confidentiality and explicit access grants:**

- Exercise `set_confidentiality`, `grant_access`, and `revoke_access` on every
  Ticket status, including `Ignored` and `Duplicated`. Manual-zone cases must
  succeed through their explicit `ensure_ticket_operable()` opt-out without
  assignment, gate reconciliation, status change, manual-zone exit, or
  `TICKET_NOT_MUTABLE`.
- A same-value confidentiality request is a true no-op. An effective `true` to
  `false` transition changes the flag, deletes every explicit grant, and creates
  exactly one acting-user `confidentiality_changed` event with no
  `access_grant_removed` events. Inject grant-deletion, audit, database, and
  flush failures and assert complete rollback of the flag, grants, and event.
- After declassification, `false` to `true` creates only its own
  `confidentiality_changed` event and does not recreate manual grants. Persisted
  `TicketPackageMaintainer` rows remain unchanged throughout; after
  reclassification an active associated user qualifies through an included
  package, while an excluded package remains non-qualifying until restored.
  No transition invokes SMELT or maintainership acquisition.
- Grant listing returns complete current `UserSummary` objects for target and
  grantor and uses fixed `granted_at ASC, user_id ASC` ordering, including
  equal timestamps. Deactivated users remain complete with `active = false`.
  An accessible non-confidential Ticket returns
  `409 TICKET_NOT_CONFIDENTIAL`, while missing or inaccessible Tickets retain
  the scoped `404 TICKET_NOT_FOUND` outcome rather than returning an empty list.
- Grant creation exercises target UUID and username forms, target absence,
  confidential-state guard, new active target, new inactive target, existing
  active target, and existing inactive target. New creation returns 201 with
  one grant/event; either existing case returns 200 with original
  `granted_by`/`granted_at` and no event; only an absent grant for an inactive
  target returns `409 USER_INACTIVE`.
- Revoke exercises target UUID and username forms, active and inactive targets,
  existing and absent grants, and the confidential-state guard. An effective
  revoke returns 204 and creates one exact `access_grant_removed`; an absent
  grant returns 204 with no event.
- Every grant mutation proves Ticket accessibility is authoritative before a
  deferred target-not-found, inactive, confidentiality, or no-op result. Missing
  and inaccessible Tickets remain indistinguishable and disclose no target
  state even though the User root is resolved first for lock ordering. After
  accessibility succeeds, confidentiality precedes the deferred target result:
  an accessible non-confidential Ticket returns `TICKET_NOT_CONFIDENTIAL`
  whether the target exists or not, and `USER_NOT_FOUND` is reachable only for
  an accessible confidential Ticket.
- Use independently connected sessions and deterministic lock-boundary
  synchronization for each race below. Assert serialized return status, final
  rows, original provenance, and exact event order/cardinality:
  - grant/grant: one 201 `created`, one 200 `already_exists`, one row, one add
    event;
  - grant/revoke: grant then revoke leaves no row with add then remove events;
    no-op revoke then grant leaves one row with only the add event;
  - revoke/revoke: at most one effective deletion and remove event;
  - confidentiality/confidentiality: same-value waiters are no-ops and opposing
    effective changes each use their true locked old value in commit order;
  - confidentiality/grant: declassification first causes the waiter to reject
    a non-confidential Ticket; grant first creates its add event before the one
    confidentiality event and the final state contains no grant;
  - confidentiality/revoke: declassification first causes revoke to reject;
    revoke first produces its remove event before the confidentiality event;
  - deactivation/grant: deactivation first rejects absent-grant creation with
    `USER_INACTIVE`, while grant first creates one row/event and later
    deactivation retains the row with an inactive current projection;
  - reactivation/grant: reactivation first permits creation, while grant first
    observes inactivity and is rejected without a later retroactive effect;
  - rename/grant and rename/revoke: event username and target identity come
    from one stabilized User state, never mixed pre/post-rename values.
- A model-level constraint test proves direct duplicate
  `(ticket_id, user_id)` insertion is rejected, retaining the unique key as a
  database backstop. Separately, the public `grant_access()` race test follows
  the mandatory User-then-Ticket locks and proves that a same-target waiter
  observes `already_exists` without reaching a unique violation, so the
  caller-owned PostgreSQL transaction remains usable. A service implementation
  must not catch a unique violation and then query in the same aborted
  transaction; the test must fail such an implementation rather than forcing a
  normally unreachable violation through the public path.
- Grant and revoke failure tests inject audit and flush failures and assert
  atomic rollback: grant creation leaves neither row nor event, and revoke
  restores the row while removing its pending event. Caller-requested rollback
  after either service returns has the same complete result.
- User deactivation and reactivation tests assert that neither operation
  inserts, updates, or deletes grant rows or creates grant events. Reactivation
  restores usability only for a still-present grant; a grant deleted by
  declassification remains absent. Deactivation-impact API and CLI tests assert
  no grant or maintainership count is present because those rows are retained.

### Maintainer Workbench

When the maintainer workbench service or API is implemented or changed, unit,
integration, and e2e coverage MUST apply the complete matrix below. The shared
Ticket Accessibility matrix remains authoritative for the visibility predicate;
these cases add workbench ownership, classification, projection, and response
requirements without defining another visibility rule.

**Authentication, visibility, and ownership:**

- All four endpoints reject missing or invalid credentials with the global
  `401 AUTH_NOT_AUTHENTICATED`. An authenticated user needs no role or
  capability.
- Exercise every canonical Ticket visibility branch: non-confidential, effective
  scope `all`, explicit grant, and included-package maintainership. Also cover
  anonymous denial, selected-invalid-credential denial, and a confidential
  Ticket with no qualifying branch.
- Prove visibility and workbench ownership independently. Scope `all` or an
  explicit grant can make a Ticket visible but cannot return a package without
  the caller's persisted `TicketPackageMaintainer` association. Conversely, an
  association through an included package supplies both its canonical
  visibility branch and workbench ownership, but creates no capability.
- Cover an included caller-maintained package, a directly excluded package, a
  retained association after package exclusion, restoration of that package,
  and another included maintained package preserving visibility. Track or
  Product exclusion affects actionability but does not delete or narrow the
  package-wide association.
- The per-Ticket endpoint is parameterized over malformed input, lowercase or
  padded SNTL forms, a Ticket UUID, a well-formed missing Ticket, and an
  inaccessible Ticket. Every case returns the same complete `404
  TICKET_NOT_FOUND` body before Ticket status, package ownership, or workbench
  data is projected.

**Classification and dimension boundaries:**

- Cover every Ticket status: `New`, `Analysis`, `Analyzed`, `Resolved`,
  `Ignored`, and `Duplicated`. `Analysis` and `Analyzed` can contribute pending,
  in-progress, and completed rows; `Resolved` can contribute only completed;
  all other combinations are excluded.
- Pending requires an actionable exact track with affectedness `affected`,
  delivery `pending`, and at least one actionable Product whose persisted
  `eligible` value is true.
- In progress requires an actionable exact track with affectedness `affected`
  or `fixed`, delivery `in_progress`, and at least one actionable Product whose
  persisted `eligible` value is true.
- Completed requires an actionable exact track with delivery `released` and
  does not require an eligible Product. Exercise all affectedness values to
  prove completed classification does not silently replace its documented
  predicates with a second gate.
- Parameterize package, track, and Product direct exclusion; ancestor-effective
  exclusion; no Product; all Products excluded or EOL; mixed actionable and
  non-actionable Products; all actionable Products ineligible; and at least one
  actionable eligible Product. Reuse one controlled UTC `evaluation_date` for
  rows and totals, including a request crossing midnight UTC.
- Exercise `ibs` and `git` tracks with the same persisted fact combinations.
  `workflow_type` is projected accurately, and Git classification performs no
  IBS correlation and invents no submission or delivery fact.
- Prove classification is a read-only presentation gate: it changes no
  affectedness, eligibility, actionability input, delivery value, Ticket status,
  or package marker.

**Filtering, ordering, pagination, and fan-out:**

- `package` is a case-sensitive exact match. Cover exact success, case variant,
  prefix, substring, alias-like, leading/trailing whitespace, and another
  declared filter composing with AND semantics.
- Exercise both `severity` and `package` sorting in both directions. Severity
  follows the semantic rank, unresolved null severity remains last, and package
  names use Unicode code-point ordering independent of database collation.
- Create equal primary sort keys and prove the internal
  `TicketPackageTrack.id` same-direction tie-breaker yields stable pages with no
  duplicate or omitted row. Cover minimum and maximum `per_page`, invalid
  pagination and sort values, an empty candidate set, and a page beyond the last
  with the correct total.
- Multiple actionable eligible Products below one track, multiple unrelated
  Product rows, duplicate join paths, and multiple maintainer associations must
  still produce one row per exact `TicketPackageTrack` and an uninflated total.
  Multiple exact tracks below one package remain distinct rows.
- Items, totals, and pages derive from one visible, caller-owned,
  classification-qualified PostgreSQL candidate set. Query-count assertions
  remain bounded independently of page size and result cardinality and fail a
  Python post-filter or per-item/Product N+1 implementation.

**Per-Ticket response and concurrency:**

- The successful response always has exactly `pending`, `in_progress`, and
  `completed` arrays under `data`, with no `meta`, `error_state`, or
  `no_packages`. An accessible Ticket with no caller association or no
  qualifying track returns all three arrays empty for every non-participating
  Ticket-status and package-policy cause.
- Every array uses fixed `package_name`, `reference`, and internal track-ID
  ascending ordering. One track appears in at most one array. The response is
  assembled from one coherent PostgreSQL observation and is not composed from
  three independently drifting endpoint calls.
- Independent-session races deterministically change confidentiality, revoke
  the final explicit grant, exclude the final package supplying a visibility or
  ownership path, restore a qualifying package, or change the final qualifying
  Product's actionability/eligibility at the protected selection boundary. The
  result may be wholly before or wholly after the committed change as allowed by
  its database view, but rows, totals, and per-Ticket arrays cannot mix
  incompatible observations or disclose post-loss data.

**Projection, privacy, and side effects:**

- Global and per-Ticket items contain exactly `package_name`, canonical
  `ticket_id`, nullable `cve_id`, nullable resolved `severity`,
  `workflow_type`, `reference`, affectedness `status`, and `delivery_status`,
  all using lowercase API enum values.
- Generated OpenAPI and response tests prove absence of Ticket UUIDs,
  maintainer IDs, usernames, emails, groups, association counts, SMELT payload
  or provenance, `submission_chain`, effective SR/proving RR fields,
  `analyzed_at`, `first_sr_created_at`, completion timestamps, waiting
  durations, and temporal lookback or sort parameters.
- Service tests prove all four functions acquire no mutation lock, write no
  database row, create no `TicketAuditEvent`, perform no commit or rollback,
  enqueue no task, and perform no external or Redis I/O. Database exceptions
  propagate; empty global and accessible per-Ticket results are normal outcomes.

### Ticket References

When Ticket-reference validation, services, endpoints, audit behavior, or
fetcher integration is affected, unit, integration, and e2e tests MUST cover
the complete matrix below. Manual and automatic inputs exercise the same
service-enforced URL boundary; API schema tests additionally verify the manual
transport contract.

**URL validity, normalization, and identity:**

| Case | Required assertion |
|---|---|
| Accepted schemes and host | `http` and `https` with a valid non-empty host are accepted; every other scheme, a missing or empty host, and malformed URL structure are rejected |
| Embedded user information | User information or credentials in the authority component are rejected, including username-only and username/password forms |
| Control characters | Every U+0000-U+001F character and U+007F is rejected rather than stripped or encoded |
| Length | Exactly 2048 characters before and after normalization is accepted when otherwise valid; a value exceeding either pre-normalization or post-normalization length is rejected |
| Scheme and host case | Scheme and host are lowercased without changing path, query, or fragment case |
| HTTP upgrade | `http` normalizes to `https` before classification, comparison, and storage |
| Empty root path | Only the slash representing an otherwise-empty root path is removed; a non-root path and its trailing slash are preserved |
| Preserved components | Explicit port, non-root path, query, and fragment are preserved exactly except for the scheme and host normalization above |
| Normalized collision | Raw URLs that normalize to the same value have one `(ticket_id, url)` identity; manual creation returns `RESOURCE_CONFLICT`, while automatic upsert follows its source-ownership merge rules |
| Ticket scope | The same normalized URL may exist on different Tickets; uniqueness is not global |

Tests use fictional hosts and values. Validation and classification tests
install spies or failing substitutes at outbound networking boundaries and
prove that manual and automatic reference processing performs zero URL
dereference, DNS resolution, probe, HTTP request, or other outbound URL call.
Rejected automatic candidates are skipped while remaining candidates continue;
their WARNING logs contain only the permitted bounded operational context and
reason, never the raw URL, title, description, query, fragment, user
information, credential material, or unsafe exception text.

**POST and PATCH field states:**

| Field | POST omitted | POST `null` | POST value | PATCH omitted | PATCH `null` | PATCH value |
|---|---|---|---|---|---|---|
| `url` | `422 VALIDATION_ERROR` | `422 VALIDATION_ERROR` | Validate and normalize; create or conflict on normalized identity | Preserve current URL | `422 VALIDATION_ERROR` | Validate and normalize; update, no-op, or conflict on normalized identity |
| `title` | Persist `NULL` | Persist `NULL` | Validate and persist the value | Preserve current value | Clear to `NULL` | Validate and persist the value |
| `description` | Persist `NULL` | Persist `NULL` | Validate and persist the value | Preserve current value | Clear to `NULL` | Validate and persist the value |
| `type` | Classify from normalized URL, then use `NULL` when unmatched | Persist explicit `NULL` without classification | Validate and persist the explicit value | Preserve current value, including when URL changes | Clear to `NULL` without classification | Validate and persist the explicit value |

POST tests include title and description blank and maximum-length boundaries.
PATCH tests cover every field alone, all fields together, an empty object,
equivalent values, and mixed omitted/null/value payloads. They prove an omitted
`type` preserves the existing value when `url` changes, while explicit `null`
clears it.

**Service and endpoint behavior:**

- `upsert_references()` covers absent and present source references; empty,
  mixed-validity, and repeated automatic candidate lists; explicit type hint,
  mapped-tag, normalized-URL-pattern, and `NULL` classification precedence;
  same-source non-NULL field updates, different-source fill-NULL-only merge,
  and manual source priority; deterministic re-invocation; skip-and-continue
  candidate validation; and propagation of unexpected database, transaction,
  and programming failures so the caller can roll back the complete per-CVE
  transaction. Its result remains `None`.
- `create_reference()` covers successful manual creation, normalized conflict,
  every validation guard, locked-current Ticket accessibility, and response
  projection from the created row.
- `update_reference()` covers wrong-parent and missing reference, automatic
  source rejection, every PATCH field state, normalized conflict, equivalent
  no-op, locked-current changed-field classification, and response projection
  from the updated row.
- `delete_reference()` covers wrong-parent and missing reference, automatic
  source rejection, effective deletion, and a waiting deletion loser that
  observes not found.
- `list_references()` covers an accessible empty result, source-only,
  type-only, and combined filters; an all-invalid enum filter; fixed type
  priority `advisory`, `patch`, `issue`, `article`, `NULL`; ascending
  `created_at` then `id` within a group; and no client-controlled sorting or
  pagination.
- Service and endpoint tests assert the documented exception inheritance and
  mappings, including the separate shared `TicketNotFoundError` catch.
  Unexpected database and infrastructure failures propagate unchanged and are
  never converted to `RESOURCE_CONFLICT`, `RESOURCE_NOT_FOUND`, or another
  domain outcome.

The three manual mutation functions are exercised on every Ticket status.
`Ignored` and `Duplicated` succeed through their explicit
`ensure_ticket_operable()` opt-out and never return `TICKET_NOT_MUTABLE`.
Every manual reference mutation proves that assignment, Ticket status, package
or Product state, gate reconciliation, manual-zone exit, and post-commit Ticket
convergence remain unchanged. `Resolved` has the same non-gate behavior.

Reference endpoint accessibility applies the canonical Ticket matrix above.
GET tests cover anonymous access to non-confidential Tickets, denial for an
anonymous confidential Ticket, denial for an authenticated
`non_confidential`-scope caller without another visibility branch,
authenticated effective scope `all`, explicit grant, included-package
maintainership, and loss of each final visibility path. Mutation tests
additionally prove `manage_references` is required before resource lookup and
does not itself grant visibility. Missing and inaccessible parents return
identical `TICKET_NOT_FOUND` responses. A valid reference UUID under the wrong
parent and an unknown reference UUID return identical `RESOURCE_NOT_FOUND`
responses only after locked-current parent accessibility succeeds; neither case
leaks the actual parent.

**Audit, rollback, and concurrency:**

- Effective POST and DELETE each create exactly one acting-user
  `reference_added` or `reference_deleted` event. Effective PATCH creates one
  event for each effectively changed field, ordered URL, type, title, then
  description, with exact old/new values, `comment = NULL`, and the documented
  URL detail. Values and action classification derive from serialized
  locked-current state.
- Automatic insert/update/no-op, rejected manual operations, missing or
  wrong-parent references, equivalent PATCH no-ops, normalized conflicts,
  concurrent losers, and rolled-back operations create zero reference events.
  Inject database, audit-validation, audit-insert, and flush failures and prove
  the reference rows and all events roll back atomically. Caller-requested
  rollback after a service returns has the same result.
- Independent-session manual/manual races cover create/create for one
  normalized identity, update/update with truthful sequential old values,
  update/delete in both commit orders, delete/delete, and URL changes that
  collide with another manual row. Exactly the effective serialized winners
  mutate or emit events; losers return the documented conflict or not-found
  outcome with no stale event.
- Independent-session manual/automatic races cover both commit orders for
  create/upsert of one normalized identity, automatic upsert against an
  existing manual row, manual URL update colliding with an automatic row, and
  manual delete concurrent with automatic processing. Final source ownership,
  fields, return or error outcome, and event cardinality follow the serialized
  winner and manual-priority rules; automatic work never emits a Ticket event.
  Include one transaction where `upsert_cve()` already holds the Ticket lock
  through Ticket-associated CVSS processing and one where automatic reference
  work reaches the unique-key boundary without that pre-existing lock.
- Force automatic unique-key conflicts through the public upsert boundary and
  prove each conflict is merged or skipped without aborting the caller-owned
  PostgreSQL transaction. A subsequent reference and unrelated per-CVE write in
  that same transaction must flush and commit successfully. Unexpected failures
  propagate so the caller rolls back the complete per-CVE transaction; they are
  not converted to skip-and-continue outcomes.
- Preserve upstream candidate order across duplicate automatic URLs. Test that
  the source candidate remains first, the first duplicate owns non-NULL fill
  precedence, and intentionally reordered upstream duplicates produce only the
  documented corresponding winner change.
- Inject an unexpected automatic-reference failure after Ticket creation,
  CVSS/severity, Product eligibility, lifecycle, audit, source-success, and an
  earlier reference write. Assert the complete per-CVE transaction rolls back
  every listed effect, not only the final reference operation.

### Application-Owned Redis Operations

Every application-owned Redis operation, regardless of application layer or
entry point, MUST have a test for the feature-specified `RedisError` behavior
(for example database fallback, fail-open, best-effort continuation, or
propagated service failure). The test uses the replaceable boundary defined in
Redis Strategy; it does not stop the shared Redis service.

### Authentication and Session

When the authentication or session feature area is affected, the following
scenarios are required:

**Session and configuration:**

- JWT issuance contains exactly `sub`, `session_id`, `iat`, `exp`,
  `session_deadline`, and `iss`; identifiers are UUID strings and time claims
  are integers (not JSON booleans)
- Normal JWT validation covers immediately before, exactly at, and immediately
  after `exp` and `session_deadline`, with no wall-clock sleeps and no leeway;
  it also rejects a future `iat`, invalid temporal ordering, missing or extra
  claims, wrong claim types, invalid UUIDs, wrong issuer, invalid signature,
  and algorithm substitution
- Logout decoding applies the same signature, algorithm, exact-claim, issuer,
  type, UUID, and temporal-ordering validation but accepts a token when its
  signed `exp` or `session_deadline` is at or before the controlled `now`
- Session creation uses one controlled login timestamp for `last_login_at`,
  the persisted deadline, and JWT timing claims; creates a new active row on
  every eligible invocation; preserves existing sessions; flushes without
  commit or rollback; rolls back the session and `last_login_at` together on
  failure; and returns `token_expires_at` equal to the JWT `exp`, not the
  later `Session.expires_at`
- Session creation acquires the User root lock and revalidates the
  locked-current active status before creating anything: an inactive or
  missing locked target creates no Session, updates no `last_login_at`, and
  returns `None`; the local login endpoint maps that outcome to the generic
  401 and the SSO callback maps it to `AUTH_SSO_USER_INACTIVE`
- Changing `SESSION_MAX_LIFETIME_DAYS` does not invalidate existing
  sessions or alter their persisted `Session.expires_at`
- A session's `Session.expires_at` (mapped to the JWT `session_deadline`
  claim) remains fixed regardless of subsequent configuration changes —
  verify by creating a session, changing the setting, and confirming
  the persisted deadline is unchanged
- Session cleanup deletes sessions whose persisted `Session.expires_at`
  has passed, not sessions derived from the current configuration value
- Cleanup immediately deletes inactive rows and deletes active or inactive
  rows only when `Session.expires_at < now`; tests cover equality on the
  deadline, confirm there is no one-hour grace or one-day buffer, and verify
  idempotent re-invocation and the returned deletion count
- Refresh tests cover immediately before, exactly at, and immediately after
  the 50% threshold; preservation of immutable claims; expiration capping;
  no refresh when the deadline cannot support a positive-lifetime token; and
  absence of database writes
- Optional authentication returns `None` only when credential selection yields
  no credential, with no user/session/API-key lookup, refresh, `last_used_at`
  touch, or unknown-key WARNING
- Optional authentication returns the same principal and performs the same JWT
  refresh or API-key operational effects as mandatory authentication for a
  valid selected credential
- Every selected credential rejection produces the same generic 401 under
  optional and mandatory authentication: malformed/expired JWT, missing or
  inactive session, unknown/revoked/expired API key, and missing/inactive user
- A selected invalid non-empty Bearer credential never falls back to a valid
  cookie; empty/whitespace-only Bearer and non-Bearer/unparseable headers retain
  the documented cookie fallback
- An absent or empty session cookie produces the same anonymous result as no
  cookie; a non-empty whitespace-only cookie is a selected invalid credential
- Database and unexpected infrastructure failures propagate and are never
  converted into an anonymous optional-authentication result
- Public endpoints marked `Authentication: Optional` are exercised without a
  credential, with each valid credential kind, and with a selected invalid
  credential. Public endpoints without that marker are exercised with a stale
  credential to prove their probe or authentication-bootstrap contract remains
  independent of credential validation

**Session liveness and invalidation:**

- A Redis value of `"1"` avoids a session query; a missing key or any other
  value performs PostgreSQL verification; only an active row writes the
  positive value with exactly 60 seconds TTL
- An inactive or absent row never authorizes and never creates a positive
  cache entry. A failed post-commit purge after logout or password reset may
  leave an existing positive entry effective only for its documented TTL
  window. After deactivation, the shared credential path's `User.active`
  check rejects the inactive user on the next authenticated request even
  when a positive liveness entry survives, so no equivalent access window
  exists while the target remains inactive; if the account is reactivated
  before a lost purge's TTL elapses, a deactivation-invalidated Session can
  be accepted for at most the entry's remaining TTL
- Deterministic `RedisError` substitution verifies PostgreSQL fallback for
  liveness reads, successful authorization after a failed positive-cache
  write, and best-effort continuation across all remaining IDs during a
  post-commit purge
- One process emits at most one PII-free WARNING per continuous Redis failure
  episode, concurrent first failures do not duplicate it, and any successful
  session-cache operation resets warning eligibility
- Single invalidation changes and advances `updated_at` only for an active
  row; missing and already-inactive rows are no-ops. Bulk invalidation changes
  only active rows and returns exactly their UUIDs. Both database operations
  flush without commit, rollback, or Redis I/O; cache purge occurs only after
  caller commit
- Logout tests cover bearer precedence, whitespace-only bearer cookie
  fallback, case-insensitive Bearer scheme matching, non-Bearer or
  scheme-less header cookie fallback, no fallback after an invalid non-empty
  bearer value, API-key rejection, current and temporally expired JWTs,
  missing and repeated sessions, exact empty 204 behavior, and the
  cookie-clearing header

**Lockout concurrency:**

- Exactly `LOGIN_MAX_ATTEMPTS` password verifications are permitted
  under concurrent load — never more. Use independent sessions and
  concurrent tasks to prove the boundary
- The atomic increment+TTL operation is indivisible — no counter exists
  without a TTL after a failure mid-operation
- A blocked attempt (counter >= limit) does not increment the counter
  or renew the TTL
- TTL is renewed only on actual failed verification, not on blocked
  attempts

**Anti-enumeration:**

- Unknown-username and wrong-password paths produce indistinguishable
  HTTP responses (same status code, error code, response body structure)
- Unknown-username path executes dummy bcrypt — verified by observing
  that the verification boundary is reached (e.g., the bcrypt function
  is called), not by asserting wall-clock timing equivalence
- Unknown-username advances the lockout counter identically to a failed
  known-user verification
- Lockout (429) is triggered identically for existing and non-existing
  usernames after `LOGIN_MAX_ATTEMPTS` attempts

**Log PII discipline:**

- No username, email, session ID, password, or password hash appears in
  application logs for any authentication path (success, failure,
  lockout, Redis failure). IP addresses are prohibited except where a
  documented PII exception exists (see
  `docs/features/identity/authentication.md`, API key validation).
  Capture logs via `caplog` and assert absence of personal identifiers
- `user_id` (UUID) is present in session lifecycle logs when the actor
  is known

**Audit trail boundaries:**

- Session lifecycle events (created, invalidated, cleanup) do NOT
  produce `IdentityAuditEvent` records
- Lockout events do NOT produce `IdentityAuditEvent` records (lockout
  is transient Redis-only state, not a persistent identity mutation)

### User Lifecycle and Management

When user lifecycle services, administrator endpoints, bootstrap/recovery CLI,
or identity audit validation are affected, tests MUST cover:

**Transactions and audit:**

- `create_user`, `update_user`, `reactivate_user`, and `reset_password` flush
  without committing or rolling back; caller rollback removes every lifecycle
  write, UserRole, Session invalidation, and IdentityAuditEvent from that
  workflow
- `deactivate_user` rollback leaves no partial User, API-key, Session, ticket,
  TicketAuditEvent, or IdentityAuditEvent mutation when any composed step fails
- API, CLI, and task workflows with PostgreSQL mutations commit exactly once
  after all database services succeed; a failure in a later composed service
  leaves no earlier mutation or audit event. Read-only and Redis-only workflows
  issue no empty commit
- authenticated API events contain the authenticated actor; CLI/manual system
  creation, initial roles, updates, reactivation, and password reset use NULL;
  external initial roles contain both `source` and `mapping`
- `last_login_at`, `last_used_at`, and `synced_at` updates create no lifecycle
  audit event and only their documented owners may write them

**Validation and audit boundaries:**

- create/update email is trimmed and lowercased before uniqueness evaluation;
  create/update explicit email NULL is rejected, while update
  `full_name = null` clears the value
- `create_user`/`update_user` reject a malformed email with `EmailFormatError`
  when called directly (bypassing any Pydantic/CLI boundary), proving the
  service enforces email format itself rather than relying solely on the
  API schema or CLI pre-validation; a duplicate username, email, or external
  ID raises `UserConflictError` with the matching `conflict_field`
- username, email, password, role, missing-field, explicit-NULL, duplicate-role,
  and password 15/16/128/129 boundaries produce the documented outcomes
- audit old/new values accept exactly 512 Unicode code points and truncate
  longer ASCII and multibyte values to the first 512 code points without an
  ellipsis
- deterministic detail serialization accepts exactly 4096 UTF-8 bytes and
  rejects 4097; tests include ASCII and multibyte content, unknown keys, wrong
  value types, missing paired source/mapping keys, and non-object payloads
- any audit validation or flush failure rolls back the owning lifecycle
  mutation

**Profile update and reactivation results:**

- `update_user()` returns `UserUpdateResult.changed_fields` in the fixed order
  `username`, `email`, `full_name`, `manager_id`, `synced_at`, containing only
  fields whose requested value differs from locked-current state; a fully
  idempotent re-invocation returns an empty sequence and creates no audit
  event
- `synced_at` appearing in `changed_fields` creates no audit event, while each
  other reported field creates exactly its matching lifecycle event
- `reactivate_user()` returns `ReactivationResult.reactivated = true` only for
  the actual `inactive → active` transition and `false` for an already-active
  local user, with no mutation or audit event in the latter case
- concurrent update serializes classification: a waiting caller whose
  requested values were already applied by the first caller observes an empty
  `changed_fields`, and a caller whose read-only pre-read differs from the
  locked-current row reports its own effective changes rather than the
  pre-read difference

**Concurrency and endpoint behavior:**

- concurrent creation for the same normalized username or email produces one
  user and one complete set of audit events; every loser receives the
  documented conflict and persists no dependent records
- concurrent update serializes old/new audit values; concurrent reactivation
  produces one mutation/event; password reset serializes with another reset
  and with deactivation, and performs no bcrypt or Redis work while locked
- concurrent removal of the final vulnerability-analyst role sources proves
  that `update_roles` serializes the remaining-role check and performs ticket
  unassignment and audit exactly once
- every assignment-capable Ticket, CVSS, and package path acquires User `FOR
  SHARE` before CVE/Ticket locks. Independent sessions cover assignment-first
  and deactivation/final-role-loss-first commit orders: the former is cleared by
  the lifecycle batch, explicit assignment in the latter raises the existing
  target error, and create/auto/embedded assignment skips without an event
- identity unassignment selects assigned Tickets without a status prefilter,
  locks them by UUID, clears locked-current `New`, `Analysis`, and `Analyzed`,
  and preserves `Resolved`, `Ignored`, and `Duplicated`. Cover anomalous assigned
  `New`, stale candidates, reassignment winners, repeated calls, exact reason
  payloads, and complete rollback after audit/flush failure
- reconciliation sanitation covers an inactive assignee, an active assignee
  with no VA origin, and both conditions with `inactive assignee` precedence for
  final `Analysis` and `Analyzed`; `Resolved` preserves the assignee. It performs
  no User lock acquisition after the Ticket lock and creates no event for an
  eligible, already-cleared, stale, losing, or rolled-back outcome
- `POST /api/v1/admin/users` returns 201 with no secret fields, enforces
  `manage_users`, covers unauthenticated 401, unauthorized 403, duplicate 409,
  validation/policy 422, initial roles, and atomic audit persistence
- every API accepting a user identifier exercises both UUID and username, and
  route handlers delegate user reads to `user_service` rather than executing
  ORM queries directly

**Manual role mutation service:**

- an effective manual addition and an effective manual removal each create
  exactly one `_manual` `UserRole` row and one matching `role_added` /
  `role_removed` event with the documented actor, target, old/new value, and
  `detail = NULL`
- duplicate entries within one list and roles present in both lists are
  normalized before any persistent access; no duplicate row, event, or
  rejection results
- adding a role whose `_manual` row already exists and removing a role
  without a `_manual` row are no-ops that create no event
- adding a `_manual` role while an external origin already grants the same
  role inserts the manual row and reports it in `added_roles`; removing that
  manual row while the external origin remains deletes only the manual row
  and reports it in `removed_roles`
- removing one of multiple `vulnerability_analyst` origins, including a manual
  row whose role remains effective through an external origin, creates zero
  Ticket mutation and zero `TicketAuditEvent`
- self-removal with a missing manual Admin row is a no-op; self-removal with
  another Admin origin present succeeds; self-removal of the final Admin
  origin raises `SelfRoleRemovalError` before any row, event, or Ticket
  mutation
- authenticated API actors populate the event actor; CLI/system callers use
  NULL
- `role_added` events precede `role_removed` events, each group ordered by
  wire-format role value
- an Identity audit failure rolls back every `UserRole` row and event, and a
  Ticket audit failure rolls back role rows, Identity events, Ticket clears,
  and Ticket events together
- effective operations on inactive users behave identically to active users

**Manual role mutation concurrency:**

- independent sessions cover duplicate additions and duplicate removals:
  exactly one winner performs the mutation and creates one event, and each
  loser acquires the User lock after the winner commits, observes the
  requested state, and is an idempotent no-op before any INSERT or DELETE
- a concurrent add and remove of the same role follows lock order: each
  transaction classifies its own effective effect from locked-current state,
  producing one effective mutation and event or two in sequence when the add
  commits first, with a final state that matches the last committed
  transaction
- the UNIQUE `(user_id, role, group_name)` constraint is an integrity
  backstop, not an expected concurrency path: a violation arising from a
  non-conforming writer propagates as a database error and rolls back the
  complete transaction instead of being converted into a no-op
- two concurrent requests touching different roles of the same User serialize
  on the User lock and both produce their documented rows and events
- two Admins removing each other's final Admin origin both succeed — the
  self-Admin guard applies only when actor and target are the same User — and
  can leave zero Admins; no global minimum is enforced and CLI recovery
  remains available
- a final manual `vulnerability_analyst` removal concurrent with a manual VA
  addition produces a stable outcome from lock order, with no duplicate
  unassignment or audit event
- final VA-origin removal concurrent with assignment retains the documented
  outcomes: an assignment that commits first is cleared by the lifecycle
  batch, while an explicit assignment that commits after the removal observes
  the ineligible User and raises its existing target error; create,
  auto-assignment, and embedded assignment skip without an event
- a manual role addition after a final VA-origin loss does not restore any
  previously cleared assignment

**Manual role mutation API (`POST /api/v1/admin/users/{user}/roles`):**

- UUID and username resolution return the same result
- unauthenticated 401, capability 403, missing-user 404, and self-removal 409
- omitted fields and empty arrays are no-ops; explicit `null`, unknown role
  values, wrong field/element types, duplicates within one list, and overlap
  between `add` and `remove` each return 422 `VALIDATION_ERROR`
- effective and no-op requests both return the complete, deterministically
  ordered profile with all role origins
- the commit completes before the response is transmitted; a failure returns
  no success response and persists nothing

**Manual role mutation CLI (`manage-user update`):**

- each mode (profile, roles, reactivation) succeeds through its single mapped
  API-equivalent operation
- cross-mode combinations are rejected with the documented message, exit 1,
  stderr output, and no mutating session; no-modification invocations print
  the no-changes message and exit 0
- an invalid username is rejected before any database access with the
  documented message, exit 1, and stderr output
- an unknown username is reported before cross-mode or
  `--full-name`/`--clear-full-name` rejection, matching the documented
  lookup-first order
- `--clear-full-name` sends `full_name = NULL`, reports `full name` only when
  the value effectively changes, prints the no-op message when the value was
  already NULL, and its combination with `--full-name` is rejected with the
  documented message, exit 1, stderr, and no mutating session
- `--full-name ''` is stored and reported as an ordinary `full_name` change,
  not as a clear
- role mode deduplicates repeated options and silently cancels overlap,
  reporting only the effective `added_roles` and `removed_roles`; a manual
  addition or removal is reported even when an external origin keeps the role
  effective
- profile output derives exclusively from `UserUpdateResult.changed_fields`:
  a stale pre-read suggesting a change while the operation is a no-op prints
  the no-op message, and a stale pre-read suggesting no change while the
  operation modifies fields prints the update message with exactly the
  returned fields in the documented order
- reactivation output derives exclusively from
  `ReactivationResult.reactivated`: `false` prints the no-op message and
  `true` prints the reactivated message, including a concurrent loser whose
  pre-read showed an inactive user
- external users: profile and reactivation modes fail with the documented
  error, role mode is permitted
- stdout carries success and no-op messages, stderr carries errors, exit
  codes are 0/1/2, no partial-success lines are printed, exactly one
  `asyncio.run()` executes per invocation, and a success commits once while a
  failure commits zero times

**Deactivation preview service (`get_deactivation_impact()`):**

- guard precedence is asserted in this exact order: unknown user raises
  `UserNotFoundError`; an already-inactive target — local or external —
  returns the zeroed result with `already_inactive = true` without evaluating
  the later guards; an active external target with an actor UUID raises
  `ExternalUserStatusReadOnlyError`; an active self-target with an actor UUID
  raises `SelfDeactivationError`
- the same active external target with `acting_user_id = None` proceeds to
  observation (the actor-NULL/system reachability contract), and the
  actor-NULL path never triggers the self guard; the CLI's manual-surface
  external guard rejects an active external target after the inactive no-op
  and before any prompt
- an active eligible target reports zero and non-zero counts for non-revoked
  API keys (including expired keys), active Sessions, and active-status
  Tickets currently assigned, plus the effective last-active-Admin flag
- explicit `TicketAccessGrant` and `TicketPackageMaintainer` rows are
  excluded from every count and no grant or maintainer observation is
  performed
- the four values are advisory rather than one aggregate snapshot: the
  preview holds no lock, creates no reservation, preview token, or durable
  record, a repeated invocation after a committed change observes the new
  state, and a resource created after the preview is still handled by the
  subsequent action whose result never depends on preview values
- database errors and exceptions propagated by
  `api_key_service.count_non_revoked_keys()` escape unchanged, and no audit
  event is created

**Deactivation action (`deactivate_user()`):**

- happy path returns `deactivated = true`, the profile with roles and
  manager, and exactly the invalidated session IDs; every non-revoked key
  (including expired keys) is revoked, every active Session invalidated,
  `User.active` set to `false`, and exactly one `assignment` event created
  per effectively cleared active-status Ticket with the canonical reason
  `user deactivated` and unchanged Ticket status
- the composite audit insertion order is asserted within the one transaction:
  the API-key `api_key_revoked` events, then the Ticket `assignment` events,
  then the single identity `user_deactivated` event
- already-inactive, concurrent-loser, and repeated invocations return
  `deactivated = false` with an empty `invalidated_session_ids` and create
  no mutation and no audit event; the guard ordering asserts that the
  inactive no-op precedes the external and self guards
- rejected external and self-target invocations perform no mutation and no
  audit event
- audit attribution asserts the derived source: actor UUID produces no
  `detail.source`; actor NULL with a local target produces no
  `detail.source`; actor NULL with an external target produces
  `source = "external_sync"`; an actor UUID with an active external target is
  rejected before mutation
- retained grants and maintainer associations survive deactivation
  unchanged, produce no grant or maintainer event, and remain subject to
  their ordinary Ticket-side contracts; reactivation recreates no revoked
  key, cleared assignment, or deleted grant
- a `RedisError` from the post-commit purge leaves the committed success
  intact, returns normally, and does not reclassify the result or raise; a
  crash-equivalent omission of the purge leaves the Session rows durably
  inactive and their positive cache entries bounded by the existing TTL

**Deactivation API (`POST .../deactivate`, `GET .../deactivation-impact`):**

- capability present/absent; JWT and API-key credentials both authenticate
  these endpoints under the ordinary rules; UUID and username resolution
  return the same result
- missing 404, active external 409 `USER_EXTERNAL_STATUS_READONLY`,
  self-target 409 `USER_SELF_DEACTIVATION`, and already-inactive 200 no-op
  for both endpoints, with the error precedence asserted and the exact
  rendered detail messages
- both endpoints return the standard `{"data": ...}` envelope; the action
  returns the current complete profile with no `deactivated` field; the
  preview returns the five documented fields with the documented types
- the action's commit completes before the response is transmitted, a
  failure during commit returns no success response and persists nothing,
  and the post-commit purge callback runs after the commit; a Redis failure
  in that callback still returns HTTP 200 with the committed profile
- OpenAPI registration exposes both endpoints under their documented paths
  and methods

**Deactivation CLI (`manage-user deactivate`):**

- an invalid username format is rejected before any database access; an
  unknown user reports the not-found error
- a non-TTY invocation that reaches the prompt prints the documented TTY
  error to stderr and exits 1 without mutation
- an already-inactive user — including an inactive external user — prints
  the no-op message and exits 0 without a prompt and without opening a
  mutating session; an active external user is rejected by the CLI's
  manual-surface guard with the external error and exits 1 after the
  inactive classification and before any impact display
- zero and non-zero impact summaries render exactly the documented lines
  from the preview result; the last-active-Admin warning goes to stderr; the
  read-only session is closed before the prompt, and no pre-read classifies
  the outcome of a confirmed invocation
- explicit decline prints `Aborted.` to stdout and exits 0; EOF/Ctrl+D
  reaches the shared mapper, prints `Aborted.`, and exits 0; SIGINT exits
  130; none of these commits
- after confirmation the command opens a fresh session, commits exactly
  once, and rolls back on a pre-commit failure; a stale preview where another
  caller already deactivated the target prints the no-op message from
  `result.deactivated = false` and exits 0
- a Redis failure during the post-commit purge does not change the success
  message or the exit code
- stdout/stderr channels match the documented contract; exit codes are
  0/1/2/130; exactly one `asyncio.run()` executes per invocation

**Deactivation concurrency:**

- use independent database sessions and deterministic barriers. Deactivation
  concurrent with deactivation yields exactly one `deactivated = true` with a
  complete audit sequence and one loser returning `deactivated = false` with
  no duplicate event
- deactivation concurrent with API-key creation: deactivation-first rejects
  creation with `InactiveUserError`; creation-first produces a key that the
  deactivation then revokes; each lock order produces exactly one outcome
- deactivation concurrent with local and SSO Session creation: session-first
  commits a Session that the deactivation then invalidates;
  deactivation-first creates no Session and returns the provider-specific
  login failure
- deactivation concurrent with manual role mutation follows the documented
  User-lock serialization and creates no duplicate Ticket event
- the existing assignment/deactivation, final-VA-loss, and
  grant-creation/deactivation races keep their coverage and assert no
  regression

### API Key Management

When API key persistence, services, authentication, API endpoints, or CLI
commands are affected, tests MUST cover:

**Name, expiration, and status:**

- trim/lowercase normalization, every allowed character class, empty and
  over-128 rejection, invalid characters, and normalized-name uniqueness
- expiration strictly in the future, equality with the operation's `now`
  rejected, no maximum expiration, NULL accepted, offset-bearing values
  normalized to UTC, offset-free datetimes interpreted as UTC, and date-only
  request values rejected
- exclusive status precedence (`revoked` over `expired` over `active`) and
  the `expires_at == now` boundary

**Queries and API:**

- self-service owner scoping and 404 concealment when revoking another
  user's key
- pagination, status filtering, both sort directions, stable ID tiebreaking,
  and `last_used_at` NULL-last ordering for self-service and admin lists
- invalid status filters produce an empty result, and filtering and serialized
  statuses use one shared UTC snapshot per request
- administrator owner filtering follows case-sensitive UUID-or-username
  resolution; owner and non-NULL revoker fields use complete User Reference
  Objects
- full secret returned only by creation and absent from every list/revoke
  response; creation returns every common-object field plus the secret
- JWT-session-only creation, authenticated self-service access, and
  `manage_users` enforcement for administrator endpoints

**Transactions, audit, and concurrency:**

- create, revoke, and bulk revoke flush without committing; caller rollback
  removes both lifecycle mutation and audit event
- same normalized-name concurrent creation produces exactly one key and one
  `api_key_created` event; every loser receives the documented conflict
- repeated and concurrent single/bulk revocation produces one mutation and
  one `api_key_revoked` event per key; self-service events identify the owner
  as actor
- concurrent single and bulk revocation with opposite lock acquisition order
  (single holds key lock, bulk holds user lock) completes without SQLSTATE
  `40P01` deadlock and produces one effective revocation and one audit event
- creation concurrent with user deactivation cannot commit a key for an
  inactive user
- `last_used_at` debounce and conditional update never move the value
  backward and create no identity audit event; successful writes commit before
  advancing the debounce timestamp, while failed writes roll back, leave the
  debounce state unchanged, and do not reject an otherwise valid credential
- authentication resolves credentials through `get_key_by_hash()` rather than
  a direct model query; `get_deactivation_impact()` obtains its non-revoked
  count through `count_non_revoked_keys()`, and the deactivation API and CLI
  perform no direct `ApiKey` query

**Logging and CLI:**

- validation-failure WARNING contains the ASGI peer address
  (`request.client.host`) only under the documented active-defense PII
  exception and never contains prefix, secret, hash, key name, username,
  or email; suppression behavior is tested without HTTP throttling
- active-key anomaly WARNING contains only safe structured fields
- `api-key list --username` includes key UUID, consistent derived status, and
  `—` for NULL last-use/expiration cells; `api-key revoke --key-id` needs no
  username and uses the same success message for first and repeated revocation
  with the documented exit codes

### Model Constraints

New models MUST be tested for:

- Creation with valid data
- Unique constraints (duplicate insert → IntegrityError)
- NOT NULL constraints (missing required field → IntegrityError)
- Foreign key relationships (cascade behavior)
- Enum constraints (invalid value → rejected)

### CLI Commands

CLI commands MUST be tested against the Output Contract in
`docs/conventions.md` and the production mechanisms in
`docs/features/platform/cli-infrastructure.md`:

- Exit code 0 on success and idempotent no-ops
- Exit code 1 on user errors
- Exit code 2 on system errors
- Error messages on stderr, success messages on stdout
- Commands permitted to expose partial success produce `✓`/`✗`/`—` prefixed
  lines
- Each invocation crosses the production sync boundary through exactly one
  `asyncio.run()` call
- A successful PostgreSQL mutation commits exactly once; a service or later
  workflow failure rolls back and commits zero times. Read-only and Redis-only
  workflows issue no empty commit
- `SIGINT` and `SIGTERM` subprocess tests wait for an observable readiness
  point proving that the CLI signal handlers are installed, then assert exit
  codes 130 and 143. A focused transaction test injects interruption after
  flush and before commit and verifies rollback with no partial mutation or
  audit event
- TTY commands verify hidden input, non-TTY rejection, and prompt behavior
  without exposing password material
- `--help` at the root, group, and command levels and root `--version` exit 0
  without loading application settings or opening database/Redis connections

The image suite verifies only CLI artifact risks: the installed `sentinel`
entry point is on `PATH`, package version metadata is readable, and
`python -m app.cli` reaches the packaged module. The gate MAY reuse a root-help
invocation as a compact command-discovery signal, but command discovery is not
a separate required artifact assertion. Detailed subcommand discovery,
options, output, interactive behavior, domain errors, and mutation workflows
remain in focused CLI tests; adding a command does not automatically require
another image test.

---

## Checklist: Adding Tests for a New Feature

When implementing a new feature, follow this checklist to ensure
comprehensive test coverage:

1. **Identify test tiers**: which functions need unit tests (pure
   logic), integration tests (DB interaction), and e2e tests (API
   endpoints)?

2. **Create test files**: mirror the `app/` structure. Service tests in
   `test_services/`, API tests in `test_api/`, model tests in
   `test_models/`.

3. **Mark tests**: apply `@pytest.mark.unit`, `@pytest.mark.integration`,
   or `@pytest.mark.e2e` to each test function or class.

4. **Use fixtures**: use `db_session` for integration tests, `client`
   for e2e tests, `redis_client` for integration or e2e paths that
   use Redis, and `db_session_factory` ONLY for concurrency/locking
   tests (all other integration tests continue using `db_session`).
   Create test data using factories (when available, see Model Factory
   Fixtures) or direct model instantiation. Do not connect test fixtures
   through application `REDIS_URL` or `CELERY_BROKER_URL`.

5. **Test audit events**: for every mutation covered by an audit trail,
   assert event creation with correct fields (see Audit Trail Testing).

6. **Test error paths**: every guard condition in the service spec
   (Q2) should have a corresponding test that triggers the guard and
   verifies the exception.

7. **Test edge cases**: empty collections, boundary values, concurrent
   access (if the function under test acquires a pessimistic row lock, a
   concurrency test using `db_session_factory` and the two-session
   pattern in Database Strategy — Concurrency Testing is mandatory),
   re-invocation behavior.

8. **Run the suite**: `cd backend && pytest` — all tests must pass
   before declaring the task complete.

9. **Review**: invoke `@test-reviewer` for new features or modules (see
   Guardrail 6).

---

## Cross-references

- `docs/conventions.md` — Testing Conventions (style rules, naming),
  Transaction and Locking (pessimistic locking pattern), Redis (error
  ownership and async I/O)
- `docs/architecture.md` — Single Docker image, multiple entrypoints
  (shared by the image smoke suite's compose services); Backend Layer
  Architecture (dependency direction enforced by structural tests)
- `docs/api-spec.md` — Base URL, Mutation Patterns, Audit Trail
  Endpoint Naming (route conventions enforced by structural tests)
- `docs/deployment.md` — Container Images (process roles), Release
  Process (build/publish pipeline gated by the image smoke suite)
- `docs/features/platform/audit-trail-infrastructure.md` — Audit Trail
  Index, `BaseAuditLog`, atomicity rules, immutability
- `docs/features/tickets/ticket-audit-log.md` — TicketAuditEvent
  contract
- `docs/features/identity/identity-audit-log.md` — IdentityAuditEvent
  contract
- `docs/features/platform/fetcher-infrastructure.md` — FetcherAuditEvent
  contract, mutable-registry test isolation, test-only fetcher exception
- `docs/features/platform/fetcher-operations.md` — Public fetcher API
  fields (consumed by the system suite's API assertions)
- `docs/features/packages/cpe-package-mapping.md` — canonical mapping
  file, parser, loader, cache, and resolver test contract
- `docs/features/platform/system-settings.md` — SettingAuditEvent
  contract
- `AGENTS.md` — Guardrail 6 (Mandatory testing)
