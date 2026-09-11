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

For every mutation covered by any audit trail registered in the Audit
Trail Index (`docs/features/platform/audit-trail-infrastructure.md`,
section "Audit Trail Index"), tests MUST verify that the corresponding
audit event is created in the same transaction with correct field
values.

When an owning mutation contract explicitly requires no event in a registered
trail, tests MUST assert that absence as part of the boundary contract. In
particular, effective and no-op `TicketPackageTrack.delivery_status` operations
must create no `TicketAuditEvent`; their tests also assert the documented
absence of assignment and Ticket reconciliation.

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
3. **Actor**: `user_id` is set for user-initiated actions and `NULL` for
   system/automated actions.
4. **Payload**: `old_value`, `new_value`, and any domain-specific fields
   (`comment`, `detail`, `target_user_id`, etc.) match the contract.
5. **Atomicity**: the audit event and the mutation are visible within the
   same test transaction (i.e., no intermediate commit separates them).

For an explicit no-event mutation, assert zero matching events before and after
the operation and verify that rollback or retry cannot synthesize one.

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

When testing code that uses module-level caches (e.g.,
`FETCHER_REGISTRY`, `_CVE_SOURCE_TYPE_MAP`), the test must clean up the
cache in a fixture or teardown. See
`docs/features/platform/cve-fetcher-infrastructure.md` for the test
helper extension rule.

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
`run_fetcher` and `cleanup_sessions` — MUST have a regression test that
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
reproduces the cross-loop bug for `run_fetcher`/`cleanup_sessions` never
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
- `REJECTED -> PUBLISHED` reopening every currently `Ignored` associated Ticket
  without consulting audit history.

The owning service specifications define detailed Ticket-convergence test
matrices: see `ticket-service.md` (Architectural Test Requirement, manual-zone
registration and operator dispatch) and `package-service.md` (Architectural
Test Requirement, affectedness authority and Ticket convergence workflow).
Those tests distinguish best-effort automatic publication failure after a
successful committed mutation from the explicit rerun endpoint's 503
publication failure.

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
  every invocation; preserves existing sessions; flushes without commit or
  rollback; rolls back the session and `last_login_at` together on failure;
  and returns `token_expires_at` equal to the JWT `exp`, not the later
  `Session.expires_at`
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
  cache entry. A failed post-commit purge may leave an existing positive entry
  effective only for its documented TTL window
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
- `POST /api/v1/admin/users` returns 201 with no secret fields, enforces
  `manage_users`, covers unauthenticated 401, unauthorized 403, duplicate 409,
  validation/policy 422, initial roles, and atomic audit persistence
- every API accepting a user identifier exercises both UUID and username, and
  route handlers delegate user reads to `user_service` rather than executing
  ORM queries directly

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
  a direct model query, and the deactivation preview obtains its non-revoked
  count through `count_non_revoked_keys()`

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
  contract, test helper extension rule, test-only fetcher exception
- `docs/features/platform/fetcher-operations.md` — Public fetcher API
  fields (consumed by the system suite's API assertions)
- `docs/features/packages/cpe-package-mapping.md` — canonical mapping
  file, parser, loader, cache, and resolver test contract
- `docs/features/platform/system-settings.md` — SettingAuditEvent
  contract
- `AGENTS.md` — Guardrail 6 (Mandatory testing)
