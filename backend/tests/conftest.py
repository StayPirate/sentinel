"""Shared test fixtures for the Sentinel backend.

See docs/features/platform/testing-strategy.md for the full testing strategy.
"""

from __future__ import annotations

import asyncio
import atexit
import itertools
import os
import warnings
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery import Celery
from httpx import ASGITransport, AsyncClient
from redbeat.schedulers import ensure_conf
from redis.exceptions import RedisError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

if TYPE_CHECKING:
    from testcontainers.community.postgres import PostgresContainer
    from testcontainers.community.redis import RedisContainer

# Provide required settings for test environment (must precede app imports)
os.environ.setdefault(
    "JWT_SECRET_KEY", "test-secret-key-not-for-production-min-32-chars"
)

from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.health import get_readiness_redis_urls
from app.celery_app import create_celery_app
from app.config import Settings
from app.core.enums import (
    IBSRequestActionType,
    IBSRequestState,
    Role,
    SessionCreationReason,
    TicketStatus,
    WorkflowType,
)
from app.core.passwords import hash_password
from app.database import Base, get_db
from app.main import app

# Import the models package (not just the User class) so all model
# tables — including ones only referenced via TYPE_CHECKING forward
# refs, like UserRole — are registered on Base.metadata before
# _engine's create_all runs.
from app.models import (
    CVE,
    CVECWE,
    ApiKey,
    CVEAffectedVersion,
    CVECVSSAssessment,
    CVEEPSSScore,
    CVEExternalIdentifier,
    CVEKEVEntry,
    CVESource,
    CVESSVCAssessment,
    FetcherAuditEvent,
    FetcherConfig,
    FetcherRun,
    IBSRequest,
    IBSRequestAction,
    IBSRequestActionTrack,
    IdentityAuditEvent,
    Product,
    ProductRepository,
    Session,
    SettingAuditEvent,
    SystemSetting,
    Ticket,
    TicketAccessGrant,
    TicketAuditEvent,
    TicketPackage,
    TicketPackageMaintainer,
    TicketPackageProduct,
    TicketPackageTrack,
    TicketReference,
    TrackReleaseCheckpoint,
    User,
    UserRole,
)
from app.services import local_auth_service, session_service
from app.services.session_service import create_session
from tests.support.audit_models import SampleAuditEvent

# Fictional bcrypt-shaped value — never a real hash (see AGENTS.md Guardrail 23)
_FICTIONAL_PASSWORD_HASH = "$2b$12$" + "a" * 53

# Module-level cache for the auto-provisioned testcontainers PostgreSQL
# instance (started once per session, reused across tests). Kept as a
# module global — rather than function attributes — for clean typing.
_container: PostgresContainer | None = None
_container_url: str | None = None


def _database_url() -> str:
    """Resolve the test database URL.

    Priority:
    1. TEST_DATABASE_URL env var (set by CI or developer override)
    2. Auto-provisioned PostgreSQL via testcontainers (local dev)
    """
    global _container, _container_url

    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        return url

    if _container_url is not None:
        return _container_url

    # Lazy import — testcontainers is only needed when no URL is provided
    from testcontainers.community.postgres import PostgresContainer

    # renovate: depName=postgres
    container = PostgresContainer("postgres:18")
    container.start()
    atexit.register(container.stop)
    # Build asyncpg URL from the container's connection params
    _container_url = container.get_connection_url().replace(
        "postgresql+psycopg2://", "postgresql+asyncpg://"
    )
    _container = container
    return _container_url


# Module-level cache for the auto-provisioned testcontainers Redis
# instance (started once per session, reused across tests). Mirrors the
# PostgreSQL pattern above.
_redis_container: RedisContainer | None = None
_redis_container_url: str | None = None

# Standard Redis server logical database count (`databases 16` default
# config). Used to validate worker-to-database allocation safety — see
# docs/features/platform/testing-strategy.md (Worker and Test Isolation).
_REDIS_LOGICAL_DB_COUNT = 16


def _redis_base_url() -> str:
    """Resolve the base Redis test-harness URL, before the per-worker
    logical database offset is applied.

    Priority:
    1. TEST_REDIS_URL env var (set by CI or developer override)
    2. Auto-provisioned Redis 7 via testcontainers (local dev)
    """
    global _redis_container, _redis_container_url

    url = os.environ.get("TEST_REDIS_URL")
    if url:
        return url

    if _redis_container_url is not None:
        return _redis_container_url

    # Lazy import — testcontainers is only needed when no URL is provided
    from testcontainers.community.redis import RedisContainer

    # renovate: depName=redis
    container = RedisContainer("redis:8")
    container.start()
    atexit.register(container.stop)
    host = container.get_container_host_ip()
    port = container.get_exposed_port(container.port)
    _redis_container_url = f"redis://{host}:{port}/0"
    _redis_container = container
    return _redis_container_url


def _redis_worker_db_index(base_index: int) -> int:
    """This pytest worker's dedicated logical database index.

    Workers are identified by `PYTEST_XDIST_WORKER` (`"gw0"`, `"gw1"`,
    ...), set by pytest-xdist when parallel execution is active; absent
    otherwise (single-process run). Each worker's index is
    `base_index + worker_number`, so consecutive workers use consecutive
    databases with no overlap. Raises explicitly — never silently
    shares a database — if the resulting index would meet or exceed the
    number of databases the server offers.
    """
    worker_input = os.environ.get("PYTEST_XDIST_WORKER")
    offset = 0 if not worker_input else int(worker_input.removeprefix("gw"))
    index = base_index + offset
    if index >= _REDIS_LOGICAL_DB_COUNT:
        raise RuntimeError(
            f"Redis test harness requires logical database {index}, but the "
            f"server only offers {_REDIS_LOGICAL_DB_COUNT} (0-"
            f"{_REDIS_LOGICAL_DB_COUNT - 1}). Reduce the number of parallel "
            "test workers or configure a server with more logical databases."
        )
    return index


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def _redis_test_url() -> str:
    """This test session's dedicated Redis URL.

    Combines the harness's base host/port (see `_redis_base_url`) with
    this worker's dedicated logical database (see
    `_redis_worker_db_index`). Verifies connectivity with `PING` before
    returning. Provisioning or connectivity failures raise rather than
    skip the test suite (see docs/features/platform/testing-strategy.md,
    Redis Strategy).
    """
    base_url = _redis_base_url()
    parsed = urlsplit(base_url)
    base_index = int((parsed.path or "/0").lstrip("/") or "0")
    db_index = _redis_worker_db_index(base_index)
    url = urlunsplit((parsed.scheme, parsed.netloc, f"/{db_index}", "", ""))

    client = redis_asyncio.Redis.from_url(url)
    try:
        await client.ping()
    except RedisError as exc:
        raise RuntimeError(f"Redis test harness unreachable at {url}: {exc}") from exc
    finally:
        await client.aclose()

    return url


@pytest.fixture
def celery_test_app(
    redis_client: redis_asyncio.Redis,
    _redis_test_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Celery:
    """A fresh Celery app configured with RedBeat pointed at this
    test's isolated Redis logical database.

    Shared by every test module that needs real redbeat/Redis I/O
    (`tests/test_services/test_fetcher_schedule.py`,
    `tests/test_services/test_fetcher_operations.py`) — see
    `docs/features/platform/testing-strategy.md` (Redis Strategy) for
    the isolation contract this fixture composes.

    `redis_client` is requested for its FLUSHDB-before/after isolation
    guarantee even though this fixture's own redbeat calls use
    RedBeat's own synchronous client, not the fixture's async client
    directly — FLUSHDB operates at the database level regardless of
    which client performs it. `CELERY_BROKER_URL` is cleared from the
    environment so this app's broker/redbeat resolution is driven
    exclusively by the explicit `Settings` constructed below (mirrors
    `test_celery_app.py`, `test_broker_url_propagated_from_settings`).

    Pre-warms `app.redbeat_conf` (via `ensure_conf`) under a local
    warning suppression: redbeat's `RedBeatConfig.__init__` emits a
    one-time `DeprecationWarning` when `redbeat_redis_url` is not
    explicitly set — Sentinel's deliberate, tested configuration (see
    `docs/features/platform/fetcher-infrastructure.md`, Redbeat
    Configuration, and `test_celery_app.py`,
    `test_no_redbeat_redis_url_override`). Every project pytest run
    turns warnings into errors (`filterwarnings = ["error"]` in
    `pyproject.toml`), so this expected, benign, already-accepted
    library warning would otherwise fail the first redbeat operation
    in every test. `ensure_conf` caches the config on the app instance,
    so pre-warming it here means the warning never resurfaces for the
    rest of the test.
    """
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    settings = Settings(
        _env_file=None,
        jwt_secret_key="a" * 32,
        app_name="sentinel-test",
        log_level="INFO",
        log_format="json",
        celery_broker_url=_redis_test_url,
        celery_timezone="UTC",
        celery_enable_utc=True,
    )
    celery_test_app = create_celery_app(settings)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ensure_conf(celery_test_app)
    return celery_test_app


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def _engine() -> AsyncGenerator[AsyncEngine]:
    """Create the async engine and tables once per session."""
    engine = create_async_engine(_database_url(), echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
def real_session_factory(_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """A real `async_sessionmaker` bound to the shared test engine.

    Mirrors the production shape in `app/database.py`. Used by tests
    that need a session factory (rather than a single `AsyncSession`)
    against a real database — e.g. the readiness PostgreSQL check,
    which opens its own fresh session per invocation.

    Unlike `db_session`/`db_session_factory`, sessions opened through
    this factory are NOT covered by the per-test savepoint rollback:
    use it for read-only checks only. A test that commits writes
    through it would leak state into the shared test database across
    tests.
    """
    return async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def db_session(_engine: AsyncEngine) -> AsyncGenerator[AsyncSession]:
    """Provide an async DB session with per-test transaction rollback.

    Uses the SQLAlchemy 2.0 recommended pattern: the session joins an
    external transaction with join_transaction_mode="create_savepoint".
    When test code (or service code) calls session.commit(), it commits
    a savepoint — not the outer transaction. The outer transaction is
    rolled back in teardown, reverting all changes.

    See: https://docs.sqlalchemy.org/en/20/orm/session_transaction.html
         #joining-a-session-into-an-external-transaction-such-as-for-test-suites
    """
    async with _engine.connect() as conn:
        transaction = await conn.begin()
        session = AsyncSession(
            bind=conn,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

        try:
            yield session
        finally:
            await session.close()
            await transaction.rollback()


@pytest.fixture
async def db_session_factory(
    _engine: AsyncEngine,
) -> AsyncGenerator[Callable[[], Awaitable[AsyncSession]]]:
    """Provide a factory of independent DB sessions, for concurrency
    and locking tests only.

    See docs/features/platform/testing-strategy.md (Database Strategy
    — Concurrency Testing, Fixture Catalog) for the full contract.
    Unlike `db_session` (a single session sharing one connection and
    savepoint-nested transaction, rolled back at teardown), each
    session this factory creates has its own connection and its own
    real transaction — required to observe genuine lock contention
    (`SELECT ... FOR UPDATE` or a conditional `UPDATE`) between two
    "concurrent" sessions within one test. `session.commit()` on a
    factory-created session is a real commit, visible to other
    sessions — tests that commit through this factory must clean up
    explicitly (see the fixture's own docstring reference above).
    Teardown closes every session and connection this factory created,
    which rolls back any transaction still open.
    """
    sessions: list[AsyncSession] = []
    connections: list[Any] = []

    async def _create() -> AsyncSession:
        conn = await _engine.connect()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        connections.append(conn)
        sessions.append(session)
        return session

    try:
        yield _create
    finally:
        for session in sessions:
            await session.close()
        for conn in connections:
            await conn.close()


@pytest.fixture
def cli_session_factory(
    _engine: AsyncEngine,
) -> Iterator[async_sessionmaker[AsyncSession]]:
    """Provide the async session factory injected into synchronous CLI
    command tests (`tests/test_cli/`).

    See docs/features/platform/testing-strategy.md (Sync Entry-Point
    Tests): a CLI command under test crosses the sync-to-async boundary
    through its own `asyncio.run()` call, so this factory's engine uses
    `NullPool` — every connection is opened and closed entirely within
    that call's event loop, never reusing a connection acquired on
    pytest-asyncio's session-scoped loop (unlike `db_session`/`_engine`
    above). Tests inject this factory by monkeypatching
    `app.cli.manage_user.get_session_factory` to return it.

    Depends on `_engine` purely for its schema-creation side effect (the
    session-scoped `Base.metadata.create_all()`) — this factory's own
    engine is a separate `NullPool`-backed connection to the same test
    database, not a reuse of `_engine`'s connection.

    A successful mutating command commits durable rows that the ordinary
    per-test savepoint rollback cannot undo — see
    `cleanup_users_by_username` below for explicit cleanup. Teardown here
    only disposes the engine itself (via its own transient event loop,
    safe because `NullPool` never leaves a connection open across
    `asyncio.run()` calls).
    """
    engine = create_async_engine(_database_url(), poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        yield factory
    finally:
        asyncio.run(engine.dispose())


@pytest.fixture
def cleanup_users_by_username(
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> Iterator[Callable[..., None]]:
    """Return a function that marks usernames for FK-safe deletion.

    CLI mutation tests (`manage-user create/set-password/unlock`,
    `api-key list/revoke`) commit real `User`, `UserRole`, `ApiKey`,
    `Session`, and `IdentityAuditEvent` rows through
    `cli_session_factory`, bypassing the ordinary per-test rollback.
    Call the returned function with the usernames created during the
    test; cleanup runs at teardown (even after an assertion failure),
    using the same `NullPool` engine on its own transient event loop.

    Deletion order respects foreign-key dependencies: `ApiKey` (matched
    by either `user_id` or `revoked_by`, since a revoker may be a
    different pending user) and `Session` first, then
    `IdentityAuditEvent`, then `UserRole`, then `User` itself.
    """
    pending: set[str] = set()

    def _mark(*usernames: str) -> None:
        pending.update(usernames)

    yield _mark

    if not pending:
        return

    async def _cleanup() -> None:
        async with cli_session_factory() as db:
            target_ids = select(User.id).where(User.username.in_(pending))
            await db.execute(
                delete(ApiKey).where(
                    ApiKey.user_id.in_(target_ids) | ApiKey.revoked_by.in_(target_ids)
                )
            )
            await db.execute(delete(Session).where(Session.user_id.in_(target_ids)))
            await db.execute(
                delete(IdentityAuditEvent).where(
                    IdentityAuditEvent.target_user_id.in_(target_ids)
                    | IdentityAuditEvent.user_id.in_(target_ids)
                )
            )
            await db.execute(delete(UserRole).where(UserRole.user_id.in_(target_ids)))
            await db.execute(delete(User).where(User.username.in_(pending)))
            await db.commit()

    asyncio.run(_cleanup())


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient]:
    """Provide an async HTTP test client with DB session override.

    The FastAPI app's get_db dependency is overridden to use the test
    session, ensuring e2e tests share the test transaction.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
    app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture
async def redis_client(
    _redis_test_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[redis_asyncio.Redis]:
    """Provide an async Redis client bound to this test's dedicated
    logical database.

    See docs/features/platform/testing-strategy.md (Redis Strategy,
    Fixture Catalog) for the full contract. Before yielding: flushes the
    dedicated database (never `FLUSHALL` — other workers use other
    databases) and overrides every application-owned Redis boundary —
    `get_readiness_redis_urls` (readiness checks),
    `session_service.get_session_redis_url` (session liveness cache,
    invalidation purge), and `local_auth_service.get_lockout_redis_url`
    (login lockout counter) — so they observe this same instance during
    the test. Teardown restores every override, flushes again, and
    closes the client. Cleanup/provisioning failures fail the test
    rather than skip.
    """
    client = redis_asyncio.Redis.from_url(_redis_test_url, decode_responses=True)
    await client.flushdb()

    app.dependency_overrides[get_readiness_redis_urls] = lambda: [_redis_test_url]
    monkeypatch.setattr(
        session_service, "get_session_redis_url", lambda: _redis_test_url
    )
    monkeypatch.setattr(
        local_auth_service, "get_lockout_redis_url", lambda: _redis_test_url
    )
    try:
        yield client
    finally:
        app.dependency_overrides.pop(get_readiness_redis_urls, None)
        await client.flushdb()
        await client.aclose()


@pytest.fixture
def user_factory(
    db_session: AsyncSession,
) -> Callable[..., Awaitable[User]]:
    """Factory fixture for User model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `username` / `email`: derived from a per-fixture counter, unique
      within the test.
    - `password_hash`: a fictional bcrypt-shaped hash, set only when the
      caller does not supply `external_id` — satisfies
      `chk_user_auth_exclusive` for the common case (local user).
      Callers creating an external user must pass `external_id` and
      leave `password_hash` unset (or explicitly `None`).
    """
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


@pytest.fixture
def user_role_factory(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
) -> Callable[..., Awaitable[UserRole]]:
    """Factory fixture for `UserRole` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `user_id`: a freshly created user, when not overridden.
    - `role`: `Role.VULNERABILITY_ANALYST` value, overridable.
    - `group_name`: `"_manual"` (model server default), overridable.
    """

    async def _create(**overrides: Any) -> UserRole:
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        defaults: dict[str, Any] = {"role": Role.VULNERABILITY_ANALYST.value}
        defaults.update(overrides)
        instance = UserRole(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


# A fixed, valid password satisfying the 16-128 char policy, paired with
# its real bcrypt hash below. `hash_password()` runs once at collection
# time (not per-test) so tests that need an actual, verifiable login
# don't each pay bcrypt's ~cost-12 latency. Fictional value — never a
# real credential (see AGENTS.md Guardrail 23).
_KNOWN_PASSWORD = "correct horse battery staple 1"
_KNOWN_PASSWORD_HASH = hash_password(_KNOWN_PASSWORD)


@pytest.fixture
def local_user_factory(
    db_session: AsyncSession,
) -> Callable[..., Awaitable[tuple[User, str]]]:
    """Factory fixture for a local `User` with a real, verifiable password.

    Unlike `user_factory`'s `_FICTIONAL_PASSWORD_HASH` (a bcrypt-*shaped*
    but unverifiable placeholder), this factory sets a real
    `hash_password()` output for a fixed, reused plaintext and returns
    `(user, plaintext_password)`. Use this fixture for tests that
    exercise an actual login (`authenticate_local_user()`, `POST
    /api/v1/auth/login`) rather than tests that only need a persisted
    `User` row.

    Defaults:
    - `username` / `email`: derived from a per-fixture counter, unique
      within the test.
    - `password_hash`: `_KNOWN_PASSWORD_HASH`, overridable to test a
      malformed stored hash.
    - `active`: `True`; `external_id`: unset (local user).
    """
    counter = itertools.count(1)

    async def _create(**overrides: Any) -> tuple[User, str]:
        n = next(counter)
        defaults: dict[str, Any] = {
            "username": f"localuser{n}",
            "email": f"localuser{n}@example.com",
            "password_hash": _KNOWN_PASSWORD_HASH,
        }
        defaults.update(overrides)
        instance = User(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance, _KNOWN_PASSWORD

    return _create


@pytest.fixture
def sample_audit_event_factory(
    db_session: AsyncSession,
) -> Callable[..., Awaitable[SampleAuditEvent]]:
    """Factory fixture for `SampleAuditEvent` instances.

    `SampleAuditEvent` (`tests/support/audit_models.py`) is the
    test-only concrete `AuditEventMixin` subclass used to exercise the
    mixin and `BaseAuditLog` without depending on a production audit
    trail. Defaults: `event_type="sample_event"`; `user_id` is left
    unset (NULL — a system-initiated event) unless overridden.
    """

    async def _create(**overrides: Any) -> SampleAuditEvent:
        defaults: dict[str, Any] = {"event_type": "sample_event"}
        defaults.update(overrides)
        instance = SampleAuditEvent(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def session_factory(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
) -> Callable[..., Awaitable[Session]]:
    """Factory fixture for `Session` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `user_id`: a freshly created user, when not overridden.
    - `expires_at`: `now() + Settings().session_max_lifetime_days`, mirroring
      the production calculation at login time (see
      `docs/features/identity/authentication.md`, Session Management).
      This is a test-time default only — the model itself never computes
      `expires_at`; login-time calculation is owned by
      `app.services.session_service`.
    """

    async def _create(**overrides: Any) -> Session:
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        defaults: dict[str, Any] = {
            "expires_at": datetime.now(UTC) + timedelta(days=30),
        }
        defaults.update(overrides)
        instance = Session(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def api_key_factory(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
) -> Callable[..., Awaitable[ApiKey]]:
    """Factory fixture for `ApiKey` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `user_id`: a freshly created user, when not overridden.
    - `key_hash`: a per-fixture-counter-derived 64-character hex string
      (fictional — never a real SHA-256 digest), unique within the test.
    - `prefix`: a fictional key prefix (`stl_ak_` + 5 hex chars).
    - `name`: derived from the same counter, unique per call — satisfies
      `uq_api_key_user_id_name_active` for the common case (distinct
      names per call).
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> ApiKey:
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        n = next(counter)
        # Fictional 64-char hex digest — never a real SHA-256 hash
        # (see AGENTS.md Guardrail 23).
        fake_hash = f"{n:064x}"
        defaults: dict[str, Any] = {
            "key_hash": fake_hash,
            "prefix": f"stl_ak_{n:05x}"[:12],
            "name": f"test-key-{n}",
        }
        defaults.update(overrides)
        instance = ApiKey(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def identity_audit_event_factory(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
) -> Callable[..., Awaitable[IdentityAuditEvent]]:
    """Factory fixture for `IdentityAuditEvent` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `IdentityAuditLog.log_event()` validation on purpose —
    model-layer tests (`tests/test_models/test_identity_audit_event.py`)
    exercise the raw persistence contract (columns, constraints,
    indexes) independently of the service-layer validation rules,
    which are covered by `tests/test_services/test_identity_audit_log.py`.

    Defaults:
    - `event_type`: `"user_created"` (a fictional, valid string value;
      not validated against `IdentityAuditEventType` at this layer).
    - `target_user_id`: a freshly created user, when not overridden.
    """

    async def _create(**overrides: Any) -> IdentityAuditEvent:
        if "target_user_id" not in overrides:
            overrides["target_user_id"] = (await user_factory()).id
        defaults: dict[str, Any] = {"event_type": "user_created"}
        defaults.update(overrides)
        instance = IdentityAuditEvent(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def system_setting_factory(
    db_session: AsyncSession,
) -> Callable[..., Awaitable[SystemSetting]]:
    """Factory fixture for `SystemSetting` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `key`: a per-fixture-counter-derived unique key
      (`test_setting_<n>`), so multiple calls within one test don't
      collide on the string primary key.
    - `value`: a fictional placeholder value derived from the same
      counter.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> SystemSetting:
        n = next(counter)
        defaults: dict[str, Any] = {
            "key": f"test_setting_{n}",
            "value": f"test-value-{n}",
        }
        defaults.update(overrides)
        instance = SystemSetting(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def setting_audit_event_factory(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> Callable[..., Awaitable[SettingAuditEvent]]:
    """Factory fixture for `SettingAuditEvent` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `SettingAuditLog.log_event()` validation on purpose —
    model-layer tests (`tests/test_models/test_setting_audit_event.py`)
    exercise the raw persistence contract (columns, constraints,
    indexes) independently of the service-layer validation rules,
    which are covered by `tests/test_services/test_settings.py`.

    Defaults:
    - `event_type`: `"setting_changed"` (a fictional, valid string
      value; not validated against `SettingAuditEventType` at this
      layer).
    - `setting_key`: a freshly created `SystemSetting` row's key, when
      not overridden.
    - `user_id`: a freshly created user, when not overridden.
    - `new_value`: a fictional placeholder value.
    """

    async def _create(**overrides: Any) -> SettingAuditEvent:
        if "setting_key" not in overrides:
            overrides["setting_key"] = (await system_setting_factory()).key
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        defaults: dict[str, Any] = {
            "event_type": "setting_changed",
            "new_value": "4.0",
        }
        defaults.update(overrides)
        instance = SettingAuditEvent(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def fetcher_config_factory(
    db_session: AsyncSession,
) -> Callable[..., Awaitable[FetcherConfig]]:
    """Factory fixture for `FetcherConfig` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `fetcher_name`: a per-fixture-counter-derived unique name
      (`test_fetcher_<n>`), so multiple calls within one test don't
      collide on the string primary key.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> FetcherConfig:
        n = next(counter)
        defaults: dict[str, Any] = {"fetcher_name": f"test_fetcher_{n}"}
        defaults.update(overrides)
        instance = FetcherConfig(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def fetcher_run_factory(
    db_session: AsyncSession,
    fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
) -> Callable[..., Awaitable[FetcherRun]]:
    """Factory fixture for `FetcherRun` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `fetcher_name`: a freshly created `FetcherConfig` row's name, when
      not overridden.
    - `started_at`: the current UTC time.
    - `created_at`: defaults to the same value as `started_at` (when
      `started_at` is not `None`), or to the current UTC time (when
      `started_at` is explicitly `None`, e.g. a `queued` run). List,
      history, and timeline queries order and filter on `created_at`
      (see `docs/features/platform/fetcher-operations.md`), so most
      tests that override `started_at` to control chronological
      ordering get the matching `created_at` for free. Override
      `created_at` explicitly to simulate real queue latency (a gap
      between acceptance and adoption).
    - `status`: `"running"` (a fictional, valid string value; not
      validated against `FetcherRunStatus` at this layer).
    - `triggered_by`: `"schedule"`.
    """

    async def _create(**overrides: Any) -> FetcherRun:
        if "fetcher_name" not in overrides:
            overrides["fetcher_name"] = (await fetcher_config_factory()).fetcher_name
        defaults: dict[str, Any] = {
            "started_at": datetime.now(UTC),
            "status": "running",
            "triggered_by": "schedule",
        }
        defaults.update(overrides)
        if "created_at" not in overrides:
            defaults["created_at"] = (
                defaults["started_at"]
                if defaults["started_at"] is not None
                else datetime.now(UTC)
            )
        instance = FetcherRun(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def fetcher_audit_event_factory(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
    fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
) -> Callable[..., Awaitable[FetcherAuditEvent]]:
    """Factory fixture for `FetcherAuditEvent` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `FetcherAuditLog.log_event()` validation on purpose —
    model-layer tests (`tests/test_models/test_fetcher_audit_event.py`)
    exercise the raw persistence contract (columns, constraints,
    indexes) independently of the service-layer validation rules,
    which are covered by `tests/test_services/test_fetcher_audit_log.py`.

    Defaults:
    - `fetcher_name`: a freshly created `FetcherConfig` row's name, when
      not overridden.
    - `user_id`: a freshly created user, when not overridden.
    - `event_type`: `"disabled"` (a fictional, valid string value; not
      validated against `FetcherAuditEventType` at this layer).
    """

    async def _create(**overrides: Any) -> FetcherAuditEvent:
        if "fetcher_name" not in overrides:
            overrides["fetcher_name"] = (await fetcher_config_factory()).fetcher_name
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        defaults: dict[str, Any] = {"event_type": "disabled"}
        defaults.update(overrides)
        instance = FetcherAuditEvent(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_factory(db_session: AsyncSession) -> Callable[..., Awaitable[CVE]]:
    """Factory fixture for `CVE` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `cve_id`: a per-fixture-counter-derived fictional identifier
      (`CVE-2099-1000<n>`, five or more digits), so multiple calls within
      one test don't collide on the UNIQUE constraint.
    - Every other column uses its model default: `cve_state` is
      `PUBLISHED`, and `severity`, `title`, `description`, and the dates
      are `NULL`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> CVE:
        n = next(counter)
        defaults: dict[str, Any] = {"cve_id": f"CVE-2099-{10000 + n}"}
        defaults.update(overrides)
        instance = CVE(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_source_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVESource]]:
    """Factory fixture for `CVESource` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `record_source_status()` on purpose: model-layer tests
    exercise the raw persistence contract independently of the service
    write semantics.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden.
    - `source`: a per-fixture-counter-derived label (`test_source_<n>`,
      matching the `CVESourceType` value format but not validated at this
      layer), so repeated calls for one CVE don't collide on the
      `(cve_id, source)` UNIQUE constraint.
    - `status`: `"success"` (not validated against `CVESourceFetchStatus`
      at this layer).
    - `fetched_at`: the current UTC time. `first_failed_at` is `NULL`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> CVESource:
        n = next(counter)
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {
            "source": f"test_source_{n}",
            "status": "success",
            "fetched_at": datetime.now(UTC),
        }
        defaults.update(overrides)
        instance = CVESource(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_cvss_assessment_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVECVSSAssessment]]:
    """Factory fixture for `CVECVSSAssessment` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults form one consistent vector-derived CVSS v3.1 unit (the
    database does not validate it):
    - `cve_id`: a freshly created CVE, when not overridden.
    - `provider_name`: a per-fixture-counter-derived fictional name
      (`Provider <n>`), so repeated calls for one CVE don't collide on the
      `(cve_id, provider_name, cvss_version)` UNIQUE constraint.
    - `cvss_version`: `"3.1"`; `score`: `Decimal("9.8")`; `severity`:
      `"critical"`; `vector_string`:
      `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> CVECVSSAssessment:
        n = next(counter)
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {
            "provider_name": f"Provider {n}",
            "cvss_version": "3.1",
            "score": Decimal("9.8"),
            "severity": "critical",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        defaults.update(overrides)
        instance = CVECVSSAssessment(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_external_identifier_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVEExternalIdentifier]]:
    """Factory fixture for `CVEExternalIdentifier` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden.
    - `source`: `"GHSA"` (not validated against
      `CVEExternalIdentifierSource` at this layer).
    - `identifier`: a per-fixture-counter-derived fictional GHSA-shaped ID
      (`GHSA-test-<nnnn>-xxxx`), so repeated calls don't collide on the
      global `(source, identifier)` UNIQUE constraint.
    - `url`: `NULL`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> CVEExternalIdentifier:
        n = next(counter)
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {
            "source": "GHSA",
            "identifier": f"GHSA-test-{n:04d}-xxxx",
        }
        defaults.update(overrides)
        instance = CVEExternalIdentifier(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_affected_version_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVEAffectedVersion]]:
    """Factory fixture for `CVEAffectedVersion` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses the CVE service on purpose: model-layer tests exercise the raw
    persistence contract, so no entry conflict key or duplicate validation
    applies at this layer.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden.
    - `source_container`: `"cna"`. The table has no unique key, so no
      counter is needed.
    - Every entry column (`vendor` through `default_status`) is `NULL`.
    """

    async def _create(**overrides: Any) -> CVEAffectedVersion:
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {"source_container": "cna"}
        defaults.update(overrides)
        instance = CVEAffectedVersion(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_cwe_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVECWE]]:
    """Factory fixture for `CVECWE` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden.
    - `cwe_id`: a per-fixture-counter-derived identifier (`CWE-<n>`), so
      repeated calls for one CVE don't collide on the
      `(cve_id, cwe_id, source)` UNIQUE constraint.
    - `source`: `"NVD"`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> CVECWE:
        n = next(counter)
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {"cwe_id": f"CWE-{n}", "source": "NVD"}
        defaults.update(overrides)
        instance = CVECWE(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_ssvc_assessment_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVESSVCAssessment]]:
    """Factory fixture for `CVESSVCAssessment` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden, so repeated
      calls don't collide on the `cve_id` UNIQUE constraint.
    - `exploitation`: `"none"`; `automatable`: `"no"`; `technical_impact`:
      `"partial"`; `version`: `"2.0.3"` (not validated at this layer).
    - `assessed_at`: `NULL`.
    """

    async def _create(**overrides: Any) -> CVESSVCAssessment:
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial",
            "version": "2.0.3",
        }
        defaults.update(overrides)
        instance = CVESSVCAssessment(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_kev_entry_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVEKEVEntry]]:
    """Factory fixture for `CVEKEVEntry` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden, so repeated
      calls don't collide on the `cve_id` UNIQUE constraint.
    - `date_added`: `2099-01-15` (a fictional date).
    - `reference_url`: `NULL`.
    """

    async def _create(**overrides: Any) -> CVEKEVEntry:
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {"date_added": date(2099, 1, 15)}
        defaults.update(overrides)
        instance = CVEKEVEntry(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def cve_epss_score_factory(
    db_session: AsyncSession,
    cve_factory: Callable[..., Awaitable[CVE]],
) -> Callable[..., Awaitable[CVEEPSSScore]]:
    """Factory fixture for `CVEEPSSScore` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `cve_id`: a freshly created CVE, when not overridden, so repeated
      calls don't collide on the `cve_id` UNIQUE constraint.
    - `score`: `0.00043`; `percentile`: `0.12345` (not range-validated at
      this layer).
    - `assessed_at`: `2099-01-15` (a fictional date).
    """

    async def _create(**overrides: Any) -> CVEEPSSScore:
        if "cve_id" not in overrides:
            overrides["cve_id"] = (await cve_factory()).id
        defaults: dict[str, Any] = {
            "score": 0.00043,
            "percentile": 0.12345,
            "assessed_at": date(2099, 1, 15),
        }
        defaults.update(overrides)
        instance = CVEEPSSScore(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_factory(db_session: AsyncSession) -> Callable[..., Awaitable[Ticket]]:
    """Factory fixture for `Ticket` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses the ticket services on purpose: model-layer tests exercise
    the raw persistence contract.

    Defaults:
    - `sequence_id`: assigned by the database identity, when not
      overridden.
    - Every other column uses its model default: `status` is `New`,
      `is_confidential` is `False`, and `cve_id`, `severity_manual`,
      `priority_auto`, `priority_override`, `assignee_id`,
      `duplicate_of_id`, and `coordinated_release_at` are `NULL`. With
      `cve_id` and `severity_manual` both `NULL` by default, overriding
      either one alone satisfies `chk_ticket_severity_manual_cve_exclusive`.
    - `chk_ticket_duplicate_status_coherence`: overriding `duplicate_of_id`
      alone defaults `status` to `Duplicated`; overriding
      `status="Duplicated"` alone links to a freshly created target Ticket.
    """

    async def _create(**overrides: Any) -> Ticket:
        if overrides.get("duplicate_of_id") is not None:
            overrides.setdefault("status", TicketStatus.DUPLICATED.value)
        elif (
            overrides.get("status") == TicketStatus.DUPLICATED
            and "duplicate_of_id" not in overrides
        ):
            overrides["duplicate_of_id"] = (await _create()).id
        instance = Ticket(**overrides)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_audit_event_factory(
    db_session: AsyncSession,
    ticket_factory: Callable[..., Awaitable[Ticket]],
) -> Callable[..., Awaitable[TicketAuditEvent]]:
    """Factory fixture for `TicketAuditEvent` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses the Ticket audit service on purpose: model-layer tests
    exercise the raw persistence contract (columns, constraints, indexes)
    independently of the typed `log_event()` validation rules.

    Defaults:
    - `ticket_id`: a freshly created Ticket, when not overridden.
    - `event_type`: `"ticket_created"` (a valid string value; not
      validated against `TicketAuditEventType` at this layer).
    - `user_id`, `old_value`, `new_value`, `comment`, and `detail`: `NULL`.
    """

    async def _create(**overrides: Any) -> TicketAuditEvent:
        if "ticket_id" not in overrides:
            overrides["ticket_id"] = (await ticket_factory()).id
        defaults: dict[str, Any] = {"event_type": "ticket_created"}
        defaults.update(overrides)
        instance = TicketAuditEvent(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_access_grant_factory(
    db_session: AsyncSession,
    ticket_factory: Callable[..., Awaitable[Ticket]],
    user_factory: Callable[..., Awaitable[User]],
) -> Callable[..., Awaitable[TicketAccessGrant]]:
    """Factory fixture for `TicketAccessGrant` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses the ticket services on purpose: model-layer tests exercise
    the raw persistence contract. The Ticket is not required to be
    confidential at this layer.

    Defaults:
    - `ticket_id`: a freshly created confidential Ticket, when not
      overridden.
    - `user_id` and `granted_by_id`: two distinct freshly created users,
      when not overridden, so repeated calls never collide on the
      composite primary key.
    - `granted_at`: assigned by the database default.
    """

    async def _create(**overrides: Any) -> TicketAccessGrant:
        if "ticket_id" not in overrides:
            overrides["ticket_id"] = (await ticket_factory(is_confidential=True)).id
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        if "granted_by_id" not in overrides:
            overrides["granted_by_id"] = (await user_factory()).id
        instance = TicketAccessGrant(**overrides)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_reference_factory(
    db_session: AsyncSession,
    ticket_factory: Callable[..., Awaitable[Ticket]],
) -> Callable[..., Awaitable[TicketReference]]:
    """Factory fixture for `TicketReference` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses the reference services on purpose: model-layer tests
    exercise the raw persistence contract, so `url` is not normalized and
    `type` is not validated against `ReferenceType` at this layer.

    Defaults:
    - `ticket_id`: a freshly created Ticket, when not overridden.
    - `url`: a per-fixture-counter-derived fictional URL
      (`https://advisories.example.com/ref-<nnnn>`), so repeated calls on
      one Ticket don't collide on the `(ticket_id, url)` UNIQUE constraint.
    - `source`: `"manual"`.
    - `title`, `description`, and `type`: `NULL`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> TicketReference:
        n = next(counter)
        if "ticket_id" not in overrides:
            overrides["ticket_id"] = (await ticket_factory()).id
        defaults: dict[str, Any] = {
            "url": f"https://advisories.example.com/ref-{n:04d}",
            "source": "manual",
        }
        defaults.update(overrides)
        instance = TicketReference(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def product_factory(db_session: AsyncSession) -> Callable[..., Awaitable[Product]]:
    """Factory fixture for `Product` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses the Product catalog synchronization on purpose: model-layer
    tests exercise the raw persistence contract.

    Defaults:
    - `cpe`: a per-fixture-counter-derived fictional CPE
      (`cpe:/o:example:product:<n>`), so repeated calls don't collide on
      the UNIQUE `cpe` constraint.
    - `name`, `version`, `display_name`: fictional counter-derived
      descriptive values (`Example Product <n>`, `<n>`, `EP <n>`).
    - `catalog_last_seen_at`: `datetime.now(UTC)` (the column has no
      default).
    - `cvss_threshold` and the four lifecycle dates: `NULL`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> Product:
        n = next(counter)
        defaults: dict[str, Any] = {
            "name": f"Example Product {n}",
            "version": str(n),
            "display_name": f"EP {n}",
            "cpe": f"cpe:/o:example:product:{n}",
            "catalog_last_seen_at": datetime.now(UTC),
        }
        defaults.update(overrides)
        instance = Product(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def product_repository_factory(
    db_session: AsyncSession,
    product_factory: Callable[..., Awaitable[Product]],
) -> Callable[..., Awaitable[ProductRepository]]:
    """Factory fixture for `ProductRepository` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Defaults:
    - `product_id`: a freshly created Product, when not overridden.
    - `repo_name`: a per-fixture-counter-derived fictional repository
      project name (`Example:Updates:<n>`), so repeated calls on one
      Product don't collide on the `(product_id, repo_name)` UNIQUE
      constraint.
    - `catalog_last_seen_at`: `datetime.now(UTC)` (the column has no
      default).
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> ProductRepository:
        n = next(counter)
        if "product_id" not in overrides:
            overrides["product_id"] = (await product_factory()).id
        defaults: dict[str, Any] = {
            "repo_name": f"Example:Updates:{n}",
            "catalog_last_seen_at": datetime.now(UTC),
        }
        defaults.update(overrides)
        instance = ProductRepository(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_package_factory(
    db_session: AsyncSession,
    ticket_factory: Callable[..., Awaitable[Ticket]],
) -> Callable[..., Awaitable[TicketPackage]]:
    """Factory fixture for `TicketPackage` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `package_service` on purpose: model-layer tests exercise the
    raw persistence contract.

    Defaults:
    - `ticket_id`: a freshly created Ticket, when not overridden.
    - `package_name`: a per-fixture-counter-derived fictional source
      package name (`example-package-<n>`), so repeated calls on one Ticket
      don't collide on the `(ticket_id, package_name)` UNIQUE constraint.
    - `deleted_at`: `NULL` (not directly excluded).
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> TicketPackage:
        n = next(counter)
        if "ticket_id" not in overrides:
            overrides["ticket_id"] = (await ticket_factory()).id
        defaults: dict[str, Any] = {"package_name": f"example-package-{n}"}
        defaults.update(overrides)
        instance = TicketPackage(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_package_track_factory(
    db_session: AsyncSession,
    ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
) -> Callable[..., Awaitable[TicketPackageTrack]]:
    """Factory fixture for `TicketPackageTrack` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `package_service` on purpose: model-layer tests exercise the
    raw persistence contract, so `workflow_type` is not validated against
    `WorkflowType` at this layer.

    Defaults:
    - `ticket_package_id`: a freshly created package, when not overridden.
    - `workflow_type`: `"ibs"`.
    - `reference`: a per-fixture-counter-derived fictional IBS codestream
      project name (`Example:Codestream:<n>:Update`), so repeated calls on
      one package don't collide on the `(ticket_package_id, reference)`
      UNIQUE constraint.
    - `status` (`ANALYSIS`), `delivery_status` (`PENDING`), and
      `deleted_at` (`NULL`): the model defaults.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> TicketPackageTrack:
        n = next(counter)
        if "ticket_package_id" not in overrides:
            overrides["ticket_package_id"] = (await ticket_package_factory()).id
        defaults: dict[str, Any] = {
            "workflow_type": WorkflowType.IBS.value,
            "reference": f"Example:Codestream:{n}:Update",
        }
        defaults.update(overrides)
        instance = TicketPackageTrack(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_package_product_factory(
    db_session: AsyncSession,
    ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
    product_factory: Callable[..., Awaitable[Product]],
) -> Callable[..., Awaitable[TicketPackageProduct]]:
    """Factory fixture for `TicketPackageProduct` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses `package_service` on purpose: model-layer tests exercise the
    raw persistence contract, so `eligible` is not computed from the CVSS
    threshold and lifecycle phase at this layer.

    Defaults:
    - `ticket_package_track_id`: a freshly created track, when not
      overridden.
    - `product_id`: a freshly created Product, when not overridden; each
      call therefore uses a distinct Product and never collides on the
      `(ticket_package_track_id, product_id)` UNIQUE constraint.
    - `eligible` (`true`), `is_eligible_override` (`false`), `released_at`
      (`NULL`), and `deleted_at` (`NULL`): the model defaults.
    """

    async def _create(**overrides: Any) -> TicketPackageProduct:
        if "ticket_package_track_id" not in overrides:
            overrides["ticket_package_track_id"] = (
                await ticket_package_track_factory()
            ).id
        if "product_id" not in overrides:
            overrides["product_id"] = (await product_factory()).id
        instance = TicketPackageProduct(**overrides)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ticket_package_maintainer_factory(
    db_session: AsyncSession,
    ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
    user_factory: Callable[..., Awaitable[User]],
) -> Callable[..., Awaitable[TicketPackageMaintainer]]:
    """Factory fixture for `TicketPackageMaintainer` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses SMELT maintainership acquisition on purpose: model-layer tests
    exercise the raw persistence contract, so the user's active state and
    email are not matched at this layer.

    Defaults:
    - `ticket_package_id`: a freshly created package, when not overridden.
    - `user_id`: a freshly created user, when not overridden; each call
      therefore uses a distinct user and never collides on the
      `(ticket_package_id, user_id)` UNIQUE constraint.
    """

    async def _create(**overrides: Any) -> TicketPackageMaintainer:
        if "ticket_package_id" not in overrides:
            overrides["ticket_package_id"] = (await ticket_package_factory()).id
        if "user_id" not in overrides:
            overrides["user_id"] = (await user_factory()).id
        instance = TicketPackageMaintainer(**overrides)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


# Fixed fictional upstream IBS chronology for request factory defaults.
_IBS_UPSTREAM_CREATED_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
_IBS_UPSTREAM_UPDATED_AT = datetime(2026, 9, 2, 9, 30, tzinfo=UTC)


@pytest.fixture
def ibs_request_factory(
    db_session: AsyncSession,
) -> Callable[..., Awaitable[IBSRequest]]:
    """Factory fixture for `IBSRequest` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses IBS submission tracking on purpose: model-layer tests exercise
    the raw persistence contract, so no request detail is fetched or
    normalized at this layer.

    Defaults:
    - `request_number`: a per-fixture-counter-derived positive number
      (`700000 + n`), so repeated calls don't collide on the UNIQUE
      constraint or on small numbers chosen explicitly by a test.
    - `state`: `"new"`.
    - `superseded_by_request_number`: `NULL`, except that when `state` is
      overridden to `"superseded"` without a successor it defaults to
      `request_number + 1`, satisfying
      `chk_ibs_request_supersession_coherence`.
    - `upstream_created_at` / `upstream_updated_at`: fixed fictional UTC
      instants.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> IBSRequest:
        n = next(counter)
        defaults: dict[str, Any] = {
            "request_number": 700000 + n,
            "state": IBSRequestState.NEW.value,
            "upstream_created_at": _IBS_UPSTREAM_CREATED_AT,
            "upstream_updated_at": _IBS_UPSTREAM_UPDATED_AT,
        }
        defaults.update(overrides)
        if (
            defaults["state"] == IBSRequestState.SUPERSEDED.value
            and "superseded_by_request_number" not in overrides
        ):
            defaults["superseded_by_request_number"] = defaults["request_number"] + 1
        instance = IBSRequest(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ibs_request_action_factory(
    db_session: AsyncSession,
    ibs_request_factory: Callable[..., Awaitable[IBSRequest]],
) -> Callable[..., Awaitable[IBSRequestAction]]:
    """Factory fixture for `IBSRequestAction` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses IBS submission tracking on purpose: model-layer tests exercise
    the raw persistence contract, so no upstream action is normalized at
    this layer. All project and package names are fictional.

    Defaults (per-fixture counter `n`, so repeated calls on one request never
    collide on a semantic-identity index):
    - `ibs_request_id`: a freshly created request, when not overridden.
    - `action_type`: `"maintenance_incident"`.
    - For `maintenance_incident` (and any unknown `action_type` a test
      supplies): `source_project` (`Example:Devel:<n>`), `source_package`
      (`example-pkg`), and `target_release_project`
      (`Example:Codestream:<n>:Update`); the target fields and
      `incident_number` stay `NULL`.
    - For `maintenance_release`: `source_project`
      (`Example:Maintenance:<incident>`), `source_package`
      (`example-pkg.Example_Codestream_<n>`), `target_project`
      (`Example:Codestream:<n>:Update`), `target_package` (`example-pkg`),
      and `incident_number` (`1000 + n`).
    - `logical_package`: `example-pkg`.
    - `codestream_name`: the effective `target_release_project` (incident)
      or `target_project` (release) after overrides, satisfying
      `chk_ibs_request_action_type_coherence`; when that anchor is
      overridden to `NULL`, a fictional codestream name so the row fails
      only on the coherence CHECK rather than on NOT NULL.
    - Revision and checksum fields: `NULL`.
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> IBSRequestAction:
        n = next(counter)
        if "ibs_request_id" not in overrides:
            overrides["ibs_request_id"] = (await ibs_request_factory()).id
        action_type = overrides.get(
            "action_type", IBSRequestActionType.MAINTENANCE_INCIDENT.value
        )
        codestream = f"Example:Codestream:{n}:Update"
        defaults: dict[str, Any]
        if action_type == IBSRequestActionType.MAINTENANCE_RELEASE.value:
            incident_number = 1000 + n
            defaults = {
                "source_project": f"Example:Maintenance:{incident_number}",
                "source_package": f"example-pkg.Example_Codestream_{n}",
                "target_project": codestream,
                "target_package": "example-pkg",
                "incident_number": incident_number,
            }
            anchor = "target_project"
        else:
            defaults = {
                "source_project": f"Example:Devel:{n}",
                "source_package": "example-pkg",
                "target_release_project": codestream,
            }
            anchor = "target_release_project"
        defaults["action_type"] = action_type
        defaults["logical_package"] = "example-pkg"
        defaults.update(overrides)
        defaults.setdefault("codestream_name", defaults.get(anchor) or codestream)
        instance = IBSRequestAction(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def track_release_checkpoint_factory(
    db_session: AsyncSession,
    ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
) -> Callable[..., Awaitable[TrackReleaseCheckpoint]]:
    """Factory fixture for `TrackReleaseCheckpoint` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses IBS track release detection on purpose: model-layer tests
    exercise the raw persistence contract, so no predecessor is validated
    and no source state is examined at this layer.

    Defaults:
    - `ticket_package_track_id`: a freshly created IBS track, when not
      overridden; each call therefore uses a distinct track and never
      collides on the UNIQUE `ticket_package_track_id`.
    - `srcmd5`: a fictional per-fixture-counter-derived 32-character
      lowercase hexadecimal value.
    - `last_seen_at`: the database default (`now()`).
    """

    counter = itertools.count(1)

    async def _create(**overrides: Any) -> TrackReleaseCheckpoint:
        n = next(counter)
        if "ticket_package_track_id" not in overrides:
            overrides["ticket_package_track_id"] = (
                await ticket_package_track_factory()
            ).id
        defaults: dict[str, Any] = {"srcmd5": f"{n:032x}"}
        defaults.update(overrides)
        instance = TrackReleaseCheckpoint(**defaults)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest.fixture
def ibs_request_action_track_factory(
    db_session: AsyncSession,
    ibs_request_action_factory: Callable[..., Awaitable[IBSRequestAction]],
    ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
) -> Callable[..., Awaitable[IBSRequestActionTrack]]:
    """Factory fixture for `IBSRequestActionTrack` model instances.

    See docs/features/platform/testing-strategy.md (Model Factory
    Fixtures) for the canonical shape this fixture follows.

    Bypasses IBS submission tracking on purpose: model-layer tests exercise
    the raw persistence contract, so the action's codestream and package are
    not matched against the track at this layer.

    Defaults:
    - `ibs_request_action_id`: a freshly created action, when not overridden.
    - `ticket_package_track_id`: a freshly created IBS track, when not
      overridden. A call therefore never collides on the
      `(ticket_package_track_id, ibs_request_action_id)` UNIQUE constraint
      unless both references are overridden.
    """

    async def _create(**overrides: Any) -> IBSRequestActionTrack:
        if "ibs_request_action_id" not in overrides:
            overrides["ibs_request_action_id"] = (await ibs_request_action_factory()).id
        if "ticket_package_track_id" not in overrides:
            overrides["ticket_package_track_id"] = (
                await ticket_package_track_factory()
            ).id
        instance = IBSRequestActionTrack(**overrides)
        db_session.add(instance)
        await db_session.flush()
        return instance

    return _create


@pytest_asyncio.fixture
async def _authenticated_user_and_client(
    client: AsyncClient,
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
    redis_client: redis_asyncio.Redis,
) -> tuple[User, AsyncClient]:
    """Shared setup for `authenticated_client` and `admin_client`.

    Creates a fresh user and a valid JWT session, then attaches the
    session cookie to the shared `client` fixture. Depending on
    `redis_client` composes the worker-isolated Redis database
    automatically — see docs/features/platform/testing-strategy.md
    (Fixture Catalog): "authenticated_client and admin_client compose
    this Redis isolation automatically; tests using either client MUST
    NOT need to request redis_client separately."
    """
    user = await user_factory()
    created = await create_session(
        db_session,
        user,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None
    client.cookies.set(SESSION_COOKIE_NAME, created.token)
    return user, client


@pytest.fixture
def authenticated_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> AsyncClient:
    """An `AsyncClient` authenticated via a valid JWT session, for a user
    with **no roles** — pure authentication without any capability.

    See docs/features/platform/testing-strategy.md (Fixture Catalog).
    Tests that need specific capabilities must either use `admin_client`
    or assign roles explicitly via `user_role_factory`.
    """
    return _authenticated_user_and_client[1]


@pytest_asyncio.fixture
async def admin_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Callable[..., Awaitable[UserRole]],
) -> AsyncClient:
    """An `authenticated_client` whose user additionally holds only the
    `admin` role.

    See docs/features/platform/testing-strategy.md (Fixture Catalog).
    """
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return client
