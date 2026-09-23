"""Tests for the session service (backend/app/services/session_service.py).

See docs/features/identity/authentication.md (Session Management) for
the contract under test, and
docs/features/platform/testing-strategy.md (Authentication and
Session, Session liveness and invalidation) for the mandatory
scenarios exercised here.
"""

from __future__ import annotations

import ast
import asyncio
import uuid
from collections.abc import Awaitable, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import RedisError
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import SessionCreationReason, SessionInvalidationReason
from app.core.jwt import decode_and_validate
from app.models.session import Session
from app.models.user import User
from app.services import session_service
from app.services.session_service import (
    cleanup_sessions,
    create_session,
    invalidate_session,
    invalidate_user_sessions,
    is_session_active,
    purge_session_cache,
)

# Fictional bcrypt-shaped value — never a real hash (see AGENTS.md Guardrail 23)
_FICTIONAL_PASSWORD_HASH = "$2b$12$" + "a" * 53


@pytest.fixture(autouse=True)
def _reset_redis_outage_state() -> Generator[None]:
    """Reset the per-process outage-episode flag around every test —
    it is module-level mutable state (see
    docs/features/platform/testing-strategy.md, Test Independence)."""
    session_service._redis_outage_active = False
    yield
    session_service._redis_outage_active = False


def _service_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join only the log records emitted by `app.services.session_service`.

    `caplog.text` also captures propagated SQLAlchemy engine echo
    records, which legitimately include bound parameter values (e.g.
    UUIDs) as part of query logging — unrelated to this module's own
    PII discipline. Scoping to this module's own records avoids a
    false PII-leak failure from that unrelated echo output.
    """
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.services.session_service"
    )


def _session_service_event_fields(
    caplog: pytest.LogCaptureFixture, event: str
) -> list[dict[str, Any]]:
    """Parse this module's structlog records matching `event` name into
    plain dicts, so tests can assert exact structured fields (e.g.
    `count` as an `int`, not a substring) instead of loose text
    containment checks. The captured record's rendered message is a
    Python dict literal (structlog's test-time renderer) — parsed
    safely via `ast.literal_eval`, never `eval`."""
    matches = []
    for record in caplog.records:
        if record.name != "app.services.session_service":
            continue
        try:
            parsed = ast.literal_eval(record.getMessage())
        except ValueError, SyntaxError:
            continue
        if isinstance(parsed, dict) and parsed.get("event") == event:
            matches.append(parsed)
    return matches


class _FailingRedisClient:
    """A Redis client double whose `get`/`set`/`delete` always raise
    `RedisError` — used to simulate deterministic outages without
    touching the shared Redis test infrastructure (see
    docs/features/platform/testing-strategy.md, Redis Strategy)."""

    async def get(self, key: str) -> str | None:
        raise RedisError("simulated outage")

    async def set(self, key: str, value: str, ex: int) -> None:
        raise RedisError("simulated outage")

    async def delete(self, key: str) -> None:
        raise RedisError("simulated outage")

    async def aclose(self) -> None:
        return None


class _PartialFailureRedisClient:
    """Fails `delete()` for one specific key, succeeds for all others —
    used to prove `purge_session_cache()` continues attempting every
    remaining ID after one failure."""

    def __init__(self, failing_key: str) -> None:
        self._failing_key = failing_key
        self.deleted: list[str] = []

    async def delete(self, key: str) -> None:
        if key == self._failing_key:
            raise RedisError("simulated outage")
        self.deleted.append(key)

    async def aclose(self) -> None:
        return None


class _YieldingFailureRedisClient(_FailingRedisClient):
    """Yield once before failing so concurrent tasks genuinely interleave."""

    async def delete(self, key: str) -> None:
        await asyncio.sleep(0)
        raise RedisError("simulated outage")


# ---------------------------------------------------------------------------
# create_session()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateSession:
    async def test_creates_active_session_with_expected_fields(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        user = await user_factory()
        result = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert result is not None
        assert result.session.user_id == user.id
        assert result.session.is_active is True
        assert result.token
        assert result.token_expires_at is not None

    async def test_issued_jwt_matches_user_session_and_deadline(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        user = await user_factory()
        result = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert result is not None
        assert user.last_login_at is not None

        claims = decode_and_validate(
            result.token,
            secret_key=settings.jwt_secret_key.get_secret_value(),
            now=user.last_login_at,
        )
        assert claims.user_id == user.id
        assert claims.session_id == result.session.id
        assert claims.issued_at == user.last_login_at.replace(microsecond=0)
        assert claims.expires_at == result.token_expires_at
        assert claims.session_deadline == result.session.expires_at.replace(
            microsecond=0
        )

    async def test_updates_last_login_at_using_same_snapshot(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        user = await user_factory()
        assert user.last_login_at is None
        result = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert result is not None
        assert user.last_login_at is not None
        # Session.expires_at derives from the same login_at snapshot as
        # last_login_at, offset by SESSION_MAX_LIFETIME_DAYS.
        from app.config import settings

        expected_deadline = user.last_login_at + timedelta(
            days=settings.session_max_lifetime_days
        )
        assert result.session.expires_at == expected_deadline

    async def test_token_expires_at_matches_jwt_exp_not_session_deadline(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        user = await user_factory()
        result = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert result is not None
        assert result.token_expires_at < result.session.expires_at

    async def test_does_not_invalidate_existing_sessions(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        user = await user_factory()
        existing = await session_factory(user_id=user.id)
        await create_session(db_session, user, SessionCreationReason.LOCAL_LOGIN)
        await db_session.refresh(existing)
        assert existing.is_active is True

    async def test_existing_deadline_is_unchanged_after_setting_change(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        monkeypatch.setattr(settings, "session_max_lifetime_days", 1)
        first = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert first is not None
        first_deadline = first.session.expires_at

        monkeypatch.setattr(settings, "session_max_lifetime_days", 2)
        second = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert second is not None

        assert first.session.expires_at == first_deadline
        assert first.session.is_active is True
        assert second.session.expires_at > first_deadline

    async def test_reinvocation_creates_independent_session(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        user = await user_factory()
        first = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert first is not None
        second = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )
        assert second is not None
        assert first.session.id != second.session.id
        assert first.token != second.token

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        await create_session(db_session, user, SessionCreationReason.LOCAL_LOGIN)
        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()

    async def test_failure_propagates_and_caller_rollback_undoes_both_writes(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Uses `db_session_factory` (real, independent sessions) rather
        than the shared `db_session` fixture: this scenario needs a
        genuine commit to establish a baseline before the failure,
        which the shared fixture's nested-savepoint join mode is not
        intended for (see docs/features/platform/testing-strategy.md,
        Database Strategy). Verification uses a second, fresh session:
        `session.rollback()` expires all ORM attributes on `user`, so
        `user.id` must be captured beforehand — accessing an expired
        attribute after rollback would trigger a synchronous lazy
        reload outside of an async-safe context.

        The committed baseline `User` row is cleaned up in a `finally`
        block so a failed assertion below cannot leave it behind for
        later tests (see docs/features/platform/testing-strategy.md,
        Test Independence)."""
        session = await db_session_factory()
        user = User(
            username="rollbacktest",
            email="rollbacktest@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        session.add(user)
        await session.commit()
        user_id = user.id

        try:

            def _boom(**kwargs: Any) -> None:
                raise RuntimeError("token encoding failed")

            monkeypatch.setattr(session_service, "issue_token", _boom)

            with pytest.raises(RuntimeError):
                await create_session(session, user, SessionCreationReason.LOCAL_LOGIN)

            await session.rollback()

            verify_session = await db_session_factory()
            refreshed_user = await verify_session.get(User, user_id)
            assert refreshed_user is not None
            assert refreshed_user.last_login_at is None
            rows = await verify_session.execute(
                select(Session).where(Session.user_id == user_id)
            )
            assert rows.scalars().all() == []
        finally:
            # Explicit cleanup: the user row was committed above, so it
            # is not covered by db_session_factory's rollback-on-teardown.
            # Runs even if an assertion above failed, so a failing run
            # cannot contaminate later tests with a leftover committed row.
            cleanup_session = await db_session_factory()
            await cleanup_session.execute(delete(User).where(User.id == user_id))
            await cleanup_session.commit()

    async def test_creates_no_identity_audit_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        from app.models.identity_audit_event import IdentityAuditEvent

        user = await user_factory()
        await create_session(db_session, user, SessionCreationReason.LOCAL_LOGIN)
        rows = await db_session.execute(
            select(IdentityAuditEvent).where(
                IdentityAuditEvent.target_user_id == user.id
            )
        )
        assert rows.scalars().all() == []

    async def test_logs_user_id_and_reason_without_jwt_or_session_id(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        with caplog.at_level("INFO"):
            result = await create_session(
                db_session, user, SessionCreationReason.LOCAL_LOGIN
            )
        assert result is not None
        assert "session_created" in _service_log_text(caplog)
        assert str(user.id) in _service_log_text(caplog)
        assert "local_login" in _service_log_text(caplog)
        assert result.token not in _service_log_text(caplog)
        assert str(result.session.id) not in _service_log_text(caplog)

    async def test_locked_current_inactive_returns_none_without_writes(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The pre-lock `active` value on the passed object is never
        authoritative: a deactivation already visible in the database
        makes `create_session()` return `None` with no Session, no
        `last_login_at` update, no token, and no `session_created` log
        (see authentication.md, Session creation, step 1)."""
        user = await user_factory()
        # Bypass the ORM identity-map synchronization so the in-memory
        # `user` instance genuinely stays stale (active=True) while the
        # persisted, locked-current row is inactive — exactly the
        # deactivation-committed-first race. Without
        # `synchronize_session=False`, SQLAlchemy's ORM-enabled UPDATE
        # would refresh the instance and the test could not tell whether
        # `create_session()` trusted the passed object or the reloaded row.
        await db_session.execute(
            update(User)
            .where(User.id == user.id)
            .values(active=False)
            .execution_options(synchronize_session=False)
        )
        await db_session.flush()
        assert user.active is True

        with caplog.at_level("INFO"):
            result = await create_session(
                db_session, user, SessionCreationReason.LOCAL_LOGIN
            )

        assert result is None
        assert user.last_login_at is None
        assert "session_created" not in _service_log_text(caplog)
        rows = await db_session.execute(
            select(Session).where(Session.user_id == user.id)
        )
        assert rows.scalars().all() == []

    async def test_missing_locked_target_returns_none(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        """A target removed between the caller's pre-read and the lock
        acquisition yields no Session and no write (see authentication.md,
        Session creation, step 1)."""
        user = await user_factory()
        user_id = user.id
        await db_session.delete(user)
        await db_session.flush()

        # The transient stand-in claims `active=True`, so a regressed
        # implementation that trusted the passed object instead of the
        # locked-current row would attempt a Session insert and fail on
        # the foreign key rather than return `None`.
        result = await create_session(
            db_session,
            User(id=user_id, active=True),
            SessionCreationReason.LOCAL_LOGIN,
        )

        assert result is None
        rows = await db_session.execute(
            select(Session).where(Session.user_id == user_id)
        )
        assert rows.scalars().all() == []

    async def test_performs_no_redis_io_while_lock_is_held(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The User lock covers only the short database phase: no Redis
        client is constructed anywhere during session creation, so no
        Redis command executes while the lock is held (see conventions.md,
        Transaction Hygiene Rules, and authentication.md, Session
        creation)."""
        user = await user_factory()

        def _forbid_redis(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError(
                "must not construct a Redis client while the User lock is held"
            )

        monkeypatch.setattr(redis_asyncio.Redis, "from_url", _forbid_redis)

        result = await create_session(
            db_session, user, SessionCreationReason.LOCAL_LOGIN
        )

        assert result is not None


# ---------------------------------------------------------------------------
# create_session() lock serialization with User state
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateSessionLockSerialization:
    """Deterministic two-session proofs of the User-root lock protocol
    that serializes Session creation with deactivation (see
    authentication.md, Session creation; user-service.md, Session
    creation concurrent with deactivation). The absent `deactivate_user()`
    workflow is intentionally not implemented; a controlled conflicting
    database operation stands in for it."""

    async def test_deactivation_committed_first_returns_none(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session = await db_session_factory()
        user = User(
            username="serializedeactivated",
            email="serializedeactivated@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        session.add(user)
        await session.commit()
        user_id = user.id

        try:
            # The conflicting active-status update commits first.
            await session.execute(
                update(User).where(User.id == user_id).values(active=False)
            )
            await session.commit()

            waiting = await db_session_factory()
            locked_target = await waiting.get(User, user_id)
            assert locked_target is not None

            result = await create_session(
                waiting, locked_target, SessionCreationReason.LOCAL_LOGIN
            )

            assert result is None
            rows = await waiting.execute(
                select(Session).where(Session.user_id == user_id)
            )
            assert rows.scalars().all() == []
            assert locked_target.last_login_at is None
            await waiting.rollback()

            verify = await db_session_factory()
            refreshed = await verify.get(User, user_id)
            assert refreshed is not None
            assert refreshed.last_login_at is None
            await verify.rollback()
        finally:
            cleanup = await db_session_factory()
            await cleanup.execute(delete(Session).where(Session.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.commit()

    async def test_session_creation_holds_lock_until_commit(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        user = User(
            username="serializelockfirst",
            email="serializelockfirst@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        session_a.add(user)
        await session_a.commit()
        user_id = user.id

        try:
            created = await create_session(
                session_a, user, SessionCreationReason.LOCAL_LOGIN
            )
            assert created is not None

            # A conflicting active-status update in an independent session
            # must block until Session creation's transaction completes.
            session_b = await db_session_factory()

            async def _conflicting_status_update() -> None:
                await session_b.execute(
                    update(User).where(User.id == user_id).values(active=False)
                )
                await session_b.commit()

            task_b = asyncio.create_task(_conflicting_status_update())
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.5)

            # Session creation commits first; only then does the blocked
            # conflicting mutation proceed.
            await session_a.commit()
            await asyncio.wait_for(task_b, timeout=5)

            verify = await db_session_factory()
            committed_session = await verify.get(Session, created.session.id)
            assert committed_session is not None
            assert committed_session.is_active is True
            updated_user = await verify.get(User, user_id)
            assert updated_user is not None
            assert updated_user.active is False
            await verify.rollback()
        finally:
            cleanup = await db_session_factory()
            await cleanup.execute(delete(Session).where(Session.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.commit()

    async def test_concurrent_logins_serialize_and_each_create_a_session(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        setup = await db_session_factory()
        user = User(
            username="serializeconcurrent",
            email="serializeconcurrent@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        setup.add(user)
        await setup.commit()
        user_id = user.id

        async def _login() -> tuple[uuid.UUID, datetime]:
            session = await db_session_factory()
            try:
                target = await session.get(User, user_id)
                assert target is not None
                created = await create_session(
                    session, target, SessionCreationReason.LOCAL_LOGIN
                )
                assert created is not None
                await session.commit()
                # `Session.expires_at` is `login_at + SESSION_MAX_LIFETIME_DAYS`,
                # so the login instant is recoverable from it.
                login_at = created.session.expires_at - timedelta(
                    days=settings.session_max_lifetime_days
                )
                return created.session.id, login_at
            finally:
                await session.close()

        try:
            (
                (first_id, first_login_at),
                (second_id, second_login_at),
            ) = await asyncio.gather(_login(), _login())
            assert first_id != second_id

            verify = await db_session_factory()
            rows = await verify.execute(
                select(Session).where(Session.user_id == user_id)
            )
            sessions = rows.scalars().all()
            assert len(sessions) == 2
            refreshed = await verify.get(User, user_id)
            assert refreshed is not None
            # Concurrent logins serialize on the same User lock;
            # `last_login_at` ends at the last committed login.
            assert refreshed.last_login_at == max(first_login_at, second_login_at)
            await verify.rollback()
        finally:
            cleanup = await db_session_factory()
            await cleanup.execute(delete(Session).where(Session.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.commit()


# ---------------------------------------------------------------------------
# is_session_active()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIsSessionActive:
    async def test_client_uses_bounded_connect_and_operation_timeouts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def _from_url(url: str, **kwargs: Any) -> _FailingRedisClient:
            captured.update(kwargs)
            return _FailingRedisClient()

        monkeypatch.setattr(redis_asyncio.Redis, "from_url", _from_url)
        client = session_service._new_redis_client()
        await client.aclose()

        assert captured["socket_connect_timeout"] == 2
        assert captured["socket_timeout"] == 2

    async def test_cache_hit_avoids_database_query(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        session = await session_factory()
        await redis_client.set(f"session_liveness:{session.id}", "1", ex=60)

        async def _boom(*args: object, **kwargs: object) -> None:
            raise AssertionError("must not query the database on a cache hit")

        monkeypatch.setattr(db_session, "get", _boom)
        assert await is_session_active(db_session, session.id) is True

    async def test_cache_miss_active_row_writes_positive_cache(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        assert await is_session_active(db_session, session.id) is True
        cached = await redis_client.get(f"session_liveness:{session.id}")
        assert cached == "1"
        ttl = await redis_client.ttl(f"session_liveness:{session.id}")
        assert 0 < ttl <= 60

    async def test_cache_miss_inactive_row_returns_false_no_cache_write(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory(is_active=False)
        assert await is_session_active(db_session, session.id) is False
        cached = await redis_client.get(f"session_liveness:{session.id}")
        assert cached is None

    async def test_missing_row_returns_false(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        assert await is_session_active(db_session, uuid.uuid4()) is False

    async def test_unexpected_cached_value_is_treated_as_miss(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        await redis_client.set(f"session_liveness:{session.id}", "garbage", ex=60)
        assert await is_session_active(db_session, session.id) is True
        # The unexpected value is overwritten by the normal positive-cache
        # write once the database confirms the session is active.
        assert await redis_client.get(f"session_liveness:{session.id}") == "1"

    async def test_redis_get_error_falls_back_to_database(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        session = await session_factory()
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _YieldingFailureRedisClient()
        )
        assert await is_session_active(db_session, session.id) is True

    async def test_redis_set_error_still_returns_true(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        session = await session_factory()
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        assert await is_session_active(db_session, session.id) is True

    async def test_redis_outage_emits_one_warning_per_episode(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        session = await session_factory()
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            await is_session_active(db_session, session.id)
            await is_session_active(db_session, session.id)
        assert _service_log_text(caplog).count("session_redis_unavailable") == 1

    async def test_concurrent_first_redis_failures_emit_one_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )

        with caplog.at_level("WARNING"):
            await asyncio.gather(
                purge_session_cache([uuid.uuid4()]),
                purge_session_cache([uuid.uuid4()]),
            )

        assert _service_log_text(caplog).count("session_redis_unavailable") == 1

    async def test_success_after_failure_resets_warning_eligibility(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Restore only `_new_redis_client` explicitly (not `monkeypatch.undo()`,
        # which would also revert the `redis_client` fixture's override of
        # `get_session_redis_url` back to the application-configured default —
        # see docs/features/platform/testing-strategy.md, Redis Strategy).
        original_new_redis_client = session_service._new_redis_client

        session = await session_factory()
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            await is_session_active(db_session, session.id)
        assert _service_log_text(caplog).count("session_redis_unavailable") == 1

        monkeypatch.setattr(
            session_service, "_new_redis_client", original_new_redis_client
        )
        await is_session_active(db_session, session.id)

        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            await is_session_active(db_session, session.id)
        assert _service_log_text(caplog).count("session_redis_unavailable") == 2

    async def test_warning_contains_no_pii(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        session = await session_factory()
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            await is_session_active(db_session, session.id)
        assert str(session.id) not in _service_log_text(caplog)
        assert str(session.user_id) not in _service_log_text(caplog)


# ---------------------------------------------------------------------------
# invalidate_session()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInvalidateSession:
    async def test_flushes_without_commit_rollback_or_redis_io(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await session_factory()
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        monkeypatch.setattr(
            session_service,
            "_new_redis_client",
            lambda: (_ for _ in ()).throw(AssertionError("must not use Redis")),
        )

        await invalidate_session(db_session, target.id)

        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()

    async def test_creates_no_identity_audit_event(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        from app.models.identity_audit_event import IdentityAuditEvent

        target = await session_factory()
        await invalidate_session(db_session, target.id)

        rows = await db_session.execute(select(IdentityAuditEvent))
        assert rows.scalars().all() == []

    async def test_active_row_is_invalidated_and_updated_at_advances(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        session = await session_factory()
        backdated = datetime.now(UTC) - timedelta(days=1)
        session.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(session)
        assert session.updated_at == backdated

        result = await invalidate_session(db_session, session.id)

        assert result == session.id
        await db_session.refresh(session)
        assert session.is_active is False
        assert session.updated_at > backdated

    async def test_already_inactive_row_is_a_noop(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        session = await session_factory(is_active=False)
        backdated = datetime.now(UTC) - timedelta(days=1)
        session.updated_at = backdated
        await db_session.flush()

        result = await invalidate_session(db_session, session.id)

        assert result == session.id
        await db_session.refresh(session)
        assert session.updated_at == backdated

    async def test_missing_row_is_a_noop_returns_given_id(
        self, db_session: AsyncSession
    ) -> None:
        missing_id = uuid.uuid4()
        result = await invalidate_session(db_session, missing_id)
        assert result == missing_id

    async def test_idempotent_reinvocation(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        session = await session_factory()
        await invalidate_session(db_session, session.id)
        # Second call must not raise and must remain a no-op.
        result = await invalidate_session(db_session, session.id)
        assert result == session.id

    async def test_logs_invalidation_with_user_id_and_reason(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        session = await session_factory()
        with caplog.at_level("INFO"):
            await invalidate_session(db_session, session.id)
        assert "session_invalidated" in _service_log_text(caplog)
        assert str(session.user_id) in _service_log_text(caplog)
        assert "logout" in _service_log_text(caplog)

    async def test_noop_does_not_emit_invalidation_log(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        session = await session_factory(is_active=False)
        with caplog.at_level("INFO"):
            await invalidate_session(db_session, session.id)
        assert "session_invalidated" not in _service_log_text(caplog)

    async def test_concurrent_invalidation_only_one_actually_changes_the_row(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Two concurrent `invalidate_session()` calls on the same
        session must not both observe an active row: Postgres row
        locking on the conditional `UPDATE` itself serializes the two
        statements, proving the single atomic conditional UPDATE is
        race-safe without a separate `SELECT ... FOR UPDATE` (see
        `docs/conventions.md`, Pessimistic Locking Pattern, the
        "operational metadata touch" exemption)."""
        session_a = await db_session_factory()
        session_b = await db_session_factory()

        user = User(
            username="concuser",
            email="concuser@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        session_a.add(user)
        await session_a.flush()
        target = Session(
            user_id=user.id, expires_at=datetime.now(UTC) + timedelta(days=1)
        )
        session_a.add(target)
        await session_a.flush()
        await session_a.commit()

        # session_a starts an UPDATE and holds it open (uncommitted).
        await invalidate_session(session_a, target.id)

        # session_b's concurrent UPDATE targeting the same row blocks
        # until session_a commits or rolls back.
        task_b = asyncio.create_task(invalidate_session(session_b, target.id))
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

        await session_a.commit()
        result_b = await asyncio.wait_for(task_b, timeout=5)
        assert result_b == target.id

        await session_b.rollback()
        refreshed = await session_b.get(Session, target.id)
        assert refreshed is not None
        assert refreshed.is_active is False

        # Explicit cleanup: user and session were committed via
        # session_a, so they are not covered by db_session_factory's
        # rollback-on-teardown (see docs/features/platform/
        # testing-strategy.md, Database Strategy).
        await session_b.delete(refreshed)
        committed_user = await session_b.get(User, user.id)
        if committed_user is not None:
            await session_b.delete(committed_user)
        await session_b.commit()


# ---------------------------------------------------------------------------
# invalidate_user_sessions()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInvalidateUserSessions:
    async def test_flushes_without_commit_rollback_or_redis_io(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        await session_factory(user_id=user.id)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        monkeypatch.setattr(
            session_service,
            "_new_redis_client",
            lambda: (_ for _ in ()).throw(AssertionError("must not use Redis")),
        )

        await invalidate_user_sessions(
            db_session, user.id, SessionInvalidationReason.DEACTIVATION
        )

        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()

    async def test_creates_no_identity_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        from app.models.identity_audit_event import IdentityAuditEvent

        user = await user_factory()
        await session_factory(user_id=user.id)
        await invalidate_user_sessions(
            db_session, user.id, SessionInvalidationReason.DEACTIVATION
        )

        rows = await db_session.execute(select(IdentityAuditEvent))
        assert rows.scalars().all() == []

    async def test_invalidates_only_active_sessions_for_the_user(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        user = await user_factory()
        active_1 = await session_factory(user_id=user.id)
        active_2 = await session_factory(user_id=user.id)
        already_inactive = await session_factory(user_id=user.id, is_active=False)
        other_user_session = await session_factory()

        result = await invalidate_user_sessions(
            db_session, user.id, SessionInvalidationReason.DEACTIVATION
        )

        assert set(result) == {active_1.id, active_2.id}
        await db_session.refresh(already_inactive)
        await db_session.refresh(other_user_session)
        assert already_inactive.is_active is False
        assert other_user_session.is_active is True

    async def test_updated_at_advances_only_for_formerly_active_sessions(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        """Mirrors `TestInvalidateSession`'s single-row `updated_at`
        coverage for the bulk path: the `UPDATE ... WHERE is_active =
        true` in `invalidate_user_sessions()` must advance `updated_at`
        only for rows it actually flips, leaving an already-inactive
        row's `updated_at` untouched."""
        user = await user_factory()
        active = await session_factory(user_id=user.id)
        already_inactive = await session_factory(user_id=user.id, is_active=False)
        backdated = datetime.now(UTC) - timedelta(days=1)
        active.updated_at = backdated
        already_inactive.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(active)
        await db_session.refresh(already_inactive)
        assert active.updated_at == backdated
        assert already_inactive.updated_at == backdated

        await invalidate_user_sessions(
            db_session, user.id, SessionInvalidationReason.DEACTIVATION
        )

        await db_session.refresh(active)
        await db_session.refresh(already_inactive)
        assert active.is_active is False
        assert active.updated_at > backdated
        assert already_inactive.updated_at == backdated

    async def test_no_active_sessions_returns_empty_list_and_logs_zero(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        with caplog.at_level("INFO"):
            result = await invalidate_user_sessions(
                db_session, user.id, SessionInvalidationReason.PASSWORD_RESET
            )
        assert result == []
        matches = _session_service_event_fields(caplog, "sessions_invalidated")
        assert len(matches) == 1
        assert matches[0]["user_id"] == str(user.id)
        assert matches[0]["count"] == 0
        assert matches[0]["reason"] == SessionInvalidationReason.PASSWORD_RESET.value

    async def test_logs_count_and_reason(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        await session_factory(user_id=user.id)
        await session_factory(user_id=user.id)
        with caplog.at_level("INFO"):
            await invalidate_user_sessions(
                db_session, user.id, SessionInvalidationReason.DEACTIVATION
            )
        matches = _session_service_event_fields(caplog, "sessions_invalidated")
        assert len(matches) == 1
        assert matches[0]["user_id"] == str(user.id)
        assert matches[0]["count"] == 2
        assert matches[0]["reason"] == SessionInvalidationReason.DEACTIVATION.value


# ---------------------------------------------------------------------------
# purge_session_cache()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPurgeSessionCache:
    async def test_deletes_cache_entries(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        await is_session_active(db_session, session.id)  # populate the cache
        assert await redis_client.get(f"session_liveness:{session.id}") == "1"

        await purge_session_cache([session.id])

        assert await redis_client.get(f"session_liveness:{session.id}") is None

    async def test_empty_input_performs_no_redis_operation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom() -> None:
            raise AssertionError("must not create a Redis client for empty input")

        monkeypatch.setattr(session_service, "_new_redis_client", _boom)
        await purge_session_cache([])

    async def test_idempotent_on_already_absent_keys(
        self, redis_client: redis_asyncio.Redis
    ) -> None:
        await purge_session_cache([uuid.uuid4()])

    async def test_continues_after_one_id_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing_id = uuid.uuid4()
        ok_id = uuid.uuid4()
        fake = _PartialFailureRedisClient(f"session_liveness:{failing_id}")
        monkeypatch.setattr(session_service, "_new_redis_client", lambda: fake)

        await purge_session_cache([failing_id, ok_id])

        assert fake.deleted == [f"session_liveness:{ok_id}"]

    async def test_emits_outage_warning_on_failure(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(
            session_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            await purge_session_cache([uuid.uuid4()])
        assert "session_redis_unavailable" in _service_log_text(caplog)


# ---------------------------------------------------------------------------
# cleanup_sessions()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCleanupSessions:
    async def test_flushes_without_commit_rollback_redis_or_audit_events(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app.models.identity_audit_event import IdentityAuditEvent

        await session_factory(is_active=False)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        monkeypatch.setattr(
            session_service,
            "_new_redis_client",
            lambda: (_ for _ in ()).throw(AssertionError("must not use Redis")),
        )

        await cleanup_sessions(db_session, datetime.now(UTC))

        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()
        rows = await db_session.execute(select(IdentityAuditEvent))
        assert rows.scalars().all() == []

    async def test_deletes_inactive_rows_immediately(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        inactive = await session_factory(
            is_active=False, expires_at=datetime.now(UTC) + timedelta(days=10)
        )
        now = datetime.now(UTC)
        deleted_count = await cleanup_sessions(db_session, now)
        assert deleted_count == 1
        assert await db_session.get(Session, inactive.id) is None

    async def test_deletes_active_rows_past_deadline(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        now = datetime.now(UTC)
        expired = await session_factory(
            is_active=True, expires_at=now - timedelta(microseconds=1)
        )
        deleted_count = await cleanup_sessions(db_session, now)
        assert deleted_count == 1
        assert await db_session.get(Session, expired.id) is None

    async def test_retains_active_row_exactly_at_deadline(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        now = datetime.now(UTC)
        at_deadline = await session_factory(is_active=True, expires_at=now)
        deleted_count = await cleanup_sessions(db_session, now)
        assert deleted_count == 0
        assert await db_session.get(Session, at_deadline.id) is not None

    async def test_retains_active_row_not_yet_expired(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        now = datetime.now(UTC)
        active = await session_factory(
            is_active=True, expires_at=now + timedelta(days=1)
        )
        deleted_count = await cleanup_sessions(db_session, now)
        assert deleted_count == 0
        assert await db_session.get(Session, active.id) is not None

    async def test_idempotent_reinvocation_deletes_nothing_more(
        self,
        db_session: AsyncSession,
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        await session_factory(is_active=False)
        now = datetime.now(UTC)
        first = await cleanup_sessions(db_session, now)
        second = await cleanup_sessions(db_session, now)
        assert first == 1
        assert second == 0
