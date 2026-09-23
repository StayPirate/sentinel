"""Tests for local authentication and Redis-backed lockout
(backend/app/services/local_auth_service.py).

See docs/features/identity/local-authentication.md (Login Endpoint,
Rate Limiting / Brute-Force Protection) for the contract under test,
and docs/features/platform/testing-strategy.md (Authentication and
Session, Lockout concurrency / Anti-enumeration) for the mandatory
scenarios exercised here.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import patch

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import RedisError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.session import Session
from app.models.user import User
from app.services import local_auth_service, session_service
from app.services.local_auth_service import (
    LockoutAdmitted,
    LockoutBlocked,
    LockoutUnavailable,
    LoginInvalidCredentials,
    LoginLocked,
    LoginSuccess,
    authenticate_local_user,
    clear_login_attempts,
    guard_and_increment,
)


class _FailingRedisClient:
    """A Redis client double whose relevant methods always raise
    `RedisError` — used to simulate deterministic outages without
    touching the shared Redis test infrastructure (see
    docs/features/platform/testing-strategy.md, Redis Strategy)."""

    async def eval(self, *args: object, **kwargs: object) -> object:
        raise RedisError("simulated outage")

    async def delete(self, key: str) -> None:
        raise RedisError("simulated outage")

    async def aclose(self) -> None:
        return None


def _service_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join only the log records emitted by this module — avoids false
    positives from unrelated propagated records (see
    test_session_service.py, `_service_log_text`, for the same
    rationale)."""
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.services.local_auth_service"
    )


# ---------------------------------------------------------------------------
# guard_and_increment()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuardAndIncrement:
    async def test_first_attempt_is_admitted_with_count_one(
        self, redis_client: redis_asyncio.Redis
    ) -> None:
        decision = await guard_and_increment("firstattempt")
        assert isinstance(decision, LockoutAdmitted)
        assert decision.attempt_count == 1

    async def test_counter_increments_on_each_admitted_attempt(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 5)
        username = "incrementing"
        first = await guard_and_increment(username)
        second = await guard_and_increment(username)
        third = await guard_and_increment(username)
        assert isinstance(first, LockoutAdmitted)
        assert isinstance(second, LockoutAdmitted)
        assert isinstance(third, LockoutAdmitted)
        assert (first.attempt_count, second.attempt_count, third.attempt_count) == (
            1,
            2,
            3,
        )

    async def test_blocked_at_exactly_max_attempts(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 2)
        username = "blockedatmax"
        await guard_and_increment(username)
        second = await guard_and_increment(username)
        third = await guard_and_increment(username)
        assert isinstance(second, LockoutAdmitted)
        assert second.attempt_count == 2
        assert isinstance(third, LockoutBlocked)
        assert third.retry_after_seconds >= 1

    async def test_blocked_attempt_does_not_increment_counter(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        username = "blockednoincrement"
        await guard_and_increment(username)
        await guard_and_increment(username)
        await guard_and_increment(username)
        assert await redis_client.get(f"login_attempts:{username}") == "1"

    async def test_blocked_attempt_does_not_renew_ttl(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deterministic proof of no-renewal: after the admitted attempt
        sets a long TTL, the key's TTL is artificially collapsed to a
        short, known value. If the blocked attempt's Lua branch ever
        called `EXPIRE` (renewal), the TTL would jump back up to the
        full lockout duration — a two-orders-of-magnitude difference
        that no test-execution jitter could produce. This replaces a
        previous wall-clock-based comparison (`asyncio.sleep` +
        `ttl_after_block <= ttl_after_admit`), which could pass even if
        renewal occurred, as long as the sleep was long enough relative
        to the real TTL decay."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        monkeypatch.setattr(settings, "login_lockout_minutes", 5)
        username = "blockedttl"
        key = f"login_attempts:{username}"
        full_lockout_ms = 5 * 60 * 1000

        admitted = await guard_and_increment(username)
        assert isinstance(admitted, LockoutAdmitted)
        ttl_after_admit = await redis_client.pttl(key)
        assert ttl_after_admit > full_lockout_ms / 2

        # Artificially collapse the TTL to a short, known value — any
        # renewal by the next (blocked) call would be unmistakable.
        short_ttl_seconds = 2
        await redis_client.expire(key, short_ttl_seconds)

        decision = await guard_and_increment(username)
        assert isinstance(decision, LockoutBlocked)

        ttl_after_block = await redis_client.pttl(key)
        assert ttl_after_block > 0
        # If the blocked branch had renewed the TTL, it would jump back
        # up to roughly `full_lockout_ms`. Asserting it stays far below
        # that (bounded instead by the short, artificial TTL) proves no
        # renewal happened, without depending on wall-clock timing.
        assert ttl_after_block <= short_ttl_seconds * 1000

    async def test_ttl_renewed_on_each_admitted_attempt(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deterministic proof of renewal, the mirror image of
        `test_blocked_attempt_does_not_renew_ttl`: after the first
        admitted attempt sets a long TTL, the key's TTL is artificially
        collapsed to a short, known value. If the next admitted
        attempt's Lua branch renews the TTL (calls `EXPIRE`), it jumps
        back up close to the full lockout duration — a two-orders-of-
        magnitude difference that requires no wall-clock sleep to
        observe."""
        monkeypatch.setattr(settings, "login_max_attempts", 10)
        monkeypatch.setattr(settings, "login_lockout_minutes", 5)
        username = "ttlrenewed"
        key = f"login_attempts:{username}"
        full_lockout_ms = 5 * 60 * 1000

        first = await guard_and_increment(username)
        assert isinstance(first, LockoutAdmitted)
        first_ttl_ms = await redis_client.pttl(key)
        assert first_ttl_ms > full_lockout_ms / 2

        short_ttl_seconds = 2
        await redis_client.expire(key, short_ttl_seconds)
        assert await redis_client.pttl(key) <= short_ttl_seconds * 1000

        second = await guard_and_increment(username)
        assert isinstance(second, LockoutAdmitted)
        second_ttl_ms = await redis_client.pttl(key)
        # If the TTL had not been renewed, it would still be close to
        # the short, artificial value set above. A renewed TTL jumps
        # back up near the full lockout duration.
        assert second_ttl_ms > full_lockout_ms / 2

    async def test_concurrent_requests_admit_exactly_max_attempts(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Proves the guard-and-increment operation is indivisible under
        concurrency — collectively, exactly `LOGIN_MAX_ATTEMPTS`
        attempts are admitted regardless of interleaving (see
        local-authentication.md, Concurrency contract)."""
        monkeypatch.setattr(settings, "login_max_attempts", 3)
        monkeypatch.setattr(settings, "login_lockout_minutes", 10)
        username = "concurrentuser"
        results = await asyncio.gather(
            *[guard_and_increment(username) for _ in range(8)]
        )
        admitted = [r for r in results if isinstance(r, LockoutAdmitted)]
        blocked = [r for r in results if isinstance(r, LockoutBlocked)]
        assert len(admitted) == 3
        assert len(blocked) == 5
        assert sorted(r.attempt_count for r in admitted) == [1, 2, 3]

    async def test_redis_error_returns_unavailable_and_logs_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            decision = await guard_and_increment("someone")
        assert isinstance(decision, LockoutUnavailable)
        assert "login_lockout_redis_unavailable" in _service_log_text(caplog)

    async def test_client_uses_bounded_connect_and_operation_timeouts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lockout Redis client carries explicit socket timeouts,
        so a hung (blackholed/firewalled) connection fails fast instead
        of blocking indefinitely — mirrors
        test_session_service.py::TestIsSessionActive::test_client_uses_bounded_connect_and_operation_timeouts."""
        captured: dict[str, Any] = {}

        def _from_url(url: str, **kwargs: Any) -> _FailingRedisClient:
            captured.update(kwargs)
            return _FailingRedisClient()

        monkeypatch.setattr(redis_asyncio.Redis, "from_url", _from_url)
        client = local_auth_service._new_redis_client()
        await client.aclose()

        assert captured["socket_connect_timeout"] == 2
        assert captured["socket_timeout"] == 2


# ---------------------------------------------------------------------------
# clear_login_attempts()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestClearLoginAttempts:
    async def test_deletes_existing_counter(
        self, redis_client: redis_asyncio.Redis
    ) -> None:
        username = "toclean"
        await guard_and_increment(username)
        await clear_login_attempts(username)
        assert await redis_client.get(f"login_attempts:{username}") is None

    async def test_noop_on_absent_key(self, redis_client: redis_asyncio.Redis) -> None:
        await clear_login_attempts("neverexisted")  # must not raise

    async def test_redis_error_is_caught_and_logged(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        with caplog.at_level("WARNING"):
            await clear_login_attempts("someone")  # must not raise
        assert "login_lockout_clear_failed" in _service_log_text(caplog)


# ---------------------------------------------------------------------------
# authenticate_local_user()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuthenticateLocalUser:
    async def test_success_creates_session_and_updates_last_login(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory()
        result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginSuccess)
        assert result.created_session.session.user_id == user.id
        assert result.created_session.session.is_active is True
        assert user.last_login_at is not None

    async def test_username_is_trimmed_and_lowercased(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        _user, password = await local_user_factory(username="alice")
        result = await authenticate_local_user(db_session, "  Alice  ", password)
        assert isinstance(result, LoginSuccess)
        assert result.normalized_username == "alice"

    async def test_wrong_password_returns_invalid_credentials(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, _password = await local_user_factory()
        result = await authenticate_local_user(
            db_session, user.username, "definitely-the-wrong-password"
        )
        assert isinstance(result, LoginInvalidCredentials)

    async def test_unknown_username_returns_invalid_credentials(
        self, db_session: AsyncSession, redis_client: redis_asyncio.Redis
    ) -> None:
        result = await authenticate_local_user(
            db_session, "nosuchuser", "whatever-password-value"
        )
        assert isinstance(result, LoginInvalidCredentials)

    async def test_inactive_user_returns_invalid_credentials(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory(active=False)
        result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginInvalidCredentials)

    async def test_external_user_returns_invalid_credentials(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(external_id=uuid.uuid4(), password_hash=None)
        result = await authenticate_local_user(
            db_session, user.username, "whatever-password-value"
        )
        assert isinstance(result, LoginInvalidCredentials)

    async def test_unknown_and_wrong_password_produce_identical_result_shape(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        """Anti-enumeration: both failure causes are the same result
        type, carrying no distinguishing information."""
        user, _password = await local_user_factory()
        unknown_result = await authenticate_local_user(
            db_session, "nosuchuser", "whatever-password-value"
        )
        wrong_password_result = await authenticate_local_user(
            db_session, user.username, "definitely-the-wrong-password"
        )
        assert isinstance(unknown_result, LoginInvalidCredentials)
        assert isinstance(wrong_password_result, LoginInvalidCredentials)
        assert type(unknown_result) is type(wrong_password_result)

    async def test_unknown_username_executes_dummy_verification(
        self, db_session: AsyncSession, redis_client: redis_asyncio.Redis
    ) -> None:
        """Verified by observing the dummy verification boundary is
        reached — not by asserting wall-clock timing equivalence (see
        testing-strategy.md, Anti-enumeration)."""
        with patch(
            "app.services.local_auth_service.verify_dummy_password"
        ) as mock_dummy:
            result = await authenticate_local_user(
                db_session, "nosuchuser", "whatever-password-value"
            )
        assert isinstance(result, LoginInvalidCredentials)
        mock_dummy.assert_called_once_with("whatever-password-value")

    async def test_ineligible_user_executes_dummy_verification(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory(active=False)
        with patch(
            "app.services.local_auth_service.verify_dummy_password"
        ) as mock_dummy:
            result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginInvalidCredentials)
        mock_dummy.assert_called_once_with(password)

    async def test_eligible_user_never_executes_dummy_verification(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory()
        with patch(
            "app.services.local_auth_service.verify_dummy_password"
        ) as mock_dummy:
            result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginSuccess)
        mock_dummy.assert_not_called()

    async def test_overlong_password_returns_invalid_credentials_without_lookup(
        self, db_session: AsyncSession, redis_client: redis_asyncio.Redis
    ) -> None:
        with patch.object(db_session, "execute") as mock_execute:
            result = await authenticate_local_user(db_session, "someone", "x" * 129)
        assert isinstance(result, LoginInvalidCredentials)
        mock_execute.assert_not_called()
        assert await redis_client.keys("login_attempts:*") == []

    async def test_empty_username_after_normalization_returns_invalid_credentials(
        self, db_session: AsyncSession, redis_client: redis_asyncio.Redis
    ) -> None:
        with patch.object(db_session, "execute") as mock_execute:
            result = await authenticate_local_user(db_session, "   ", "some-password")
        assert isinstance(result, LoginInvalidCredentials)
        mock_execute.assert_not_called()
        assert await redis_client.keys("login_attempts:*") == []

    async def test_overlong_username_returns_invalid_credentials_without_lookup(
        self, db_session: AsyncSession, redis_client: redis_asyncio.Redis
    ) -> None:
        with patch.object(db_session, "execute") as mock_execute:
            result = await authenticate_local_user(
                db_session, "a" * 65, "some-password"
            )
        assert isinstance(result, LoginInvalidCredentials)
        mock_execute.assert_not_called()
        assert await redis_client.keys("login_attempts:*") == []

    async def test_lockout_blocks_after_max_attempts(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 2)
        for _ in range(2):
            result = await authenticate_local_user(
                db_session, "lockeduser", "wrong-password-value"
            )
            assert isinstance(result, LoginInvalidCredentials)
        locked = await authenticate_local_user(
            db_session, "lockeduser", "wrong-password-value"
        )
        assert isinstance(locked, LoginLocked)
        assert locked.retry_after_seconds >= 1

    async def test_blocked_attempt_performs_no_db_query_or_bcrypt(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Once the lockout gate reports `LockoutBlocked` (step 4,
        "Blocked" in local-authentication.md), the function returns
        immediately: no database lookup, no real `verify_password()`,
        and no dummy `verify_dummy_password()` — proving the guard
        short-circuits before any of the subsequent work."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory()

        # Exhaust the single admitted attempt first (real DB lookup and
        # real bcrypt verification legitimately happen here).
        first = await authenticate_local_user(
            db_session, user.username, "wrong-password-value"
        )
        assert isinstance(first, LoginInvalidCredentials)

        # The next attempt must be blocked before touching the database
        # or either verification path.
        with (
            patch.object(db_session, "execute") as mock_execute,
            patch("app.services.local_auth_service.verify_password") as mock_verify,
            patch(
                "app.services.local_auth_service.verify_dummy_password"
            ) as mock_dummy,
        ):
            blocked = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(blocked, LoginLocked)
        mock_execute.assert_not_called()
        mock_verify.assert_not_called()
        mock_dummy.assert_not_called()

    async def test_lockout_transition_log_emitted_once_with_user_id(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, _password = await local_user_factory()
        with caplog.at_level("INFO"):
            result = await authenticate_local_user(
                db_session, user.username, "wrong-password-value"
            )
        assert isinstance(result, LoginInvalidCredentials)
        log_text = _service_log_text(caplog)
        assert log_text.count("login_lockout_triggered") == 1
        assert str(user.id) in log_text

        # Lockout is tracked via application logging only — see
        # local-authentication.md and testing-strategy.md (Authentication
        # and Session, Audit trail boundaries): "Lockout events do NOT
        # produce IdentityAuditEvent records."
        from app.models.identity_audit_event import IdentityAuditEvent

        rows = await db_session.execute(
            select(IdentityAuditEvent).where(
                IdentityAuditEvent.target_user_id == user.id
            )
        )
        assert rows.scalars().all() == []

    async def test_lockout_transition_log_omits_user_id_for_unknown_username(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The prior version of this test looped over `caplog.records`
        with a conditional `assert` inside the loop body, and matched on
        `record.getMessage() == "login_lockout_triggered"` — but
        structlog renders the full event dict (event name, level,
        timestamp, bound fields) into the record's message, so that
        equality check never matched and the assertion never actually
        ran (vacuous pass). This version matches by substring — the same
        approach already used by the "known user" sibling test — proves
        exactly one `login_lockout_triggered` record was emitted, and
        checks the `user_id` key's absence directly on that record's
        rendered message."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        with caplog.at_level("INFO"):
            result = await authenticate_local_user(
                db_session, "nosuchuser", "wrong-password-value"
            )
        assert isinstance(result, LoginInvalidCredentials)
        matching_records = [
            record
            for record in caplog.records
            if record.name == "app.services.local_auth_service"
            and "login_lockout_triggered" in record.getMessage()
        ]
        assert len(matching_records) == 1
        assert "user_id" not in matching_records[0].getMessage()

    async def test_lockout_log_not_emitted_on_successful_login_at_threshold(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory()
        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginSuccess)
        assert "login_lockout_triggered" not in _service_log_text(caplog)

    async def test_successful_login_does_not_clear_the_counter_itself(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        """Clearing the counter is the caller's (route's) post-commit
        responsibility — see local-authentication.md, login step 11."""
        user, password = await local_user_factory()
        result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginSuccess)
        counter = await redis_client.get(f"login_attempts:{result.normalized_username}")
        assert counter == "1"

    async def test_redis_unavailable_fails_open_and_allows_valid_login(
        self,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        user, password = await local_user_factory()
        result = await authenticate_local_user(db_session, user.username, password)
        assert isinstance(result, LoginSuccess)

    async def test_redis_unavailable_still_rejects_wrong_password(
        self,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        user, _password = await local_user_factory()
        result = await authenticate_local_user(
            db_session, user.username, "definitely-the-wrong-password"
        )
        assert isinstance(result, LoginInvalidCredentials)

    @staticmethod
    def _deactivate_as_create_session_side_effect(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simulate a deactivation that commits after the step-7 pre-check
        but before the locked revalidation: the module's
        `create_session` reference is wrapped so the conflicting
        active-status update happens, then the real locked revalidation
        runs. No `deactivate_user()` workflow is implemented (it is out of
        scope), so a controlled database operation stands in for it."""
        real_create = session_service.create_session

        async def _create_after_deactivation(
            db: AsyncSession,
            target: User,
            reason: Any,
            *,
            expected_password_hash: str | None,
        ) -> Any:
            await db.execute(
                update(User).where(User.id == target.id).values(active=False)
            )
            await db.flush()
            return await real_create(
                db,
                target,
                reason,
                expected_password_hash=expected_password_hash,
            )

        monkeypatch.setattr(
            local_auth_service, "create_session", _create_after_deactivation
        )

    @staticmethod
    def _reset_password_as_create_session_side_effect(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simulate a password reset that commits after the step-8
        verification but before the locked revalidation: the module's
        `create_session` reference is wrapped so the conflicting
        `password_hash` replacement happens, then the real locked
        revalidation runs. The conflicting write stands in for the
        committed `reset_password()` transaction."""
        real_create = session_service.create_session

        async def _create_after_reset(
            db: AsyncSession,
            target: User,
            reason: Any,
            *,
            expected_password_hash: str | None,
        ) -> Any:
            await db.execute(
                update(User)
                .where(User.id == target.id)
                .values(password_hash="$2b$12$" + "b" * 53)
            )
            await db.flush()
            return await real_create(
                db,
                target,
                reason,
                expected_password_hash=expected_password_hash,
            )

        monkeypatch.setattr(local_auth_service, "create_session", _create_after_reset)

    async def test_locked_current_inactive_returns_invalid_credentials(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid password followed by a committed deactivation yields
        the generic failure, no Session, no `last_login_at`, and a
        retained counter (see local-authentication.md, step 11)."""
        user, password = await local_user_factory()
        username = user.username
        self._deactivate_as_create_session_side_effect(monkeypatch)

        result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert user.last_login_at is None
        rows = await db_session.execute(
            select(Session).where(Session.user_id == user.id)
        )
        assert rows.scalars().all() == []
        assert await redis_client.get(f"login_attempts:{username}") == "1"

    async def test_locked_current_superseded_credential_returns_invalid_credentials(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid password followed by a committed password reset yields
        the generic failure, no Session, no `last_login_at`, and a
        retained counter (see local-authentication.md, step 11, and
        authentication.md, Password-reset serialization)."""
        user, password = await local_user_factory()
        username = user.username
        self._reset_password_as_create_session_side_effect(monkeypatch)

        result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert user.last_login_at is None
        rows = await db_session.execute(
            select(Session).where(Session.user_id == user.id)
        )
        assert rows.scalars().all() == []
        assert await redis_client.get(f"login_attempts:{username}") == "1"

    async def test_superseded_credential_at_threshold_logs_transition_once(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory()
        self._reset_password_as_create_session_side_effect(monkeypatch)

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert _service_log_text(caplog).count("login_lockout_triggered") == 1
        assert str(user.id) in _service_log_text(caplog)

    async def test_locked_current_inactive_at_threshold_logs_transition_once(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory()
        self._deactivate_as_create_session_side_effect(monkeypatch)

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert _service_log_text(caplog).count("login_lockout_triggered") == 1
        assert str(user.id) in _service_log_text(caplog)

    async def test_locked_current_inactive_below_threshold_logs_no_transition(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 5)
        user, password = await local_user_factory()
        self._deactivate_as_create_session_side_effect(monkeypatch)

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert "login_lockout_triggered" not in _service_log_text(caplog)
        assert await redis_client.get(f"login_attempts:{user.username}") == "1"


# ---------------------------------------------------------------------------
# Log PII discipline (docs/features/platform/testing-strategy.md,
# Log PII discipline)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLogPIIDiscipline:
    async def test_no_pii_across_success_failure_lockout_and_redis_failure_paths(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No username, email, password, password hash, JWT, or session ID
        ever appears in this module's log output — across a successful
        login, a wrong-password failure, an unknown-username failure, a
        lockout transition, and a Redis-unavailable fail-open path."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory(username="piiuser")
        wrong_password = "definitely-the-wrong-password"

        with caplog.at_level("DEBUG"):
            success = await authenticate_local_user(db_session, user.username, password)
            assert isinstance(success, LoginSuccess)

            # Reset the counter so the next failure is the one that
            # crosses login_max_attempts=1 and triggers the transition log.
            await clear_login_attempts(user.username)
            locked_out_failure = await authenticate_local_user(
                db_session, user.username, wrong_password
            )
            assert isinstance(locked_out_failure, LoginInvalidCredentials)

            await authenticate_local_user(
                db_session, "nosuchpiiuser", "whatever-password-value"
            )

            monkeypatch.setattr(
                local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
            )
            await authenticate_local_user(db_session, user.username, wrong_password)

        log_text = _service_log_text(caplog)
        assert user.password_hash is not None
        forbidden_values = [
            user.username,
            user.email,
            password,
            wrong_password,
            "whatever-password-value",
            user.password_hash,
            success.created_session.token,
            str(success.created_session.session.id),
        ]
        for value in forbidden_values:
            assert value not in log_text, f"forbidden value leaked into logs: {value!r}"
        # The lockout transition log legitimately carries user_id (UUID) —
        # confirms the assertions above are not vacuously passing.
        assert str(user.id) in log_text
