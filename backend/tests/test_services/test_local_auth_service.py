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
import base64
import hashlib
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import RedisError
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.passwords import verify_dummy_password, verify_password
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


# Keys the logging pipeline adds to every record (app/core/logging.py);
# the remaining keys of a record are the fields its call site passed.
_PIPELINE_KEYS = frozenset({"event", "logger", "level", "timestamp", "app"})

# The two login outcome events (local-authentication.md, Login outcome
# logging): `session_created` is emitted by `session_service`.
_OUTCOME_EVENTS = frozenset({"session_created", "login_failed"})


def _app_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """The structured event dicts of every captured `app.*` record, in
    emission order."""
    return [
        record.msg
        for record in caplog.records
        if record.name.startswith("app.") and isinstance(record.msg, dict)
    ]


def _service_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """The structured event dicts of this module's records, in emission
    order."""
    return [
        event
        for event in _app_events(caplog)
        if event["logger"] == "app.services.local_auth_service"
    ]


def _login_failed_fields(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """The call-site fields of every captured `login_failed` record, each
    emitted at INFO (local-authentication.md, Login outcome logging)."""
    records = [
        event for event in _service_events(caplog) if event["event"] == "login_failed"
    ]
    assert [event["level"] for event in records] == ["info"] * len(records)
    return [_call_site_fields(event) for event in records]


def _call_site_fields(event: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key not in _PIPELINE_KEYS}


@dataclass
class _IOCounts:
    db_execute: int = 0
    redis_clients: int = 0


def _count_io(monkeypatch: pytest.MonkeyPatch, db: AsyncSession) -> _IOCounts:
    """Count `db.execute()` calls and lockout Redis clients created from
    now on, delegating to the real implementations."""
    counts = _IOCounts()
    real_execute = db.execute
    real_new_redis_client = local_auth_service._new_redis_client

    async def _counting_execute(*args: Any, **kwargs: Any) -> Any:
        counts.db_execute += 1
        return await real_execute(*args, **kwargs)

    def _counting_new_redis_client() -> redis_asyncio.Redis:
        counts.redis_clients += 1
        return real_new_redis_client()

    monkeypatch.setattr(db, "execute", _counting_execute)
    monkeypatch.setattr(
        local_auth_service, "_new_redis_client", _counting_new_redis_client
    )
    return counts


def _deactivate_as_create_session_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate a deactivation that commits after the step-7 pre-check
    but before the locked revalidation: the module's
    `create_session` reference is wrapped so the conflicting
    active-status update happens, then the real locked revalidation
    runs. A controlled same-transaction database operation stands in
    for the deactivation so that these single-session tests isolate the
    login mapping; the real `deactivate_user()` committed in an
    independent session is covered in
    `tests/test_services/test_deactivate_user_atomicity.py`."""
    real_create = session_service.create_session

    async def _create_after_deactivation(
        db: AsyncSession,
        target: User,
        reason: Any,
        *,
        expected_password_hash: str | None,
    ) -> Any:
        await db.execute(update(User).where(User.id == target.id).values(active=False))
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
        _deactivate_as_create_session_side_effect(monkeypatch)

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
        _reset_password_as_create_session_side_effect(monkeypatch)

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
        _reset_password_as_create_session_side_effect(monkeypatch)

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
        _deactivate_as_create_session_side_effect(monkeypatch)

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
        _deactivate_as_create_session_side_effect(monkeypatch)

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert "login_lockout_triggered" not in _service_log_text(caplog)
        assert await redis_client.get(f"login_attempts:{user.username}") == "1"

    async def test_superseded_credential_below_threshold_logs_no_transition(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The superseded-credential failure emits no lockout transition
        while the admitted counter is below `LOGIN_MAX_ATTEMPTS`, and the
        counter is retained (see local-authentication.md, Lockout
        transition logging)."""
        monkeypatch.setattr(settings, "login_max_attempts", 5)
        user, password = await local_user_factory()
        _reset_password_as_create_session_side_effect(monkeypatch)

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert "login_lockout_triggered" not in _service_log_text(caplog)
        assert await redis_client.get(f"login_attempts:{user.username}") == "1"


# ---------------------------------------------------------------------------
# Login outcome logging (local-authentication.md, Login outcome logging;
# testing-strategy.md, Authentication and Session: Login outcome logging)
# ---------------------------------------------------------------------------

_WRONG_PASSWORD = "definitely-the-wrong-password"
_ANY_PASSWORD = "whatever-password-value"

# The `reason` each admitted-failure scenario must produce.
_SCENARIO_REASONS = {
    "unknown_user": "unknown_user",
    "inactive_user": "ineligible_user",
    "external_user": "ineligible_user",
    "invalid_password": "invalid_password",
    "deactivation_race": "revalidation_failed",
    "password_reset_race": "revalidation_failed",
}


async def _arrange_failure(
    scenario: str,
    monkeypatch: pytest.MonkeyPatch,
    local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    user_factory: Callable[..., Awaitable[User]],
) -> tuple[str, str, str | None]:
    """Arrange a login that the lockout gate admits and that fails as
    `scenario`; return `(username, password, user_id)`, where `user_id`
    is the id the step-5 lookup finds (None for an unknown username).

    An external user has no `password_hash` (`chk_user_auth_exclusive`
    forbids a local user without one)."""
    if scenario == "unknown_user":
        return "nosuchuser", _ANY_PASSWORD, None
    if scenario == "external_user":
        external = await user_factory(external_id=uuid.uuid4(), password_hash=None)
        return external.username, _ANY_PASSWORD, str(external.id)
    user, password = await local_user_factory(active=scenario != "inactive_user")
    if scenario == "invalid_password":
        password = _WRONG_PASSWORD
    elif scenario == "deactivation_race":
        _deactivate_as_create_session_side_effect(monkeypatch)
    elif scenario == "password_reset_race":
        _reset_password_as_create_session_side_effect(monkeypatch)
    return user.username, password, str(user.id)


def _expected_fields(
    reason: str, user_id: str | None, attempt_count: int | None
) -> dict[str, Any]:
    fields: dict[str, Any] = {"reason": reason}
    if user_id is not None:
        fields["user_id"] = user_id
    if attempt_count is not None:
        fields["attempt_count"] = attempt_count
    return fields


@pytest.mark.integration
class TestLoginOutcomeLogging:
    @pytest.mark.parametrize(
        ("username", "password"),
        [
            ("jdoe", "x" * 129),
            ("a" * 65, "some-password"),
            ("   ", "some-password"),
        ],
        ids=["overlong_password", "overlong_username", "whitespace_only_username"],
    )
    async def test_invalid_input_logs_reason_only_without_io(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        username: str,
        password: str,
    ) -> None:
        """Steps 1-3: `invalid_input` with neither `user_id` nor
        `attempt_count`, and no database or Redis operation at all."""
        counts = _count_io(monkeypatch, db_session)

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert [event["event"] for event in _service_events(caplog)] == ["login_failed"]
        assert _login_failed_fields(caplog) == [{"reason": "invalid_input"}]
        assert (counts.db_execute, counts.redis_clients) == (0, 0)

    async def test_blocked_attempt_logs_locked_without_user_id_or_attempt_count(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Step 4 Blocked: `locked` carries no `user_id` even though the
        username exists (no lookup ran), and no `attempt_count`."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory()
        first = await authenticate_local_user(
            db_session, user.username, _WRONG_PASSWORD
        )
        assert isinstance(first, LoginInvalidCredentials)

        with caplog.at_level("INFO"):
            caplog.clear()
            blocked = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(blocked, LoginLocked)
        assert [event["event"] for event in _service_events(caplog)] == ["login_failed"]
        assert _login_failed_fields(caplog) == [{"reason": "locked"}]

    @pytest.mark.parametrize("scenario", list(_SCENARIO_REASONS))
    async def test_admitted_failure_logs_reason_with_lookup_and_counter_fields(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        scenario: str,
    ) -> None:
        """Steps 6, 7, 9, and 11: the documented `reason`, `user_id`
        exactly when the lookup found a user, and the admitted
        `attempt_count`; below the threshold no transition follows."""
        monkeypatch.setattr(settings, "login_max_attempts", 5)
        username, password, user_id = await _arrange_failure(
            scenario, monkeypatch, local_user_factory, user_factory
        )

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert [event["event"] for event in _service_events(caplog)] == ["login_failed"]
        assert _login_failed_fields(caplog) == [
            _expected_fields(_SCENARIO_REASONS[scenario], user_id, 1)
        ]

    @pytest.mark.parametrize("redis_state", ["available", "fail_open"])
    async def test_success_logs_session_created_and_no_login_failed(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        redis_state: str,
    ) -> None:
        user, password = await local_user_factory()
        if redis_state == "fail_open":
            monkeypatch.setattr(
                local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
            )

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, user.username, password)

        assert isinstance(result, LoginSuccess)
        outcomes = [
            event["event"]
            for event in _app_events(caplog)
            if event["event"] in _OUTCOME_EVENTS
        ]
        assert outcomes == ["session_created"]

    @pytest.mark.parametrize(
        "scenario", ["unknown_user", "inactive_user", "invalid_password"]
    )
    async def test_redis_fail_open_failure_omits_attempt_count_and_transition(
        self,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        scenario: str,
    ) -> None:
        """No counter value exists on the fail-open path: `login_failed`
        omits `attempt_count` and no transition is emitted, even with
        `LOGIN_MAX_ATTEMPTS` at 1."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )
        username, password, user_id = await _arrange_failure(
            scenario, monkeypatch, local_user_factory, user_factory
        )

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert [event["event"] for event in _service_events(caplog)] == [
            "login_lockout_redis_unavailable",
            "login_failed",
        ]
        assert _login_failed_fields(caplog) == [
            _expected_fields(_SCENARIO_REASONS[scenario], user_id, None)
        ]

    @pytest.mark.parametrize(
        "scenario",
        [
            "unknown_user",
            "invalid_password",
            "deactivation_race",
            "password_reset_race",
        ],
    )
    async def test_threshold_failure_logs_login_failed_before_transition(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        scenario: str,
    ) -> None:
        """At the threshold `login_failed` precedes
        `login_lockout_triggered`, and both carry the same `user_id` and
        `attempt_count` (below the threshold, see
        `test_admitted_failure_logs_reason_with_lookup_and_counter_fields`)."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        username, password, user_id = await _arrange_failure(
            scenario, monkeypatch, local_user_factory, user_factory
        )

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        events = _service_events(caplog)
        assert [event["event"] for event in events] == [
            "login_failed",
            "login_lockout_triggered",
        ]
        failed, transition = (_call_site_fields(event) for event in events)
        expected = _expected_fields(_SCENARIO_REASONS[scenario], user_id, 1)
        assert failed == expected
        del expected["reason"]
        assert transition == expected

    @pytest.mark.parametrize(
        ("scenario", "verification"),
        [
            ("unknown_user", "verify_dummy_password"),
            ("inactive_user", "verify_dummy_password"),
            ("invalid_password", "verify_password"),
        ],
    )
    async def test_login_failed_is_emitted_after_verification(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        scenario: str,
        verification: str,
    ) -> None:
        """The real or dummy bcrypt verification has completed before
        `login_failed` is emitted, so logging adds no timing difference
        between existing and unknown usernames."""
        username, password, _user_id = await _arrange_failure(
            scenario, monkeypatch, local_user_factory, user_factory
        )
        observed: list[tuple[str, bool]] = []

        def _failure_logged() -> bool:
            return any(
                isinstance(record.msg, dict)
                and record.msg.get("event") == "login_failed"
                for record in caplog.records
            )

        def _verify_password(candidate: str, password_hash: str) -> bool:
            verified = verify_password(candidate, password_hash)
            observed.append(("verify_password", _failure_logged()))
            return verified

        def _verify_dummy_password(candidate: str) -> None:
            verify_dummy_password(candidate)
            observed.append(("verify_dummy_password", _failure_logged()))

        monkeypatch.setattr(local_auth_service, "verify_password", _verify_password)
        monkeypatch.setattr(
            local_auth_service, "verify_dummy_password", _verify_dummy_password
        )

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(db_session, username, password)

        assert isinstance(result, LoginInvalidCredentials)
        assert observed == [(verification, False)]
        assert len(_login_failed_fields(caplog)) == 1

    @pytest.mark.parametrize(
        ("scenario", "expected_db_execute", "expected_redis_clients"),
        [
            ("locked", 0, 1),
            ("unknown_user", 1, 1),
            ("inactive_user", 1, 1),
            ("invalid_password", 1, 1),
        ],
    )
    async def test_failure_logging_adds_no_database_or_redis_operation(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        scenario: str,
        expected_db_execute: int,
        expected_redis_clients: int,
    ) -> None:
        """Each outcome performs exactly the operations of the login flow
        itself — the step-4 gate and the step-5 lookup where reached — so
        logging the failure adds none (`invalid_input`'s zero operations
        are covered by `test_invalid_input_logs_reason_only_without_io`)."""
        if scenario == "locked":
            monkeypatch.setattr(settings, "login_max_attempts", 1)
            username, password, _user_id = await _arrange_failure(
                "invalid_password", monkeypatch, local_user_factory, user_factory
            )
            await authenticate_local_user(db_session, username, password)
        else:
            username, password, _user_id = await _arrange_failure(
                scenario, monkeypatch, local_user_factory, user_factory
            )
        counts = _count_io(monkeypatch, db_session)

        with caplog.at_level("INFO"):
            caplog.clear()
            await authenticate_local_user(db_session, username, password)

        assert len(_login_failed_fields(caplog)) == 1
        assert (counts.db_execute, counts.redis_clients) == (
            expected_db_execute,
            expected_redis_clients,
        )

    async def test_database_error_propagates_without_login_failed(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        async def _failing_execute(*args: Any, **kwargs: Any) -> Any:
            raise SQLAlchemyError("simulated database failure")

        monkeypatch.setattr(db_session, "execute", _failing_execute)

        with caplog.at_level("INFO"), pytest.raises(SQLAlchemyError):
            await authenticate_local_user(db_session, "jdoe", _ANY_PASSWORD)

        assert _login_failed_fields(caplog) == []

    async def test_session_creation_error_propagates_without_login_failed(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user, password = await local_user_factory()

        async def _failing_create_session(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("simulated session creation failure")

        monkeypatch.setattr(
            local_auth_service, "create_session", _failing_create_session
        )

        with (
            caplog.at_level("INFO"),
            pytest.raises(RuntimeError, match="simulated session creation failure"),
        ):
            await authenticate_local_user(db_session, user.username, password)

        assert _login_failed_fields(caplog) == []


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

    async def test_no_pii_on_blocked_invalid_input_ineligible_revalidation_paths(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """`login_failed` never contains the raw or normalized attempted
        username, the password or a value derived from it, a password
        hash, or the lockout key (local-authentication.md, Login outcome
        logging) — across both `invalid_input` forms, a blocked attempt,
        an ineligible user, and a revalidation failure."""
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, password = await local_user_factory(username="piiuser")
        inactive, _ = await local_user_factory(username="piiinactive", active=False)
        revalidated, _ = await local_user_factory(username="piirevalidated")
        raw_username = "  PiiUser  "
        overlong_username = "piiuser" + "q" * 58
        overlong_password = "p" * 129

        with caplog.at_level("DEBUG"):
            await authenticate_local_user(db_session, raw_username, overlong_password)
            await authenticate_local_user(db_session, overlong_username, password)
            # The first admitted failure reaches the threshold; the next
            # attempt for the same normalized username is blocked.
            await authenticate_local_user(db_session, raw_username, _WRONG_PASSWORD)
            await authenticate_local_user(db_session, raw_username, password)
            await authenticate_local_user(db_session, inactive.username, password)
            _deactivate_as_create_session_side_effect(monkeypatch)
            await authenticate_local_user(db_session, revalidated.username, password)

        assert [fields["reason"] for fields in _login_failed_fields(caplog)] == [
            "invalid_input",
            "invalid_input",
            "invalid_password",
            "locked",
            "ineligible_user",
            "revalidation_failed",
        ]
        log_text = "\n".join(
            record.getMessage()
            for record in caplog.records
            if record.name.startswith("app.")
        )
        assert user.password_hash is not None
        prehash = base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()
        forbidden_values = [
            raw_username,
            raw_username.strip(),
            user.username,
            overlong_username,
            inactive.username,
            revalidated.username,
            "login_attempts:",
            password,
            _WRONG_PASSWORD,
            overlong_password,
            prehash,
            hashlib.sha256(password.encode()).hexdigest(),
            user.password_hash,
            user.email,
            inactive.email,
            revalidated.email,
        ]
        for value in forbidden_values:
            assert value not in log_text, f"forbidden value leaked into logs: {value!r}"
        # The records legitimately carry the internal user ids — confirms
        # the assertions above are not vacuously passing.
        assert str(inactive.id) in log_text
        assert str(revalidated.id) in log_text
