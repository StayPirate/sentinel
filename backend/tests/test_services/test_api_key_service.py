"""Tests for the API key lifecycle, query, and audit service
(backend/app/services/api_key_service.py).

See docs/features/identity/api-key-service.md and
docs/features/identity/api-key-management.md for the contract under
test, and docs/features/platform/testing-strategy.md (API Key
Management) for the mandatory scenarios exercised here.

Request/schema-layer concerns (offset/date-only expiry parsing,
status-filter validation, session-only creation enforcement, and CLI
output formatting) belong to the later API/CLI pieces that build on
this service and are out of scope here (see
docs/features/identity/api-key-service.md, Purpose).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import secrets
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import EmulatedDBAPIException, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ApiKeySortField, ApiKeyStatus, SortOrder
from app.core.exceptions import InactiveUserError, UserNotFoundError
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services import api_key_service
from app.services.api_key_service import (
    ApiKeyInvalidExpiryError,
    ApiKeyNameConflictError,
    ApiKeyNameValidationError,
    ApiKeyNotFoundError,
    count_non_revoked_keys,
    create_key,
    derive_api_key_status,
    get_key_by_hash,
    list_all_keys,
    list_user_keys,
    list_user_keys_for_cli,
    revoke_all_user_keys,
    revoke_key,
    update_last_used_at,
)
from app.services.identity_audit_log import IdentityAuditLog
from tests.support.database import rollback_test_scope

# Fictional bcrypt-shaped value — never a real hash (see AGENTS.md Guardrail 23)
_FICTIONAL_PASSWORD_HASH = "$2b$12$" + "a" * 53


def _service_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join only the log records emitted by `app.services.api_key_service`.

    Scoping to this module's own records avoids a false PII-leak
    failure from unrelated propagated SQLAlchemy engine echo records
    (see the identical helper in test_session_service.py).
    """
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.services.api_key_service"
    )


async def _audit_events_for(
    db_session: AsyncSession, target_user_id: uuid.UUID
) -> list[IdentityAuditEvent]:
    rows = await db_session.execute(
        select(IdentityAuditEvent).where(
            IdentityAuditEvent.target_user_id == target_user_id
        )
    )
    return list(rows.scalars().all())


async def _cleanup_committed_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Explicit cleanup for a `User` committed through `db_session_factory`
    in a concurrency test — not covered by the fixture's rollback-on-
    teardown (see docs/features/platform/testing-strategy.md, Database
    Strategy — Concurrency Testing). Deletes in FK-safe order: audit
    events (both actor and target references), then API keys (both
    owner and revoker references), then the user itself.
    """
    await session.execute(
        delete(IdentityAuditEvent).where(
            or_(
                IdentityAuditEvent.target_user_id == user_id,
                IdentityAuditEvent.user_id == user_id,
            )
        )
    )
    await session.execute(
        delete(ApiKey).where(
            or_(ApiKey.user_id == user_id, ApiKey.revoked_by == user_id)
        )
    )
    await session.execute(delete(User).where(User.id == user_id))
    await session.commit()


async def _cancel_pending_task(task: asyncio.Task[Any] | None) -> None:
    """Cancel and consume a task that did not finish before test cleanup."""
    if task is None:
        return
    if task.done():
        if not task.cancelled():
            task.exception()
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def _concurrency_teardown(
    task: asyncio.Task[Any] | None,
    session_a: AsyncSession,
    session_b: AsyncSession,
    cleanup_session: AsyncSession,
    user_id: uuid.UUID | None,
) -> None:
    """Robust teardown for concurrency tests using `db_session_factory`.

    Guarantees that each step is attempted even if a previous one fails:
    cancel the pending task, roll back both sessions (releasing locks),
    then DELETE committed test data.  Errors are not suppressed — the
    first failure propagates after every step has been attempted.
    """
    first_error: Exception | None = None
    for coro in (
        _cancel_pending_task(task),
        session_a.rollback(),
        session_b.rollback(),
    ):
        try:
            await coro
        except Exception as exc:
            if first_error is None:
                first_error = exc

    if user_id is not None:
        try:
            await _cleanup_committed_user(cleanup_session, user_id)
        except Exception as exc:
            if first_error is None:
                first_error = exc

    if first_error is not None:
        raise first_error


class _FakeConstraintError(Exception):
    """A minimal double for asyncpg's `UniqueViolationError`, exposing
    only the `constraint_name` attribute `_is_name_conflict()` reads."""

    def __init__(self, constraint_name: str | None) -> None:
        super().__init__("simulated database error")
        self.constraint_name = constraint_name


# ---------------------------------------------------------------------------
# derive_api_key_status()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDeriveApiKeyStatus:
    def test_revoked_takes_precedence_over_expired(self) -> None:
        now = datetime.now(UTC)
        key = ApiKey(
            revoked_at=now - timedelta(days=1),
            expires_at=now - timedelta(days=2),
        )
        assert derive_api_key_status(key, now) is ApiKeyStatus.REVOKED

    def test_expired_when_expires_at_before_now(self) -> None:
        now = datetime.now(UTC)
        key = ApiKey(expires_at=now - timedelta(seconds=1))
        assert derive_api_key_status(key, now) is ApiKeyStatus.EXPIRED

    def test_expired_at_exact_boundary(self) -> None:
        now = datetime.now(UTC)
        key = ApiKey(expires_at=now)
        assert derive_api_key_status(key, now) is ApiKeyStatus.EXPIRED

    def test_active_when_expires_at_is_none(self) -> None:
        now = datetime.now(UTC)
        key = ApiKey(expires_at=None)
        assert derive_api_key_status(key, now) is ApiKeyStatus.ACTIVE

    def test_active_when_expires_at_in_future(self) -> None:
        now = datetime.now(UTC)
        key = ApiKey(expires_at=now + timedelta(days=1))
        assert derive_api_key_status(key, now) is ApiKeyStatus.ACTIVE


# ---------------------------------------------------------------------------
# _normalize_name() (API Key Name Rule)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNormalizeName:
    def test_trims_and_lowercases(self) -> None:
        assert api_key_service._normalize_name("  CI.Production  ") == "ci.production"

    def test_minimum_length_one_accepted(self) -> None:
        assert api_key_service._normalize_name("a") == "a"

    def test_maximum_length_128_accepted(self) -> None:
        name = "a" * 128
        assert api_key_service._normalize_name(name) == name

    def test_empty_after_trim_rejected(self) -> None:
        with pytest.raises(ApiKeyNameValidationError):
            api_key_service._normalize_name("   ")

    def test_over_128_characters_rejected(self) -> None:
        with pytest.raises(ApiKeyNameValidationError):
            api_key_service._normalize_name("a" * 129)

    @pytest.mark.parametrize("invalid_char", ["@", "/", "!", " ", "\t", "#"])
    def test_rejects_characters_outside_allowed_set(self, invalid_char: str) -> None:
        with pytest.raises(ApiKeyNameValidationError):
            api_key_service._normalize_name(f"ci{invalid_char}prod")

    def test_allows_digits_dot_underscore_hyphen(self) -> None:
        assert api_key_service._normalize_name("ci-prod_01.v2") == "ci-prod_01.v2"


# ---------------------------------------------------------------------------
# _generate_plaintext_key() / _hash_key()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGeneratePlaintextKey:
    def test_format_and_length(self) -> None:
        key = api_key_service._generate_plaintext_key()
        assert key.startswith("stl_ak_")
        assert len(key) == len("stl_ak_") + 32

    def test_suffix_is_alphanumeric(self) -> None:
        key = api_key_service._generate_plaintext_key()
        suffix = key.removeprefix("stl_ak_")
        assert suffix.isalnum()

    def test_uses_csprng_source(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []

        def _fake_choice(alphabet: str) -> str:
            calls.append(alphabet)
            return "a"

        monkeypatch.setattr(secrets, "choice", _fake_choice)
        key = api_key_service._generate_plaintext_key()
        assert key == "stl_ak_" + "a" * 32
        assert len(calls) == 32


@pytest.mark.unit
class TestHashKey:
    def test_matches_hashlib_sha256_hexdigest(self) -> None:
        plaintext = "stl_ak_" + "b" * 32
        assert (
            api_key_service._hash_key(plaintext)
            == hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
        )

    def test_is_lowercase_hex_of_correct_length(self) -> None:
        digest = api_key_service._hash_key("stl_ak_" + "c" * 32)
        assert digest == digest.lower()
        assert len(digest) == 64
        int(digest, 16)  # raises ValueError if not valid hex


# ---------------------------------------------------------------------------
# _is_name_conflict()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsNameConflict:
    def test_matching_constraint_name_is_a_conflict(self) -> None:
        exc = IntegrityError(
            "stmt", {}, _FakeConstraintError("uq_api_key_user_id_name_active")
        )
        assert api_key_service._is_name_conflict(exc) is True

    def test_emulated_wrapper_with_matching_constraint_is_a_conflict(self) -> None:
        """Mirrors the real SQLAlchemy 2.1 + asyncpg shape: `exc.orig` is
        the dialect's emulated DBAPI error, which carries no
        `constraint_name` itself and exposes the raw driver error through
        `driver_exception`."""
        wrapper = EmulatedDBAPIException(
            "emulated dbapi error",
            _FakeConstraintError("uq_api_key_user_id_name_active"),
        )
        exc = IntegrityError("stmt", {}, wrapper)
        assert api_key_service._is_name_conflict(exc) is True

    def test_emulated_wrapper_with_different_constraint_is_not_a_conflict(
        self,
    ) -> None:
        wrapper = EmulatedDBAPIException(
            "emulated dbapi error", _FakeConstraintError("api_key_key_hash_key")
        )
        exc = IntegrityError("stmt", {}, wrapper)
        assert api_key_service._is_name_conflict(exc) is False

    def test_different_constraint_name_is_not_a_conflict(self) -> None:
        exc = IntegrityError(
            "stmt", {}, _FakeConstraintError("chk_api_key_hash_is_sha256_hex")
        )
        assert api_key_service._is_name_conflict(exc) is False

    def test_orig_without_constraint_name_attribute_is_not_a_conflict(self) -> None:
        exc = IntegrityError("stmt", {}, Exception("no constraint_name attribute"))
        assert api_key_service._is_name_conflict(exc) is False


# ---------------------------------------------------------------------------
# create_key()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateKey:
    async def test_creates_key_with_normalized_name_and_correct_fields(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        result = await create_key(db_session, owner.id, "  CI.Production  ", None)

        assert result.api_key.user_id == owner.id
        assert result.api_key.name == "ci.production"
        assert result.api_key.expires_at is None
        assert result.api_key.revoked_at is None
        assert result.plaintext_key.startswith("stl_ak_")
        assert result.api_key.prefix == result.plaintext_key[:12]
        assert (
            result.api_key.key_hash
            == hashlib.sha256(result.plaintext_key.encode("utf-8")).hexdigest()
        )

    async def test_plaintext_is_never_persisted(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        result = await create_key(db_session, owner.id, "ci-key", None)
        row = await db_session.get(ApiKey, result.api_key.id)
        assert row is not None
        assert row.key_hash != result.plaintext_key

    async def test_missing_owner_raises_user_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await create_key(db_session, uuid.uuid4(), "ci-key", None)

    async def test_inactive_owner_raises_inactive_user_error(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory(active=False)
        with pytest.raises(InactiveUserError):
            await create_key(db_session, owner.id, "ci-key", None)

    async def test_invalid_name_raises_name_validation_error(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        with pytest.raises(ApiKeyNameValidationError):
            await create_key(db_session, owner.id, "   ", None)

    async def test_expiry_in_the_past_rejected(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        with pytest.raises(ApiKeyInvalidExpiryError):
            await create_key(
                db_session,
                owner.id,
                "ci-key",
                datetime.now(UTC) - timedelta(seconds=1),
            )

    async def test_expiry_exactly_equal_to_now_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Boundary: `expires_at == now` must be rejected (<=, not <)."""
        owner = await user_factory()
        fixed_now = datetime(2030, 6, 15, 12, 0, 0, tzinfo=UTC)
        monkeypatch.setattr(
            "app.services.api_key_service.datetime",
            type("FakeDatetime", (), {"now": staticmethod(lambda tz: fixed_now)}),
        )
        with pytest.raises(ApiKeyInvalidExpiryError):
            await create_key(db_session, owner.id, "ci-key", fixed_now)

    async def test_expiry_in_future_is_accepted(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        future = datetime.now(UTC) + timedelta(days=30)
        result = await create_key(db_session, owner.id, "ci-key", future)
        assert result.api_key.expires_at == future

    async def test_no_maximum_expiration(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        far_future = datetime.now(UTC) + timedelta(days=365 * 50)
        result = await create_key(db_session, owner.id, "ci-key", far_future)
        assert result.api_key.expires_at == far_future

    async def test_existing_active_key_with_same_normalized_name_raises_conflict(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        await api_key_factory(user_id=owner.id, name="ci-key")
        with pytest.raises(ApiKeyNameConflictError):
            await create_key(db_session, owner.id, "CI-KEY", None)

    async def test_revoked_key_does_not_block_name_reuse(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        await api_key_factory(
            user_id=owner.id, name="ci-key", revoked_at=datetime.now(UTC)
        )
        result = await create_key(db_session, owner.id, "ci-key", None)
        assert result.api_key.name == "ci-key"

    async def test_expired_non_revoked_key_still_blocks_name_reuse(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        """An expired but non-revoked key still reserves its name
        (api-key-management.md). The partial unique index condition is
        `revoked_at IS NULL`, so expiry alone does not free the slot."""
        owner = await user_factory()
        await api_key_factory(
            user_id=owner.id,
            name="ci-key",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        with pytest.raises(ApiKeyNameConflictError):
            await create_key(db_session, owner.id, "ci-key", None)

    async def test_same_normalized_name_different_owners_both_succeed(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """The partial unique index is `(user_id, name)`, not global.
        Two different owners must be able to use the same name."""
        owner_a = await user_factory()
        owner_b = await user_factory()
        result_a = await create_key(db_session, owner_a.id, "shared-name", None)
        result_b = await create_key(db_session, owner_b.id, "shared-name", None)
        assert result_a.api_key.name == "shared-name"
        assert result_b.api_key.name == "shared-name"
        assert result_a.api_key.id != result_b.api_key.id

    async def test_creates_exactly_one_api_key_created_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        result = await create_key(db_session, owner.id, "ci-key", None)

        events = await _audit_events_for(db_session, owner.id)
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "api_key_created"
        assert event.user_id == owner.id
        assert event.target_user_id == owner.id
        assert event.old_value is None
        assert event.new_value == "ci-key"
        assert event.detail == {"key_id": str(result.api_key.id)}

    async def test_no_warning_at_threshold(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        owner = await user_factory()
        with caplog.at_level("WARNING"):
            for i in range(20):
                await create_key(db_session, owner.id, f"key-{i}", None)
        assert "api_key_active_count_exceeded" not in _service_log_text(caplog)

    async def test_warning_above_threshold_has_safe_fields_only(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        owner = await user_factory()
        for i in range(20):
            await create_key(db_session, owner.id, f"key-{i}", None)
        with caplog.at_level("WARNING"):
            await create_key(db_session, owner.id, "key-21", None)

        text = _service_log_text(caplog)
        assert "api_key_active_count_exceeded" in text
        assert str(owner.id) in text
        assert "21" in text
        assert "threshold" in text
        assert "key-21" not in text

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await user_factory()
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        await create_key(db_session, owner.id, "ci-key", None)
        commit_spy.assert_not_called()

    async def test_rollback_removes_key_and_audit_event_together(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        result = await create_key(db_session, owner.id, "ci-key", None)
        key_id = result.api_key.id

        await db_session.rollback()

        assert await db_session.get(ApiKey, key_id) is None
        assert await _audit_events_for(db_session, owner.id) == []

    async def test_audit_failure_rolls_back_the_pending_key_too(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await user_factory()
        owner_id = owner.id

        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated audit failure")

        monkeypatch.setattr(IdentityAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await create_key(db_session, owner_id, "ci-key", None)

        rows = await db_session.execute(
            select(ApiKey).where(ApiKey.user_id == owner_id)
        )
        assert rows.scalars().all() == []

    async def test_unrelated_integrity_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A CHECK-constraint violation (SHA-256 hash format), unrelated
        to the name-uniqueness index, must propagate unchanged rather
        than being mistranslated to `ApiKeyNameConflictError`."""
        owner = await user_factory()
        monkeypatch.setattr(
            api_key_service, "_hash_key", lambda plaintext_key: "not-a-valid-hash"
        )
        with pytest.raises(IntegrityError):
            await create_key(db_session, owner.id, "ci-key", None)

    async def test_precheck_miss_still_translates_via_savepoint(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simulates the race the sequential pre-check is documented not
        to guarantee against: a conflicting active key already exists,
        but `_has_conflicting_name()` (monkeypatched) misses it — so the
        insert genuinely violates the partial unique index, and the
        SAVEPOINT correctly translates that real `IntegrityError` to
        `ApiKeyNameConflictError`.

        Also verifies that unrelated caller work pending in the same
        session survives the translated error — the SAVEPOINT must roll
        back only its own INSERT, preserving everything flushed before
        it (api-key-service.md, Transaction Ownership contract)."""
        owner = await user_factory()
        await api_key_factory(user_id=owner.id, name="ci-key")

        # Unrelated pending work: an extra user added before the
        # conflict — must survive the SAVEPOINT rollback.
        bystander = User(
            username="savepoint-bystander",
            email="savepoint-bystander@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        db_session.add(bystander)
        await db_session.flush()
        bystander_id = bystander.id

        async def _no_conflict(*args: object, **kwargs: object) -> bool:
            return False

        monkeypatch.setattr(api_key_service, "_has_conflicting_name", _no_conflict)

        with pytest.raises(ApiKeyNameConflictError):
            await create_key(db_session, owner.id, "ci-key", None)

        # The session must still be usable and the bystander visible.
        # Force a real SQL round-trip (not an identity-map hit) so a
        # regression that poisons the outer transaction instead of just
        # the SAVEPOINT would fail with PendingRollbackError here.
        result = await db_session.execute(select(User).where(User.id == bystander_id))
        recovered = result.scalar_one()
        assert recovered.username == "savepoint-bystander"

    async def test_two_concurrent_creates_same_owner_and_name_serialize_via_owner_lock(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_id: uuid.UUID | None = None
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-api-key-owner",
                email="conc-api-key-owner@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add(user)
            await session_a.commit()
            user_id = user.id

            # session_a's create_key() call fully completes (flushed, not
            # committed) — its initial owner FOR UPDATE lock remains held by
            # the still-open transaction.
            result_a = await create_key(session_a, user_id, "shared-name", None)

            task_b = asyncio.create_task(
                create_key(session_b, user_id, "shared-name", None)
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            with pytest.raises(ApiKeyNameConflictError):
                await asyncio.wait_for(task_b, timeout=5)
            await session_b.rollback()  # release session_b's own owner-row lock

            keys = await session_a.execute(
                select(ApiKey).where(ApiKey.user_id == user_id)
            )
            assert [key.id for key in keys.scalars().all()] == [result_a.api_key.id]
            assert len(await _audit_events_for(session_a, user_id)) == 1
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_id
            )

    async def test_create_waits_for_deactivation_and_observes_inactive_owner(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        create_session = await db_session_factory()
        deactivation_session = await db_session_factory()
        user_id: uuid.UUID | None = None
        create_task: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-deactivate-owner",
                email="conc-deactivate-owner@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            create_session.add(user)
            await create_session.commit()
            user_id = user.id

            # Keep the active User instance cached in create_session, then
            # change the persisted state while deactivation_session holds the
            # owner lock (FOR NO KEY UPDATE, matching the mode
            # deactivate_user() will use — see api-key-service.md).
            # create_key() must refresh the cached instance after acquiring
            # that lock rather than trusting stale identity-map data.
            assert user.active is True
            locked_user = (
                await deactivation_session.execute(
                    select(User)
                    .where(User.id == user_id)
                    .with_for_update(key_share=True)
                )
            ).scalar_one()
            locked_user.active = False
            await deactivation_session.flush()

            create_task = asyncio.create_task(
                create_key(create_session, user_id, "blocked-key", None)
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(create_task), timeout=0.3)

            await deactivation_session.commit()

            with pytest.raises(InactiveUserError):
                await asyncio.wait_for(create_task, timeout=5)
            await create_session.rollback()

            keys = await deactivation_session.execute(
                select(ApiKey).where(ApiKey.user_id == user_id)
            )
            assert keys.scalars().all() == []
            assert await _audit_events_for(deactivation_session, user_id) == []
        finally:
            await _concurrency_teardown(
                create_task,
                create_session,
                deactivation_session,
                deactivation_session,
                user_id,
            )


# ---------------------------------------------------------------------------
# revoke_key()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRevokeKey:
    async def test_missing_key_raises_not_found(self, db_session: AsyncSession) -> None:
        with pytest.raises(ApiKeyNotFoundError):
            await revoke_key(db_session, uuid.uuid4(), acting_user_id=None)

    async def test_owner_mismatch_raises_not_found(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        other = await user_factory()
        key = await api_key_factory(user_id=owner.id)
        with pytest.raises(ApiKeyNotFoundError):
            await revoke_key(
                db_session, key.id, acting_user_id=other.id, owner_user_id=other.id
            )

    async def test_self_service_revoke_sets_fields_and_returns_owner(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        key = await api_key_factory(user_id=owner.id)
        result = await revoke_key(
            db_session, key.id, acting_user_id=owner.id, owner_user_id=owner.id
        )
        assert result.api_key.revoked_at is not None
        assert result.api_key.revoked_by == owner.id
        assert result.owner.id == owner.id

        # Self-service events must identify the owner as actor
        # (testing-strategy.md, Transactions, audit, and concurrency).
        events = await _audit_events_for(db_session, owner.id)
        assert len(events) == 1
        assert events[0].user_id == owner.id

    async def test_admin_revoke_has_no_owner_restriction(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        admin = await user_factory()
        key = await api_key_factory(user_id=owner.id)
        result = await revoke_key(db_session, key.id, acting_user_id=admin.id)
        assert result.api_key.revoked_by == admin.id
        assert result.owner.id == owner.id

    async def test_system_revoke_sets_null_revoked_by(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        key = await api_key_factory(user_id=owner.id)
        result = await revoke_key(db_session, key.id, acting_user_id=None)
        assert result.api_key.revoked_by is None

        # Audit event must record NULL actor for system-initiated revocation
        events = await _audit_events_for(db_session, owner.id)
        assert len(events) == 1
        assert events[0].user_id is None

    async def test_creates_exactly_one_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        admin = await user_factory()
        key = await api_key_factory(user_id=owner.id, name="ci-prod")
        await revoke_key(db_session, key.id, acting_user_id=admin.id)

        events = await _audit_events_for(db_session, owner.id)
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "api_key_revoked"
        assert event.user_id == admin.id
        assert event.target_user_id == owner.id
        assert event.old_value == "ci-prod"
        assert event.new_value is None
        assert event.detail == {"key_id": str(key.id)}

    async def test_idempotent_second_call_leaves_original_revoker_unchanged(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        admin = await user_factory()
        other_admin = await user_factory()
        key = await api_key_factory(user_id=owner.id)

        first = await revoke_key(db_session, key.id, acting_user_id=admin.id)
        second = await revoke_key(db_session, key.id, acting_user_id=other_admin.id)

        assert second.api_key.revoked_by == admin.id
        assert second.api_key.revoked_at == first.api_key.revoked_at
        assert len(await _audit_events_for(db_session, owner.id)) == 1

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await user_factory()
        key = await api_key_factory(user_id=owner.id)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        await revoke_key(db_session, key.id, acting_user_id=owner.id)
        commit_spy.assert_not_called()

    async def test_rollback_restores_unrevoked_state_and_removes_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        key = await api_key_factory(user_id=owner.id)
        owner_id = owner.id
        key_id = key.id

        async with rollback_test_scope(db_session):
            await revoke_key(db_session, key_id, acting_user_id=owner_id)

        refreshed = await db_session.get(ApiKey, key_id, populate_existing=True)
        assert refreshed is not None
        assert refreshed.revoked_at is None
        assert await _audit_events_for(db_session, owner_id) == []

    async def test_concurrent_revocation_produces_one_mutation_and_one_event(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_id: uuid.UUID | None = None
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-revoke-owner",
                email="conc-revoke-owner@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add(user)
            await session_a.flush()
            key = ApiKey(
                user_id=user.id,
                key_hash="f" * 64,
                prefix="stl_ak_concr",
                name="conc-key",
            )
            session_a.add(key)
            await session_a.flush()
            await session_a.commit()
            user_id = user.id
            key_id = key.id

            # Cache the original unrevoked row in session_b before the winning
            # transaction mutates it. The locking read in revoke_key() must
            # refresh this instance after waiting for session_a's commit.
            cached_key = await session_b.get(ApiKey, key_id)
            assert cached_key is not None
            assert cached_key.revoked_at is None

            # session_a's revoke_key() call fully completes (mutated,
            # flushed, audit event created) without committing — its row
            # lock on the key remains held.
            await revoke_key(session_a, key_id, acting_user_id=None)

            task_b = asyncio.create_task(
                revoke_key(session_b, key_id, acting_user_id=None)
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()
            result_b = await asyncio.wait_for(task_b, timeout=5)
            await session_b.commit()
            assert result_b.api_key.revoked_at is not None

            assert len(await _audit_events_for(session_a, user_id)) == 1
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_id
            )


# ---------------------------------------------------------------------------
# revoke_all_user_keys()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRevokeAllUserKeys:
    async def test_missing_user_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await revoke_all_user_keys(db_session, uuid.uuid4(), acting_user_id=None)

    async def test_revokes_non_revoked_keys_including_expired(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        active_key = await api_key_factory(user_id=owner.id, name="active-key")
        expired_key = await api_key_factory(
            user_id=owner.id,
            name="expired-key",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        already_revoked = await api_key_factory(
            user_id=owner.id, name="already-revoked", revoked_at=datetime.now(UTC)
        )

        count = await revoke_all_user_keys(db_session, owner.id, acting_user_id=None)

        assert count == 2
        await db_session.refresh(active_key)
        await db_session.refresh(expired_key)
        await db_session.refresh(already_revoked)
        assert active_key.revoked_at is not None
        assert expired_key.revoked_at is not None
        # Already-revoked key untouched: revoked_by stays whatever the
        # factory default left it (NULL), not overwritten.
        assert already_revoked.revoked_by is None

    async def test_no_eligible_keys_returns_zero_and_no_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        owner = await user_factory()
        count = await revoke_all_user_keys(db_session, owner.id, acting_user_id=None)
        assert count == 0
        assert await _audit_events_for(db_session, owner.id) == []

    async def test_creates_one_event_per_revoked_key_with_reason(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        admin = await user_factory()
        key1 = await api_key_factory(user_id=owner.id, name="key-1")
        key2 = await api_key_factory(user_id=owner.id, name="key-2")

        await revoke_all_user_keys(db_session, owner.id, acting_user_id=admin.id)

        events = await _audit_events_for(db_session, owner.id)
        assert len(events) == 2
        events_by_key = {e.detail["key_id"]: e for e in events if e.detail}
        for key in (key1, key2):
            event = events_by_key[str(key.id)]
            assert event.event_type == "api_key_revoked"
            assert event.user_id == admin.id
            assert event.target_user_id == owner.id
            assert event.old_value == key.name
            assert event.new_value is None
            assert event.detail is not None
            assert event.detail["reason"] == "user_deactivated"

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        owner = await user_factory()
        await api_key_factory(user_id=owner.id)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        await revoke_all_user_keys(db_session, owner.id, acting_user_id=None)
        commit_spy.assert_not_called()

    async def test_rollback_restores_all_keys_and_removes_all_events(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        key1 = await api_key_factory(user_id=owner.id, name="key-1")
        key2 = await api_key_factory(user_id=owner.id, name="key-2")
        owner_id = owner.id
        key1_id = key1.id
        key2_id = key2.id

        async with rollback_test_scope(db_session):
            await revoke_all_user_keys(db_session, owner_id, acting_user_id=None)

        refreshed1 = await db_session.get(ApiKey, key1_id, populate_existing=True)
        refreshed2 = await db_session.get(ApiKey, key2_id, populate_existing=True)
        assert refreshed1 is not None
        assert refreshed1.revoked_at is None
        assert refreshed2 is not None
        assert refreshed2.revoked_at is None
        assert await _audit_events_for(db_session, owner_id) == []

    async def test_audit_failure_during_bulk_revoke_rolls_back_all_mutations(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failure in the audit loop on the second key must not leave
        the first key revoked — caller rollback must undo all mutations
        and all partial audit events created before the failure."""
        owner = await user_factory()
        key1 = await api_key_factory(user_id=owner.id, name="key-1")
        key2 = await api_key_factory(user_id=owner.id, name="key-2")
        owner_id = owner.id
        key1_id = key1.id
        key2_id = key2.id

        call_count = 0
        _real_log_event = IdentityAuditLog.log_event

        async def _fail_on_second_call(*args: object, **kwargs: object) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise ValueError("simulated audit failure on second key")
            await _real_log_event(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(IdentityAuditLog, "log_event", _fail_on_second_call)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await revoke_all_user_keys(db_session, owner_id, acting_user_id=None)

        refreshed1 = await db_session.get(ApiKey, key1_id, populate_existing=True)
        refreshed2 = await db_session.get(ApiKey, key2_id, populate_existing=True)
        assert refreshed1 is not None
        assert refreshed1.revoked_at is None
        assert refreshed2 is not None
        assert refreshed2.revoked_at is None
        assert await _audit_events_for(db_session, owner_id) == []

    async def test_single_and_bulk_lock_inversion_completes_with_one_revocation(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Regression test for #171: single revocation holds ApiKey FOR
        UPDATE, bulk revocation holds User FOR NO KEY UPDATE and waits
        for ApiKey.  Single then flushes FK-backed revoked_by/audit
        mutations that need FOR KEY SHARE on User.  With FOR UPDATE on
        User this produced SQLSTATE 40P01 (deadlock).  With FOR NO KEY
        UPDATE the FK validation is compatible and both complete.
        """
        single_session = await db_session_factory()
        bulk_session = await db_session_factory()
        verify_session = await db_session_factory()
        user_id: uuid.UUID | None = None
        bulk_task: asyncio.Task[Any] | None = None

        try:
            # -- baseline: one user, one non-revoked key --
            user = User(
                username="conc-inversion-owner",
                email="conc-inversion-owner@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            single_session.add(user)
            await single_session.flush()
            key = ApiKey(
                user_id=user.id,
                key_hash="e" * 64,
                prefix="stl_ak_concb",
                name="shared-key",
            )
            single_session.add(key)
            await single_session.flush()
            await single_session.commit()
            user_id = user.id
            key_id = key.id

            # Step 1: single_session pre-locks the ApiKey row (same lock
            # revoke_key() acquires as its first DB operation).
            await single_session.execute(
                select(ApiKey).where(ApiKey.id == key_id).with_for_update()
            )

            # Step 2: launch bulk revocation; it will acquire the user
            # FOR NO KEY UPDATE lock, then block waiting for the ApiKey
            # FOR UPDATE lock held by single_session.
            bulk_task = asyncio.create_task(
                revoke_all_user_keys(bulk_session, user_id, acting_user_id=None)
            )

            # Give the bulk task enough time to acquire the user lock
            # and begin waiting for the key lock.
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(bulk_task), timeout=0.5)

            # Step 3: while bulk holds the user lock and waits for the
            # key, execute the single revocation in full.  This flushes
            # revoked_by (FK → user) and an IdentityAuditEvent
            # (target_user_id FK → user), both requiring FOR KEY SHARE
            # on User.  With the old FOR UPDATE on User this would
            # deadlock; with FOR NO KEY UPDATE it succeeds.
            await revoke_key(
                single_session,
                key_id,
                acting_user_id=user_id,
                owner_user_id=user_id,
            )

            # Step 4: commit single_session to release the key lock.
            await single_session.commit()

            # Step 5: bulk_task should now complete — the key is already
            # revoked so it finds no eligible rows and returns 0.
            bulk_count = await asyncio.wait_for(bulk_task, timeout=5)
            assert bulk_count == 0
            await bulk_session.commit()

            # -- assertions on committed state --
            key_row = (
                await verify_session.execute(select(ApiKey).where(ApiKey.id == key_id))
            ).scalar_one()
            assert key_row.revoked_at is not None
            assert key_row.revoked_by == user_id

            events = await _audit_events_for(verify_session, user_id)
            assert len(events) == 1
            event = events[0]
            assert event.event_type == "api_key_revoked"
            assert event.user_id == user_id
            assert event.target_user_id == user_id
            assert event.old_value == "shared-key"
            assert event.detail is not None
            assert event.detail["key_id"] == str(key_id)
            # No "reason" key — this was a single revocation, not a
            # bulk deactivation revocation.
            assert "reason" not in event.detail
        finally:
            await _cancel_pending_task(bulk_task)
            for sess in (single_session, bulk_session):
                with contextlib.suppress(Exception):
                    await sess.rollback()
            if user_id is not None:
                await _cleanup_committed_user(verify_session, user_id)


# ---------------------------------------------------------------------------
# get_key_by_hash()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGetKeyByHash:
    async def test_returns_matching_key(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        key = await api_key_factory(key_hash="a" * 64)
        found = await get_key_by_hash(db_session, "a" * 64)
        assert found is not None
        assert found.id == key.id

    async def test_returns_none_when_not_found(self, db_session: AsyncSession) -> None:
        assert await get_key_by_hash(db_session, "b" * 64) is None


# ---------------------------------------------------------------------------
# list_user_keys()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListUserKeys:
    async def test_missing_user_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await list_user_keys(
                db_session,
                uuid.uuid4(),
                status=None,
                page=1,
                per_page=20,
                sort_by=ApiKeySortField.CREATED_AT,
                sort_order=SortOrder.DESC,
            )

    async def test_only_returns_owners_own_keys(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        other = await user_factory()
        mine = await api_key_factory(user_id=owner.id)
        await api_key_factory(user_id=other.id)

        page = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert [item.id for item in page.items] == [mine.id]
        assert page.total == 1

    async def test_status_filter_active_expired_revoked(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        now = datetime.now(UTC)
        active = await api_key_factory(user_id=owner.id, name="active")
        expired = await api_key_factory(
            user_id=owner.id, name="expired", expires_at=now - timedelta(days=1)
        )
        revoked = await api_key_factory(
            user_id=owner.id, name="revoked", revoked_at=now
        )
        # A revoked-and-expired key must classify as revoked, never expired.
        revoked_and_expired = await api_key_factory(
            user_id=owner.id,
            name="revoked-expired",
            expires_at=now - timedelta(days=1),
            revoked_at=now,
        )

        async def _ids(status: ApiKeyStatus) -> set[uuid.UUID]:
            page = await list_user_keys(
                db_session,
                owner.id,
                status=status,
                page=1,
                per_page=20,
                sort_by=ApiKeySortField.CREATED_AT,
                sort_order=SortOrder.DESC,
                now=now,
            )
            return {item.id for item in page.items}

        assert await _ids(ApiKeyStatus.ACTIVE) == {active.id}
        assert await _ids(ApiKeyStatus.EXPIRED) == {expired.id}
        assert await _ids(ApiKeyStatus.REVOKED) == {revoked.id, revoked_and_expired.id}

    async def test_status_filter_boundary_expires_at_equals_now_is_expired(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        """Boundary: a key with `expires_at == now` is EXPIRED, not ACTIVE."""
        owner = await user_factory()
        fixed_now = datetime(2030, 6, 15, 12, 0, 0, tzinfo=UTC)
        boundary_key = await api_key_factory(
            user_id=owner.id, name="boundary", expires_at=fixed_now
        )

        expired_page = await list_user_keys(
            db_session,
            owner.id,
            status=ApiKeyStatus.EXPIRED,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
            now=fixed_now,
        )
        active_page = await list_user_keys(
            db_session,
            owner.id,
            status=ApiKeyStatus.ACTIVE,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
            now=fixed_now,
        )
        assert boundary_key.id in {item.id for item in expired_page.items}
        assert boundary_key.id not in {item.id for item in active_page.items}

    async def test_sorting_created_at_both_directions_with_id_tiebreak(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        same_time = datetime.now(UTC)
        key1 = await api_key_factory(user_id=owner.id, name="k1", created_at=same_time)
        key2 = await api_key_factory(user_id=owner.id, name="k2", created_at=same_time)
        expected_asc = sorted([key1.id, key2.id])
        expected_desc = list(reversed(expected_asc))

        asc_page = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.ASC,
        )
        desc_page = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )

        assert [item.id for item in asc_page.items] == expected_asc
        assert [item.id for item in desc_page.items] == expected_desc

    async def test_last_used_at_nulls_sort_last_both_directions(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        now = datetime.now(UTC)
        used_earlier = await api_key_factory(
            user_id=owner.id, name="used-earlier", last_used_at=now - timedelta(days=2)
        )
        used_later = await api_key_factory(
            user_id=owner.id, name="used-later", last_used_at=now - timedelta(days=1)
        )
        never_used = await api_key_factory(user_id=owner.id, name="never-used")

        asc_page = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.LAST_USED_AT,
            sort_order=SortOrder.ASC,
        )
        desc_page = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.LAST_USED_AT,
            sort_order=SortOrder.DESC,
        )

        assert [item.id for item in asc_page.items] == [
            used_earlier.id,
            used_later.id,
            never_used.id,
        ]
        assert [item.id for item in desc_page.items] == [
            used_later.id,
            used_earlier.id,
            never_used.id,
        ]

    async def test_out_of_range_page_returns_empty_items_with_correct_total(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        await api_key_factory(user_id=owner.id)

        page = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=5,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert page.items == []
        assert page.total == 1

    async def test_uses_supplied_now_snapshot_for_status_filtering(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        fixed_now = datetime.now(UTC)
        key = await api_key_factory(
            user_id=owner.id, expires_at=fixed_now + timedelta(days=1)
        )
        page = await list_user_keys(
            db_session,
            owner.id,
            status=ApiKeyStatus.ACTIVE,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
            now=fixed_now,
        )
        assert [item.id for item in page.items] == [key.id]

    async def test_multi_page_pagination_splits_results_correctly(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        """Real multi-page pagination: 3 keys, per_page=2 — page 1 gets
        2 keys, page 2 gets 1 key, with correct total on both."""
        owner = await user_factory()
        k1 = await api_key_factory(user_id=owner.id, name="k1")
        k2 = await api_key_factory(user_id=owner.id, name="k2")
        k3 = await api_key_factory(user_id=owner.id, name="k3")

        page1 = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=1,
            per_page=2,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.ASC,
        )
        page2 = await list_user_keys(
            db_session,
            owner.id,
            status=None,
            page=2,
            per_page=2,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.ASC,
        )

        assert len(page1.items) == 2
        assert page1.total == 3
        assert len(page2.items) == 1
        assert page2.total == 3
        # No overlap between pages
        page1_ids = {item.id for item in page1.items}
        page2_ids = {item.id for item in page2.items}
        assert page1_ids & page2_ids == set()
        assert page1_ids | page2_ids == {k1.id, k2.id, k3.id}


# ---------------------------------------------------------------------------
# list_all_keys()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListAllKeys:
    async def test_no_owner_filter_returns_all_owners_keys_with_owner_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner1 = await user_factory()
        owner2 = await user_factory()
        key1 = await api_key_factory(user_id=owner1.id)
        key2 = await api_key_factory(user_id=owner2.id)

        page = await list_all_keys(
            db_session,
            owner=None,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert {item.api_key.id for item in page.items} == {key1.id, key2.id}
        for item in page.items:
            assert item.owner.id == item.api_key.user_id

    async def test_owner_filter_by_uuid(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner1 = await user_factory()
        owner2 = await user_factory()
        key1 = await api_key_factory(user_id=owner1.id)
        await api_key_factory(user_id=owner2.id)

        page = await list_all_keys(
            db_session,
            owner=str(owner1.id),
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert [item.api_key.id for item in page.items] == [key1.id]

    async def test_owner_filter_by_exact_case_sensitive_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory(username="preciseowner")
        key = await api_key_factory(user_id=owner.id)

        matching_page = await list_all_keys(
            db_session,
            owner="preciseowner",
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert [item.api_key.id for item in matching_page.items] == [key.id]

        mismatched_case_page = await list_all_keys(
            db_session,
            owner="PreciseOwner",
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert mismatched_case_page.items == []
        assert mismatched_case_page.total == 0

    async def test_unknown_owner_returns_empty_page_not_an_error(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_all_keys(
            db_session,
            owner="no-such-user",
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert page.items == []
        assert page.total == 0

    async def test_unknown_owner_uuid_returns_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        """A syntactically valid UUID that matches no user must return an
        empty page — this is a structurally distinct code path from the
        username-miss case above (`_resolve_owner_id` uses the UUID
        directly as a filter rather than looking up the user first)."""
        page = await list_all_keys(
            db_session,
            owner=str(uuid.uuid4()),
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert page.items == []
        assert page.total == 0

    @pytest.mark.parametrize(
        ("status_filter", "expected_name"),
        [
            (ApiKeyStatus.ACTIVE, "active"),
            (ApiKeyStatus.EXPIRED, "expired"),
            (ApiKeyStatus.REVOKED, "revoked"),
        ],
    )
    async def test_status_filter_applies_across_owners(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        status_filter: ApiKeyStatus,
        expected_name: str,
    ) -> None:
        owner1 = await user_factory()
        owner2 = await user_factory()
        owner3 = await user_factory()
        now = datetime.now(UTC)
        active = await api_key_factory(user_id=owner1.id, name="active")
        expired = await api_key_factory(
            user_id=owner2.id, name="expired", expires_at=now - timedelta(days=1)
        )
        revoked = await api_key_factory(
            user_id=owner3.id, name="revoked", revoked_at=now
        )
        expected_by_name = {
            "active": active,
            "expired": expired,
            "revoked": revoked,
        }

        page = await list_all_keys(
            db_session,
            owner=None,
            status=status_filter,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.DESC,
        )
        assert [item.api_key.id for item in page.items] == [
            expected_by_name[expected_name].id
        ]

    async def test_sorting_and_id_tiebreak_across_owners(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        """Verifies that `list_all_keys()` applies sorting identically to
        `list_user_keys()` — this is re-implemented, not delegated."""
        owner = await user_factory()
        same_time = datetime.now(UTC)
        key1 = await api_key_factory(user_id=owner.id, name="k1", created_at=same_time)
        key2 = await api_key_factory(user_id=owner.id, name="k2", created_at=same_time)
        expected_asc = sorted([key1.id, key2.id])

        asc_page = await list_all_keys(
            db_session,
            owner=None,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.ASC,
        )
        assert [item.api_key.id for item in asc_page.items] == expected_asc

    @pytest.mark.parametrize("sort_order", [SortOrder.ASC, SortOrder.DESC])
    async def test_last_used_at_nulls_sort_last_across_owners(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        sort_order: SortOrder,
    ) -> None:
        """Verifies NULL-last ordering for `last_used_at` in admin list,
        in both sort directions (docs/features/platform/testing-strategy.md,
        API Key Management: "last_used_at NULL-last ordering for
        self-service and admin lists")."""
        owner = await user_factory()
        other = await user_factory()
        now = datetime.now(UTC)
        used = await api_key_factory(
            user_id=owner.id, name="used", last_used_at=now - timedelta(days=1)
        )
        never_used = await api_key_factory(user_id=other.id, name="never-used")

        page = await list_all_keys(
            db_session,
            owner=None,
            status=None,
            page=1,
            per_page=20,
            sort_by=ApiKeySortField.LAST_USED_AT,
            sort_order=sort_order,
        )
        ids = [item.api_key.id for item in page.items]
        assert ids == [used.id, never_used.id]

    async def test_multi_page_pagination(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        """Admin list pagination: 3 keys, per_page=2."""
        owner = await user_factory()
        k1 = await api_key_factory(user_id=owner.id, name="k1")
        k2 = await api_key_factory(user_id=owner.id, name="k2")
        k3 = await api_key_factory(user_id=owner.id, name="k3")

        page1 = await list_all_keys(
            db_session,
            owner=None,
            status=None,
            page=1,
            per_page=2,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.ASC,
        )
        page2 = await list_all_keys(
            db_session,
            owner=None,
            status=None,
            page=2,
            per_page=2,
            sort_by=ApiKeySortField.CREATED_AT,
            sort_order=SortOrder.ASC,
        )

        assert len(page1.items) == 2
        assert page1.total == 3
        assert len(page2.items) == 1
        assert page2.total == 3
        all_ids = {item.api_key.id for item in page1.items} | {
            item.api_key.id for item in page2.items
        }
        assert all_ids == {k1.id, k2.id, k3.id}


# ---------------------------------------------------------------------------
# count_non_revoked_keys()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCountNonRevokedKeys:
    async def test_unknown_user_returns_zero(self, db_session: AsyncSession) -> None:
        assert await count_non_revoked_keys(db_session, uuid.uuid4()) == 0

    async def test_includes_expired_excludes_revoked(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory()
        await api_key_factory(user_id=owner.id, name="active")
        await api_key_factory(
            user_id=owner.id,
            name="expired",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        await api_key_factory(
            user_id=owner.id, name="revoked", revoked_at=datetime.now(UTC)
        )

        assert await count_non_revoked_keys(db_session, owner.id) == 2


# ---------------------------------------------------------------------------
# list_user_keys_for_cli()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListUserKeysForCli:
    async def test_unknown_username_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await list_user_keys_for_cli(db_session, "no-such-user")

    async def test_normalizes_username_before_lookup(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory(username="clitestuser")
        key = await api_key_factory(user_id=owner.id)

        result = await list_user_keys_for_cli(db_session, "  CLITestUser  ")
        assert [item.id for item in result.items] == [key.id]

    async def test_orders_newest_first_via_id_desc(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory(username="cliorderuser")
        same_time = datetime.now(UTC)
        key1 = await api_key_factory(user_id=owner.id, name="k1", created_at=same_time)
        key2 = await api_key_factory(user_id=owner.id, name="k2", created_at=same_time)
        expected = sorted([key1.id, key2.id], reverse=True)

        result = await list_user_keys_for_cli(db_session, "cliorderuser")
        assert [item.id for item in result.items] == expected

    async def test_evaluated_at_is_a_single_snapshot(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        owner = await user_factory(username="clisnapshotuser")
        await api_key_factory(user_id=owner.id)
        fixed_now = datetime.now(UTC)

        result = await list_user_keys_for_cli(
            db_session, "clisnapshotuser", now=fixed_now
        )
        assert result.evaluated_at == fixed_now


# ---------------------------------------------------------------------------
# update_last_used_at()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateLastUsedAt:
    async def test_sets_last_used_at_when_null(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        key = await api_key_factory(last_used_at=None)
        now = datetime.now(UTC)

        changed = await update_last_used_at(db_session, key.id, now)

        assert changed is True
        await db_session.refresh(key)
        assert key.last_used_at == now

    async def test_advances_when_used_at_is_later(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        earlier = datetime.now(UTC) - timedelta(minutes=5)
        key = await api_key_factory(last_used_at=earlier)
        later = datetime.now(UTC)

        changed = await update_last_used_at(db_session, key.id, later)

        assert changed is True
        await db_session.refresh(key)
        assert key.last_used_at == later

    async def test_does_not_move_backward(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        current = datetime.now(UTC)
        key = await api_key_factory(last_used_at=current)
        earlier = current - timedelta(minutes=5)

        changed = await update_last_used_at(db_session, key.id, earlier)

        assert changed is False
        await db_session.refresh(key)
        assert key.last_used_at == current

    async def test_equal_timestamp_does_not_change(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        current = datetime.now(UTC)
        key = await api_key_factory(last_used_at=current)

        changed = await update_last_used_at(db_session, key.id, current)

        assert changed is False

    async def test_missing_key_returns_false(self, db_session: AsyncSession) -> None:
        changed = await update_last_used_at(db_session, uuid.uuid4(), datetime.now(UTC))

        assert changed is False

    async def test_creates_no_identity_audit_event(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        key = await api_key_factory(last_used_at=None)

        await update_last_used_at(db_session, key.id, datetime.now(UTC))

        events = await _audit_events_for(db_session, key.user_id)
        assert events == []

    async def test_does_not_touch_lifecycle_fields(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        key = await api_key_factory(last_used_at=None)

        await update_last_used_at(db_session, key.id, datetime.now(UTC))

        await db_session.refresh(key)
        assert key.revoked_at is None
        assert key.revoked_by is None

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        key = await api_key_factory(last_used_at=None)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await update_last_used_at(db_session, key.id, datetime.now(UTC))

        commit_spy.assert_not_called()

    async def test_rollback_removes_last_used_at_update(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        key = await api_key_factory(last_used_at=None)
        key_id = key.id

        async with rollback_test_scope(db_session):
            await update_last_used_at(db_session, key_id, datetime.now(UTC))

        refreshed = await db_session.get(ApiKey, key_id, populate_existing=True)
        assert refreshed is not None
        assert refreshed.last_used_at is None
