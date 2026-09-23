"""Tests for user identifier resolution, lifecycle, and role queries
(backend/app/services/user_service.py).

See docs/features/identity/user-service.md (`create_user()`,
`update_user()`, `reactivate_user()`, `reset_password()`,
`unlock_user()`, `resolve_user_identifier()`) and
docs/features/identity/rbac.md (`require_capability()` Dependency) for the
contract under test, and docs/features/platform/testing-strategy.md (User
Lifecycle and Management) for the mandatory scenarios exercised here.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from email_validator import validate_email
from redis.exceptions import RedisError
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    IdentityAuditEventType,
    Role,
    SortOrder,
    UserSortField,
    UserType,
)
from app.core.exceptions import UserNotFoundError
from app.core.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordValidationError,
    verify_password,
)
from app.core.permissions import role_to_wire
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session
from app.models.user import User
from app.models.user_role import UserRole
from app.services import local_auth_service, user_service
from app.services.identity_audit_log import IdentityAuditLog
from app.services.session_service import purge_session_cache
from app.services.user_service import (
    EmailFormatError,
    ExternalUserFieldReadOnlyError,
    ExternalUserPasswordError,
    ExternalUserStatusReadOnlyError,
    UserConflictError,
    UsernameFormatError,
    create_user,
    get_user,
    get_user_by_id,
    get_user_roles,
    list_users,
    reactivate_user,
    reset_password,
    resolve_user_identifier,
    unlock_user,
    update_user,
)
from tests.support.database import rollback_test_scope

# Fictional bcrypt-shaped value — never a real hash (see AGENTS.md Guardrail 23)
_FICTIONAL_PASSWORD_HASH = "$2b$12$" + "a" * 53
_VALID_PASSWORD = "a-valid-password-16"


class _FailingRedisClient:
    """A Redis client double whose relevant methods always raise
    `RedisError` — used to simulate a deterministic Redis outage for
    `clear_login_attempts()` without touching the shared Redis test
    infrastructure (mirrors the double in `test_local_auth_service.py`,
    docs/features/platform/testing-strategy.md, Redis Strategy)."""

    async def delete(self, key: str) -> None:
        raise RedisError("simulated outage")

    async def aclose(self) -> None:
        return None


def _service_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join only the log records emitted by `app.services.user_service`."""
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.services.user_service"
    )


def _hash(user: User) -> str:
    """Narrow `User.password_hash` (`str | None`) to `str` for callers that
    already know the row is a local user with a stored hash."""
    assert user.password_hash is not None
    return user.password_hash


def _identity_related_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join log records emitted by every module composed into
    `reset_password()`/`unlock_user()` — `user_service` itself plus the
    delegated `session_service` (`sessions_invalidated`) and
    `local_auth_service` (`login_lockout_clear_failed`) modules — so PII/
    secret-safety assertions cover the whole composed log surface, not
    just this module's own log records."""
    relevant_loggers = {
        "app.services.user_service",
        "app.services.session_service",
        "app.services.local_auth_service",
    }
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name in relevant_loggers
    )


async def _audit_events_for(
    db_session: AsyncSession, target_user_id: uuid.UUID
) -> list[IdentityAuditEvent]:
    rows = await db_session.execute(
        select(IdentityAuditEvent)
        .where(IdentityAuditEvent.target_user_id == target_user_id)
        .order_by(IdentityAuditEvent.created_at, IdentityAuditEvent.id)
    )
    return list(rows.scalars().all())


async def _cleanup_committed_users(
    session: AsyncSession, user_ids: list[uuid.UUID]
) -> None:
    """Explicit cleanup for `User` rows committed through
    `db_session_factory` in a concurrency test — not covered by the
    fixture's rollback-on-teardown (see
    docs/features/platform/testing-strategy.md, Database Strategy —
    Concurrency Testing). Deletes in FK-safe order: audit events (both
    actor and target references), then roles, then the users themselves.
    """
    await session.execute(
        delete(IdentityAuditEvent).where(
            or_(
                IdentityAuditEvent.target_user_id.in_(user_ids),
                IdentityAuditEvent.user_id.in_(user_ids),
            )
        )
    )
    await session.execute(delete(UserRole).where(UserRole.user_id.in_(user_ids)))
    await session.execute(delete(User).where(User.id.in_(user_ids)))
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
    user_ids: list[uuid.UUID],
) -> None:
    """Robust teardown for concurrency tests using `db_session_factory`.

    Guarantees that each step is attempted even if a previous one fails:
    cancel the pending task, roll back both sessions (releasing locks),
    then DELETE committed test data. Errors are not suppressed — the first
    failure propagates after every step has been attempted.
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

    if user_ids:
        try:
            await _cleanup_committed_users(cleanup_session, user_ids)
        except Exception as exc:
            if first_error is None:
                first_error = exc

    if first_error is not None:
        raise first_error


class _FakeConstraintError(Exception):
    """A minimal double for asyncpg's `UniqueViolationError`, exposing
    only the `constraint_name` attribute `_conflict_field()` reads."""

    def __init__(self, constraint_name: str | None) -> None:
        super().__init__("simulated database error")
        self.constraint_name = constraint_name


# ---------------------------------------------------------------------------
# _normalize_username()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNormalizeUsername:
    def test_trims_and_lowercases(self) -> None:
        assert user_service._normalize_username("  JDoe  ") == "jdoe"

    def test_minimum_length_one_accepted(self) -> None:
        assert user_service._normalize_username("a") == "a"

    def test_maximum_length_64_accepted(self) -> None:
        name = "a" * 64
        assert user_service._normalize_username(name) == name

    def test_over_64_characters_rejected(self) -> None:
        with pytest.raises(UsernameFormatError):
            user_service._normalize_username("a" * 65)

    def test_empty_after_trim_rejected(self) -> None:
        with pytest.raises(UsernameFormatError):
            user_service._normalize_username("   ")

    def test_must_start_with_a_letter(self) -> None:
        with pytest.raises(UsernameFormatError):
            user_service._normalize_username("1jdoe")

    def test_allows_digits_dot_underscore_hyphen(self) -> None:
        assert user_service._normalize_username("j.doe-01_x") == "j.doe-01_x"

    @pytest.mark.parametrize("invalid_char", ["@", "/", "!", " ", "\t", "#"])
    def test_rejects_characters_outside_allowed_set(self, invalid_char: str) -> None:
        with pytest.raises(UsernameFormatError):
            user_service._normalize_username(f"jdoe{invalid_char}x")

    def test_error_message_never_includes_the_value(self) -> None:
        with pytest.raises(UsernameFormatError) as exc_info:
            user_service._normalize_username("1-invalid-secret-username")
        assert "1-invalid-secret-username" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# _normalize_and_validate_email()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNormalizeAndValidateEmail:
    def test_trims_and_lowercases_entire_address(self) -> None:
        """The local part is also lowercased — unlike `email-validator`'s
        own `.normalized`, which lowercases only the domain (see
        docs/features/identity/user-service.md, `create_user()` step 2)."""
        assert (
            user_service._normalize_and_validate_email("  John.DOE@Example.COM  ")
            == "john.doe@example.com"
        )

    def test_accepts_plus_tag_addressing(self) -> None:
        assert (
            user_service._normalize_and_validate_email("user+tag@example.com")
            == "user+tag@example.com"
        )

    def test_missing_at_sign_rejected(self) -> None:
        with pytest.raises(EmailFormatError):
            user_service._normalize_and_validate_email("not-an-email")

    def test_missing_domain_rejected(self) -> None:
        with pytest.raises(EmailFormatError):
            user_service._normalize_and_validate_email("user@")

    def test_missing_tld_rejected(self) -> None:
        with pytest.raises(EmailFormatError):
            user_service._normalize_and_validate_email("user@localhost")

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(EmailFormatError):
            user_service._normalize_and_validate_email("")

    def test_error_message_never_includes_the_value(self) -> None:
        with pytest.raises(EmailFormatError) as exc_info:
            user_service._normalize_and_validate_email("secret-invalid-value")
        assert "secret-invalid-value" not in str(exc_info.value)

    def test_performs_no_deliverability_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`check_deliverability=False` must be passed explicitly — a DNS
        lookup would be network I/O inside a pure validation helper."""
        calls: list[dict[str, Any]] = []

        def _spy(value: str, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return validate_email(value, **kwargs)

        monkeypatch.setattr(user_service, "validate_email", _spy)
        user_service._normalize_and_validate_email("user@example.com")
        assert calls == [{"check_deliverability": False}]


# ---------------------------------------------------------------------------
# _conflict_field()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConflictField:
    @pytest.mark.parametrize(
        ("constraint_name", "expected_field"),
        [
            ("user_username_key", "username"),
            ("user_email_key", "email"),
            ("user_external_id_key", "external_id"),
        ],
    )
    def test_matching_constraint_name_is_a_conflict(
        self, constraint_name: str, expected_field: str
    ) -> None:
        exc = IntegrityError("stmt", {}, _FakeConstraintError(constraint_name))
        assert user_service._conflict_field(exc) == expected_field

    def test_matching_constraint_name_on_cause_is_a_conflict(self) -> None:
        wrapped = Exception("wrapped")
        wrapped.__cause__ = _FakeConstraintError("user_email_key")
        exc = IntegrityError("stmt", {}, wrapped)
        assert user_service._conflict_field(exc) == "email"

    def test_different_constraint_name_is_not_a_conflict(self) -> None:
        exc = IntegrityError("stmt", {}, _FakeConstraintError("user_manager_id_fkey"))
        assert user_service._conflict_field(exc) is None

    def test_orig_without_constraint_name_attribute_is_not_a_conflict(self) -> None:
        exc = IntegrityError("stmt", {}, Exception("plain"))
        assert user_service._conflict_field(exc) is None


# ---------------------------------------------------------------------------
# create_user()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateUser:
    async def test_creates_local_user_with_normalized_fields(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="  JDoe  ",
            email="  John.DOE@Example.COM  ",
            full_name="John Doe",
            password=_VALID_PASSWORD,
            acting_user_id=None,
        )

        assert user.username == "jdoe"
        assert user.email == "john.doe@example.com"
        assert user.full_name == "John Doe"
        assert user.active is True
        assert user.external_id is None
        assert user.synced_at is None
        assert user.password_hash is not None
        assert verify_password(_VALID_PASSWORD, user.password_hash) is True

    async def test_active_defaults_to_true_and_can_be_overridden(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="inactive-new",
            email="inactive-new@example.com",
            password=_VALID_PASSWORD,
            active=False,
            acting_user_id=None,
        )
        assert user.active is False

    async def test_creates_external_user_without_password(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        manager = await user_factory()
        external_id = uuid.uuid4()

        user = await create_user(
            db_session,
            username="ext-user",
            email="ext-user@example.com",
            external_id=external_id,
            manager_id=manager.id,
            acting_user_id=None,
        )

        assert user.external_id == external_id
        assert user.password_hash is None
        assert user.manager_id == manager.id
        assert user.synced_at is not None

    async def test_invalid_username_format_raises(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UsernameFormatError):
            await create_user(
                db_session,
                username="1-invalid",
                email="valid@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )

    async def test_invalid_email_format_raises(self, db_session: AsyncSession) -> None:
        with pytest.raises(EmailFormatError):
            await create_user(
                db_session,
                username="valid-user",
                email="not-an-email",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )

    async def test_external_id_and_password_both_provided_raises(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(ExternalUserPasswordError):
            await create_user(
                db_session,
                username="ext-with-pw",
                email="ext-with-pw@example.com",
                external_id=uuid.uuid4(),
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )

    async def test_local_user_without_password_raises(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(PasswordValidationError):
            await create_user(
                db_session,
                username="local-no-pw",
                email="local-no-pw@example.com",
                acting_user_id=None,
            )

    async def test_manager_id_on_local_user_raises(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(ExternalUserFieldReadOnlyError):
            await create_user(
                db_session,
                username="local-with-manager",
                email="local-with-manager@example.com",
                password=_VALID_PASSWORD,
                manager_id=uuid.uuid4(),
                acting_user_id=None,
            )

    async def test_duplicate_username_raises_conflict_with_field(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="taken-user")

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="taken-user",
                email="different@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )
        assert exc_info.value.conflict_field == "username"

    async def test_duplicate_email_raises_conflict_with_field(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(email="taken@example.com")

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="different-user",
                email="taken@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )
        assert exc_info.value.conflict_field == "email"

    async def test_duplicate_external_id_raises_conflict_with_field(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        shared_external_id = uuid.uuid4()
        await user_factory(external_id=shared_external_id)

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="different-ext-user",
                email="different-ext@example.com",
                external_id=shared_external_id,
                acting_user_id=None,
            )
        assert exc_info.value.conflict_field == "external_id"

    async def test_conflict_error_message_never_includes_the_value(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(email="secret-taken@example.com")

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="another-user",
                email="secret-taken@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )
        assert "secret-taken@example.com" not in str(exc_info.value)

    async def test_uniqueness_guard_precedes_password_length_guard(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """A duplicate username with an also-invalid password raises the
        conflict, not the password error — matching the documented guard
        order (uniqueness before password length validation)."""
        await user_factory(username="ordering-conflict")

        with pytest.raises(UserConflictError):
            await create_user(
                db_session,
                username="ordering-conflict",
                email="ordering@example.com",
                password="short",
                acting_user_id=None,
            )

    @pytest.mark.parametrize(
        "password",
        ["a" * (MIN_PASSWORD_LENGTH - 1), "a" * (MAX_PASSWORD_LENGTH + 1)],
    )
    async def test_password_outside_length_policy_raises(
        self, db_session: AsyncSession, password: str
    ) -> None:
        with pytest.raises(PasswordValidationError):
            await create_user(
                db_session,
                username="bad-password-user",
                email="bad-password@example.com",
                password=password,
                acting_user_id=None,
            )

    async def test_deduplicates_identical_role_pairs(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="role-dedupe",
            email="role-dedupe@example.com",
            password=_VALID_PASSWORD,
            roles=[
                (Role.ADMIN, "_manual"),
                (Role.ADMIN, "_manual"),
                (Role.VULNERABILITY_ANALYST, "ext-group"),
            ],
            acting_user_id=None,
        )

        rows = await db_session.execute(
            select(UserRole).where(UserRole.user_id == user.id)
        )
        pairs = {(role_row.role, role_row.group_name) for role_row in rows.scalars()}
        assert pairs == {
            (Role.ADMIN.value, "_manual"),
            (Role.VULNERABILITY_ANALYST.value, "ext-group"),
        }

    async def test_role_assigned_by_is_acting_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        admin = await user_factory()

        user = await create_user(
            db_session,
            username="role-assigned-by",
            email="role-assigned-by@example.com",
            password=_VALID_PASSWORD,
            roles=[(Role.ADMIN, "_manual")],
            acting_user_id=admin.id,
        )

        role_row = (
            await db_session.execute(
                select(UserRole).where(UserRole.user_id == user.id)
            )
        ).scalar_one()
        assert role_row.assigned_by == admin.id

    async def test_creates_exactly_one_user_created_and_one_role_added_per_role(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="audit-count",
            email="audit-count@example.com",
            password=_VALID_PASSWORD,
            roles=[(Role.ADMIN, "_manual"), (Role.VULNERABILITY_ANALYST, "ext-group")],
            acting_user_id=None,
        )

        events = await _audit_events_for(db_session, user.id)
        event_types = [event.event_type for event in events]
        assert event_types.count(IdentityAuditEventType.ROLE_ADDED.value) == 2
        assert event_types.count(IdentityAuditEventType.USER_CREATED.value) == 1
        assert len(events) == 3

    async def test_role_added_detail_is_none_for_manual_role(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="manual-role-detail",
            email="manual-role-detail@example.com",
            password=_VALID_PASSWORD,
            roles=[(Role.ADMIN, "_manual")],
            acting_user_id=None,
        )

        events = await _audit_events_for(db_session, user.id)
        role_event = next(
            e for e in events if e.event_type == IdentityAuditEventType.ROLE_ADDED.value
        )
        assert role_event.detail is None
        assert role_event.new_value == role_to_wire(Role.ADMIN)
        assert role_event.old_value is None
        assert role_event.target_user_id == user.id
        assert role_event.user_id is None

    async def test_role_added_detail_includes_source_and_mapping_for_external_role(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="ext-role-detail",
            email="ext-role-detail@example.com",
            password=_VALID_PASSWORD,
            roles=[(Role.VULNERABILITY_ANALYST, "SecurityTeam")],
            acting_user_id=None,
        )

        events = await _audit_events_for(db_session, user.id)
        role_event = next(
            e for e in events if e.event_type == IdentityAuditEventType.ROLE_ADDED.value
        )
        assert role_event.detail == {
            "source": "external_sync",
            "mapping": "SecurityTeam",
        }
        assert role_event.old_value is None
        assert role_event.target_user_id == user.id
        assert role_event.user_id is None

    async def test_role_added_actor_is_the_authenticated_acting_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        """The `role_added` event's actor (`user_id`) is the admin who
        created the user, not just the `user_created` event's actor --
        both events must carry the same acting-user attribution."""
        admin = await user_factory()

        user = await create_user(
            db_session,
            username="role-added-actor",
            email="role-added-actor@example.com",
            password=_VALID_PASSWORD,
            roles=[(Role.ADMIN, "_manual")],
            acting_user_id=admin.id,
        )

        events = await _audit_events_for(db_session, user.id)
        role_event = next(
            e for e in events if e.event_type == IdentityAuditEventType.ROLE_ADDED.value
        )
        assert role_event.user_id == admin.id
        assert role_event.target_user_id == user.id

    async def test_user_created_detail_is_none_for_local_creation(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="local-created-detail",
            email="local-created-detail@example.com",
            password=_VALID_PASSWORD,
            acting_user_id=None,
        )
        event = (await _audit_events_for(db_session, user.id))[0]
        assert event.detail is None
        assert event.new_value == "local-created-detail"

    async def test_user_created_detail_includes_source_for_external_creation(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="ext-created-detail",
            email="ext-created-detail@example.com",
            external_id=uuid.uuid4(),
            acting_user_id=None,
        )
        event = (await _audit_events_for(db_session, user.id))[0]
        assert event.detail == {"source": "external_sync"}

    async def test_user_created_actor_is_the_authenticated_acting_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        """A real, authenticated admin creates a local user: the resulting
        `user_created` event's actor (`user_id`) must be the admin, not
        `None` -- proving the actor is threaded through correctly for a
        human-initiated creation, not just the system-caller (`None`) path
        exercised by every other creation test in this class."""
        admin = await user_factory()

        user = await create_user(
            db_session,
            username="actor-created",
            email="actor-created@example.com",
            password=_VALID_PASSWORD,
            acting_user_id=admin.id,
        )

        event = (await _audit_events_for(db_session, user.id))[0]
        assert event.event_type == IdentityAuditEventType.USER_CREATED.value
        assert event.user_id == admin.id
        assert event.target_user_id == user.id

    async def test_returns_user_with_roles_and_manager_eagerly_loaded(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        manager = await user_factory()
        user = await create_user(
            db_session,
            username="eager-load",
            email="eager-load@example.com",
            external_id=uuid.uuid4(),
            manager_id=manager.id,
            roles=[(Role.ADMIN, "_manual")],
            acting_user_id=None,
        )

        # Direct attribute access — an unloaded relationship would raise
        # MissingGreenlet in this async context if accessed synchronously.
        assert len(user.roles) == 1
        assert user.manager is not None
        assert user.manager.id == manager.id

    async def test_flushes_without_commit(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        await create_user(
            db_session,
            username="no-commit-user",
            email="no-commit-user@example.com",
            password=_VALID_PASSWORD,
            acting_user_id=None,
        )
        commit_spy.assert_not_called()

    async def test_rollback_removes_user_role_and_audit_events_together(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="rollback-user",
            email="rollback-user@example.com",
            password=_VALID_PASSWORD,
            roles=[(Role.ADMIN, "_manual")],
            acting_user_id=None,
        )
        user_id = user.id

        await db_session.rollback()

        assert await db_session.get(User, user_id) is None
        rows = await db_session.execute(
            select(UserRole).where(UserRole.user_id == user_id)
        )
        assert rows.scalars().all() == []
        assert await _audit_events_for(db_session, user_id) == []

    async def test_audit_failure_rolls_back_the_pending_user_too(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated audit failure")

        monkeypatch.setattr(IdentityAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await create_user(
                    db_session,
                    username="audit-fail-user",
                    email="audit-fail-user@example.com",
                    password=_VALID_PASSWORD,
                    acting_user_id=None,
                )

        rows = await db_session.execute(
            select(User).where(User.username == "audit-fail-user")
        )
        assert rows.scalars().all() == []

    async def test_unrelated_integrity_error_propagates_unchanged(
        self, db_session: AsyncSession
    ) -> None:
        """A foreign-key violation on `manager_id` (unrelated to the three
        UNIQUE constraints) must propagate unchanged rather than being
        mistranslated to `UserConflictError`."""
        with pytest.raises(IntegrityError):
            await create_user(
                db_session,
                username="fk-violation-user",
                email="fk-violation-user@example.com",
                external_id=uuid.uuid4(),
                manager_id=uuid.uuid4(),
                acting_user_id=None,
            )

    async def test_precheck_miss_still_translates_email_conflict_via_savepoint(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simulates the race the sequential pre-check is documented not to
        guarantee against: a conflicting email already exists, but
        `_email_taken()` (monkeypatched) misses it — so the insert
        genuinely violates the UNIQUE constraint, and the SAVEPOINT
        correctly translates that real `IntegrityError` to
        `UserConflictError`. Also verifies unrelated pending work survives
        the SAVEPOINT rollback."""
        await user_factory(email="precheck-miss@example.com")

        bystander = User(
            username="precheck-bystander",
            email="precheck-bystander@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        db_session.add(bystander)
        await db_session.flush()
        bystander_id = bystander.id

        async def _no_conflict(*args: object, **kwargs: object) -> bool:
            return False

        monkeypatch.setattr(user_service, "_email_taken", _no_conflict)

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="precheck-miss-user",
                email="precheck-miss@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )
        assert exc_info.value.conflict_field == "email"

        result = await db_session.execute(select(User).where(User.id == bystander_id))
        recovered = result.scalar_one()
        assert recovered.username == "precheck-bystander"

    async def test_precheck_miss_still_translates_external_id_conflict(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        shared_external_id = uuid.uuid4()
        await user_factory(external_id=shared_external_id)

        async def _no_conflict(*args: object, **kwargs: object) -> bool:
            return False

        monkeypatch.setattr(user_service, "_external_id_taken", _no_conflict)

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="precheck-miss-ext-user",
                email="precheck-miss-ext@example.com",
                external_id=shared_external_id,
                acting_user_id=None,
            )
        assert exc_info.value.conflict_field == "external_id"

    async def test_two_concurrent_creates_same_username_serialize_via_unique_index(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user_a = await create_user(
                session_a,
                username="conc-same-username",
                email="conc-same-username-a@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )

            task_b = asyncio.create_task(
                create_user(
                    session_b,
                    username="conc-same-username",
                    email="conc-same-username-b@example.com",
                    password=_VALID_PASSWORD,
                    acting_user_id=None,
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()
            user_ids.append(user_a.id)

            with pytest.raises(UserConflictError) as exc_info:
                await asyncio.wait_for(task_b, timeout=5)
            assert exc_info.value.conflict_field == "username"
            await session_b.rollback()

            rows = await session_a.execute(
                select(User).where(User.username == "conc-same-username")
            )
            assert [row.id for row in rows.scalars().all()] == [user_a.id]
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )

    async def test_two_concurrent_creates_same_email_serialize_via_unique_index(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user_a = await create_user(
                session_a,
                username="conc-same-email-a",
                email="conc-same-email@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )

            task_b = asyncio.create_task(
                create_user(
                    session_b,
                    username="conc-same-email-b",
                    email="conc-same-email@example.com",
                    password=_VALID_PASSWORD,
                    acting_user_id=None,
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()
            user_ids.append(user_a.id)

            with pytest.raises(UserConflictError) as exc_info:
                await asyncio.wait_for(task_b, timeout=5)
            assert exc_info.value.conflict_field == "email"
            await session_b.rollback()

            rows = await session_a.execute(
                select(User).where(User.email == "conc-same-email@example.com")
            )
            assert [row.id for row in rows.scalars().all()] == [user_a.id]
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )


# ---------------------------------------------------------------------------
# update_user()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateUser:
    async def test_missing_user_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await update_user(
                db_session, uuid.uuid4(), acting_user_id=None, full_name="New Name"
            )

    async def test_human_caller_on_external_user_raises(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4())
        admin = await user_factory()

        with pytest.raises(ExternalUserFieldReadOnlyError):
            await update_user(
                db_session,
                target.id,
                acting_user_id=admin.id,
                full_name="New Name",
            )

    async def test_manager_id_on_local_user_raises(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory()
        with pytest.raises(ExternalUserFieldReadOnlyError):
            await update_user(
                db_session, target.id, acting_user_id=None, manager_id=uuid.uuid4()
            )

    async def test_synced_at_on_local_user_raises(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory()
        with pytest.raises(ExternalUserFieldReadOnlyError):
            await update_user(
                db_session,
                target.id,
                acting_user_id=None,
                synced_at=datetime.now(UTC),
            )

    async def test_updates_username_and_creates_audit_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(username="old-name")

        result = await update_user(
            db_session, target.id, acting_user_id=None, username="new-name"
        )

        assert result.changed_fields == ["username"]
        assert result.user.username == "new-name"
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == IdentityAuditEventType.USERNAME_CHANGED.value
        assert events[0].old_value == "old-name"
        assert events[0].new_value == "new-name"

    async def test_username_changed_actor_is_the_authenticated_acting_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        """A real, authenticated admin renames a local user: the resulting
        `username_changed` event's actor (`user_id`) must be the admin, not
        `None` -- proving the actor is threaded through correctly for a
        human-initiated update, not just the system-caller (`None`) path
        exercised by every other update test in this class."""
        admin = await user_factory()
        target = await user_factory(username="pre-actor-rename")

        await update_user(
            db_session, target.id, acting_user_id=admin.id, username="post-actor-rename"
        )

        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].user_id == admin.id
        assert events[0].target_user_id == target.id

    async def test_username_is_normalized_before_comparison(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(username="already-set")

        result = await update_user(
            db_session, target.id, acting_user_id=None, username="  Already-Set  "
        )

        assert result.changed_fields == []
        assert result.user.username == "already-set"
        assert await _audit_events_for(db_session, target.id) == []

    async def test_invalid_username_format_raises(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory()
        with pytest.raises(UsernameFormatError):
            await update_user(
                db_session, target.id, acting_user_id=None, username="1-invalid"
            )

    async def test_duplicate_username_raises_conflict(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        await user_factory(username="already-taken")
        target = await user_factory(username="other-user")

        with pytest.raises(UserConflictError) as exc_info:
            await update_user(
                db_session, target.id, acting_user_id=None, username="already-taken"
            )
        assert exc_info.value.conflict_field == "username"

    async def test_updates_email_fully_lowercased(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory()

        result = await update_user(
            db_session,
            target.id,
            acting_user_id=None,
            email="  New.EMAIL@Example.COM  ",
        )

        assert result.changed_fields == ["email"]
        assert result.user.email == "new.email@example.com"

    async def test_updates_email_and_creates_audit_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(email="old@example.com")

        result = await update_user(
            db_session, target.id, acting_user_id=None, email="new@example.com"
        )

        assert result.changed_fields == ["email"]
        assert result.user.email == "new@example.com"
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == IdentityAuditEventType.EMAIL_CHANGED.value
        assert events[0].old_value == "old@example.com"
        assert events[0].new_value == "new@example.com"
        assert events[0].target_user_id == target.id
        assert events[0].user_id is None
        assert events[0].detail is None

    async def test_email_changed_actor_is_the_authenticated_acting_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(email="old@example.com")
        admin = await user_factory()

        await update_user(
            db_session,
            target.id,
            acting_user_id=admin.id,
            email="new@example.com",
        )

        events = await _audit_events_for(db_session, target.id)
        assert events[0].user_id == admin.id
        assert events[0].target_user_id == target.id

    async def test_email_changed_detail_includes_source_for_external_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(
            external_id=uuid.uuid4(), email="ext-old@example.com"
        )

        await update_user(
            db_session, target.id, acting_user_id=None, email="ext-new@example.com"
        )

        events = await _audit_events_for(db_session, target.id)
        assert events[0].detail == {"source": "external_sync"}

    async def test_email_no_op_when_normalized_value_already_stored(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(email="already@example.com")

        result = await update_user(
            db_session, target.id, acting_user_id=None, email="Already@Example.com"
        )

        assert result.changed_fields == []
        assert result.user.email == "already@example.com"
        assert await _audit_events_for(db_session, target.id) == []

    async def test_invalid_email_format_raises(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory()
        with pytest.raises(EmailFormatError):
            await update_user(
                db_session, target.id, acting_user_id=None, email="not-an-email"
            )

    async def test_duplicate_email_raises_conflict_excluding_self(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        other = await user_factory(email="other@example.com")
        target = await user_factory(email="mine@example.com")

        # Updating to its own current email must NOT conflict (self-exclusion).
        await update_user(
            db_session, target.id, acting_user_id=None, email="mine@example.com"
        )

        with pytest.raises(UserConflictError) as exc_info:
            await update_user(
                db_session, target.id, acting_user_id=None, email=other.email
            )
        assert exc_info.value.conflict_field == "email"

    async def test_full_name_explicit_none_clears_it(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(full_name="Original Name")

        result = await update_user(
            db_session, target.id, acting_user_id=None, full_name=None
        )

        assert result.changed_fields == ["full_name"]
        assert result.user.full_name is None
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == IdentityAuditEventType.FULL_NAME_CHANGED.value
        assert events[0].old_value == "Original Name"
        assert events[0].new_value is None

    async def test_full_name_omitted_leaves_it_unchanged(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(full_name="Keep Me")

        result = await update_user(
            db_session, target.id, acting_user_id=None, email="x@example.com"
        )

        assert result.changed_fields == ["email"]
        assert result.user.full_name == "Keep Me"

    async def test_full_name_same_value_is_a_no_op(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(full_name="Same Name")

        result = await update_user(
            db_session, target.id, acting_user_id=None, full_name="Same Name"
        )

        assert result.changed_fields == []
        assert result.user.full_name == "Same Name"
        assert await _audit_events_for(db_session, target.id) == []

    async def test_manager_id_change_audits_manager_usernames(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        manager_one = await user_factory(username="manager-one")
        manager_two = await user_factory(username="manager-two")
        target = await user_factory(external_id=uuid.uuid4(), manager_id=manager_one.id)

        await update_user(
            db_session, target.id, acting_user_id=None, manager_id=manager_two.id
        )

        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        event = events[0]
        assert event.event_type == IdentityAuditEventType.MANAGER_CHANGED.value
        assert event.user_id is None
        assert event.old_value == "manager-one"
        assert event.new_value == "manager-two"
        assert event.detail is None

    async def test_manager_id_explicit_none_clears_it_and_audits(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        manager = await user_factory(username="the-manager")
        target = await user_factory(external_id=uuid.uuid4(), manager_id=manager.id)

        result = await update_user(
            db_session, target.id, acting_user_id=None, manager_id=None
        )

        assert result.changed_fields == ["manager_id"]
        assert result.user.manager_id is None
        events = await _audit_events_for(db_session, target.id)
        assert events[0].old_value == "the-manager"
        assert events[0].new_value is None

    async def test_synced_at_applies_without_audit_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4())
        new_synced_at = datetime.now(UTC)

        result = await update_user(
            db_session, target.id, acting_user_id=None, synced_at=new_synced_at
        )

        assert result.changed_fields == ["synced_at"]
        assert result.user.synced_at == new_synced_at
        assert await _audit_events_for(db_session, target.id) == []

    async def test_username_changed_detail_includes_source_for_external_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4(), username="ext-old-name")

        await update_user(
            db_session, target.id, acting_user_id=None, username="ext-new-name"
        )

        events = await _audit_events_for(db_session, target.id)
        assert events[0].detail == {"source": "external_sync"}

    async def test_all_omitted_fields_is_a_total_no_op(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(full_name="Untouched")

        result = await update_user(db_session, target.id, acting_user_id=None)

        assert result.changed_fields == []
        assert result.user.full_name == "Untouched"
        assert await _audit_events_for(db_session, target.id) == []

    async def test_multi_field_update_creates_one_event_per_field(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(username="multi-old", full_name="Old Name")

        await update_user(
            db_session,
            target.id,
            acting_user_id=None,
            username="multi-new",
            email="multi-new@example.com",
            full_name="New Name",
        )

        events = await _audit_events_for(db_session, target.id)
        event_types = {event.event_type for event in events}
        assert event_types == {
            IdentityAuditEventType.USERNAME_CHANGED.value,
            IdentityAuditEventType.EMAIL_CHANGED.value,
            IdentityAuditEventType.FULL_NAME_CHANGED.value,
        }
        assert len(events) == 3

    async def test_changed_fields_report_all_effective_changes_in_fixed_order(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        manager_one = await user_factory(username="order-manager-one")
        manager_two = await user_factory(username="order-manager-two")
        old_synced_at = datetime(2020, 1, 1, tzinfo=UTC)
        new_synced_at = datetime(2021, 1, 1, tzinfo=UTC)
        target = await user_factory(
            external_id=uuid.uuid4(),
            username="order-old",
            email="order-old@example.com",
            full_name="Old Name",
            manager_id=manager_one.id,
            synced_at=old_synced_at,
        )

        result = await update_user(
            db_session,
            target.id,
            acting_user_id=None,
            full_name="New Name",
            synced_at=new_synced_at,
            manager_id=manager_two.id,
            username="order-new",
            email="order-new@example.com",
        )

        assert result.changed_fields == [
            "username",
            "email",
            "full_name",
            "manager_id",
            "synced_at",
        ]
        assert result.user.username == "order-new"
        assert result.user.email == "order-new@example.com"
        assert result.user.full_name == "New Name"
        assert result.user.manager_id == manager_two.id
        assert result.user.synced_at == new_synced_at

        events = await _audit_events_for(db_session, target.id)
        event_types = {event.event_type for event in events}
        assert event_types == {
            IdentityAuditEventType.USERNAME_CHANGED.value,
            IdentityAuditEventType.EMAIL_CHANGED.value,
            IdentityAuditEventType.FULL_NAME_CHANGED.value,
            IdentityAuditEventType.MANAGER_CHANGED.value,
        }
        assert len(events) == 4

    async def test_synced_at_same_value_is_a_no_op(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        stored_synced_at = datetime(2022, 5, 5, tzinfo=UTC)
        target = await user_factory(
            external_id=uuid.uuid4(), synced_at=stored_synced_at
        )

        result = await update_user(
            db_session, target.id, acting_user_id=None, synced_at=stored_synced_at
        )

        assert result.changed_fields == []
        assert result.user.synced_at == stored_synced_at
        assert await _audit_events_for(db_session, target.id) == []

    async def test_reinvocation_after_a_successful_update_is_a_no_op(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(username="reinvoke-old")

        first = await update_user(
            db_session, target.id, acting_user_id=None, username="reinvoke-new"
        )
        second = await update_user(
            db_session, target.id, acting_user_id=None, username="reinvoke-new"
        )

        assert first.changed_fields == ["username"]
        assert second.changed_fields == []
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1

    async def test_explicit_clear_classified_only_when_it_changes_state(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(full_name="Clear Me")

        cleared = await update_user(
            db_session, target.id, acting_user_id=None, full_name=None
        )
        already_clear = await update_user(
            db_session, target.id, acting_user_id=None, full_name=None
        )

        assert cleared.changed_fields == ["full_name"]
        assert cleared.user.full_name is None
        assert already_clear.changed_fields == []
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == IdentityAuditEventType.FULL_NAME_CHANGED.value

    async def test_two_concurrent_same_value_updates_second_reports_no_change(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-same-value",
                email="conc-same-value@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add(user)
            await session_a.commit()
            user_id = user.id
            user_ids.append(user_id)

            result_a = await update_user(
                session_a,
                user_id,
                acting_user_id=None,
                email="conc-same-value-new@example.com",
            )

            task_b = asyncio.create_task(
                update_user(
                    session_b,
                    user_id,
                    acting_user_id=None,
                    email="conc-same-value-new@example.com",
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            result_b = await asyncio.wait_for(task_b, timeout=5)
            await session_b.commit()

            assert result_a.changed_fields == ["email"]
            assert result_b.changed_fields == []
            assert result_a.user.email == "conc-same-value-new@example.com"
            assert result_b.user.email == "conc-same-value-new@example.com"

            events = await _audit_events_for(session_a, user_id)
            email_events = [
                e
                for e in events
                if e.event_type == IdentityAuditEventType.EMAIL_CHANGED.value
            ]
            assert len(email_events) == 1
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )

    async def test_returns_user_with_roles_and_manager_eagerly_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        manager = await user_factory()
        target = await user_factory(external_id=uuid.uuid4(), manager_id=manager.id)
        await user_role_factory(user_id=target.id, role=Role.ADMIN.value)

        result = await update_user(
            db_session, target.id, acting_user_id=None, synced_at=datetime.now(UTC)
        )

        assert len(result.user.roles) == 1
        assert result.user.manager is not None
        assert result.user.manager.id == manager.id

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory()
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        await update_user(db_session, target.id, acting_user_id=None, full_name="X")
        commit_spy.assert_not_called()

    async def test_rollback_removes_mutation_and_audit_event_together(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(full_name="Before")
        target_id = target.id

        async with rollback_test_scope(db_session):
            await update_user(
                db_session, target_id, acting_user_id=None, full_name="After"
            )

        reloaded = await db_session.get(User, target_id)
        assert reloaded is not None
        assert reloaded.full_name == "Before"
        assert await _audit_events_for(db_session, target_id) == []

    async def test_audit_failure_rolls_back_the_pending_update_too(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory(full_name="Before")
        target_id = target.id

        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated audit failure")

        monkeypatch.setattr(IdentityAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await update_user(
                    db_session, target_id, acting_user_id=None, full_name="After"
                )

        reloaded = await db_session.get(User, target_id)
        assert reloaded is not None
        assert reloaded.full_name == "Before"

    async def test_unrelated_integrity_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4())
        with pytest.raises(IntegrityError):
            await update_user(
                db_session, target.id, acting_user_id=None, manager_id=uuid.uuid4()
            )

    async def test_precheck_miss_still_translates_conflict_keeps_transaction_usable(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression test for a SAVEPOINT-ordering bug: `update_user()`
        used to assign `user.username`/`user.email` directly onto the ORM
        object, one field at a time, each *before* the next field's own
        uniqueness pre-check query. Since a pre-check query
        (`_email_taken()`) triggers SQLAlchemy autoflush, a prior field's
        pending mutation could be flushed *before* `begin_nested()`
        established its SAVEPOINT protection -- leaving the whole parent
        transaction aborted instead of just the nested one. This simulates
        the race the sequential pre-check is documented not to guarantee
        against (`_email_taken()` monkeypatched to miss a real conflict)
        while changing BOTH `username` and `email` in the same call --
        the exact combination that triggered the bug -- and verifies the
        transaction remains usable for unrelated work after the translated
        `UserConflictError`."""
        await user_factory(email="update-precheck-miss@example.com")
        target = await user_factory(username="update-precheck-target")
        target_id = target.id

        bystander = User(
            username="update-precheck-bystander",
            email="update-precheck-bystander@example.com",
            password_hash=_FICTIONAL_PASSWORD_HASH,
        )
        db_session.add(bystander)
        await db_session.flush()
        bystander_id = bystander.id

        async def _no_conflict(*args: object, **kwargs: object) -> bool:
            return False

        monkeypatch.setattr(user_service, "_email_taken", _no_conflict)

        with pytest.raises(UserConflictError) as exc_info:
            await update_user(
                db_session,
                target_id,
                acting_user_id=None,
                username="update-precheck-new-name",
                email="update-precheck-miss@example.com",
            )
        assert exc_info.value.conflict_field == "email"

        # The transaction must still be usable: an unrelated read succeeds,
        # proving the parent transaction was not left in PostgreSQL's
        # aborted state by the failed flush.
        result = await db_session.execute(select(User).where(User.id == bystander_id))
        recovered = result.scalar_one()
        assert recovered.username == "update-precheck-bystander"

        # The whole staged mutation set rolled back together: the
        # username change must not have been persisted either.
        reloaded = await db_session.get(User, target_id)
        assert reloaded is not None
        assert reloaded.username == "update-precheck-target"

    async def test_two_concurrent_updates_same_user_serialize_via_row_lock(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-update-target",
                email="conc-update-target@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add(user)
            await session_a.commit()
            user_id = user.id
            user_ids.append(user_id)

            result_a = await update_user(
                session_a,
                user_id,
                acting_user_id=None,
                email="first-update@example.com",
            )

            task_b = asyncio.create_task(
                update_user(
                    session_b,
                    user_id,
                    acting_user_id=None,
                    email="second-update@example.com",
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            result_b = await asyncio.wait_for(task_b, timeout=5)
            await session_b.commit()

            assert result_a.changed_fields == ["email"]
            assert result_b.changed_fields == ["email"]
            assert result_a.user.email == "first-update@example.com"
            assert result_b.user.email == "second-update@example.com"

            # session_b must have refreshed post-commit state: its own
            # email_changed old_value reflects session_a's committed
            # email, not the pre-session_a original.
            events = await _audit_events_for(session_a, user_id)
            email_events = [
                e
                for e in events
                if e.event_type == IdentityAuditEventType.EMAIL_CHANGED.value
            ]
            assert len(email_events) == 2
            assert email_events[1].old_value == "first-update@example.com"
            assert email_events[1].new_value == "second-update@example.com"
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )

    async def test_two_concurrent_updates_different_users_same_email_serialize(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user_a = User(
                username="conc-cross-user-a",
                email="conc-cross-user-a@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            user_b = User(
                username="conc-cross-user-b",
                email="conc-cross-user-b@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add_all([user_a, user_b])
            await session_a.commit()
            user_ids.extend([user_a.id, user_b.id])

            result_a = await update_user(
                session_a,
                user_a.id,
                acting_user_id=None,
                email="conc-cross-target@example.com",
            )

            task_b = asyncio.create_task(
                update_user(
                    session_b,
                    user_b.id,
                    acting_user_id=None,
                    email="conc-cross-target@example.com",
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            with pytest.raises(UserConflictError) as exc_info:
                await asyncio.wait_for(task_b, timeout=5)
            assert exc_info.value.conflict_field == "email"
            await session_b.rollback()

            assert result_a.changed_fields == ["email"]
            assert result_a.user.email == "conc-cross-target@example.com"
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )


# ---------------------------------------------------------------------------
# reactivate_user()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReactivateUser:
    async def test_missing_user_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await reactivate_user(db_session, uuid.uuid4(), acting_user_id=None)

    async def test_already_active_is_a_no_op(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(active=True)

        result = await reactivate_user(db_session, target.id, acting_user_id=None)

        assert result.reactivated is False
        assert result.user.active is True
        assert await _audit_events_for(db_session, target.id) == []

    async def test_already_active_external_user_with_human_caller_raises(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """The external-status guard runs BEFORE the already-active
        short-circuit, so a human caller reactivating an already-active
        external user is rejected -- there is no no-op path for a human
        caller on an external user, active or not."""
        admin = await user_factory()
        target = await user_factory(external_id=uuid.uuid4(), active=True)

        with pytest.raises(ExternalUserStatusReadOnlyError):
            await reactivate_user(db_session, target.id, acting_user_id=admin.id)

        assert await _audit_events_for(db_session, target.id) == []

    async def test_reactivates_inactive_local_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(active=False)

        result = await reactivate_user(db_session, target.id, acting_user_id=None)

        assert result.reactivated is True
        assert result.user.active is True
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == IdentityAuditEventType.USER_REACTIVATED.value
        assert events[0].old_value == "inactive"
        assert events[0].new_value == "active"
        assert events[0].detail is None

    async def test_reactivated_actor_is_the_authenticated_acting_user(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        """A real, authenticated admin reactivates a local user: the
        resulting `user_reactivated` event's actor (`user_id`) must be the
        admin, not `None` -- proving the actor is threaded through
        correctly for a human-initiated reactivation, not just the
        system-caller (`None`) path exercised by every other reactivation
        test in this class."""
        admin = await user_factory()
        target = await user_factory(active=False)

        await reactivate_user(db_session, target.id, acting_user_id=admin.id)

        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].user_id == admin.id
        assert events[0].target_user_id == target.id

    async def test_reactivates_inactive_external_user_via_system_caller(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4(), active=False)

        result = await reactivate_user(db_session, target.id, acting_user_id=None)

        assert result.reactivated is True
        assert result.user.active is True
        events = await _audit_events_for(db_session, target.id)
        assert events[0].detail == {"source": "external_sync"}
        assert events[0].old_value == "inactive"
        assert events[0].new_value == "active"
        assert events[0].user_id is None
        assert events[0].target_user_id == target.id

    async def test_human_caller_reactivating_inactive_external_user_raises(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        target = await user_factory(external_id=uuid.uuid4(), active=False)

        with pytest.raises(ExternalUserStatusReadOnlyError):
            await reactivate_user(db_session, target.id, acting_user_id=admin.id)

        reloaded = await db_session.get(User, target.id)
        assert reloaded is not None
        assert reloaded.active is False
        assert await _audit_events_for(db_session, target.id) == []

    async def test_returns_user_with_roles_and_manager_eagerly_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        manager = await user_factory()
        target = await user_factory(
            active=False, external_id=uuid.uuid4(), manager_id=manager.id
        )
        await user_role_factory(user_id=target.id, role=Role.ADMIN.value)

        result = await reactivate_user(db_session, target.id, acting_user_id=None)

        assert len(result.user.roles) == 1
        assert result.user.manager is not None
        assert result.user.manager.id == manager.id

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory(active=False)
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        await reactivate_user(db_session, target.id, acting_user_id=None)
        commit_spy.assert_not_called()

    async def test_rollback_restores_inactive_state_and_removes_audit_event(
        self, db_session: AsyncSession, user_factory: Callable[..., Awaitable[User]]
    ) -> None:
        target = await user_factory(active=False)
        target_id = target.id

        async with rollback_test_scope(db_session):
            await reactivate_user(db_session, target_id, acting_user_id=None)

        reloaded = await db_session.get(User, target_id)
        assert reloaded is not None
        assert reloaded.active is False
        assert await _audit_events_for(db_session, target_id) == []

    async def test_audit_failure_rolls_back_the_pending_reactivation_too(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory(active=False)
        target_id = target.id

        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated audit failure")

        monkeypatch.setattr(IdentityAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await reactivate_user(db_session, target_id, acting_user_id=None)

        reloaded = await db_session.get(User, target_id)
        assert reloaded is not None
        assert reloaded.active is False
        assert await _audit_events_for(db_session, target_id) == []

    async def test_two_concurrent_reactivations_produce_one_mutation_and_event(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-reactivate-target",
                email="conc-reactivate-target@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
                active=False,
            )
            session_a.add(user)
            await session_a.commit()
            user_id = user.id
            user_ids.append(user_id)

            result_a = await reactivate_user(session_a, user_id, acting_user_id=None)

            task_b = asyncio.create_task(
                reactivate_user(session_b, user_id, acting_user_id=None)
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            result_b = await asyncio.wait_for(task_b, timeout=5)

            assert result_a.reactivated is True
            assert result_b.reactivated is False
            assert result_a.user.active is True
            assert result_b.user.active is True

            events = await _audit_events_for(session_a, user_id)
            reactivated_events = [
                e
                for e in events
                if e.event_type == IdentityAuditEventType.USER_REACTIVATED.value
            ]
            assert len(reactivated_events) == 1
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )


# ---------------------------------------------------------------------------
# reset_password()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestResetPassword:
    async def test_missing_user_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await reset_password(
                db_session, uuid.uuid4(), _VALID_PASSWORD, acting_user_id=None
            )

    async def test_external_user_raises_external_user_password_error(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4())

        with pytest.raises(ExternalUserPasswordError):
            await reset_password(
                db_session, target.id, _VALID_PASSWORD, acting_user_id=None
            )

    @pytest.mark.parametrize(
        "length", [MIN_PASSWORD_LENGTH - 1, MAX_PASSWORD_LENGTH + 1]
    )
    async def test_password_length_boundaries_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        length: int,
    ) -> None:
        target = await user_factory()

        with pytest.raises(PasswordValidationError):
            await reset_password(
                db_session, target.id, "a" * length, acting_user_id=None
            )

    @pytest.mark.parametrize("length", [MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH])
    async def test_password_length_boundaries_accepted(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        length: int,
    ) -> None:
        target = await user_factory()

        result = await reset_password(
            db_session, target.id, "a" * length, acting_user_id=None
        )

        assert verify_password("a" * length, _hash(result.user))

    async def test_validation_and_hashing_occur_before_any_database_lookup(
        self,
        db_session: AsyncSession,
    ) -> None:
        """An invalid password raises `PasswordValidationError` even for a
        `user_id` that does not exist — proving validation runs before the
        database lookup, per `docs/features/identity/user-service.md`
        (`reset_password()`, step 1-2 occur "before acquiring a row lock")."""
        with pytest.raises(PasswordValidationError):
            await reset_password(
                db_session, uuid.uuid4(), "too-short", acting_user_id=None
            )

    async def test_hashing_delegates_to_hash_password_off_the_event_loop(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory()
        # `wraps=` preserves the real `asyncio.to_thread()` behavior (still
        # runs `hash_password()` in a worker thread) while letting the spy
        # record that the offloading call was actually made.
        to_thread_spy = AsyncMock(wraps=asyncio.to_thread)
        monkeypatch.setattr(asyncio, "to_thread", to_thread_spy)

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        to_thread_spy.assert_awaited_once()
        assert verify_password(_VALID_PASSWORD, _hash(result.user))

    async def test_hashing_completes_before_row_lock_is_acquired(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Proves the documented Transaction Hygiene guarantee: bcrypt work
        completes before the `FOR UPDATE` lock is acquired. A refactor that
        moved hashing to after the lock would violate this ordering and
        would be caught by this test."""
        target = await user_factory()
        call_order: list[str] = []

        original_to_thread = asyncio.to_thread

        async def _recording_to_thread(func: Any, *args: Any) -> Any:
            result = await original_to_thread(func, *args)
            call_order.append("hash")
            return result

        original_execute = db_session.execute

        async def _recording_execute(*args: Any, **kwargs: Any) -> Any:
            # Only record the first execute (the FOR UPDATE query)
            if not any(entry == "db_execute" for entry in call_order):
                call_order.append("db_execute")
            return await original_execute(*args, **kwargs)

        monkeypatch.setattr(asyncio, "to_thread", _recording_to_thread)
        monkeypatch.setattr(db_session, "execute", _recording_execute)

        await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert call_order.index("hash") < call_order.index("db_execute")

    async def test_active_status_unchanged_by_password_reset(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(active=True)

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert result.user.active is True

    async def test_resets_password_for_inactive_local_user(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(active=False)

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert result.user.active is False
        assert verify_password(_VALID_PASSWORD, _hash(result.user))

    async def test_stored_hash_verifies_new_password_and_rejects_old(
        self,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        target, old_password = await local_user_factory()

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert verify_password(_VALID_PASSWORD, _hash(result.user))
        assert not verify_password(old_password, _hash(result.user))

    async def test_zero_active_sessions_returns_empty_list(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert result.invalidated_session_ids == []

    async def test_one_active_session_is_invalidated_and_returned(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        target = await user_factory()
        active_session = await session_factory(user_id=target.id, is_active=True)

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert result.invalidated_session_ids == [active_session.id]
        await db_session.refresh(active_session)
        assert active_session.is_active is False

    async def test_multiple_sessions_only_active_ones_invalidated(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        target = await user_factory()
        other_user = await user_factory()
        active_1 = await session_factory(user_id=target.id, is_active=True)
        active_2 = await session_factory(user_id=target.id, is_active=True)
        already_inactive = await session_factory(user_id=target.id, is_active=False)
        other_user_session = await session_factory(
            user_id=other_user.id, is_active=True
        )

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert set(result.invalidated_session_ids) == {active_1.id, active_2.id}
        await db_session.refresh(already_inactive)
        await db_session.refresh(other_user_session)
        assert already_inactive.is_active is False
        assert other_user_session.is_active is True

    async def test_creates_exactly_one_password_reset_event_with_null_payload(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        target = await user_factory()

        await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=admin.id
        )

        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == IdentityAuditEventType.PASSWORD_RESET.value
        assert events[0].user_id == admin.id
        assert events[0].target_user_id == target.id
        assert events[0].old_value is None
        assert events[0].new_value is None
        assert events[0].detail is None

    async def test_system_actor_is_preserved_as_null(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()

        await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        events = await _audit_events_for(db_session, target.id)
        assert events[0].user_id is None

    async def test_returns_normalized_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(username="reset-target-user")

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert result.username == "reset-target-user"

    async def test_flushes_without_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory()
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        commit_spy.assert_not_called()

    async def test_rollback_restores_password_sessions_and_removes_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
    ) -> None:
        target = await user_factory()
        target_id = target.id
        original_hash = target.password_hash
        active_session = await session_factory(user_id=target_id, is_active=True)
        session_id = active_session.id

        async with rollback_test_scope(db_session):
            await reset_password(
                db_session, target_id, _VALID_PASSWORD, acting_user_id=None
            )

        reloaded_user = await db_session.get(User, target_id)
        assert reloaded_user is not None
        assert reloaded_user.password_hash == original_hash
        reloaded_session = await db_session.get(Session, session_id)
        assert reloaded_session is not None
        assert reloaded_session.is_active is True
        assert await _audit_events_for(db_session, target_id) == []

    async def test_audit_failure_rolls_back_password_and_session_changes(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory()
        target_id = target.id
        original_hash = target.password_hash
        active_session = await session_factory(user_id=target_id, is_active=True)
        session_id = active_session.id

        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated audit failure")

        monkeypatch.setattr(IdentityAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await reset_password(
                    db_session, target_id, _VALID_PASSWORD, acting_user_id=None
                )

        reloaded_user = await db_session.get(User, target_id)
        assert reloaded_user is not None
        assert reloaded_user.password_hash == original_hash
        reloaded_session = await db_session.get(Session, session_id)
        assert reloaded_session is not None
        assert reloaded_session.is_active is True

    async def test_lockout_key_unaffected_by_service_call(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """`reset_password()` performs only the database phase and issues
        no Redis I/O at all — the lockout key is untouched regardless of
        whether it existed before the call."""
        target = await user_factory(username="reset-no-redis-io")
        await redis_client.set("login_attempts:reset-no-redis-io", "3")

        await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )

        assert await redis_client.get("login_attempts:reset-no-redis-io") == "3"

    async def test_post_commit_workflow_purges_cache_and_clears_lockout(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """Simulates the caller-owned post-commit workflow: the service's
        database phase commits, then the caller invokes
        `purge_session_cache()` and `clear_login_attempts()` — mirroring
        the sequence a future API/CLI/task workflow will perform."""
        target = await user_factory(username="reset-post-commit-user")
        active_session = await session_factory(user_id=target.id, is_active=True)
        await redis_client.set(f"session_liveness:{active_session.id}", "1")
        await redis_client.set("login_attempts:reset-post-commit-user", "2")

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )
        await db_session.commit()

        await purge_session_cache(result.invalidated_session_ids)
        await local_auth_service.clear_login_attempts(result.username)

        assert await redis_client.get(f"session_liveness:{active_session.id}") is None
        assert await redis_client.get("login_attempts:reset-post-commit-user") is None

    async def test_post_commit_redis_failure_leaves_committed_state_intact(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory(username="reset-redis-failure-user")

        result = await reset_password(
            db_session, target.id, _VALID_PASSWORD, acting_user_id=None
        )
        await db_session.commit()

        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )

        with caplog.at_level("WARNING"):
            await local_auth_service.clear_login_attempts(result.username)

        reloaded = await db_session.get(User, target.id)
        assert reloaded is not None
        assert verify_password(_VALID_PASSWORD, _hash(reloaded))
        assert len(await _audit_events_for(db_session, target.id)) == 1

    async def test_two_concurrent_resets_serialize_last_commit_wins(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Two resets for the same user serialize on the `User` row lock:
        the second call's `FOR UPDATE` blocks until the first commits.
        Each successful invocation hashes and stores its own password (the
        hashing/validation phase — which is where bcrypt work would occur —
        already completed for both calls before the lock was contended, per
        the documented "validate/hash before lock" ordering) and creates
        its own `password_reset` event; the last committed reset determines
        the accepted password."""
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-reset-target",
                email="conc-reset-target@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add(user)
            await session_a.commit()
            user_id = user.id
            user_ids.append(user_id)

            result_a = await reset_password(
                session_a, user_id, "first-new-password-16", acting_user_id=None
            )

            task_b = asyncio.create_task(
                reset_password(
                    session_b,
                    user_id,
                    "second-new-password-16",
                    acting_user_id=None,
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            result_b = await asyncio.wait_for(task_b, timeout=5)
            await session_b.commit()

            assert verify_password("first-new-password-16", _hash(result_a.user))
            assert verify_password("second-new-password-16", _hash(result_b.user))

            events = await _audit_events_for(session_a, user_id)
            reset_events = [
                e
                for e in events
                if e.event_type == IdentityAuditEventType.PASSWORD_RESET.value
            ]
            assert len(reset_events) == 2
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )

    async def test_reset_serializes_with_concurrent_update_user_on_same_row(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        user_ids: list[uuid.UUID] = []
        task_b: asyncio.Task[Any] | None = None

        try:
            user = User(
                username="conc-reset-serialize",
                email="conc-reset-serialize@example.com",
                password_hash=_FICTIONAL_PASSWORD_HASH,
            )
            session_a.add(user)
            await session_a.commit()
            user_id = user.id
            user_ids.append(user_id)

            await reset_password(
                session_a, user_id, "first-password-value-16", acting_user_id=None
            )

            task_b = asyncio.create_task(
                update_user(
                    session_b,
                    user_id,
                    acting_user_id=None,
                    full_name="Concurrent Update",
                )
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

            await session_a.commit()

            result_b = await asyncio.wait_for(task_b, timeout=5)
            await session_b.commit()

            assert result_b.changed_fields == ["full_name"]
            assert result_b.user.full_name == "Concurrent Update"
        finally:
            await _concurrency_teardown(
                task_b, session_a, session_b, session_a, user_ids
            )

    async def test_reset_logs_contain_no_password_or_hash(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory(username="reset-log-safety-user")

        with caplog.at_level("DEBUG"):
            result = await reset_password(
                db_session, target.id, _VALID_PASSWORD, acting_user_id=None
            )

        text = _identity_related_log_text(caplog)
        assert _VALID_PASSWORD not in text
        assert _hash(result.user) not in text
        assert "reset-log-safety-user" not in text

    async def test_reset_exception_messages_contain_no_password(
        self,
        db_session: AsyncSession,
    ) -> None:
        with pytest.raises(PasswordValidationError) as exc_info:
            await reset_password(
                db_session, uuid.uuid4(), "too-short", acting_user_id=None
            )
        assert "too-short" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# unlock_user()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUnlockUser:
    async def test_missing_user_raises_not_found(
        self,
        db_session: AsyncSession,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await unlock_user(db_session, uuid.uuid4(), acting_user_id=None)

    async def test_deletes_existing_lockout_key(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory(username="unlock-existing-key")
        await redis_client.set("login_attempts:unlock-existing-key", "5")

        await unlock_user(db_session, target.id, acting_user_id=None)

        assert await redis_client.get("login_attempts:unlock-existing-key") is None

    async def test_absent_key_is_a_no_op_success(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory(username="unlock-absent-key")

        await unlock_user(db_session, target.id, acting_user_id=None)

        assert await redis_client.get("login_attempts:unlock-absent-key") is None

    async def test_zero_valued_key_is_deleted_successfully(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory(username="unlock-zero-key")
        await redis_client.set("login_attempts:unlock-zero-key", "0")

        await unlock_user(db_session, target.id, acting_user_id=None)

        assert await redis_client.get("login_attempts:unlock-zero-key") is None

    async def test_only_current_username_key_is_deleted(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory(username="unlock-target-user")
        await user_factory(username="unlock-bystander-user")
        await redis_client.set("login_attempts:unlock-target-user", "3")
        await redis_client.set("login_attempts:unlock-bystander-user", "4")

        await unlock_user(db_session, target.id, acting_user_id=None)

        assert await redis_client.get("login_attempts:unlock-target-user") is None
        assert await redis_client.get("login_attempts:unlock-bystander-user") == "4"

    @pytest.mark.parametrize("active", [True, False])
    async def test_works_for_active_and_inactive_local_users(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        active: bool,
    ) -> None:
        target = await user_factory(active=active)

        await unlock_user(db_session, target.id, acting_user_id=None)

        reloaded = await db_session.get(User, target.id)
        assert reloaded is not None
        assert reloaded.active is active

    async def test_works_for_external_user(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory(external_id=uuid.uuid4())

        with caplog.at_level("INFO"):
            await unlock_user(db_session, target.id, acting_user_id=None)

        assert "user_unlocked" in _service_log_text(caplog)
        assert await _audit_events_for(db_session, target.id) == []

    async def test_redis_error_is_caught_and_logged_as_warning(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory(username="unlock-redis-error-user")

        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )

        with caplog.at_level("WARNING"):
            await unlock_user(db_session, target.id, acting_user_id=None)

        assert "login_lockout_clear_failed" in _identity_related_log_text(caplog)

    async def test_no_database_mutation_flush_or_commit(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory()
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await unlock_user(db_session, target.id, acting_user_id=None)

        commit_spy.assert_not_called()

    async def test_no_session_invalidation(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory()
        active_session = await session_factory(user_id=target.id, is_active=True)

        await unlock_user(db_session, target.id, acting_user_id=None)

        await db_session.refresh(active_session)
        assert active_session.is_active is True

    async def test_no_identity_audit_event_created(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory(username="unlock-no-audit-user")
        await redis_client.set("login_attempts:unlock-no-audit-user", "3")

        await unlock_user(db_session, target.id, acting_user_id=None)

        assert await _audit_events_for(db_session, target.id) == []

    async def test_repeated_unlock_is_idempotent(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        target = await user_factory(username="unlock-repeated-user")
        await redis_client.set("login_attempts:unlock-repeated-user", "3")

        await unlock_user(db_session, target.id, acting_user_id=None)
        await unlock_user(db_session, target.id, acting_user_id=None)

        assert await redis_client.get("login_attempts:unlock-repeated-user") is None

    async def test_info_event_emitted_on_success(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory()

        with caplog.at_level("INFO"):
            await unlock_user(db_session, target.id, acting_user_id=None)

        text = _service_log_text(caplog)
        assert "user_unlocked" in text

    async def test_info_event_emitted_even_after_redis_error(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory()

        monkeypatch.setattr(
            local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
        )

        with caplog.at_level("INFO"):
            await unlock_user(db_session, target.id, acting_user_id=None)

        text = _service_log_text(caplog)
        assert "user_unlocked" in text

    async def test_logs_contain_no_username_or_other_pii(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target = await user_factory(
            username="unlock-pii-safety-user",
            email="unlock-pii-safety-user@example.com",
            full_name="Unlock Pii Safety",
        )

        with caplog.at_level("DEBUG"):
            await unlock_user(db_session, target.id, acting_user_id=None)

        text = _identity_related_log_text(caplog)
        assert "unlock-pii-safety-user" not in text
        assert "Unlock Pii Safety" not in text

    async def test_acting_user_id_has_no_effect_on_outcome(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        admin = await user_factory()
        target = await user_factory(username="unlock-actor-agnostic-user")
        await redis_client.set("login_attempts:unlock-actor-agnostic-user", "3")

        await unlock_user(db_session, target.id, acting_user_id=admin.id)

        assert (
            await redis_client.get("login_attempts:unlock-actor-agnostic-user") is None
        )
        assert await _audit_events_for(db_session, target.id) == []


# ---------------------------------------------------------------------------
# Pre-existing read functions (regression coverage — unchanged behavior)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGetUserById:
    async def test_returns_user_when_exists(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()

        result = await get_user_by_id(db_session, user.id)

        assert result is not None
        assert result.id == user.id

    async def test_returns_none_when_not_exists(self, db_session: AsyncSession) -> None:
        result = await get_user_by_id(db_session, uuid.uuid4())

        assert result is None


@pytest.mark.integration
class TestResolveUserIdentifier:
    async def test_resolves_by_uuid(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()

        resolved = await resolve_user_identifier(db_session, str(user.id))

        assert resolved.id == user.id

    async def test_resolves_by_exact_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="jdoe")

        resolved = await resolve_user_identifier(db_session, "jdoe")

        assert resolved.id == user.id

    async def test_username_lookup_is_case_sensitive(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="jdoe")

        with pytest.raises(UserNotFoundError):
            await resolve_user_identifier(db_session, "JDoe")

    async def test_unknown_uuid_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await resolve_user_identifier(db_session, str(uuid.uuid4()))

    async def test_unknown_username_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await resolve_user_identifier(db_session, "nonexistent-user")

    async def test_valid_uuid_with_no_match_does_not_fall_back_to_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """A syntactically valid but non-existent UUID must not be
        reinterpreted as a username lookup, even if a user happens to
        have that exact string as their username."""
        unknown_id = uuid.uuid4()
        await user_factory(username=str(unknown_id))

        with pytest.raises(UserNotFoundError):
            await resolve_user_identifier(db_session, str(unknown_id))


@pytest.mark.integration
class TestGetUserRoles:
    async def test_no_roles_returns_empty_list(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()

        roles = await get_user_roles(db_session, user.id)

        assert roles == []

    async def test_returns_single_role(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()
        db_session.add(UserRole(user_id=user.id, role=Role.ADMIN.value))
        await db_session.flush()

        roles = await get_user_roles(db_session, user.id)

        assert roles == [Role.ADMIN]

    async def test_role_held_from_multiple_origins_counts_once(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()
        db_session.add_all(
            [
                UserRole(
                    user_id=user.id,
                    role=Role.VULNERABILITY_ANALYST.value,
                    group_name="_manual",
                ),
                UserRole(
                    user_id=user.id,
                    role=Role.VULNERABILITY_ANALYST.value,
                    group_name="external-group",
                ),
            ]
        )
        await db_session.flush()

        roles = await get_user_roles(db_session, user.id)

        assert roles == [Role.VULNERABILITY_ANALYST]

    async def test_multiple_distinct_roles(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()
        db_session.add_all(
            [
                UserRole(user_id=user.id, role=Role.ADMIN.value),
                UserRole(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value),
            ]
        )
        await db_session.flush()

        roles = await get_user_roles(db_session, user.id)

        assert set(roles) == {Role.ADMIN, Role.VULNERABILITY_ANALYST}

    async def test_unknown_user_id_returns_empty_list(
        self, db_session: AsyncSession
    ) -> None:
        """An unresolved `user_id` is not an error here — the caller has
        already resolved the principal via a validated credential."""
        roles = await get_user_roles(db_session, uuid.uuid4())

        assert roles == []


# ---------------------------------------------------------------------------
# PII / secret safety across create_user / update_user / reactivate_user
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPiiAndSecretSafety:
    async def test_create_user_logs_contain_no_pii_or_secret(
        self, db_session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("DEBUG"):
            await create_user(
                db_session,
                username="pii-safe-user",
                email="pii-safe-user@example.com",
                full_name="Pii Safe",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )
        text = _service_log_text(caplog)
        assert "pii-safe-user" not in text
        assert _VALID_PASSWORD not in text

    async def test_conflict_error_str_contains_no_secret_value(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="conflict-secret-user")

        with pytest.raises(UserConflictError) as exc_info:
            await create_user(
                db_session,
                username="conflict-secret-user",
                email="another@example.com",
                password=_VALID_PASSWORD,
                acting_user_id=None,
            )
        assert _VALID_PASSWORD not in str(exc_info.value)


# ---------------------------------------------------------------------------
# list_users() / get_user() — read/query boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListUsers:
    async def test_empty_database_returns_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_users(db_session)

        assert page.items == []
        assert page.total == 0

    async def test_default_ordering_is_username_ascending(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="charlie")
        await user_factory(username="alice")
        await user_factory(username="bob")

        page = await list_users(db_session)

        assert [user.username for user in page.items] == ["alice", "bob", "charlie"]

    async def test_search_matches_username_case_insensitively(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="johndoe")
        await user_factory(username="alicesmith")

        page = await list_users(db_session, search="JohnD")

        assert [user.username for user in page.items] == ["johndoe"]

    async def test_search_matches_email(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(email="findme@example.com")
        await user_factory(email="other@example.com")

        page = await list_users(db_session, search="findme")

        assert [user.id for user in page.items] == [target.id]

    async def test_search_matches_full_name(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory(full_name="Alice Smith")
        await user_factory(full_name="Bob Wilson")

        page = await list_users(db_session, search="Alice")

        assert [user.id for user in page.items] == [target.id]

    async def test_search_combines_with_active_filter_via_and(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """docs/features/identity/user-management.md (List Users):
        filters of different kinds combine with AND semantics."""
        active_match = await user_factory(username="searchmatch1", active=True)
        await user_factory(username="searchmatch2", active=False)

        page = await list_users(db_session, search="searchmatch", active=True)

        assert [user.id for user in page.items] == [active_match.id]

    async def test_type_filter_local(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        local_user = await user_factory()
        await user_factory(external_id=uuid.uuid4(), password_hash=None)

        page = await list_users(db_session, user_type=UserType.LOCAL)

        assert [user.id for user in page.items] == [local_user.id]

    async def test_type_filter_external(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory()
        external_user = await user_factory(external_id=uuid.uuid4(), password_hash=None)

        page = await list_users(db_session, user_type=UserType.EXTERNAL)

        assert [user.id for user in page.items] == [external_user.id]

    async def test_active_filter_true(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        active_user = await user_factory(active=True)
        await user_factory(active=False)

        page = await list_users(db_session, active=True)

        assert [user.id for user in page.items] == [active_user.id]

    async def test_active_filter_false(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(active=True)
        inactive_user = await user_factory(active=False)

        page = await list_users(db_session, active=False)

        assert [user.id for user in page.items] == [inactive_user.id]

    async def test_role_filter_or_semantics(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        admin_user = await user_factory(username="adminuser")
        await user_role_factory(user_id=admin_user.id, role=Role.ADMIN.value)
        analyst_user = await user_factory(username="analystuser")
        await user_role_factory(
            user_id=analyst_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        no_role_user = await user_factory(username="noroleuser")

        page = await list_users(
            db_session, roles=[Role.ADMIN, Role.VULNERABILITY_ANALYST]
        )

        result_ids = {user.id for user in page.items}
        assert result_ids == {admin_user.id, analyst_user.id}
        assert no_role_user.id not in result_ids

    async def test_role_filter_no_duplicate_for_multiple_origins(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        """A user holding the same role from two origins (manual + one
        external group) must appear exactly once, with an accurate
        total — the `EXISTS` subquery must not duplicate the row."""
        user = await user_factory(username="dualorigin")
        await user_role_factory(
            user_id=user.id, role=Role.ADMIN.value, group_name="_manual"
        )
        await user_role_factory(
            user_id=user.id, role=Role.ADMIN.value, group_name="O SUSE Security"
        )

        page = await list_users(db_session, roles=[Role.ADMIN])

        assert [u.id for u in page.items] == [user.id]
        assert page.total == 1

    async def test_has_role_true(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        with_role = await user_factory(username="hasrole")
        await user_role_factory(user_id=with_role.id)
        await user_factory(username="norole")

        page = await list_users(db_session, has_role=True)

        assert [user.id for user in page.items] == [with_role.id]

    async def test_has_role_false(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        with_role = await user_factory(username="hasrole2")
        await user_role_factory(user_id=with_role.id)
        no_role = await user_factory(username="norole2")

        page = await list_users(db_session, has_role=False)

        assert [user.id for user in page.items] == [no_role.id]

    @pytest.mark.parametrize(
        ("sort_by", "field"),
        [
            (UserSortField.USERNAME, "username"),
            (UserSortField.EMAIL, "email"),
            (UserSortField.CREATED_AT, "created_at"),
        ],
    )
    async def test_sort_by_field_ascending_and_descending(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        sort_by: UserSortField,
        field: str,
    ) -> None:
        first = await user_factory(username="aaa-user", email="aaa@example.com")
        second = await user_factory(username="zzz-user", email="zzz@example.com")

        ascending = await list_users(
            db_session, sort_by=sort_by, sort_order=SortOrder.ASC
        )
        descending = await list_users(
            db_session, sort_by=sort_by, sort_order=SortOrder.DESC
        )

        asc_values = [getattr(user, field) for user in ascending.items]
        desc_values = [getattr(user, field) for user in descending.items]
        assert asc_values == sorted(asc_values)
        assert desc_values == sorted(desc_values, reverse=True)
        assert {u.id for u in ascending.items} == {first.id, second.id}

    async def test_full_name_sort_places_nulls_last_ascending(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="hasnameuser", full_name="Alice Smith")
        await user_factory(username="nonameuser", full_name=None)

        page = await list_users(
            db_session, sort_by=UserSortField.FULL_NAME, sort_order=SortOrder.ASC
        )

        assert [user.full_name for user in page.items] == ["Alice Smith", None]

    async def test_full_name_sort_places_nulls_last_descending(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="hasnameuser2", full_name="Alice Smith")
        await user_factory(username="nonameuser2", full_name=None)

        page = await list_users(
            db_session, sort_by=UserSortField.FULL_NAME, sort_order=SortOrder.DESC
        )

        assert [user.full_name for user in page.items] == ["Alice Smith", None]

    async def test_tie_break_by_id_same_direction_as_sort_order(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """Two users sharing the same non-unique sort value
        (`full_name`) fall back to the deterministic `User.id`
        tiebreaker in the same direction as `sort_order`."""
        first = await user_factory(username="tieuser1", full_name="Same Name")
        second = await user_factory(username="tieuser2", full_name="Same Name")
        expected_asc = sorted([first.id, second.id])
        expected_desc = list(reversed(expected_asc))

        ascending = await list_users(
            db_session, sort_by=UserSortField.FULL_NAME, sort_order=SortOrder.ASC
        )
        descending = await list_users(
            db_session, sort_by=UserSortField.FULL_NAME, sort_order=SortOrder.DESC
        )

        assert [u.id for u in ascending.items] == expected_asc
        assert [u.id for u in descending.items] == expected_desc

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory()

        page = await list_users(db_session, page=2, per_page=20)

        assert page.items == []
        assert page.total == 1

    async def test_roles_and_manager_are_eagerly_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        """Accessing `.roles`/`.manager` on a returned item must not
        require additional I/O — SQLAlchemy async raises a
        `MissingGreenlet`-style error on implicit lazy load, so a clean
        attribute access proves eager loading."""
        manager = await user_factory(username="managerof")
        user = await user_factory(username="hasmanager", manager_id=manager.id)
        await user_role_factory(user_id=user.id)

        page = await list_users(db_session, search="hasmanager")

        (item,) = page.items
        assert item.manager is not None
        assert item.manager.id == manager.id
        assert len(item.roles) == 1


@pytest.mark.integration
class TestGetUser:
    async def test_resolves_by_uuid_with_roles_and_manager_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        manager = await user_factory(username="managerof2")
        user = await user_factory(username="target-user", manager_id=manager.id)
        await user_role_factory(user_id=user.id)

        result = await get_user(db_session, str(user.id))

        assert result.id == user.id
        assert result.manager is not None
        assert result.manager.id == manager.id
        assert len(result.roles) == 1

    async def test_resolves_by_exact_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="byusername")

        result = await get_user(db_session, "byusername")

        assert result.id == user.id

    async def test_unknown_uuid_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await get_user(db_session, str(uuid.uuid4()))

    async def test_unknown_username_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await get_user(db_session, "no-such-user")
