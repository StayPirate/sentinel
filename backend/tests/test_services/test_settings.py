"""Tests for the system settings service (backend/app/services/settings.py).

See `docs/features/platform/system-settings.md` for the contract under
test: `bootstrap_system_settings()`, `get_default_cvss_version()`, the
`SettingAuditLog` audit trail, and `list_setting_audit_events()`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IdentityAuditEventType, SettingAuditEventType
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.user import User
from app.services import base_audit_log
from app.services.settings import (
    RequiredSystemSettingMissingError,
    SettingAuditLog,
    bootstrap_system_settings,
    default_cvss_version_select,
    get_default_cvss_version,
    list_setting_audit_events,
)

_DEFAULT_KEY = "default_cvss_version"


@pytest.mark.unit
class TestSettingAuditLogRegistration:
    def test_registered_under_setting_name(self) -> None:
        assert base_audit_log.AUDIT_LOG_REGISTRY["setting"] is SettingAuditLog

    def test_binds_to_setting_audit_event_model(self) -> None:
        assert SettingAuditLog.model_class is SettingAuditEvent

    def test_description(self) -> None:
        assert SettingAuditLog.description == "System setting modifications"


@pytest.mark.integration
class TestBootstrapSystemSettingsFirstInvocation:
    async def test_creates_the_missing_row_with_initial_value(
        self, db_session: AsyncSession
    ) -> None:
        await bootstrap_system_settings(db_session)

        setting = await db_session.get(SystemSetting, _DEFAULT_KEY)
        assert setting is not None
        assert setting.value == "3.1"

    async def test_creates_no_audit_event(self, db_session: AsyncSession) -> None:
        await bootstrap_system_settings(db_session)

        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert rows == []


@pytest.mark.integration
class TestBootstrapSystemSettingsRepeatedInvocation:
    async def test_repeated_invocation_is_a_no_op(
        self, db_session: AsyncSession
    ) -> None:
        await bootstrap_system_settings(db_session)
        await bootstrap_system_settings(db_session)

        rows = (await db_session.execute(select(SystemSetting))).scalars().all()
        assert len(rows) == 1
        assert rows[0].value == "3.1"

    async def test_preserves_an_existing_custom_value(
        self, db_session: AsyncSession
    ) -> None:
        await bootstrap_system_settings(db_session)
        setting = await db_session.get(SystemSetting, _DEFAULT_KEY)
        assert setting is not None
        setting.value = "4.0"
        await db_session.flush()

        await bootstrap_system_settings(db_session)

        refreshed = await db_session.get(
            SystemSetting, _DEFAULT_KEY, populate_existing=True
        )
        assert refreshed is not None
        assert refreshed.value == "4.0"

    async def test_creates_no_audit_event(self, db_session: AsyncSession) -> None:
        await bootstrap_system_settings(db_session)
        setting = await db_session.get(SystemSetting, _DEFAULT_KEY)
        assert setting is not None
        setting.value = "4.0"
        await db_session.flush()

        await bootstrap_system_settings(db_session)

        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert rows == []


@pytest.mark.integration
class TestBootstrapSystemSettingsConcurrency:
    async def test_concurrent_invocations_are_safe(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Two independent sessions bootstrap concurrently — the
        `ON CONFLICT DO NOTHING` insert guarantees at most one insert
        succeeds and every caller observes a completed insert or
        conflict before returning, leaving exactly one row."""
        session_a = await db_session_factory()
        session_b = await db_session_factory()

        async def _bootstrap_and_commit(session: AsyncSession) -> None:
            await bootstrap_system_settings(session)
            await session.commit()

        try:
            await asyncio.gather(
                _bootstrap_and_commit(session_a), _bootstrap_and_commit(session_b)
            )

            verify_session = await db_session_factory()
            value = await get_default_cvss_version(verify_session)
            assert value == "3.1"
        finally:
            # This test commits durable rows; db_session_factory's
            # rollback-on-teardown does not cover committed data (see
            # docs/features/platform/testing-strategy.md, Database
            # Strategy — Concurrency Testing). Cleanup runs even if the
            # assertion above fails, so a regression never leaks a
            # committed row into the shared test database.
            cleanup_session = await db_session_factory()
            await cleanup_session.execute(
                delete(SystemSetting).where(SystemSetting.key == _DEFAULT_KEY)
            )
            await cleanup_session.commit()


@pytest.mark.integration
class TestBootstrapSystemSettingsTransactionContract:
    async def test_does_not_commit(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await bootstrap_system_settings(db_session)

        commit_spy.assert_not_called()

    async def test_flushes_within_the_caller_transaction(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        await bootstrap_system_settings(db_session)

        flush_spy.assert_called_once()

    async def test_database_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await bootstrap_system_settings(db_session)


@pytest.mark.integration
class TestGetDefaultCvssVersion:
    async def test_returns_the_persisted_initial_value(
        self, db_session: AsyncSession
    ) -> None:
        await bootstrap_system_settings(db_session)

        assert await get_default_cvss_version(db_session) == "3.1"

    async def test_returns_a_custom_persisted_value(
        self, db_session: AsyncSession
    ) -> None:
        await bootstrap_system_settings(db_session)
        setting = await db_session.get(SystemSetting, _DEFAULT_KEY)
        assert setting is not None
        setting.value = "4.0"
        await db_session.flush()

        assert await get_default_cvss_version(db_session) == "4.0"

    async def test_missing_row_raises_without_fallback(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(RequiredSystemSettingMissingError):
            await get_default_cvss_version(db_session)

    async def test_creates_no_audit_event(self, db_session: AsyncSession) -> None:
        await bootstrap_system_settings(db_session)
        await get_default_cvss_version(db_session)

        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert rows == []

    async def test_database_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await get_default_cvss_version(db_session)


@pytest.mark.integration
class TestDefaultCvssVersionSelect:
    """The reusable SELECT behind `get_default_cvss_version()`, embeddable as
    a scalar subquery by reads that need the setting in the same view."""

    async def test_scalar_subquery_yields_the_persisted_value(
        self, db_session: AsyncSession
    ) -> None:
        await bootstrap_system_settings(db_session)

        value = await db_session.scalar(
            select(default_cvss_version_select().scalar_subquery())
        )

        assert value == "3.1"

    async def test_scalar_subquery_yields_null_when_the_row_is_missing(
        self, db_session: AsyncSession
    ) -> None:
        value = await db_session.scalar(
            select(default_cvss_version_select().scalar_subquery())
        )

        assert value is None


@pytest.mark.integration
class TestSettingAuditLogValidation:
    async def test_creates_expected_row(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
    ) -> None:
        admin = await user_factory()
        setting = await system_setting_factory(value="3.1")

        await SettingAuditLog.log_event(
            db_session,
            event_type=SettingAuditEventType.SETTING_CHANGED,
            setting_key=setting.key,
            user_id=admin.id,
            old_value="3.1",
            new_value="4.0",
        )

        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert len(rows) == 1
        assert rows[0].event_type == "setting_changed"
        assert rows[0].setting_key == setting.key
        assert rows[0].user_id == admin.id
        assert rows[0].old_value == "3.1"
        assert rows[0].new_value == "4.0"

    async def test_rejects_non_setting_audit_event_type_enum(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
    ) -> None:
        """A member of a different `StrEnum` (even with the same string
        value) must be rejected — `isinstance` is checked, not value
        equality."""
        admin = await user_factory()
        setting = await system_setting_factory()

        with pytest.raises(ValueError, match="SettingAuditEventType"):
            await SettingAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.USER_CREATED,  # type: ignore[arg-type]
                setting_key=setting.key,
                user_id=admin.id,
                old_value=None,
                new_value="4.0",
            )

        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert rows == []

    async def test_rejects_missing_user_id(
        self,
        db_session: AsyncSession,
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
    ) -> None:
        setting = await system_setting_factory()

        with pytest.raises(ValueError, match="user_id is required"):
            await SettingAuditLog.log_event(
                db_session,
                event_type=SettingAuditEventType.SETTING_CHANGED,
                setting_key=setting.key,
                user_id=None,
                old_value=None,
                new_value="4.0",
            )

        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert rows == []

    async def test_does_not_commit(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        user_factory: Callable[..., Awaitable[User]],
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
    ) -> None:
        admin = await user_factory()
        setting = await system_setting_factory()
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await SettingAuditLog.log_event(
            db_session,
            event_type=SettingAuditEventType.SETTING_CHANGED,
            setting_key=setting.key,
            user_id=admin.id,
            old_value=None,
            new_value="4.0",
        )

        commit_spy.assert_not_called()

    async def test_flushes_within_the_caller_transaction(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        user_factory: Callable[..., Awaitable[User]],
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
    ) -> None:
        admin = await user_factory()
        setting = await system_setting_factory()
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        await SettingAuditLog.log_event(
            db_session,
            event_type=SettingAuditEventType.SETTING_CHANGED,
            setting_key=setting.key,
            user_id=admin.id,
            old_value=None,
            new_value="4.0",
        )

        flush_spy.assert_called_once()


@pytest.mark.integration
class TestSettingAuditLogAtomicity:
    async def test_rollback_removes_the_flushed_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
    ) -> None:
        """If the caller's transaction rolls back (e.g. because the
        setting update itself failed later in the same business
        operation), the audit event created via `log_event()` does not
        survive — it shares the same transaction as the mutation it
        records."""
        admin = await user_factory()
        setting = await system_setting_factory()

        await SettingAuditLog.log_event(
            db_session,
            event_type=SettingAuditEventType.SETTING_CHANGED,
            setting_key=setting.key,
            user_id=admin.id,
            old_value=None,
            new_value="4.0",
        )
        rows = (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        assert len(rows) == 1

        await db_session.rollback()

        rows_after = (
            (await db_session.execute(select(SettingAuditEvent))).scalars().all()
        )
        assert rows_after == []


@pytest.mark.integration
class TestListSettingAuditEventsEmpty:
    async def test_returns_empty_page_with_zero_total(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_setting_audit_events(db_session)

        assert page.items == []
        assert page.total == 0
        assert page.page == 1
        assert page.per_page == 20


@pytest.mark.integration
class TestListSettingAuditEventsActorLoading:
    async def test_actor_is_eagerly_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        admin = await user_factory(username="eagerloadactor")
        await setting_audit_event_factory(user_id=admin.id)

        page = await list_setting_audit_events(db_session)

        assert len(page.items) == 1
        assert page.items[0].actor is not None
        assert page.items[0].actor.username == "eagerloadactor"


@pytest.mark.integration
class TestListSettingAuditEventsSettingKeyFilter:
    async def test_exact_match_filters_to_one_setting(
        self,
        db_session: AsyncSession,
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        setting_a = await system_setting_factory()
        setting_b = await system_setting_factory()
        await setting_audit_event_factory(setting_key=setting_a.key)
        await setting_audit_event_factory(setting_key=setting_b.key)

        page = await list_setting_audit_events(db_session, setting_key=setting_a.key)

        assert page.total == 1
        assert page.items[0].setting_key == setting_a.key

    async def test_unknown_setting_key_returns_empty_page(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        page = await list_setting_audit_events(
            db_session, setting_key="no_such_setting_key"
        )

        assert page.total == 0
        assert page.items == []


@pytest.mark.integration
class TestListSettingAuditEventsActorFilter:
    async def test_filter_by_actor_uuid(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        actor = await user_factory()
        other_actor = await user_factory()
        await setting_audit_event_factory(user_id=actor.id)
        await setting_audit_event_factory(user_id=other_actor.id)

        page = await list_setting_audit_events(db_session, actor=str(actor.id))

        assert page.total == 1
        assert page.items[0].user_id == actor.id

    async def test_filter_by_actor_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        actor = await user_factory(username="filterbyusernamesetting")
        await setting_audit_event_factory(user_id=actor.id)

        page = await list_setting_audit_events(
            db_session, actor="filterbyusernamesetting"
        )

        assert page.total == 1

    async def test_unknown_actor_returns_empty_page(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        page = await list_setting_audit_events(db_session, actor="no-such-actor")

        assert page.total == 0

    async def test_system_literal_returns_empty_page(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        """Every setting audit event has a human actor — `"system"` never
        matches any row (system-settings.md, List Settings Audit
        Events)."""
        await setting_audit_event_factory()

        page = await list_setting_audit_events(db_session, actor="system")

        assert page.total == 0


@pytest.mark.integration
class TestListSettingAuditEventsEventTypeFilter:
    async def test_matching_type_is_included(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory(event_type="setting_changed")

        page = await list_setting_audit_events(
            db_session, event_types=[SettingAuditEventType.SETTING_CHANGED]
        )

        assert page.total == 1

    async def test_empty_event_types_list_applies_no_filter(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()
        await setting_audit_event_factory()

        page = await list_setting_audit_events(db_session, event_types=[])

        assert page.total == 2


@pytest.mark.integration
class TestListSettingAuditEventsDateFilter:
    async def test_inclusive_from_and_to_date(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        in_range = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 13, tzinfo=UTC)
        )
        await setting_audit_event_factory(created_at=datetime(2026, 1, 1, tzinfo=UTC))

        page = await list_setting_audit_events(
            db_session,
            from_date=datetime(2026, 5, 1, tzinfo=UTC),
            to_date=datetime(2026, 5, 31, tzinfo=UTC),
        )

        assert page.total == 1
        assert page.items[0].id == in_range.id

    async def test_date_only_bounds_cover_full_day(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        event = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 13, 23, 59, 0, tzinfo=UTC)
        )

        page = await list_setting_audit_events(
            db_session, from_date=datetime(2026, 5, 13, tzinfo=UTC).date(), to_date=None
        )

        assert page.total == 1
        assert page.items[0].id == event.id


@pytest.mark.integration
class TestListSettingAuditEventsCombinedFilters:
    async def test_filters_combine_with_and(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        actor = await user_factory()
        setting = await system_setting_factory()
        await setting_audit_event_factory(
            user_id=actor.id, setting_key=setting.key, event_type="setting_changed"
        )
        # Same setting, different actor — must not match the actor filter.
        other_actor = await user_factory()
        await setting_audit_event_factory(
            user_id=other_actor.id, setting_key=setting.key
        )

        page = await list_setting_audit_events(
            db_session,
            actor=str(actor.id),
            setting_key=setting.key,
            event_types=[SettingAuditEventType.SETTING_CHANGED],
        )

        assert page.total == 1


@pytest.mark.integration
class TestListSettingAuditEventsPagination:
    async def test_reports_filtered_total(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        for _ in range(3):
            await setting_audit_event_factory()

        page = await list_setting_audit_events(db_session, per_page=2)

        assert page.total == 3
        assert len(page.items) == 2

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        page = await list_setting_audit_events(db_session, page=2)

        assert page.items == []
        assert page.total == 1


@pytest.mark.integration
class TestListSettingAuditEventsOrdering:
    async def test_orders_newest_first(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        older = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 1, tzinfo=UTC)
        )
        newer = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 2, tzinfo=UTC)
        )

        page = await list_setting_audit_events(db_session)

        assert [item.id for item in page.items] == [newer.id, older.id]

    async def test_equal_timestamps_break_tie_by_id_desc(
        self,
        db_session: AsyncSession,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        same_time = datetime(2026, 5, 13, tzinfo=UTC)
        first = await setting_audit_event_factory(created_at=same_time)
        second = await setting_audit_event_factory(created_at=same_time)
        expected_order = sorted([first.id, second.id], reverse=True)

        page = await list_setting_audit_events(db_session)

        assert [item.id for item in page.items] == expected_order


@pytest.mark.integration
class TestListSettingAuditEventsErrorPropagation:
    async def test_database_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await list_setting_audit_events(db_session)
