"""Tests for the shared audit trail service base class
(backend/app/services/base_audit_log.py).

See `docs/features/platform/audit-trail-infrastructure.md` for the
contract under test: registry semantics, `log_event()` validation and
atomicity, date filtering, and actor filtering.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Generator
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services import base_audit_log
from app.services.base_audit_log import BaseAuditLog
from app.services.fetcher_audit_log import FetcherAuditLog
from app.services.identity_audit_log import IdentityAuditLog
from app.services.settings import SettingAuditLog
from app.services.ticket_audit_log import TicketAuditLog
from tests.support.audit_models import SampleAuditEvent


class SampleAuditLog(BaseAuditLog):
    """The single, module-level `BaseAuditLog` subclass shared by every
    test below. Defined once at import time so `AUDIT_LOG_REGISTRY`
    always contains a stable "sample" baseline entry across this
    file's tests (restored by `_isolated_registry` after any test that
    registers additional throwaway subclasses)."""

    name = "sample"
    description = "Test-only audit trail for BaseAuditLog"
    model_class = SampleAuditEvent


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `AUDIT_LOG_REGISTRY` around every test.

    Several tests below define additional throwaway `BaseAuditLog`
    subclasses (duplicate-name, missing-attribute, override scenarios).
    Each such class definition mutates the shared, module-level
    registry via `__init_subclass__`. Without this fixture, those
    registrations would leak into later tests (see
    docs/features/platform/testing-strategy.md, Test Independence).
    """
    original = dict(base_audit_log.AUDIT_LOG_REGISTRY)
    yield
    base_audit_log.AUDIT_LOG_REGISTRY.clear()
    base_audit_log.AUDIT_LOG_REGISTRY.update(original)


async def _event_types(db_session: AsyncSession, query: Any) -> set[str]:
    rows = (await db_session.execute(query)).scalars().all()
    return {row.event_type for row in rows}


@pytest.mark.unit
class TestRegistryAutoRegistration:
    def test_subclass_is_registered_by_name(self) -> None:
        assert base_audit_log.AUDIT_LOG_REGISTRY["sample"] is SampleAuditLog

    def test_duplicate_name_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="sample"):

            class DuplicateAuditLog(BaseAuditLog):
                name = "sample"
                description = "Attempts to reuse an existing name"
                model_class = SampleAuditEvent

    def test_duplicate_name_does_not_replace_existing_registration(self) -> None:
        with pytest.raises(ValueError, match="sample"):

            class DuplicateAuditLog(BaseAuditLog):
                name = "sample"
                description = "Attempts to reuse an existing name"
                model_class = SampleAuditEvent

        assert base_audit_log.AUDIT_LOG_REGISTRY["sample"] is SampleAuditLog

    def test_missing_model_class_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="model_class"):

            class IncompleteAuditLog(BaseAuditLog):
                name = "incomplete"
                description = "Missing model_class"

        assert "incomplete" not in base_audit_log.AUDIT_LOG_REGISTRY

    def test_missing_name_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="name"):

            class NamelessAuditLog(BaseAuditLog):
                description = "Missing name"
                model_class = SampleAuditEvent

    def test_missing_description_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="description"):

            class UndescribedAuditLog(BaseAuditLog):
                name = "undescribed"
                model_class = SampleAuditEvent

        assert "undescribed" not in base_audit_log.AUDIT_LOG_REGISTRY


@pytest.mark.integration
class TestLogEventCreation:
    async def test_creates_exactly_one_row_with_given_fields(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()

        # log_event()'s `-> None` contract is enforced statically by
        # mypy strict mode on base_audit_log.py itself (any non-None
        # return would fail type checking there); this test focuses on
        # the row it persists.
        await SampleAuditLog.log_event(
            db_session, event_type="widget_created", user_id=user.id
        )

        rows = (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        assert len(rows) == 1
        assert rows[0].event_type == "widget_created"
        assert rows[0].user_id == user.id
        assert rows[0].created_at is not None

    async def test_user_id_defaults_to_null_for_system_events(
        self, db_session: AsyncSession
    ) -> None:
        await SampleAuditLog.log_event(db_session, event_type="system_event")

        rows = (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        assert len(rows) == 1
        assert rows[0].user_id is None

    async def test_unknown_kwarg_raises_value_error_before_any_insert(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(ValueError, match="nonexistent_field"):
            await SampleAuditLog.log_event(
                db_session, event_type="x", nonexistent_field="y"
            )

        rows = (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        assert rows == []

    async def test_relationship_kwarg_is_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()

        with pytest.raises(ValueError, match="actor"):
            await SampleAuditLog.log_event(db_session, event_type="x", actor=user)

        rows = (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        assert rows == []

    async def test_does_not_commit(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await SampleAuditLog.log_event(db_session, event_type="x", user_id=user.id)

        commit_spy.assert_not_called()

    async def test_flushes_within_the_caller_transaction(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """Explicit spy on `flush()`, distinguishing a deliberate flush
        from an incidental autoflush-before-query — the query in other
        tests could otherwise mask a missing explicit flush call."""
        user = await user_factory()
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        await SampleAuditLog.log_event(db_session, event_type="x", user_id=user.id)

        flush_spy.assert_called_once()


@pytest.mark.integration
class TestLogEventAtomicity:
    async def test_rollback_removes_the_flushed_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """If the caller's transaction rolls back (e.g. because a later
        step of the same business operation failed), the audit event
        created via `log_event()` does not survive — it shares the same
        transaction as the mutation it records."""
        user = await user_factory()

        await SampleAuditLog.log_event(db_session, event_type="x", user_id=user.id)
        rows = (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        assert len(rows) == 1

        await db_session.rollback()

        rows_after = (
            (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        )
        assert rows_after == []


@pytest.mark.integration
class TestLogEventSubclassOverride:
    async def test_subclass_can_enforce_required_actor_before_delegating(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        class StrictAuditLog(BaseAuditLog):
            name = "strict_sample"
            description = "Requires a human actor"
            model_class = SampleAuditEvent

            @classmethod
            async def log_event(cls, session: AsyncSession, **kwargs: Any) -> None:
                if kwargs.get("user_id") is None:
                    raise ValueError("user_id is required for this trail")
                await super().log_event(session, **kwargs)

        with pytest.raises(ValueError, match="user_id is required"):
            await StrictAuditLog.log_event(db_session, event_type="x")

        user = await user_factory()
        await StrictAuditLog.log_event(db_session, event_type="x", user_id=user.id)

        rows = (await db_session.execute(select(SampleAuditEvent))).scalars().all()
        assert len(rows) == 1


@pytest.mark.integration
class TestApplyDateFilters:
    """`SampleAuditLog.apply_date_filters()` against four fixed
    `created_at` instants spanning three UTC calendar days."""

    _JAN_14 = datetime(2025, 1, 14, 23, 59, 59, tzinfo=UTC)
    _JAN_15_MORNING = datetime(2025, 1, 15, 8, 0, 0, tzinfo=UTC)
    _JAN_15_EVENING = datetime(2025, 1, 15, 23, 59, 59, 999999, tzinfo=UTC)
    _JAN_16 = datetime(2025, 1, 16, 0, 0, 1, tzinfo=UTC)

    @pytest.fixture(autouse=True)
    async def _seed_events(
        self,
        db_session: AsyncSession,
        sample_audit_event_factory: Callable[..., Awaitable[SampleAuditEvent]],
    ) -> None:
        await sample_audit_event_factory(event_type="jan_14", created_at=self._JAN_14)
        await sample_audit_event_factory(
            event_type="jan_15_morning", created_at=self._JAN_15_MORNING
        )
        await sample_audit_event_factory(
            event_type="jan_15_evening", created_at=self._JAN_15_EVENING
        )
        await sample_audit_event_factory(event_type="jan_16", created_at=self._JAN_16)

    async def test_no_filters_returns_everything(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.apply_date_filters(select(SampleAuditEvent))
        assert await _event_types(db_session, query) == {
            "jan_14",
            "jan_15_morning",
            "jan_15_evening",
            "jan_16",
        }

    async def test_date_only_from_date_is_inclusive_start_of_day_utc(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.apply_date_filters(
            select(SampleAuditEvent), from_date=date(2025, 1, 15)
        )
        assert await _event_types(db_session, query) == {
            "jan_15_morning",
            "jan_15_evening",
            "jan_16",
        }

    async def test_date_only_to_date_is_inclusive_end_of_day_utc(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.apply_date_filters(
            select(SampleAuditEvent), to_date=date(2025, 1, 15)
        )
        assert await _event_types(db_session, query) == {
            "jan_14",
            "jan_15_morning",
            "jan_15_evening",
        }

    async def test_date_only_both_bounds_same_day(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.apply_date_filters(
            select(SampleAuditEvent),
            from_date=date(2025, 1, 15),
            to_date=date(2025, 1, 15),
        )
        assert await _event_types(db_session, query) == {
            "jan_15_morning",
            "jan_15_evening",
        }

    async def test_naive_datetime_is_interpreted_as_utc(
        self, db_session: AsyncSession
    ) -> None:
        # Intentionally naive — this test verifies that
        # apply_date_filters() interprets a tzinfo-less datetime as UTC.
        naive_bound = datetime(2025, 1, 15, 8, 0, 0)  # noqa: DTZ001
        query = SampleAuditLog.apply_date_filters(
            select(SampleAuditEvent), from_date=naive_bound
        )
        assert await _event_types(db_session, query) == {
            "jan_15_morning",
            "jan_15_evening",
            "jan_16",
        }

    async def test_offset_aware_datetime_is_converted_to_utc(
        self, db_session: AsyncSession
    ) -> None:
        # 2025-01-15T10:00:00+02:00 == 2025-01-15T08:00:00Z
        aware_bound = datetime(
            2025, 1, 15, 10, 0, 0, tzinfo=timezone(timedelta(hours=2))
        )
        query = SampleAuditLog.apply_date_filters(
            select(SampleAuditEvent), from_date=aware_bound
        )
        assert await _event_types(db_session, query) == {
            "jan_15_morning",
            "jan_15_evening",
            "jan_16",
        }


@pytest.mark.integration
class TestFilterByActor:
    @pytest.fixture(autouse=True)
    async def _seed_events(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        sample_audit_event_factory: Callable[..., Awaitable[SampleAuditEvent]],
    ) -> None:
        self.user_a = await user_factory()
        self.user_b = await user_factory()
        await sample_audit_event_factory(event_type="system_event")
        await sample_audit_event_factory(event_type="event_a", user_id=self.user_a.id)
        await sample_audit_event_factory(event_type="event_b", user_id=self.user_b.id)

    async def test_none_applies_no_filter(self, db_session: AsyncSession) -> None:
        query = SampleAuditLog.filter_by_actor(select(SampleAuditEvent), None)
        assert await _event_types(db_session, query) == {
            "system_event",
            "event_a",
            "event_b",
        }

    async def test_system_matches_null_user_id(self, db_session: AsyncSession) -> None:
        query = SampleAuditLog.filter_by_actor(select(SampleAuditEvent), "system")
        assert await _event_types(db_session, query) == {"system_event"}

    async def test_uuid_string_matches_by_user_id(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.filter_by_actor(
            select(SampleAuditEvent), str(self.user_a.id)
        )
        assert await _event_types(db_session, query) == {"event_a"}

    async def test_unknown_uuid_yields_empty_result(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.filter_by_actor(
            select(SampleAuditEvent), str(uuid.uuid4())
        )
        assert await _event_types(db_session, query) == set()

    async def test_username_matches_by_exact_join(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.filter_by_actor(
            select(SampleAuditEvent), self.user_a.username
        )
        assert await _event_types(db_session, query) == {"event_a"}

    async def test_username_match_is_case_sensitive(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.filter_by_actor(
            select(SampleAuditEvent), self.user_a.username.upper()
        )
        assert await _event_types(db_session, query) == set()

    async def test_unknown_username_yields_empty_result(
        self, db_session: AsyncSession
    ) -> None:
        query = SampleAuditLog.filter_by_actor(select(SampleAuditEvent), "no-such-user")
        assert await _event_types(db_session, query) == set()

    async def test_matching_is_independent_of_a_user_already_in_the_statement(
        self, db_session: AsyncSession
    ) -> None:
        # Regression (#658): the caller's statement already selects FROM
        # `User` (bound to user_b). The actor match must neither re-join
        # `User` nor correlate to that outer entity, so filtering by
        # user_a still finds user_a's event.
        query = select(SampleAuditEvent).join(User, User.id == self.user_b.id)
        filtered = SampleAuditLog.filter_by_actor(query, self.user_a.username)
        assert await _event_types(db_session, filtered) == {"event_a"}


@pytest.mark.unit
class TestConcreteTrailsInheritActorFilter:
    """Every production audit trail uses the base `filter_by_actor()`,
    so the base-level actor matrix above covers all of them."""

    @pytest.mark.parametrize(
        "trail_class",
        [TicketAuditLog, IdentityAuditLog, SettingAuditLog, FetcherAuditLog],
        ids=["ticket", "identity", "setting", "fetcher"],
    )
    def test_trail_does_not_override_filter_by_actor(
        self, trail_class: type[BaseAuditLog]
    ) -> None:
        overriding = [
            klass.__name__
            for klass in trail_class.__mro__[: trail_class.__mro__.index(BaseAuditLog)]
            if "filter_by_actor" in vars(klass)
        ]
        assert overriding == []
