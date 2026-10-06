"""Service tests for the setting mutation `update_default_cvss_version()`
(backend/app/services/settings.py).

Owning specifications:

- docs/features/platform/system-settings.md (Default CVSS Version; Setting
  Mutation Service; Service Exceptions);
- docs/features/platform/default-cvss-version-operations.md (Execution
  Fence: the identifier the mutation requests in transaction-level form);
- docs/features/platform/testing-strategy.md (System Settings Mutation,
  Service tests; Rollback Within a Test; Concurrency Testing; Audit Trail
  Testing).

Most tests run in the shared `db_session`, where no `default_cvss_version`
row exists unless a test seeds it. Statement order and absence are observed
with `StatementRecorder` on the test engine. Rollback atomicity uses
`rollback_test_scope()`, and its audit-validation case is also the proof
that a missing actor raises and logs nothing; the one test that proves the
commit through the caller's transaction uses independent
`db_session_factory` sessions and deletes its committed rows explicitly.
An out-of-set value is proven to raise before any database access by a
unit test whose stand-in session fails on use.

The service's behavior under a held execution fence (an effective change
rejected before any write, a no-op succeeding without a fence request), the
multi-session races, and the committed fence rejection are covered by
`tests/test_services/test_settings_mutation_races.py`; the commit-failure
cases and the endpoint by `tests/test_api/test_settings_update.py`.
Expected values are transcribed from the specifications.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any, Literal, cast
from unittest.mock import AsyncMock

import celery
import celery.app.task
import pytest
import redis
import redis.asyncio as redis_asyncio
from sqlalchemy import Executable, delete, event, select, update
from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app import database
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.user import User
from app.services import cvss_recalculation_coordination as coordination
from app.services import task_publication
from app.services.cvss_recalculation_coordination import EXECUTION_FENCE_ID
from app.services.settings import (
    RequiredSystemSettingMissingError,
    update_default_cvss_version,
)
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[[], Awaitable[AsyncSession]]
SettingFactory = Callable[..., Awaitable[SystemSetting]]
UserFactory = Callable[..., Awaitable[User]]
Version = Literal["3.1", "4.0"]

_KEY = "default_cvss_version"
_ADVISORY = "pg_try_advisory_xact_lock"

_CHANGES = [
    pytest.param("3.1", "4.0", id="3.1-to-4.0"),
    pytest.param("4.0", "3.1", id="4.0-to-3.1"),
]
_VALUES = [pytest.param("3.1", id="3.1"), pytest.param("4.0", id="4.0")]
_OUT_OF_SET: list[Any] = [
    "3.0",
    "4.0 ",
    "",
    None,
    pytest.param(4.0, id="float-4.0"),
]

_UNKNOWN_USER_ID = uuid.UUID("00000000-0000-4000-8000-00000000d0d0")
"""A fictional user UUID with no `user` row."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def admin(user_factory: UserFactory) -> User:
    return await user_factory(
        username="settings.admin", email="settings.admin@example.com"
    )


async def _seed(system_setting_factory: SettingFactory, value: str) -> SystemSetting:
    return await system_setting_factory(key=_KEY, value=value)


async def _persisted(session: AsyncSession) -> str | None:
    """The stored value, read with a column query that bypasses the
    identity map."""
    return await session.scalar(
        select(SystemSetting.value).where(SystemSetting.key == _KEY)
    )


async def _events(session: AsyncSession) -> list[tuple[Any, ...]]:
    """Every `SettingAuditEvent` as `(event_type, setting_key, user_id,
    old_value, new_value)`, in insertion (UUIDv7 `id`) order."""
    rows = await session.execute(
        select(
            SettingAuditEvent.event_type,
            SettingAuditEvent.setting_key,
            SettingAuditEvent.user_id,
            SettingAuditEvent.old_value,
            SettingAuditEvent.new_value,
        ).order_by(SettingAuditEvent.id)
    )
    return [tuple(row) for row in rows]


def _changed(user_id: uuid.UUID, old: str, new: str) -> tuple[Any, ...]:
    return ("setting_changed", _KEY, user_id, old, new)


def _is_row_lock(statement: str) -> bool:
    return (
        statement.lstrip().upper().startswith("SELECT")
        and "FROM system_setting" in statement
        and statement.rstrip().endswith("FOR UPDATE")
    )


def _indices(statements: list[str], predicate: Callable[[str], bool]) -> list[int]:
    return [i for i, s in enumerate(statements) if predicate(s)]


def _advisory(statements: list[str]) -> list[int]:
    return _indices(statements, lambda s: "advisory" in s)


@contextmanager
def _failing_statement(
    session: AsyncSession, prefix: str, error: BaseException
) -> Iterator[None]:
    """Raise `error` from the driver boundary when a statement starting with
    `prefix` is about to run on the test engine."""
    engine = session.get_bind().engine

    def _raise(*args: Any) -> None:
        if args[2].lstrip().startswith(prefix):
            raise error

    event.listen(engine, "before_cursor_execute", _raise)
    try:
        yield
    finally:
        event.remove(engine, "before_cursor_execute", _raise)


def _failing_execute(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    marker: str,
    error: BaseException,
) -> list[str]:
    """Make `session.execute()` raise `error` for a statement whose SQL
    contains `marker`; returns the SQL of every intercepted statement."""
    original = session.execute
    intercepted: list[str] = []

    async def _execute(statement: Executable, *args: Any, **kwargs: Any) -> Any:
        sql = str(statement)
        if marker in sql:
            intercepted.append(sql)
            raise error
        return await original(statement, *args, **kwargs)

    monkeypatch.setattr(session, "execute", _execute)
    return intercepted


def _database_error() -> OperationalError:
    return OperationalError(
        "SELECT fictional", None, ConnectionResetError("fictional reset by peer")
    )


# ---------------------------------------------------------------------------
# Effective change
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEffectiveChange:
    """The persisted row and its single event, in both directions, are
    proven by `TestCommitThroughCallersTransaction`."""

    async def test_flushes_without_committing_or_rolling_back(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _seed(system_setting_factory, "3.1")
        commit = AsyncMock(side_effect=AssertionError("commit"))
        rollback = AsyncMock(side_effect=AssertionError("rollback"))
        monkeypatch.setattr(db_session, "commit", commit)
        monkeypatch.setattr(db_session, "rollback", rollback)

        await update_default_cvss_version(
            db_session, new_version="4.0", acting_user_id=admin.id
        )

        commit.assert_not_called()
        rollback.assert_not_called()
        assert db_session.in_transaction()
        assert not db_session.dirty
        assert not db_session.new


@pytest.mark.integration
class TestCommitThroughCallersTransaction:
    """The update and its event become visible together, and only when the
    caller commits (testing-strategy.md, System Settings Mutation: each
    committing the setting row and its audit event through the caller's
    transaction)."""

    @pytest.mark.parametrize(("old", "new"), _CHANGES)
    async def test_caller_commit_publishes_the_row_and_the_event(
        self, db_session_factory: Factory, old: Version, new: Version
    ) -> None:
        setup = await db_session_factory()
        actor = User(
            username="settings.committer",
            email="settings.committer@example.com",
            password_hash="$2b$12$" + "c" * 53,
        )
        setup.add_all([actor, SystemSetting(key=_KEY, value=old)])
        await setup.commit()
        caller = await db_session_factory()
        probe = await db_session_factory()
        try:
            result = await update_default_cvss_version(
                caller, new_version=new, acting_user_id=actor.id
            )

            assert result == new
            assert await _persisted(probe) == old
            assert await _events(probe) == []
            await probe.rollback()

            await caller.commit()

            assert await _persisted(probe) == new
            assert await _events(probe) == [_changed(actor.id, old, new)]
            await probe.rollback()
        finally:
            # A failed assertion before the caller's commit must not leave
            # its row lock blocking the cleanup.
            await caller.rollback()
            await probe.rollback()
            cleanup = await db_session_factory()
            await cleanup.execute(
                delete(SettingAuditEvent).where(SettingAuditEvent.setting_key == _KEY)
            )
            await cleanup.execute(
                delete(SystemSetting).where(SystemSetting.key == _KEY)
            )
            await cleanup.execute(delete(User).where(User.id == actor.id))
            await cleanup.commit()


# ---------------------------------------------------------------------------
# Statement order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStatementOrder:
    async def test_row_lock_first_then_fence_before_the_writes(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        await _seed(system_setting_factory, "3.1")

        with StatementRecorder(db_session) as recorder:
            await update_default_cvss_version(
                db_session, new_version="4.0", acting_user_id=admin.id
            )

        statements = recorder.statements
        assert _is_row_lock(statements[0])
        assert len(recorder.row_locks()) == 1
        advisory = _advisory(statements)
        updates = _indices(statements, lambda s: s.startswith("UPDATE system_setting"))
        inserts = _indices(
            statements, lambda s: s.startswith("INSERT INTO setting_audit_event")
        )
        assert len(advisory) == len(updates) == len(inserts) == 1
        # The UPDATE and the audit INSERT share one flush, whose internal
        # order the contract leaves open.
        assert 0 < advisory[0] < min(updates[0], inserts[0])
        assert len(recorder.writes()) == 2

    async def test_fence_request_is_transaction_level_and_non_blocking(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        await _seed(system_setting_factory, "3.1")

        with StatementRecorder(db_session) as recorder:
            await update_default_cvss_version(
                db_session, new_version="4.0", acting_user_id=admin.id
            )

        [index] = _advisory(recorder.statements)
        assert f"{_ADVISORY}(" in recorder.statements[index]
        assert tuple(recorder.parameters[index]) == (EXECUTION_FENCE_ID,)


# ---------------------------------------------------------------------------
# No-op
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOp:
    @pytest.mark.parametrize("value", _VALUES)
    async def test_returns_the_persisted_value_after_only_the_row_lock(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
        value: Version,
    ) -> None:
        await _seed(system_setting_factory, value)

        with StatementRecorder(db_session) as recorder:
            result = await update_default_cvss_version(
                db_session, new_version=value, acting_user_id=admin.id
            )

        assert result == value
        assert len(recorder.statements) == 1
        assert _is_row_lock(recorder.statements[0])
        assert not db_session.dirty
        assert await _persisted(db_session) == value
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# Input validation and the required row
# ---------------------------------------------------------------------------


class _NoDatabase:
    """A stand-in session that fails on any attribute access."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"database access before validation: {name}")


@pytest.mark.unit
class TestOutOfSetValueWithoutSession:
    @pytest.mark.parametrize("value", _OUT_OF_SET)
    async def test_raises_value_error_before_touching_the_session(
        self, value: Any
    ) -> None:
        with pytest.raises(ValueError, match="new_version"):
            await update_default_cvss_version(
                cast(AsyncSession, _NoDatabase()),
                new_version=value,
                acting_user_id=_UNKNOWN_USER_ID,
            )


@pytest.mark.integration
class TestMissingRequiredRow:
    @pytest.mark.parametrize("value", _VALUES)
    async def test_raises_without_fallback_fence_or_event(
        self, db_session: AsyncSession, admin: User, value: Version
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(RequiredSystemSettingMissingError),
        ):
            await update_default_cvss_version(
                db_session, new_version=value, acting_user_id=admin.id
            )

        assert len(recorder.statements) == 1
        assert _is_row_lock(recorder.statements[0])
        assert await db_session.get(SystemSetting, _KEY) is None
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# Execution fence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFenceRequestFailure:
    """A database or session error during the fence request propagates
    unchanged and is never reported as the 409 exception."""

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(_database_error(), id="operational"),
            pytest.param(
                InterfaceError("SELECT fictional", None, Exception("closed")),
                id="interface",
            ),
        ],
    )
    async def test_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        await _seed(system_setting_factory, "3.1")
        intercepted = _failing_execute(db_session, monkeypatch, _ADVISORY, error)

        with pytest.raises(type(error)) as raised:
            await update_default_cvss_version(
                db_session, new_version="4.0", acting_user_id=admin.id
            )

        assert raised.value is error
        assert len(intercepted) == 1
        monkeypatch.undo()
        assert not db_session.dirty
        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# Atomicity
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollbackAtomicity:
    """Each failure, followed by the caller's rollback, leaves the prior
    value and no event (testing-strategy.md, System Settings Mutation)."""

    @staticmethod
    async def _assert_prior_state(session: AsyncSession) -> None:
        assert await _persisted(session) == "3.1"
        setting = await session.get(SystemSetting, _KEY, populate_existing=True)
        assert setting is not None
        assert setting.value == "3.1"
        assert await _events(session) == []

    async def test_audit_validation_failure(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
    ) -> None:
        await _seed(system_setting_factory, "3.1")

        with pytest.raises(ValueError, match="user_id is required"):
            async with rollback_test_scope(db_session):
                await update_default_cvss_version(
                    db_session,
                    new_version="4.0",
                    acting_user_id=None,  # type: ignore[arg-type]
                )

        await self._assert_prior_state(db_session)

    async def test_caller_rollback_after_success(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        await _seed(system_setting_factory, "3.1")

        async with rollback_test_scope(db_session):
            await update_default_cvss_version(
                db_session, new_version="4.0", acting_user_id=admin.id
            )
            assert await _persisted(db_session) == "4.0"
            assert len(await _events(db_session)) == 1

        await self._assert_prior_state(db_session)

    async def test_audit_insertion_failure(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
    ) -> None:
        """The audit INSERT violates the `user_id` foreign key in the
        database."""
        await _seed(system_setting_factory, "3.1")

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(IntegrityError, match="setting_audit_event"),
        ):
            async with rollback_test_scope(db_session):
                await update_default_cvss_version(
                    db_session, new_version="4.0", acting_user_id=_UNKNOWN_USER_ID
                )

        assert any(
            s.startswith("INSERT INTO setting_audit_event") for s in recorder.statements
        )
        await self._assert_prior_state(db_session)

    async def test_flush_failure(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The flush sends both writes and then reports a failure, as when
        the error surfaces after the statements reached PostgreSQL."""
        await _seed(system_setting_factory, "3.1")
        error = _database_error()
        real_flush = db_session.flush
        flushes: list[str] = []

        async def _flush_then_fail(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            flushes.append("flush")
            raise error

        monkeypatch.setattr(db_session, "flush", _flush_then_fail)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(OperationalError) as raised,
        ):
            async with rollback_test_scope(db_session):
                await update_default_cvss_version(
                    db_session, new_version="4.0", acting_user_id=admin.id
                )

        monkeypatch.undo()
        assert raised.value is error
        assert flushes == ["flush"]
        assert any(s.startswith("UPDATE system_setting") for s in recorder.statements)
        assert any(
            s.startswith("INSERT INTO setting_audit_event") for s in recorder.statements
        )
        await self._assert_prior_state(db_session)

    async def test_database_failure_on_the_setting_update(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        await _seed(system_setting_factory, "3.1")
        error = _database_error()

        with (
            pytest.raises(OperationalError) as raised,
            _failing_statement(db_session, "UPDATE system_setting", error),
        ):
            async with rollback_test_scope(db_session):
                await update_default_cvss_version(
                    db_session, new_version="4.0", acting_user_id=admin.id
                )

        assert raised.value is error
        await self._assert_prior_state(db_session)

    async def test_database_failure_on_the_row_lock(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _seed(system_setting_factory, "3.1")
        error = _database_error()

        intercepted = _failing_execute(db_session, monkeypatch, "FOR UPDATE", error)

        with pytest.raises(OperationalError) as raised:
            async with rollback_test_scope(db_session):
                await update_default_cvss_version(
                    db_session, new_version="4.0", acting_user_id=admin.id
                )

        assert raised.value is error
        assert len(intercepted) == 1
        monkeypatch.undo()
        await self._assert_prior_state(db_session)


# ---------------------------------------------------------------------------
# Locked-current classification
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestClassifiesAgainstTheLockedValue:
    """The identity map holds a stale `"3.1"` while the database holds
    `"4.0"`: classification uses the value read under the row lock, never
    an observation made before it."""

    @staticmethod
    async def _stale(
        session: AsyncSession, system_setting_factory: SettingFactory
    ) -> SystemSetting:
        setting = await _seed(system_setting_factory, "3.1")
        await session.execute(
            update(SystemSetting)
            .where(SystemSetting.key == _KEY)
            .values(value="4.0")
            .execution_options(synchronize_session=False)
        )
        assert setting.value == "3.1"
        assert await _persisted(session) == "4.0"
        return setting

    async def test_request_equal_to_the_stale_value_is_an_effective_change(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        # The identity map holds weak references: keep the stale instance
        # alive so the service's lock query meets it.
        setting = await self._stale(db_session, system_setting_factory)

        result = await update_default_cvss_version(
            db_session, new_version="3.1", acting_user_id=admin.id
        )

        assert result == "3.1"
        assert setting.value == "3.1"
        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == [_changed(admin.id, "4.0", "3.1")]

    async def test_request_equal_to_the_locked_value_is_a_no_op(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        setting = await self._stale(db_session, system_setting_factory)

        with StatementRecorder(db_session) as recorder:
            result = await update_default_cvss_version(
                db_session, new_version="4.0", acting_user_id=admin.id
            )

        assert result == "4.0"
        assert setting.value == "4.0"
        assert recorder.writes() == []
        assert _advisory(recorder.statements) == []
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# Re-invocation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReinvocation:
    async def test_repeating_an_effective_change_is_a_no_op(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
    ) -> None:
        await _seed(system_setting_factory, "3.1")
        await update_default_cvss_version(
            db_session, new_version="4.0", acting_user_id=admin.id
        )

        with StatementRecorder(db_session) as recorder:
            result = await update_default_cvss_version(
                db_session, new_version="4.0", acting_user_id=admin.id
            )

        assert result == "4.0"
        assert recorder.writes() == []
        assert _advisory(recorder.statements) == []
        assert await _events(db_session) == [_changed(admin.id, "3.1", "4.0")]

    async def test_each_effective_change_creates_one_event(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        user_factory: UserFactory,
        admin: User,
    ) -> None:
        other = await user_factory(
            username="settings.other", email="settings.other@example.com"
        )
        await _seed(system_setting_factory, "3.1")

        await update_default_cvss_version(
            db_session, new_version="4.0", acting_user_id=admin.id
        )
        await update_default_cvss_version(
            db_session, new_version="3.1", acting_user_id=other.id
        )

        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == [
            _changed(admin.id, "3.1", "4.0"),
            _changed(other.id, "4.0", "3.1"),
        ]


# ---------------------------------------------------------------------------
# External side effects
# ---------------------------------------------------------------------------


@pytest.fixture
def external_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every Redis, lease, session-level fence, publication, Celery,
    and post-commit entry point with a recorder that also fails the call."""
    calls: list[str] = []

    def _forbidden(name: str) -> Callable[..., Any]:
        def _call(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"unexpected external side effect: {name}")

        return _call

    targets: list[tuple[object, str]] = [
        (redis_asyncio.Redis, "from_url"),
        (redis.Redis, "from_url"),
        (coordination, "new_cvss_recalculation_redis_client"),
        (coordination, "acquire_lease"),
        (coordination, "compare_and_renew_lease"),
        (coordination, "compare_and_delete_lease"),
        (coordination, "try_acquire_execution_fence"),
        (coordination, "release_execution_fence"),
        (task_publication, "publish_task"),
        (celery.Celery, "send_task"),
        (celery.app.task.Task, "apply_async"),
        (database, "register_post_commit_callback"),
    ]
    for target, name in targets:
        monkeypatch.setattr(target, name, _forbidden(name))
    return calls


@pytest.mark.integration
class TestNoExternalSideEffects:
    @pytest.mark.parametrize(
        ("old", "new"),
        [
            pytest.param("3.1", "4.0", id="effective"),
            pytest.param("3.1", "3.1", id="no-op"),
        ],
    )
    async def test_no_redis_lease_publication_or_post_commit_callback(
        self,
        db_session: AsyncSession,
        system_setting_factory: SettingFactory,
        admin: User,
        external_calls: list[str],
        old: Version,
        new: Version,
    ) -> None:
        await _seed(system_setting_factory, old)

        result = await update_default_cvss_version(
            db_session, new_version=new, acting_user_id=admin.id
        )

        assert result == new
        assert external_calls == []
        assert db_session.info.get(database._POST_COMMIT_CALLBACKS_KEY, []) == []
