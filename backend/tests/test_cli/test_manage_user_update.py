"""Tests for `sentinel manage-user update`.

See docs/features/identity/user-management.md (`sentinel manage-user
update`) for the authoritative contract exercised here: lookup-first
ordering, single-mode selection, the per-mode guards and exact messages,
result-derived reporting, and the atomic single-operation transaction.
docs/features/platform/testing-strategy.md (Manual role mutation CLI, CLI
Commands, Sync Entry-Point Tests) defines the required coverage.

Every test invoking the command is a synchronous `def`. Integration tests
run against the real PostgreSQL test database through
`cli_session_factory`; setup rows are committed directly through that
factory and removed by `cleanup_users_by_username` (plus the module-local
`ticket_ids` fixture for Tickets). Unit tests replace the session factory
and the `user_service` operations with in-memory doubles.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import click
import pytest
from click.testing import CliRunner, Result
from sqlalchemy import delete, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.cli.manage_user as manage_user_module
from app.cli import cli, main
from app.core.enums import (
    IdentityAuditEventType,
    Role,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import UserNotFoundError
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import user_service as user_service_module
from app.services.user_service import (
    ExternalUserFieldReadOnlyError,
    ExternalUserStatusReadOnlyError,
    ReactivationResult,
    RoleUpdateResult,
    UserUpdateResult,
)

_MANUAL = "_manual"
_EXTERNAL_GROUP = "Example Security Group"
_PARTIAL_SUCCESS_MARKERS = ("✓", "✗", "—")
_COMBINED_MODES_ERROR = (
    "Error: Profile updates, role updates, and --reactivate cannot be combined."
)
_FULL_NAME_CONFLICT_ERROR = (
    "Error: --full-name and --clear-full-name cannot be used together."
)
_EXTERNAL_REACTIVATION_ERROR = "Error: Cannot reactivate external users."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _username(tag: str) -> str:
    """A unique, format-valid username so parallel workers never collide."""
    return f"{tag}.{uuid4().hex[:10]}"


def _invoke(args: list[str], **extra: Any) -> Result:
    """Invoke `manage-user update` through the raw `cli` group with
    `standalone_mode=False`, mirroring how production's `main()` invokes
    it."""
    return CliRunner().invoke(
        cli, ["manage-user", "update", *args], standalone_mode=False, **extra
    )


def _inject_session_factory(monkeypatch: pytest.MonkeyPatch, factory: object) -> None:
    monkeypatch.setattr(manage_user_module, "get_session_factory", lambda: factory)


def _assert_no_partial_success_lines(result: Result) -> None:
    for marker in _PARTIAL_SUCCESS_MARKERS:
        assert marker not in result.stdout
        assert marker not in result.stderr


def _assert_success(result: Result, message: str) -> None:
    """Exit 0, exactly `message` on stdout, and nothing on stderr."""
    assert result.exit_code == 0, result.output
    assert result.stdout == f"{message}\n"
    assert result.stderr == ""
    _assert_no_partial_success_lines(result)


def _assert_error(result: Result, message: str) -> None:
    """Exit 1, exactly `message` on stderr, and nothing on stdout."""
    assert result.exit_code == 1, result.output
    assert result.stderr == f"{message}\n"
    assert result.stdout == ""
    _assert_no_partial_success_lines(result)


def _not_found(username: str) -> str:
    return f"Error: User '{username}' not found."


def _external_profile_error(username: str) -> str:
    return (
        f"Error: User '{username}' is managed by an external identity provider. "
        "Identity fields cannot be modified manually."
    )


class _CountingSessionFactory:
    """Delegates to a real session factory, counting opened sessions."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.calls = 0

    def __call__(self) -> AsyncSession:
        self.calls += 1
        return self._factory()


def _forbidden_session_factory() -> None:
    raise AssertionError("the command must not access the database")


def _count_commits(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Count every `AsyncSession.commit()` from this point on; install only
    after the test's own setup commits."""
    counter = {"n": 0}
    original_commit = AsyncSession.commit

    async def _counting_commit(self: AsyncSession) -> None:
        counter["n"] += 1
        await original_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", _counting_commit)
    return counter


def _spy_asyncio_run(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the command module's `asyncio` with a namespace whose `run`
    delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(manage_user_module, "asyncio", SimpleNamespace(run=spy))
    return spy


async def _create_user(
    factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
    email: str | None = None,
    full_name: str | None = None,
    active: bool = True,
    external: bool = False,
    roles: list[tuple[Role, str]] | None = None,
) -> User:
    """Insert and commit a `User` with optional roles, bypassing
    `user_service` (setup only)."""
    async with factory() as db:
        user = User(
            username=username,
            email=email or f"{username}@example.com",
            full_name=full_name,
            active=active,
            external_id=uuid4() if external else None,
            password_hash=None if external else "$2b$12$" + "a" * 53,
        )
        db.add(user)
        await db.flush()
        for role, group_name in roles or []:
            db.add(UserRole(user_id=user.id, role=role.value, group_name=group_name))
        await db.commit()
        return user


async def _fetch_user(factory: async_sessionmaker[AsyncSession], user_id: UUID) -> User:
    async with factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        return user


async def _fetch_roles(
    factory: async_sessionmaker[AsyncSession], user_id: UUID
) -> list[UserRole]:
    async with factory() as db:
        rows = await db.scalars(
            select(UserRole)
            .where(UserRole.user_id == user_id)
            .order_by(UserRole.role, UserRole.group_name)
        )
        return list(rows)


async def _fetch_identity_events(
    factory: async_sessionmaker[AsyncSession], user_id: UUID
) -> list[IdentityAuditEvent]:
    async with factory() as db:
        rows = await db.scalars(
            select(IdentityAuditEvent)
            .where(IdentityAuditEvent.target_user_id == user_id)
            .order_by(IdentityAuditEvent.id)
        )
        return list(rows)


async def _fetch_ticket(
    factory: async_sessionmaker[AsyncSession], ticket_id: UUID
) -> Ticket:
    async with factory() as db:
        ticket = await db.get(Ticket, ticket_id)
        assert ticket is not None
        return ticket


async def _fetch_ticket_events(
    factory: async_sessionmaker[AsyncSession], ticket_ids: list[UUID]
) -> list[TicketAuditEvent]:
    async with factory() as db:
        rows = await db.scalars(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(ticket_ids))
            .order_by(TicketAuditEvent.id)
        )
        return list(rows)


async def _create_ticket(
    factory: async_sessionmaker[AsyncSession],
    tracked: list[UUID],
    *,
    status: TicketStatus,
    assignee_id: UUID,
) -> UUID:
    """Insert and commit a minimal Ticket, registering it for cleanup."""
    async with factory() as db:
        ticket = Ticket(
            status=status.value,
            cve_id=None,
            is_confidential=False,
            assignee_id=assignee_id,
        )
        db.add(ticket)
        await db.flush()
        tracked.append(ticket.id)
        await db.commit()
        return ticket.id


def _event_tuples(
    events: list[IdentityAuditEvent],
) -> list[tuple[str, UUID | None, str | None, str | None, object]]:
    return [
        (e.event_type, e.user_id, e.old_value, e.new_value, e.detail) for e in events
    ]


def _role_tuples(rows: list[UserRole]) -> list[tuple[str, str, UUID | None]]:
    return [(r.role, r.group_name, r.assigned_by) for r in rows]


def _snapshot(
    factory: async_sessionmaker[AsyncSession], user_id: UUID
) -> tuple[object, ...]:
    """Persisted user state used to prove that a rejection changed nothing."""
    user = asyncio.run(_fetch_user(factory, user_id))
    roles = asyncio.run(_fetch_roles(factory, user_id))
    return (
        user.email,
        user.full_name,
        user.active,
        [(r.role, r.group_name) for r in roles],
    )


@pytest.fixture
def ticket_ids(
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> Iterator[list[UUID]]:
    """Collect committed Ticket IDs and delete them (with their audit
    events) at teardown.

    Depends on `cleanup_users_by_username` so this teardown runs before the
    user cleanup: the Tickets reference the users as assignees.
    """
    tracked: list[UUID] = []
    yield tracked
    if not tracked:
        return

    async def _cleanup() -> None:
        async with cli_session_factory() as db:
            await db.execute(
                delete(TicketAuditEvent).where(TicketAuditEvent.ticket_id.in_(tracked))
            )
            await db.execute(delete(Ticket).where(Ticket.id.in_(tracked)))
            await db.commit()

    asyncio.run(_cleanup())


# ---------------------------------------------------------------------------
# Unit doubles: fake session factory and mocked user_service operations
# ---------------------------------------------------------------------------


_FAKE_USER_ID = UUID("01900000-0000-7000-8000-000000000001")


class _FakeSession:
    """Records direct statement execution and transaction control."""

    def __init__(self) -> None:
        self.executed: list[tuple[object, ...]] = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, *args: object, **kwargs: object) -> None:
        self.executed.append(args)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


class _FakeSessionContext:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def __aenter__(self) -> _FakeSession:
        return self._session

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _FakeSessionFactory:
    def __init__(self) -> None:
        self.sessions: list[_FakeSession] = []

    def __call__(self) -> _FakeSessionContext:
        session = _FakeSession()
        self.sessions.append(session)
        return _FakeSessionContext(session)


def _result_user() -> User:
    return User(username="alice.example", email="alice.example@example.com")


_MUTATING_SERVICES = (
    "update_user",
    "update_roles",
    "reactivate_user",
    "create_user",
    "reset_password",
    "unlock_user",
)


@pytest.fixture
def fake_factory(monkeypatch: pytest.MonkeyPatch) -> _FakeSessionFactory:
    factory = _FakeSessionFactory()
    _inject_session_factory(monkeypatch, factory)
    return factory


@pytest.fixture
def fake_services(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Replace the lookup and every mutating `user_service` operation."""
    services = SimpleNamespace(
        get_user=AsyncMock(
            return_value=SimpleNamespace(id=_FAKE_USER_ID, external_id=None)
        ),
        update_user=AsyncMock(
            return_value=UserUpdateResult(
                user=_result_user(), changed_fields=["email", "full_name"]
            )
        ),
        update_roles=AsyncMock(
            return_value=RoleUpdateResult(
                user=_result_user(),
                added_roles=[Role.ADMIN],
                removed_roles=[Role.VULNERABILITY_ANALYST],
            )
        ),
        reactivate_user=AsyncMock(
            return_value=ReactivationResult(user=_result_user(), reactivated=True)
        ),
        create_user=AsyncMock(),
        reset_password=AsyncMock(),
        unlock_user=AsyncMock(),
    )
    for name in ("get_user", *_MUTATING_SERVICES):
        monkeypatch.setattr(user_service_module, name, getattr(services, name))
    return services


def _assert_only_service_awaited(services: SimpleNamespace, name: str) -> None:
    for other in _MUTATING_SERVICES:
        mock: AsyncMock = getattr(services, other)
        if other == name:
            assert mock.await_count == 1
        else:
            mock.assert_not_awaited()


def _assert_single_transaction(factory: _FakeSessionFactory) -> _FakeSession:
    """One read-only lookup session (no commit) followed by one mutating
    session committed exactly once; the CLI itself executes nothing."""
    assert len(factory.sessions) == 2
    lookup, mutating = factory.sessions
    assert lookup.commits == 0
    assert mutating.commits == 1
    assert mutating.rollbacks == 0
    for session in factory.sessions:
        assert session.executed == []
    return mutating


# ---------------------------------------------------------------------------
# Unit: delegation to exactly one service operation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_lookup_uses_normalized_username(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    result = _invoke(["--username", "  Alice.Example  ", "--reactivate"])

    assert result.exit_code == 0, result.output
    fake_services.get_user.assert_awaited_once_with(
        fake_factory.sessions[0], "alice.example"
    )


@pytest.mark.unit
def test_profile_email_only_delegates_normalized_email_without_full_name(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    fake_services.update_user.return_value = UserUpdateResult(
        user=_result_user(), changed_fields=["email"]
    )

    result = _invoke(
        ["--username", "alice.example", "--email", "  New.Mail@Example.COM "]
    )

    _assert_success(result, "Updated user 'alice.example': email.")
    mutating = _assert_single_transaction(fake_factory)
    _assert_only_service_awaited(fake_services, "update_user")
    fake_services.update_user.assert_awaited_once_with(
        mutating, _FAKE_USER_ID, acting_user_id=None, email="new.mail@example.com"
    )
    assert "full_name" not in fake_services.update_user.await_args.kwargs


@pytest.mark.unit
def test_profile_full_name_only_delegates_without_email(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    fake_services.update_user.return_value = UserUpdateResult(
        user=_result_user(), changed_fields=["full_name"]
    )

    result = _invoke(["--username", "alice.example", "--full-name", "Alice Example"])

    _assert_success(result, "Updated user 'alice.example': full name.")
    mutating = _assert_single_transaction(fake_factory)
    _assert_only_service_awaited(fake_services, "update_user")
    fake_services.update_user.assert_awaited_once_with(
        mutating, _FAKE_USER_ID, acting_user_id=None, full_name="Alice Example"
    )
    assert "email" not in fake_services.update_user.await_args.kwargs


@pytest.mark.unit
def test_profile_email_and_full_name_delegate_in_one_call(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    result = _invoke(
        [
            "--username",
            "alice.example",
            "--full-name",
            "Alice Example",
            "--email",
            "Alice.New@Example.com",
        ]
    )

    _assert_success(result, "Updated user 'alice.example': email, full name.")
    mutating = _assert_single_transaction(fake_factory)
    _assert_only_service_awaited(fake_services, "update_user")
    fake_services.update_user.assert_awaited_once_with(
        mutating,
        _FAKE_USER_ID,
        acting_user_id=None,
        email="alice.new@example.com",
        full_name="Alice Example",
    )


@pytest.mark.unit
def test_profile_clear_full_name_sends_explicit_none(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    fake_services.update_user.return_value = UserUpdateResult(
        user=_result_user(), changed_fields=["full_name"]
    )

    result = _invoke(["--username", "alice.example", "--clear-full-name"])

    _assert_success(result, "Updated user 'alice.example': full name.")
    mutating = _assert_single_transaction(fake_factory)
    fake_services.update_user.assert_awaited_once_with(
        mutating, _FAKE_USER_ID, acting_user_id=None, full_name=None
    )
    assert "email" not in fake_services.update_user.await_args.kwargs


@pytest.mark.unit
def test_profile_clear_full_name_with_email_delegates_both(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    result = _invoke(
        [
            "--username",
            "alice.example",
            "--clear-full-name",
            "--email",
            "alice.new@example.com",
        ]
    )

    assert result.exit_code == 0, result.output
    mutating = _assert_single_transaction(fake_factory)
    fake_services.update_user.assert_awaited_once_with(
        mutating,
        _FAKE_USER_ID,
        acting_user_id=None,
        email="alice.new@example.com",
        full_name=None,
    )


@pytest.mark.unit
def test_profile_empty_full_name_is_passed_verbatim(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    result = _invoke(["--username", "alice.example", "--full-name", ""])

    assert result.exit_code == 0, result.output
    mutating = _assert_single_transaction(fake_factory)
    fake_services.update_user.assert_awaited_once_with(
        mutating, _FAKE_USER_ID, acting_user_id=None, full_name=""
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("args", "expected_add", "expected_remove"),
    [
        pytest.param(
            [
                "--add-role",
                "restricted_analyst",
                "--add-role",
                "admin",
                "--add-role",
                "admin",
                "--add-role",
                "vulnerability_analyst",
                "--remove-role",
                "vulnerability_analyst",
            ],
            [Role.ADMIN, Role.RESTRICTED_ANALYST],
            [],
            id="dedup-sort-and-cancel-overlap",
        ),
        pytest.param(
            [
                "--remove-role",
                "vulnerability_analyst",
                "--remove-role",
                "admin",
                "--remove-role",
                "admin",
            ],
            [],
            [Role.ADMIN, Role.VULNERABILITY_ANALYST],
            id="remove-dedup-and-sort",
        ),
        pytest.param(
            [
                "--add-role",
                "vulnerability_analyst",
                "--remove-role",
                "restricted_analyst",
                "--add-role",
                "admin",
            ],
            [Role.ADMIN, Role.VULNERABILITY_ANALYST],
            [Role.RESTRICTED_ANALYST],
            id="both-sides",
        ),
        pytest.param(
            ["--add-role", "admin", "--remove-role", "admin"],
            [],
            [],
            id="full-overlap",
        ),
    ],
)
def test_role_mode_delegates_deduplicated_cancelled_sorted_roles(
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
    args: list[str],
    expected_add: list[Role],
    expected_remove: list[Role],
) -> None:
    result = _invoke(["--username", "alice.example", *args])

    assert result.exit_code == 0, result.output
    mutating = _assert_single_transaction(fake_factory)
    _assert_only_service_awaited(fake_services, "update_roles")
    fake_services.update_roles.assert_awaited_once_with(
        mutating,
        _FAKE_USER_ID,
        add=expected_add,
        remove=expected_remove,
        acting_user_id=None,
    )
    kwargs = fake_services.update_roles.await_args.kwargs
    for role in (*kwargs["add"], *kwargs["remove"]):
        assert type(role) is Role


@pytest.mark.unit
def test_role_mode_report_derives_only_from_result(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    """Only `restricted_analyst` is requested; the output repeats exactly
    what the service returned."""
    fake_services.update_roles.return_value = RoleUpdateResult(
        user=_result_user(),
        added_roles=[Role.ADMIN, Role.RESTRICTED_ANALYST],
        removed_roles=[Role.VULNERABILITY_ANALYST],
    )

    result = _invoke(
        ["--username", "alice.example", "--add-role", "restricted_analyst"]
    )

    _assert_success(
        result,
        "Updated user 'alice.example': roles: added 'admin', "
        "'restricted_analyst'; removed 'vulnerability_analyst'.",
    )


@pytest.mark.unit
def test_reactivation_mode_delegates_to_reactivate_user(
    fake_factory: _FakeSessionFactory, fake_services: SimpleNamespace
) -> None:
    result = _invoke(["--username", "alice.example", "--reactivate"])

    _assert_success(result, "Reactivated user 'alice.example'.")
    mutating = _assert_single_transaction(fake_factory)
    _assert_only_service_awaited(fake_services, "reactivate_user")
    fake_services.reactivate_user.assert_awaited_once_with(
        mutating, _FAKE_USER_ID, acting_user_id=None
    )


# ---------------------------------------------------------------------------
# Unit: defensive mapping of service exceptions
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("args", "service", "exception", "expected"),
    [
        pytest.param(
            ["--email", "alice.new@example.com"],
            "update_user",
            UserNotFoundError(),
            _not_found("alice.example"),
            id="update_user-not-found",
        ),
        pytest.param(
            ["--add-role", "admin"],
            "update_roles",
            UserNotFoundError(),
            _not_found("alice.example"),
            id="update_roles-not-found",
        ),
        pytest.param(
            ["--reactivate"],
            "reactivate_user",
            UserNotFoundError(),
            _not_found("alice.example"),
            id="reactivate_user-not-found",
        ),
        pytest.param(
            ["--full-name", "Alice Example"],
            "update_user",
            ExternalUserFieldReadOnlyError(),
            _external_profile_error("alice.example"),
            id="update_user-external-field",
        ),
        pytest.param(
            ["--reactivate"],
            "reactivate_user",
            ExternalUserStatusReadOnlyError(),
            _EXTERNAL_REACTIVATION_ERROR,
            id="reactivate_user-external-status",
        ),
    ],
)
def test_service_exception_is_mapped_and_rolled_back(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
    args: list[str],
    service: str,
    exception: Exception,
    expected: str,
) -> None:
    monkeypatch.setattr(user_service_module, service, AsyncMock(side_effect=exception))

    result = _invoke(["--username", "alice.example", *args])

    _assert_error(result, expected)
    assert len(fake_factory.sessions) == 2
    assert [s.commits for s in fake_factory.sessions] == [0, 0]
    assert fake_factory.sessions[1].rollbacks == 1


# ---------------------------------------------------------------------------
# Unit: system error exit code through the real `main()`
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_database_unreachable_exits_two_through_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fake_factory: _FakeSessionFactory,
) -> None:
    monkeypatch.setattr(
        user_service_module,
        "get_user",
        AsyncMock(
            side_effect=OperationalError(
                "SELECT 1", {}, Exception("connection refused")
            )
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sentinel", "manage-user", "update", "--username", "alice.example"],
    )
    previous_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }

    try:
        with pytest.raises(SystemExit) as exc_info:
            main()
    finally:
        for signum, handler in previous_handlers.items():
            if handler is not None:
                signal.signal(signum, handler)

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("Error: ")
    assert captured.out == ""


# ---------------------------------------------------------------------------
# Integration: ordering (username format, lookup, no modification)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_invalid_username_rejected_before_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inject_session_factory(monkeypatch, _forbidden_session_factory)
    run_spy = _spy_asyncio_run(monkeypatch)

    result = _invoke(["--username", "  9BAD ", "--reactivate"])

    _assert_error(
        result,
        "Error: Invalid username '9bad'. Username must be 1-64 characters, "
        "start with a letter, and contain only lowercase letters, numbers, "
        "dots, hyphens, and underscores.",
    )
    assert run_spy.call_count == 0


@pytest.mark.integration
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(
            ["--email", "alice@example.com", "--add-role", "admin", "--reactivate"],
            id="cross-mode",
        ),
        pytest.param(
            ["--full-name", "Alice Example", "--clear-full-name"],
            id="full-name-conflict",
        ),
        pytest.param(["--add-role", "bogus"], id="invalid-role"),
        pytest.param([], id="no-modification"),
    ],
)
def test_unknown_username_reported_before_mode_rejections(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    args: list[str],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("nobody")

    result = _invoke(["--username", username, *args])

    _assert_error(result, _not_found(username))


@pytest.mark.integration
def test_no_modification_flags_prints_no_changes_specified(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.nochange")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    commits = _count_commits(monkeypatch)

    result = _invoke(["--username", username])

    _assert_success(result, f"No changes specified for user '{username}'.")
    assert factory.calls == 1
    assert commits["n"] == 0
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


# ---------------------------------------------------------------------------
# Integration: mode selection conflicts
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize(
    ("args", "expected"),
    [
        pytest.param(
            ["--email", "alice.other@example.com", "--add-role", "admin"],
            _COMBINED_MODES_ERROR,
            id="profile-and-role",
        ),
        pytest.param(
            ["--full-name", "Alice Other", "--reactivate"],
            _COMBINED_MODES_ERROR,
            id="profile-and-reactivate",
        ),
        pytest.param(
            ["--remove-role", "admin", "--reactivate"],
            _COMBINED_MODES_ERROR,
            id="role-and-reactivate",
        ),
        pytest.param(
            ["--clear-full-name", "--add-role", "admin", "--reactivate"],
            _COMBINED_MODES_ERROR,
            id="all-three",
        ),
        pytest.param(
            ["--full-name", "Alice Other", "--clear-full-name"],
            _FULL_NAME_CONFLICT_ERROR,
            id="full-name-and-clear",
        ),
    ],
)
def test_mode_conflict_rejected_without_mutating_session(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    args: list[str],
    expected: str,
) -> None:
    username = _username("alice.conflict")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            full_name="Alice Example",
            active=False,
            roles=[(Role.ADMIN, _MANUAL)],
        )
    )
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)

    result = _invoke(["--username", username, *args])

    _assert_error(result, expected)
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


# ---------------------------------------------------------------------------
# Integration: profile mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_profile_email_only_success(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.email")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, full_name="Alice Example")
    )
    new_email = f"{username}.new@example.com"

    result = _invoke(
        ["--username", username, "--email", f"  {username.upper()}.New@Example.COM "]
    )

    _assert_success(result, f"Updated user '{username}': email.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.email == new_email
    assert refreshed.full_name == "Alice Example"
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.EMAIL_CHANGED.value,
            None,
            f"{username}@example.com",
            new_email,
            None,
        )
    ]


@pytest.mark.integration
def test_profile_full_name_only_success_on_inactive_user(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.fullname")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            full_name="Alice Example",
            active=False,
        )
    )

    result = _invoke(["--username", username, "--full-name", "Alice Renamed"])

    _assert_success(result, f"Updated user '{username}': full name.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.full_name == "Alice Renamed"
    assert refreshed.email == f"{username}@example.com"
    assert refreshed.active is False
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.FULL_NAME_CHANGED.value,
            None,
            "Alice Example",
            "Alice Renamed",
            None,
        )
    ]


@pytest.mark.integration
def test_profile_email_and_full_name_success_in_fixed_order(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.both")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    new_email = f"{username}.new@example.com"

    result = _invoke(
        ["--username", username, "--full-name", "Alice Example", "--email", new_email]
    )

    _assert_success(result, f"Updated user '{username}': email, full name.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.email == new_email
    assert refreshed.full_name == "Alice Example"
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert sorted(_event_tuples(events), key=lambda e: e[0]) == [
        (
            IdentityAuditEventType.EMAIL_CHANGED.value,
            None,
            f"{username}@example.com",
            new_email,
            None,
        ),
        (
            IdentityAuditEventType.FULL_NAME_CHANGED.value,
            None,
            None,
            "Alice Example",
            None,
        ),
    ]


@pytest.mark.integration
def test_profile_clear_full_name_clears_existing_name(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.clear")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, full_name="Alice Example")
    )

    result = _invoke(["--username", username, "--clear-full-name"])

    _assert_success(result, f"Updated user '{username}': full name.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.full_name is None
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.FULL_NAME_CHANGED.value,
            None,
            "Alice Example",
            None,
            None,
        )
    ]


@pytest.mark.integration
def test_profile_clear_full_name_already_null_is_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.clearnull")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))

    result = _invoke(["--username", username, "--clear-full-name"])

    _assert_success(result, f"No changes applied to user '{username}'.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.full_name is None
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_profile_empty_full_name_is_stored_not_cleared(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """Starting from NULL: a clear would be a no-op, while `''` is an
    ordinary value that effectively changes the field."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.emptyname")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))

    result = _invoke(["--username", username, "--full-name", ""])

    _assert_success(result, f"Updated user '{username}': full name.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.full_name == ""
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (IdentityAuditEventType.FULL_NAME_CHANGED.value, None, None, "", None)
    ]


@pytest.mark.integration
def test_profile_invalid_email_rejected_without_mutating_session(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.bademail")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)

    result = _invoke(["--username", username, "--email", "  Not-An-Email "])

    _assert_error(result, "Error: Invalid email format 'not-an-email'.")
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before


@pytest.mark.integration
def test_profile_duplicate_email_rejected_and_commits_zero_times(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.dupemail")
    owner = _username("bob.owner")
    cleanup_users_by_username(username, owner)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, full_name="Alice Example")
    )
    asyncio.run(_create_user(cli_session_factory, username=owner))
    before = _snapshot(cli_session_factory, user.id)
    commits = _count_commits(monkeypatch)

    result = _invoke(
        [
            "--username",
            username,
            "--email",
            f"{owner.upper()}@Example.com",
            "--full-name",
            "Alice Renamed",
        ]
    )

    _assert_error(
        result, f"Error: A user with email '{owner}@example.com' already exists."
    )
    assert commits["n"] == 0
    assert _snapshot(cli_session_factory, user.id) == before
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_profile_stale_pre_read_suggesting_change_prints_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """The lookup still sees the old email; a concurrent writer commits the
    requested email before the service locks the row."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.stalenoop")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    new_email = f"{username}.new@example.com"
    original_update_user = user_service_module.update_user

    async def _concurrent_write_then_delegate(*args: Any, **kwargs: Any) -> Any:
        async with cli_session_factory() as other:
            await other.execute(
                update(User).where(User.id == user.id).values(email=new_email)
            )
            await other.commit()
        return await original_update_user(*args, **kwargs)

    monkeypatch.setattr(
        user_service_module, "update_user", _concurrent_write_then_delegate
    )

    result = _invoke(["--username", username, "--email", new_email])

    _assert_success(result, f"No changes applied to user '{username}'.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.email == new_email
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_profile_stale_pre_read_suggesting_noop_prints_update(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """The lookup sees the requested name already stored; a concurrent
    writer changes it before the service locks the row."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.stalechange")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, full_name="Alice Example")
    )
    original_update_user = user_service_module.update_user

    async def _concurrent_write_then_delegate(*args: Any, **kwargs: Any) -> Any:
        async with cli_session_factory() as other:
            await other.execute(
                update(User)
                .where(User.id == user.id)
                .values(full_name="Alice Concurrent")
            )
            await other.commit()
        return await original_update_user(*args, **kwargs)

    monkeypatch.setattr(
        user_service_module, "update_user", _concurrent_write_then_delegate
    )

    result = _invoke(["--username", username, "--full-name", "Alice Example"])

    _assert_success(result, f"Updated user '{username}': full name.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.full_name == "Alice Example"
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.FULL_NAME_CHANGED.value,
            None,
            "Alice Concurrent",
            "Alice Example",
            None,
        )
    ]


@pytest.mark.integration
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--email", "alice.ext.new@example.com"], id="email"),
        pytest.param(["--full-name", "Alice Example"], id="full-name"),
        pytest.param(["--clear-full-name"], id="clear-full-name"),
        pytest.param(["--email", "not-an-email"], id="guard-before-email-format"),
    ],
)
def test_profile_external_user_rejected_without_mutating_session(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    args: list[str],
) -> None:
    username = _username("alice.extprofile")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            full_name="Alice External",
            external=True,
        )
    )
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)

    result = _invoke(["--username", username, *args])

    _assert_error(result, _external_profile_error(username))
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


# ---------------------------------------------------------------------------
# Integration: role mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_role_add_admin_to_user_without_roles_records_null_actor(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.recovery")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))

    result = _invoke(["--username", username, "--add-role", "admin"])

    _assert_success(result, f"Updated user '{username}': roles: added 'admin'.")
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [(Role.ADMIN.value, _MANUAL, None)]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (IdentityAuditEventType.ROLE_ADDED.value, None, None, "admin", None)
    ]


@pytest.mark.integration
def test_role_remove_only_on_inactive_user(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.removeonly")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            active=False,
            roles=[(Role.RESTRICTED_ANALYST, _MANUAL)],
        )
    )

    result = _invoke(["--username", username, "--remove-role", "restricted_analyst"])

    _assert_success(
        result, f"Updated user '{username}': roles: removed 'restricted_analyst'."
    )
    assert asyncio.run(_fetch_roles(cli_session_factory, user.id)) == []
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.active is False
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.ROLE_REMOVED.value,
            None,
            "restricted_analyst",
            None,
            None,
        )
    ]


@pytest.mark.integration
def test_role_add_and_remove_multi_role_rendering(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.multirole")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            roles=[(Role.VULNERABILITY_ANALYST, _MANUAL)],
        )
    )

    result = _invoke(
        [
            "--username",
            username,
            "--add-role",
            "restricted_analyst",
            "--remove-role",
            "vulnerability_analyst",
            "--add-role",
            "admin",
        ]
    )

    _assert_success(
        result,
        f"Updated user '{username}': roles: added 'admin', 'restricted_analyst'; "
        "removed 'vulnerability_analyst'.",
    )
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [
        (Role.ADMIN.value, _MANUAL, None),
        (Role.RESTRICTED_ANALYST.value, _MANUAL, None),
    ]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (IdentityAuditEventType.ROLE_ADDED.value, None, None, "admin", None),
        (
            IdentityAuditEventType.ROLE_ADDED.value,
            None,
            None,
            "restricted_analyst",
            None,
        ),
        (
            IdentityAuditEventType.ROLE_REMOVED.value,
            None,
            "vulnerability_analyst",
            None,
            None,
        ),
    ]


@pytest.mark.integration
def test_role_repeated_option_is_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.dedup")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))

    result = _invoke(
        ["--username", username, "--add-role", "admin", "--add-role", "admin"]
    )

    _assert_success(result, f"Updated user '{username}': roles: added 'admin'.")
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [(Role.ADMIN.value, _MANUAL, None)]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert len(events) == 1


@pytest.mark.integration
def test_role_overlap_is_cancelled_silently(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.overlap")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory, username=username, roles=[(Role.ADMIN, _MANUAL)]
        )
    )

    result = _invoke(
        [
            "--username",
            username,
            "--add-role",
            "admin",
            "--remove-role",
            "admin",
            "--add-role",
            "restricted_analyst",
        ]
    )

    _assert_success(
        result, f"Updated user '{username}': roles: added 'restricted_analyst'."
    )
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [
        (Role.ADMIN.value, _MANUAL, None),
        (Role.RESTRICTED_ANALYST.value, _MANUAL, None),
    ]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.ROLE_ADDED.value,
            None,
            None,
            "restricted_analyst",
            None,
        )
    ]


@pytest.mark.integration
def test_role_full_overlap_is_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.fulloverlap")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))

    result = _invoke(
        ["--username", username, "--add-role", "admin", "--remove-role", "admin"]
    )

    _assert_success(result, f"No changes applied to user '{username}'.")
    assert asyncio.run(_fetch_roles(cli_session_factory, user.id)) == []
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_role_manual_add_reported_when_external_origin_already_effective(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.extadd")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            external=True,
            roles=[(Role.VULNERABILITY_ANALYST, _EXTERNAL_GROUP)],
        )
    )

    result = _invoke(["--username", username, "--add-role", "vulnerability_analyst"])

    _assert_success(
        result, f"Updated user '{username}': roles: added 'vulnerability_analyst'."
    )
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [
        (Role.VULNERABILITY_ANALYST.value, _EXTERNAL_GROUP, None),
        (Role.VULNERABILITY_ANALYST.value, _MANUAL, None),
    ]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.ROLE_ADDED.value,
            None,
            None,
            "vulnerability_analyst",
            None,
        )
    ]


@pytest.mark.integration
def test_role_manual_removal_reported_while_external_origin_keeps_tickets(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    ticket_ids: list[UUID],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.extremove")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            external=True,
            roles=[
                (Role.VULNERABILITY_ANALYST, _EXTERNAL_GROUP),
                (Role.VULNERABILITY_ANALYST, _MANUAL),
            ],
        )
    )
    ticket_id = asyncio.run(
        _create_ticket(
            cli_session_factory,
            ticket_ids,
            status=TicketStatus.ANALYSIS,
            assignee_id=user.id,
        )
    )

    result = _invoke(["--username", username, "--remove-role", "vulnerability_analyst"])

    _assert_success(
        result, f"Updated user '{username}': roles: removed 'vulnerability_analyst'."
    )
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [
        (Role.VULNERABILITY_ANALYST.value, _EXTERNAL_GROUP, None)
    ]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.ROLE_REMOVED.value,
            None,
            "vulnerability_analyst",
            None,
            None,
        )
    ]
    ticket = asyncio.run(_fetch_ticket(cli_session_factory, ticket_id))
    assert ticket.assignee_id == user.id
    assert asyncio.run(_fetch_ticket_events(cli_session_factory, [ticket_id])) == []


@pytest.mark.integration
def test_role_mode_permitted_for_external_user(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.extrole")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, external=True)
    )

    result = _invoke(["--username", username, "--add-role", "admin"])

    _assert_success(result, f"Updated user '{username}': roles: added 'admin'.")
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [(Role.ADMIN.value, _MANUAL, None)]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (IdentityAuditEventType.ROLE_ADDED.value, None, None, "admin", None)
    ]


@pytest.mark.integration
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--add-role", "admin", "--add-role", "bogus"], id="add"),
        pytest.param(["--remove-role", "bogus"], id="remove"),
    ],
)
def test_role_invalid_value_rejected_without_mutating_session(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    args: list[str],
) -> None:
    username = _username("alice.badrole")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)

    result = _invoke(["--username", username, *args])

    _assert_error(
        result,
        "Error: Invalid role 'bogus'. Valid roles are: admin, "
        "restricted_analyst, vulnerability_analyst.",
    )
    assert factory.calls == 1
    assert asyncio.run(_fetch_roles(cli_session_factory, user.id)) == []
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_role_final_manual_va_removal_unassigns_active_tickets(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    ticket_ids: list[UUID],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.finalva")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            roles=[(Role.VULNERABILITY_ANALYST, _MANUAL)],
        )
    )
    analysis_id = asyncio.run(
        _create_ticket(
            cli_session_factory,
            ticket_ids,
            status=TicketStatus.ANALYSIS,
            assignee_id=user.id,
        )
    )
    resolved_id = asyncio.run(
        _create_ticket(
            cli_session_factory,
            ticket_ids,
            status=TicketStatus.RESOLVED,
            assignee_id=user.id,
        )
    )

    result = _invoke(["--username", username, "--remove-role", "vulnerability_analyst"])

    _assert_success(
        result, f"Updated user '{username}': roles: removed 'vulnerability_analyst'."
    )
    assert asyncio.run(_fetch_roles(cli_session_factory, user.id)) == []
    analysis = asyncio.run(_fetch_ticket(cli_session_factory, analysis_id))
    assert analysis.assignee_id is None
    assert analysis.status == TicketStatus.ANALYSIS.value
    resolved = asyncio.run(_fetch_ticket(cli_session_factory, resolved_id))
    assert resolved.assignee_id == user.id

    ticket_events = asyncio.run(
        _fetch_ticket_events(cli_session_factory, [analysis_id, resolved_id])
    )
    assert [
        (
            e.ticket_id,
            e.event_type,
            e.user_id,
            e.old_value,
            e.new_value,
            e.comment,
            e.detail,
        )
        for e in ticket_events
    ] == [
        (
            analysis_id,
            TicketAuditEventType.ASSIGNMENT.value,
            None,
            username,
            None,
            f"Unassigned from {username}: vulnerability_analyst role removed",
            None,
        )
    ]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.ROLE_REMOVED.value,
            None,
            "vulnerability_analyst",
            None,
            None,
        )
    ]


# ---------------------------------------------------------------------------
# Integration: reactivation mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_reactivate_inactive_local_user(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.reactivate")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            active=False,
            roles=[(Role.ADMIN, _MANUAL)],
        )
    )

    result = _invoke(["--username", username, "--reactivate"])

    _assert_success(result, f"Reactivated user '{username}'.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.active is True
    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [(Role.ADMIN.value, _MANUAL, None)]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert _event_tuples(events) == [
        (
            IdentityAuditEventType.USER_REACTIVATED.value,
            None,
            "inactive",
            "active",
            None,
        )
    ]


@pytest.mark.integration
def test_reactivate_already_active_user_is_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.active")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))

    result = _invoke(["--username", username, "--reactivate"])

    _assert_success(result, f"No changes applied to user '{username}'.")
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_reactivate_concurrent_loser_prints_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """The lookup sees an inactive user; a concurrent writer reactivates it
    before the service locks the row."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.reactloser")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, active=False)
    )
    original_reactivate_user = user_service_module.reactivate_user

    async def _concurrent_reactivation_then_delegate(*args: Any, **kwargs: Any) -> Any:
        async with cli_session_factory() as other:
            await other.execute(
                update(User).where(User.id == user.id).values(active=True)
            )
            await other.commit()
        return await original_reactivate_user(*args, **kwargs)

    monkeypatch.setattr(
        user_service_module, "reactivate_user", _concurrent_reactivation_then_delegate
    )

    result = _invoke(["--username", username, "--reactivate"])

    _assert_success(result, f"No changes applied to user '{username}'.")
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.active is True
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_reactivate_external_user_rejected_without_mutating_session(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.extreact")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory, username=username, active=False, external=True
        )
    )
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)

    result = _invoke(["--username", username, "--reactivate"])

    _assert_error(result, _EXTERNAL_REACTIVATION_ERROR)
    assert factory.calls == 1
    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.active is False
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


# ---------------------------------------------------------------------------
# Integration: sync boundary and transaction contract
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize(
    ("args", "active", "expected_exit"),
    [
        pytest.param(["--full-name", "Alice Example"], True, 0, id="profile"),
        pytest.param(["--add-role", "admin"], True, 0, id="role"),
        pytest.param(["--reactivate"], False, 0, id="reactivation"),
        pytest.param(["--add-role", "admin", "--reactivate"], True, 1, id="rejection"),
    ],
)
def test_exactly_one_asyncio_run_per_invocation(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    args: list[str],
    active: bool,
    expected_exit: int,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.asyncrun")
    cleanup_users_by_username(username)
    asyncio.run(_create_user(cli_session_factory, username=username, active=active))
    run_spy = _spy_asyncio_run(monkeypatch)

    result = _invoke(["--username", username, *args])

    assert result.exit_code == expected_exit, result.output
    assert run_spy.call_count == 1


@pytest.mark.integration
@pytest.mark.parametrize(
    ("args", "active", "expected"),
    [
        pytest.param(
            ["--full-name", "Alice Example"],
            True,
            "Updated user '{u}': full name.",
            id="profile",
        ),
        pytest.param(
            ["--add-role", "admin"],
            True,
            "Updated user '{u}': roles: added 'admin'.",
            id="role",
        ),
        pytest.param(
            ["--reactivate"], False, "Reactivated user '{u}'.", id="reactivation"
        ),
        pytest.param(
            ["--reactivate"],
            True,
            "No changes applied to user '{u}'.",
            id="reactivation-noop",
        ),
        pytest.param(
            ["--add-role", "admin", "--remove-role", "admin"],
            True,
            "No changes applied to user '{u}'.",
            id="role-noop",
        ),
    ],
)
def test_success_commits_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    args: list[str],
    active: bool,
    expected: str,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.commitonce")
    cleanup_users_by_username(username)
    asyncio.run(_create_user(cli_session_factory, username=username, active=active))
    commits = _count_commits(monkeypatch)

    result = _invoke(["--username", username, *args])

    _assert_success(result, expected.format(u=username))
    assert commits["n"] == 1


# ---------------------------------------------------------------------------
# Integration: interruption after the service flush and before commit
# ---------------------------------------------------------------------------


def _interrupt_after(original: Callable[..., Any]) -> Callable[..., Any]:
    async def _run_then_interrupt(*args: Any, **kwargs: Any) -> Any:
        await original(*args, **kwargs)
        raise KeyboardInterrupt()

    return _run_then_interrupt


def _invoke_interrupted(args: list[str]) -> None:
    # Click's own `main()` converts a raw `KeyboardInterrupt` escaping the
    # command into `click.Abort` regardless of `standalone_mode`; the
    # workflow's `except BaseException` rollback has already run by then.
    with pytest.raises(click.Abort):
        _invoke(args, catch_exceptions=False)


@pytest.mark.integration
def test_interrupted_role_update_rolls_back_unassignment(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    ticket_ids: list[UUID],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.introle")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory,
            username=username,
            roles=[(Role.VULNERABILITY_ANALYST, _MANUAL)],
        )
    )
    ticket_id = asyncio.run(
        _create_ticket(
            cli_session_factory,
            ticket_ids,
            status=TicketStatus.ANALYSIS,
            assignee_id=user.id,
        )
    )
    monkeypatch.setattr(
        user_service_module,
        "update_roles",
        _interrupt_after(user_service_module.update_roles),
    )

    _invoke_interrupted(
        ["--username", username, "--remove-role", "vulnerability_analyst"]
    )

    roles = asyncio.run(_fetch_roles(cli_session_factory, user.id))
    assert _role_tuples(roles) == [(Role.VULNERABILITY_ANALYST.value, _MANUAL, None)]
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []
    ticket = asyncio.run(_fetch_ticket(cli_session_factory, ticket_id))
    assert ticket.assignee_id == user.id
    assert asyncio.run(_fetch_ticket_events(cli_session_factory, [ticket_id])) == []


@pytest.mark.integration
def test_interrupted_profile_update_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.intprofile")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, full_name="Alice Example")
    )
    before = _snapshot(cli_session_factory, user.id)
    monkeypatch.setattr(
        user_service_module,
        "update_user",
        _interrupt_after(user_service_module.update_user),
    )

    _invoke_interrupted(
        [
            "--username",
            username,
            "--email",
            f"{username}.new@example.com",
            "--full-name",
            "Alice Renamed",
        ]
    )

    assert _snapshot(cli_session_factory, user.id) == before
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_interrupted_reactivation_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.intreact")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, active=False)
    )
    monkeypatch.setattr(
        user_service_module,
        "reactivate_user",
        _interrupt_after(user_service_module.reactivate_user),
    )

    _invoke_interrupted(["--username", username, "--reactivate"])

    refreshed = asyncio.run(_fetch_user(cli_session_factory, user.id))
    assert refreshed.active is False
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []
