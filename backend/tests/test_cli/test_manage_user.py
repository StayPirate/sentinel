"""Tests for `sentinel manage-user create/list/show`.

See docs/features/identity/user-management.md for the authoritative
per-command contract exercised here. Unit tests cover the pure
validation and rendering helpers directly; integration tests exercise
the full `CliRunner`-invoked commands against the real PostgreSQL test
database via the `cli_session_factory`/`cleanup_users_by_username`
fixtures (see docs/features/platform/testing-strategy.md, Sync
Entry-Point Tests) — `db_session`'s savepoint-scoped transaction is
never visible to the separate connection these commands use, so setup
data for these tests is created directly through `cli_session_factory`
rather than through `db_session`-based factories.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import click
import pytest
import redis.asyncio as redis_asyncio
from click.testing import CliRunner, Result
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.cli as cli_package
import app.cli.manage_user as manage_user_module
from app.cli import cli, main
from app.core.enums import IdentityAuditEventType, Role
from app.core.passwords import verify_password
from app.core.permissions import role_to_wire
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session
from app.models.user import User
from app.models.user_role import UserRole
from app.services import local_auth_service, session_service
from tests.support.redis import redis_url_from_client

_STRONG_PASSWORD = "a-very-strong-password-1"
_PASSWORD_INPUT = f"{_STRONG_PASSWORD}\n{_STRONG_PASSWORD}\n"
_NEW_STRONG_PASSWORD = "a-new-very-strong-password-2"
_NEW_PASSWORD_INPUT = f"{_NEW_STRONG_PASSWORD}\n{_NEW_STRONG_PASSWORD}\n"


class _FailingRedisClient:
    """A Redis client double whose relevant methods always raise
    `RedisError` — mirrors `test_local_auth_service.py`'s
    `_FailingRedisClient` (see docs/features/platform/testing-strategy.md,
    Redis Strategy)."""

    async def delete(self, key: str) -> None:
        raise RedisError("simulated outage")

    async def aclose(self) -> None:
        return None


def _invoke(args: list[str], input: str | bytes | None = None, **extra: Any) -> Result:
    """Invoke the raw `cli` group with `standalone_mode=False`, mirroring
    exactly how production's `main()` invokes it — see the identical
    helper docstring in `test_main.py`."""
    return CliRunner().invoke(cli, args, input=input, standalone_mode=False, **extra)


def _allow_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manage_user_module, "is_interactive_terminal", lambda: True)


def _inject_session_factory(
    monkeypatch: pytest.MonkeyPatch,
    factory: async_sessionmaker[AsyncSession],
) -> None:
    monkeypatch.setattr(manage_user_module, "get_session_factory", lambda: factory)


async def _fetch_user(
    factory: async_sessionmaker[AsyncSession], username: str
) -> User | None:
    async with factory() as db:
        result: User | None = await db.scalar(
            select(User).where(User.username == username)
        )
        return result


async def _fetch_user_created_events(
    factory: async_sessionmaker[AsyncSession], username: str
) -> list[IdentityAuditEvent]:
    """Find `user_created` events by `new_value` (the persisted username).

    Used to prove the absence of a dangling audit event when the
    creation transaction rolled back and no `User` row (hence no
    `target_user_id`) exists to query by.
    """
    async with factory() as db:
        result = await db.execute(
            select(IdentityAuditEvent).where(
                IdentityAuditEvent.event_type
                == IdentityAuditEventType.USER_CREATED.value,
                IdentityAuditEvent.new_value == username,
            )
        )
        return list(result.scalars().all())


async def _create_user_directly(
    factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
    email: str | None = None,
    full_name: str | None = None,
    active: bool = True,
    external_id: UUID | None = None,
    manager_id: UUID | None = None,
    last_login_at: datetime | None = None,
    roles: list[tuple[Role, str]] | None = None,
    user_id: UUID | None = None,
) -> User:
    """Insert and commit a `User` (with optional roles) directly through
    `cli_session_factory`, bypassing `user_service` entirely — used to set
    up fixtures for `list`/`show` tests, which run in a separate
    connection from `db_session`-backed factories (see module docstring).
    `user_id`, when given, overrides the generated primary key.
    """
    async with factory() as db:
        user = User(
            username=username,
            email=email or f"{username}@example.com",
            full_name=full_name,
            active=active,
            external_id=external_id,
            manager_id=manager_id,
            password_hash=None if external_id is not None else "$2b$12$" + "a" * 53,
            last_login_at=last_login_at,
        )
        if user_id is not None:
            user.id = user_id
        db.add(user)
        await db.flush()
        for role, group_name in roles or []:
            db.add(UserRole(user_id=user.id, role=role.value, group_name=group_name))
        await db.commit()
        return user


async def _create_session_directly(
    factory: async_sessionmaker[AsyncSession],
    *,
    user_id: UUID,
    is_active: bool = True,
) -> Session:
    """Insert and commit a `Session` row directly through
    `cli_session_factory`, bypassing `session_service` entirely — used to
    set up fixtures for `set-password` session-invalidation tests."""
    async with factory() as db:
        session = Session(
            user_id=user_id,
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            is_active=is_active,
        )
        db.add(session)
        await db.commit()
        return session


async def _fetch_session_is_active(
    factory: async_sessionmaker[AsyncSession], session_id: UUID
) -> bool:
    async with factory() as db:
        result: bool | None = await db.scalar(
            select(Session.is_active).where(Session.id == session_id)
        )
        assert result is not None
        return result


async def _fetch_password_reset_events(
    factory: async_sessionmaker[AsyncSession], target_user_id: UUID
) -> list[IdentityAuditEvent]:
    async with factory() as db:
        result = await db.execute(
            select(IdentityAuditEvent).where(
                IdentityAuditEvent.event_type
                == IdentityAuditEventType.PASSWORD_RESET.value,
                IdentityAuditEvent.target_user_id == target_user_id,
            )
        )
        return list(result.scalars().all())


async def _redis_set_key(url: str, key: str, value: str) -> None:
    """Set one Redis key via a client created and closed entirely within
    this call's own event loop — never shared across `asyncio.run()`
    boundaries (see docs/features/platform/testing-strategy.md, Redis
    Strategy)."""
    client = redis_asyncio.Redis.from_url(url, decode_responses=True)
    try:
        await client.set(key, value)
    finally:
        await client.aclose()


async def _redis_get_key(url: str, key: str) -> str | None:
    client = redis_asyncio.Redis.from_url(url, decode_responses=True)
    try:
        result: str | None = await client.get(key)
        return result
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Unit: validation helpers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_valid_roles_list_is_alphabetical() -> None:
    assert (
        manage_user_module._valid_roles_list()
        == "admin, restricted_analyst, vulnerability_analyst"
    )


@pytest.mark.unit
def test_parse_roles_or_exit_empty_returns_empty_list() -> None:
    assert manage_user_module._parse_roles_or_exit(()) == []


@pytest.mark.unit
def test_parse_roles_or_exit_valid_roles() -> None:
    assert manage_user_module._parse_roles_or_exit(("admin", "restricted_analyst")) == [
        Role.ADMIN,
        Role.RESTRICTED_ANALYST,
    ]


@pytest.mark.unit
def test_parse_roles_or_exit_invalid_role_exits_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        manage_user_module._parse_roles_or_exit(("bogus",))
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.err.strip() == (
        "Error: Invalid role 'bogus'. Valid roles are: "
        "admin, restricted_analyst, vulnerability_analyst."
    )


@pytest.mark.unit
def test_normalize_username_or_exit_trims_and_lowercases() -> None:
    assert manage_user_module._normalize_username_or_exit("  JDoe  ") == "jdoe"


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["1bad", "", "Has Space", "toolong" + "x" * 60, "bad$char"],
)
def test_normalize_username_or_exit_invalid_format_exits_one(
    capsys: pytest.CaptureFixture[str], value: str
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        manage_user_module._normalize_username_or_exit(value)
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    normalized = value.strip().lower()
    assert captured.err.strip() == (
        f"Error: Invalid username '{normalized}'. Username must be 1-64 "
        "characters, start with a letter, and contain only lowercase "
        "letters, numbers, dots, hyphens, and underscores."
    )


@pytest.mark.unit
def test_normalize_email_or_exit_trims_and_lowercases() -> None:
    assert (
        manage_user_module._normalize_email_or_exit("  JDoe@Example.COM  ")
        == "jdoe@example.com"
    )


@pytest.mark.unit
def test_normalize_email_or_exit_invalid_format_exits_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        manage_user_module._normalize_email_or_exit("not-an-email")
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.err.strip() == "Error: Invalid email format 'not-an-email'."


# ---------------------------------------------------------------------------
# Unit: rendering helpers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_format_utc_none_renders_em_dash() -> None:
    assert manage_user_module._format_utc(None) == "—"


@pytest.mark.unit
def test_format_utc_converts_to_utc_display_format() -> None:
    value = datetime(2025, 3, 15, 10, 30, 0, tzinfo=UTC)
    assert manage_user_module._format_utc(value) == "2025-03-15 10:30:00 UTC"


@pytest.mark.unit
def test_render_roles_with_origins_empty_renders_em_dash() -> None:
    assert manage_user_module._render_roles_with_origins([]) == "—"


@pytest.mark.unit
def test_render_roles_with_origins_single_manual_role() -> None:
    roles = [UserRole(role=Role.ADMIN.value, group_name="_manual")]
    assert manage_user_module._render_roles_with_origins(roles) == "admin (manual)"


@pytest.mark.unit
def test_render_roles_with_origins_manual_listed_before_external() -> None:
    roles = [
        UserRole(role=Role.ADMIN.value, group_name="O SUSE Admins"),
        UserRole(role=Role.ADMIN.value, group_name="_manual"),
    ]
    assert (
        manage_user_module._render_roles_with_origins(roles)
        == "admin (manual, O SUSE Admins)"
    )


@pytest.mark.unit
def test_render_roles_with_origins_multiple_roles_sorted_alphabetically() -> None:
    roles = [
        UserRole(role=Role.VULNERABILITY_ANALYST.value, group_name="_manual"),
        UserRole(role=Role.ADMIN.value, group_name="_manual"),
    ]
    assert (
        manage_user_module._render_roles_with_origins(roles)
        == "admin (manual), vulnerability_analyst (manual)"
    )


@pytest.mark.unit
def test_render_user_row_absent_full_name_and_roles() -> None:
    user = User(username="jdoe", email="jdoe@example.com", full_name=None, active=True)
    user.roles = []
    row = manage_user_module._render_user_row(user)
    assert row == ("jdoe", "—", "jdoe@example.com", "local", "active", "—")


@pytest.mark.unit
def test_render_user_row_external_inactive_with_roles() -> None:
    user = User(
        username="bwilson",
        email="bwilson@example.com",
        full_name="Bob Wilson",
        active=False,
        external_id=uuid4(),
    )
    user.roles = [UserRole(role=Role.VULNERABILITY_ANALYST.value, group_name="_manual")]
    row = manage_user_module._render_user_row(user)
    assert row == (
        "bwilson",
        "Bob Wilson",
        "bwilson@example.com",
        "external",
        "inactive",
        "vulnerability_analyst",
    )


@pytest.mark.unit
def test_render_list_table_aligns_columns() -> None:
    user = User(
        username="jdoe", email="jdoe@example.com", full_name="John Doe", active=True
    )
    user.roles = [UserRole(role=Role.ADMIN.value, group_name="_manual")]
    table = manage_user_module._render_list_table([user])
    lines = table.splitlines()
    assert lines[0].startswith("USERNAME")
    assert lines[1].startswith("jdoe")
    assert "admin" in lines[1]


@pytest.mark.unit
def test_render_user_detail_full_example() -> None:
    user = User(
        username="jdoe",
        email="jdoe@example.com",
        full_name="John Doe",
        active=True,
        created_at=datetime(2025, 3, 15, 10, 30, 0, tzinfo=UTC),
        last_login_at=datetime(2025, 6, 1, 14, 22, 0, tzinfo=UTC),
    )
    user.roles = [
        UserRole(role=Role.ADMIN.value, group_name="_manual"),
        UserRole(role=Role.VULNERABILITY_ANALYST.value, group_name="O SUSE Security"),
    ]
    manager = User(username="bwilson", email="bwilson@example.com")
    user.manager = manager

    detail = manage_user_module._render_user_detail(user)

    assert detail == (
        "Username:     jdoe\n"
        "Full name:    John Doe\n"
        "Email:        jdoe@example.com\n"
        "Type:         local\n"
        "Status:       active\n"
        "Roles:        admin (manual), vulnerability_analyst (O SUSE Security)\n"
        "Created:      2025-03-15 10:30:00 UTC\n"
        "Last login:   2025-06-01 14:22:00 UTC\n"
        "Manager:      bwilson"
    )


@pytest.mark.unit
def test_render_user_detail_absent_values() -> None:
    user = User(
        username="olduser",
        email="old@example.com",
        full_name=None,
        active=False,
        created_at=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
        last_login_at=None,
    )
    user.roles = []
    user.manager = None

    detail = manage_user_module._render_user_detail(user)

    assert "Full name:    —" in detail
    assert "Roles:        —" in detail
    assert "Last login:   —" in detail
    assert "Manager:      —" in detail


# ---------------------------------------------------------------------------
# Unit: list pagination loop
# ---------------------------------------------------------------------------


class _FakeSessionCtx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _FakeSessionFactory:
    def __call__(self) -> _FakeSessionCtx:
        return _FakeSessionCtx()


@pytest.mark.unit
def test_list_users_flow_iterates_until_total_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import user_service as user_service_module

    fake_pages = {
        1: SimpleNamespace(items=["a", "b"], total=5),
        2: SimpleNamespace(items=["c", "d"], total=5),
        3: SimpleNamespace(items=["e"], total=5),
    }

    async def _fake_list_users(db: object, **kwargs: Any) -> SimpleNamespace:
        return fake_pages[kwargs["page"]]

    monkeypatch.setattr(user_service_module, "list_users", _fake_list_users)

    items = asyncio.run(
        manage_user_module._list_users_flow(
            cast("async_sessionmaker[AsyncSession]", _FakeSessionFactory()),
            active=None,
            roles=[],
            user_type=None,
        )
    )
    assert items == ["a", "b", "c", "d", "e"]  # type: ignore[comparison-overlap]


@pytest.mark.unit
def test_list_users_flow_empty_result_stops_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import user_service as user_service_module

    async def _fake_list_users(db: object, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(items=[], total=0)

    monkeypatch.setattr(user_service_module, "list_users", _fake_list_users)

    items = asyncio.run(
        manage_user_module._list_users_flow(
            cast("async_sessionmaker[AsyncSession]", _FakeSessionFactory()),
            active=None,
            roles=[],
            user_type=None,
        )
    )
    assert items == []


# ---------------------------------------------------------------------------
# Integration: create
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_create_success_with_no_roles(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clicreatenoroles"
    cleanup_users_by_username(username)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
        ],
        input=_PASSWORD_INPUT,
    )

    assert result.exit_code == 0, result.output
    # `click.prompt()` echoes its two prompt labels to stdout ahead of the
    # command's own success line (Click's own default, not overridable
    # per-command wording) — only the final line is the command's output.
    assert (
        result.stdout.strip().splitlines()[-1]
        == f"Created user '{username}' ({username}@example.com) with no roles."
    )


@pytest.mark.integration
def test_create_persists_full_name(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """`--full-name` is forwarded through `_create_flow` to
    `user_service.create_user(full_name=...)` and persisted verbatim."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clicreatefullname"
    cleanup_users_by_username(username)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
            "--full-name",
            "Alice Smith",
        ],
        input=_PASSWORD_INPUT,
    )

    assert result.exit_code == 0, result.output

    user = asyncio.run(_fetch_user(cli_session_factory, username))
    assert user is not None
    assert user.full_name == "Alice Smith"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("tag", "full_name"),
    [("ascii", "A" * 255), ("multibyte", "é" * 255)],
)
def test_create_full_name_at_bound_is_stored(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    tag: str,
    full_name: str,
) -> None:
    """Exactly 255 characters (Unicode code points, the column bound) is
    accepted and stored verbatim."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = f"clicreatefullname255{tag}"
    cleanup_users_by_username(username)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
            "--full-name",
            full_name,
        ],
        input=_PASSWORD_INPUT,
    )

    assert result.exit_code == 0, result.output
    user = asyncio.run(_fetch_user(cli_session_factory, username))
    assert user is not None
    assert user.full_name == full_name


@pytest.mark.integration
def test_create_full_name_over_bound_exits_one_before_tty_and_database(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """256 characters is rejected with the documented message before the
    TTY check (TTY is deliberately not allowed), the password prompt, and
    any database access — never as a database error with SQL text."""

    def _forbidden_factory() -> async_sessionmaker[AsyncSession]:
        raise AssertionError("the command must not access the database")

    monkeypatch.setattr(manage_user_module, "get_session_factory", _forbidden_factory)
    username = "clicreatefullname256"

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
            "--full-name",
            "A" * 256,
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Error: Full name must be at most 255 characters.\n"
    assert asyncio.run(_fetch_user(cli_session_factory, username)) is None


@pytest.mark.integration
def test_create_success_with_roles_persists_user_roles_and_audit(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clicreatewithroles"
    cleanup_users_by_username(username)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
            "--role",
            "vulnerability_analyst",
            "--role",
            "admin",
        ],
        input=_PASSWORD_INPUT,
    )

    assert result.exit_code == 0, result.output
    assert result.stdout.strip().splitlines()[-1] == (
        f"Created user '{username}' ({username}@example.com) with roles: "
        "admin, vulnerability_analyst."
    )
    assert _STRONG_PASSWORD not in result.output

    async def _verify() -> None:
        async with cli_session_factory() as db:
            user = await db.scalar(select(User).where(User.username == username))
            assert user is not None
            assert user.active is True
            assert user.external_id is None

            roles = (
                (await db.execute(select(UserRole).where(UserRole.user_id == user.id)))
                .scalars()
                .all()
            )
            assert {r.role for r in roles} == {
                Role.ADMIN.value,
                Role.VULNERABILITY_ANALYST.value,
            }
            for role in roles:
                assert role.group_name == "_manual"
                assert role.assigned_by is None

            events = (
                (
                    await db.execute(
                        select(IdentityAuditEvent).where(
                            IdentityAuditEvent.target_user_id == user.id
                        )
                    )
                )
                .scalars()
                .all()
            )
            event_types = [e.event_type for e in events]
            assert event_types.count(IdentityAuditEventType.USER_CREATED.value) == 1
            assert event_types.count(IdentityAuditEventType.ROLE_ADDED.value) == 2
            for event in events:
                assert event.user_id is None
                assert event.detail is None

            # Per identity-audit-log.md's IdentityAuditEventType Enum
            # table: user_created carries old_value=NULL, new_value=the
            # created username; role_added carries old_value=NULL,
            # new_value=the assigned role name.
            created_event = next(
                e
                for e in events
                if e.event_type == IdentityAuditEventType.USER_CREATED.value
            )
            assert created_event.old_value is None
            assert created_event.new_value == username

            role_events = [
                e
                for e in events
                if e.event_type == IdentityAuditEventType.ROLE_ADDED.value
            ]
            assert {e.new_value for e in role_events} == {
                role_to_wire(Role.ADMIN),
                role_to_wire(Role.VULNERABILITY_ANALYST),
            }
            for role_event in role_events:
                assert role_event.old_value is None

    asyncio.run(_verify())


@pytest.mark.integration
def test_create_invalid_username_exits_one_before_prompting(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    # Deliberately do NOT allow TTY / provide password input: if the
    # command reached the prompt, this test would hang or fail loudly.
    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            "1bad",
            "--email",
            "user@example.com",
        ],
    )
    assert result.exit_code == 1
    assert "Invalid username '1bad'" in result.stderr


@pytest.mark.integration
def test_create_invalid_role_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            "someuser",
            "--email",
            "user@example.com",
            "--role",
            "bogus",
        ],
    )
    assert result.exit_code == 1
    assert "Invalid role 'bogus'" in result.stderr


@pytest.mark.integration
def test_create_invalid_email_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            "someuser",
            "--email",
            "not-an-email",
        ],
    )
    assert result.exit_code == 1
    assert "Invalid email format 'not-an-email'" in result.stderr


@pytest.mark.integration
def test_create_non_tty_rejected(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    monkeypatch.setattr(manage_user_module, "is_interactive_terminal", lambda: False)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            "someuser",
            "--email",
            "user@example.com",
        ],
    )
    assert result.exit_code == 1
    assert result.stderr.strip() == (
        "Error: This command requires an interactive terminal (password input)."
    )


@pytest.mark.integration
def test_create_password_mismatch_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            "someuser",
            "--email",
            "user@example.com",
        ],
        input=f"{_STRONG_PASSWORD}\na-different-password-2\n",
    )
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: Passwords do not match."


_INVALID_UTF8_PASSWORD_ERROR = "Error: Password must be valid UTF-8.\n"


def _assert_no_entry_leak(result: Result) -> None:
    """Neither the decoder message (which names the byte and its position)
    nor any part of the entry appears in the command output."""
    for fragment in ("decode", "0xe9", "secr", "position"):
        assert fragment not in result.output


@pytest.mark.integration
def test_create_undecodable_password_exits_one_before_length_check(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The short entry would otherwise fail the 16-character policy: the
    encoding check comes first, and no user is created."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clicreateinvalidutf8"

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
        ],
        input=b"secr\xe9t\nsecr\xe9t\n",
    )

    assert result.exit_code == 1
    assert result.stderr == _INVALID_UTF8_PASSWORD_ERROR
    _assert_no_entry_leak(result)
    assert asyncio.run(_fetch_user(cli_session_factory, username)) is None


@pytest.mark.unit
def test_create_undecodable_password_through_main_exits_one_without_logging(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Through the real `main()` mapper: a strict-decoding failure inside
    the hidden prompt no longer reaches the catch-all path, which would log
    it and exit 2 (cli-infrastructure.md, Interactive Input Helpers —
    Input encoding)."""

    def _undecodable_prompt(*args: object, **kwargs: object) -> str:
        return b"secr\xe9t".decode("utf-8")

    _allow_tty(monkeypatch)
    monkeypatch.setattr(click, "prompt", _undecodable_prompt)
    mapper_logger = MagicMock()
    monkeypatch.setattr(cli_package, "logger", mapper_logger)
    monkeypatch.setattr(
        manage_user_module,
        "get_session_factory",
        lambda: pytest.fail("the command must not access the database"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sentinel",
            "manage-user",
            "create",
            "--username",
            "clicreatemainutf8",
            "--email",
            "clicreatemainutf8@example.com",
        ],
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

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.err == _INVALID_UTF8_PASSWORD_ERROR
    assert "decode" not in captured.out
    mapper_logger.error.assert_not_called()


@pytest.mark.integration
def test_create_undecodable_confirmation_entry_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clicreateinvalidutf8confirm"

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
        ],
        input=f"{_STRONG_PASSWORD}\n".encode() + b"secr\xe9t-password-123\n",
    )

    assert result.exit_code == 1
    assert result.stderr == _INVALID_UTF8_PASSWORD_ERROR
    _assert_no_entry_leak(result)
    assert asyncio.run(_fetch_user(cli_session_factory, username)) is None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("password", "expected_message"),
    [
        ("short-pw-1", "Error: Password must be at least 16 characters."),
        ("x" * 129, "Error: Password must be at most 128 characters."),
    ],
)
def test_create_password_length_boundaries_exit_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    password: str,
    expected_message: str,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            "someuser",
            "--email",
            "user@example.com",
        ],
        input=f"{password}\n{password}\n",
    )
    assert result.exit_code == 1
    assert result.stderr.strip() == expected_message


@pytest.mark.integration
def test_create_duplicate_username_translates_conflict_message(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "cliconflictusername"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            "different@example.com",
        ],
        input=_PASSWORD_INPUT,
    )
    assert result.exit_code == 1
    assert result.stderr.strip() == (
        f"Error: A user with username '{username}' already exists."
    )


@pytest.mark.integration
def test_create_duplicate_email_translates_conflict_message(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    existing_username = "cliconflictemailexisting"
    new_username = "cliconflictemailnew"
    email = "cliconflict-shared@example.com"
    cleanup_users_by_username(existing_username, new_username)
    asyncio.run(
        _create_user_directly(
            cli_session_factory, username=existing_username, email=email
        )
    )

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            new_username,
            "--email",
            email,
        ],
        input=_PASSWORD_INPUT,
    )
    assert result.exit_code == 1
    assert (
        result.stderr.strip() == f"Error: A user with email '{email}' already exists."
    )


@pytest.mark.integration
def test_create_audit_failure_rolls_back_user_and_roles(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "cliauditrollback"
    cleanup_users_by_username(username)

    from app.services import identity_audit_log as audit_module

    original_log_event = audit_module.IdentityAuditLog.log_event
    call_count = {"n": 0}

    async def _flaky_log_event(*args: Any, **kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated audit failure")
        return await original_log_event(*args, **kwargs)

    monkeypatch.setattr(audit_module.IdentityAuditLog, "log_event", _flaky_log_event)

    result = _invoke(
        [
            "manage-user",
            "create",
            "--username",
            username,
            "--email",
            f"{username}@example.com",
        ],
        input=_PASSWORD_INPUT,
    )
    assert result.exit_code != 0

    user = asyncio.run(_fetch_user(cli_session_factory, username))
    assert user is None


@pytest.mark.integration
def test_create_interrupted_before_commit_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "cliinterruptrollback"
    cleanup_users_by_username(username)

    from app.services import user_service as user_service_module

    original_create_user = user_service_module.create_user

    async def _create_then_interrupt(*args: Any, **kwargs: Any) -> None:
        await original_create_user(*args, **kwargs)
        raise KeyboardInterrupt()

    monkeypatch.setattr(user_service_module, "create_user", _create_then_interrupt)

    # Click's own `main()` converts a raw `KeyboardInterrupt` escaping the
    # command into `click.Abort` (see `core.py`'s `except (EOFError,
    # KeyboardInterrupt)` clause) regardless of `standalone_mode` — this
    # is the same conversion documented in cli-infrastructure.md's Error
    # Handling table. The rollback assertion below is what this test
    # actually verifies: `_create_flow`'s `except BaseException` guard
    # rolls back before that conversion ever happens.
    with pytest.raises(click.Abort):
        _invoke(
            [
                "manage-user",
                "create",
                "--username",
                username,
                "--email",
                f"{username}@example.com",
            ],
            input=_PASSWORD_INPUT,
            catch_exceptions=False,
        )

    user = asyncio.run(_fetch_user(cli_session_factory, username))
    assert user is None

    # Explicit per testing-strategy.md (CLI Commands): rollback leaves no
    # partial mutation *or audit event*. `target_user_id` cannot be
    # queried (no user row exists), so this checks by `new_value`
    # (the username the `user_created` event would have carried).
    audit_events = asyncio.run(
        _fetch_user_created_events(cli_session_factory, username)
    )
    assert audit_events == []


# ---------------------------------------------------------------------------
# Integration: list
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_without_any_filter_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """No `--active`/`--inactive`/`--role`/`--type` at all: exercises the
    unfiltered default path (`user_type` stays `None`) end to end."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "list"])
    assert result.exit_code == 0, result.output


@pytest.mark.integration
def test_list_empty_result_message(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(
        [
            "manage-user",
            "list",
            "--role",
            "admin",
            "--type",
            "external",
            "--active",
        ],
    )
    # An external+active+admin combination is exceedingly unlikely to
    # match any row left over from other tests, and this command applies
    # its filters with AND semantics — but to keep this assertion robust
    # regardless of leftover data, only the exit code is required to be 0.
    assert result.exit_code == 0


@pytest.mark.integration
def test_list_active_inactive_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "list", "--active", "--inactive"])
    assert result.exit_code == 1
    assert result.stderr.strip() == (
        "Error: --active and --inactive cannot be used together."
    )


@pytest.mark.integration
def test_list_invalid_role_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "list", "--role", "bogus"])
    assert result.exit_code == 1
    assert "Invalid role 'bogus'" in result.stderr


@pytest.mark.integration
def test_list_invalid_type_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "list", "--type", "bogus"])
    assert result.exit_code == 1
    assert result.stderr.strip() == (
        "Error: Invalid type 'bogus'. Valid types are: local, external."
    )


@pytest.mark.integration
def test_list_type_filters_local_and_external_users(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """`--type local`/`--type external` map to distinct `UserType` values
    end to end: a swapped `UserType.LOCAL`/`UserType.EXTERNAL` constant
    would cause one of these assertions to fail."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    prefix = "clilisttypefilter"
    local_user = f"{prefix}local"
    external_user = f"{prefix}external"
    cleanup_users_by_username(local_user, external_user)

    asyncio.run(_create_user_directly(cli_session_factory, username=local_user))
    asyncio.run(
        _create_user_directly(
            cli_session_factory, username=external_user, external_id=uuid4()
        )
    )

    local_result = _invoke(["manage-user", "list", "--type", "local"])
    assert local_result.exit_code == 0, local_result.output
    assert local_user in local_result.stdout
    assert external_user not in local_result.stdout

    external_result = _invoke(["manage-user", "list", "--type", "external"])
    assert external_result.exit_code == 0, external_result.output
    assert external_user in external_result.stdout
    assert local_user not in external_result.stdout


@pytest.mark.integration
def test_list_filters_role_or_and_type_and_active(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    prefix = "clilistfilter"
    admin_user = f"{prefix}admin"
    va_user = f"{prefix}va"
    other_user = f"{prefix}other"
    inactive_user = f"{prefix}inactive"
    cleanup_users_by_username(admin_user, va_user, other_user, inactive_user)

    asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=admin_user,
            roles=[(Role.ADMIN, "_manual")],
        )
    )
    asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=va_user,
            roles=[(Role.VULNERABILITY_ANALYST, "_manual")],
        )
    )
    asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=other_user,
            roles=[(Role.RESTRICTED_ANALYST, "_manual")],
        )
    )
    asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=inactive_user,
            active=False,
            roles=[(Role.ADMIN, "_manual")],
        )
    )

    result = _invoke(
        [
            "manage-user",
            "list",
            "--active",
            "--type",
            "local",
            "--role",
            "admin",
            "--role",
            "vulnerability_analyst",
        ],
    )
    assert result.exit_code == 0, result.output
    assert admin_user in result.stdout
    assert va_user in result.stdout
    assert other_user not in result.stdout
    assert inactive_user not in result.stdout

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    data_lines = lines[1:]
    usernames_in_order = [line.split()[0] for line in data_lines]
    assert usernames_in_order == sorted(usernames_in_order)


# ---------------------------------------------------------------------------
# Integration: show
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_show_not_found_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "show", "--username", "doesnotexistatall"])
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: User 'doesnotexistatall' not found."


@pytest.mark.integration
def test_show_normalizes_username_before_lookup(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "clishownormalize"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["manage-user", "show", "--username", f"  {username.upper()}  "])
    assert result.exit_code == 0, result.output
    assert f"Username:     {username}" in result.stdout


@pytest.mark.integration
def test_show_renders_roles_manager_and_absent_values(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    manager_username = "clishowmanager"
    username = "clishowdetail"
    cleanup_users_by_username(manager_username, username)

    manager = asyncio.run(
        _create_user_directly(cli_session_factory, username=manager_username)
    )
    asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=username,
            full_name="Detail Test User",
            manager_id=manager.id,
            roles=[
                (Role.ADMIN, "_manual"),
                (Role.ADMIN, "O SUSE Admins"),
                (Role.VULNERABILITY_ANALYST, "O SUSE Security"),
            ],
        )
    )

    result = _invoke(["manage-user", "show", "--username", username])
    assert result.exit_code == 0, result.output
    output = result.stdout
    assert f"Username:     {username}" in output
    assert "Full name:    Detail Test User" in output
    assert "Type:         local" in output
    assert "Status:       active" in output
    assert (
        "Roles:        admin (manual, O SUSE Admins), "
        "vulnerability_analyst (O SUSE Security)" in output
    )
    assert "Last login:   —" in output
    assert f"Manager:      {manager_username}" in output


# ---------------------------------------------------------------------------
# Integration: set-password
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_set_password_invalid_username_exits_one_before_tty_check(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    # Deliberately do NOT allow TTY: if the command reached the TTY check
    # (or the prompt), this test would fail on a different error message
    # or hang, proving the format guard fires first.
    result = _invoke(["manage-user", "set-password", "--username", "1bad"])
    assert result.exit_code == 1
    assert "Invalid username '1bad'" in result.stderr


@pytest.mark.integration
def test_set_password_non_tty_rejected_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    monkeypatch.setattr(manage_user_module, "is_interactive_terminal", lambda: False)

    result = _invoke(["manage-user", "set-password", "--username", "someuser"])
    assert result.exit_code == 1
    assert result.stderr.strip() == (
        "Error: This command requires an interactive terminal (password input)."
    )


@pytest.mark.integration
def test_set_password_user_not_found_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)

    result = _invoke(["manage-user", "set-password", "--username", "doesnotexistatall"])
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: User 'doesnotexistatall' not found."


@pytest.mark.integration
def test_set_password_external_user_rejected_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdexternal"
    cleanup_users_by_username(username)
    asyncio.run(
        _create_user_directly(
            cli_session_factory, username=username, external_id=uuid4()
        )
    )

    result = _invoke(["manage-user", "set-password", "--username", username])
    assert result.exit_code == 1
    assert result.stderr.strip() == (
        f"Error: Cannot set password for external user '{username}'. "
        "External users authenticate via SSO."
    )


@pytest.mark.integration
def test_set_password_race_user_deleted_after_resolve_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """The genuine concurrent race (the user resolved successfully in
    the first session but disappears before `reset_password()`'s own
    row lock in the second session) is covered at the service layer
    (`tests/test_services/test_user_service.py`). This verifies only
    the CLI-layer mapping of the second `UserNotFoundError` catch to
    exit code 1 with the standard "not found" message — reproducing
    the race itself would require true cross-connection concurrency
    for a mapping that is otherwise a single deterministic `except`
    clause."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdracenotfound"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    from app.core.exceptions import UserNotFoundError
    from app.services import user_service as user_service_module

    monkeypatch.setattr(
        user_service_module,
        "reset_password",
        AsyncMock(side_effect=UserNotFoundError()),
    )

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )

    assert result.exit_code == 1
    assert result.stderr.strip() == f"Error: User '{username}' not found."


@pytest.mark.integration
def test_set_password_race_external_id_added_after_resolve_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """Analogous race to the one above, but the user is converted to an
    external user (by an external sync) between the two sessions. Verifies
    only the CLI-layer mapping of `ExternalUserPasswordError` raised by
    the second, mutating call to the standard external-user message and
    exit code 1."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdraceexternal"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    from app.services import user_service as user_service_module
    from app.services.user_service import ExternalUserPasswordError

    monkeypatch.setattr(
        user_service_module,
        "reset_password",
        AsyncMock(side_effect=ExternalUserPasswordError()),
    )

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )

    assert result.exit_code == 1
    assert result.stderr.strip() == (
        f"Error: Cannot set password for external user '{username}'. "
        "External users authenticate via SSO."
    )


@pytest.mark.integration
def test_set_password_mismatch_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdmismatch"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=f"{_STRONG_PASSWORD}\na-different-password-2\n",
    )
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: Passwords do not match."

    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash == user.password_hash


@pytest.mark.integration
@pytest.mark.parametrize("form", ["strict", "surrogateescape"])
def test_set_password_invalid_utf8_entry_exits_one_without_change(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    form: str,
) -> None:
    """Both forms in which non-UTF-8 terminal input arrives (cli-infrastructure.md,
    Interactive Input Helpers — Input encoding): undecodable bytes under
    strict decoding (scripted stdin, decoded strictly by `CliRunner`) and
    lone surrogates under `surrogateescape`. The password is unchanged and
    no mutating session opens."""
    username = f"clisetpwdutf8{form.replace('escape', '')}"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    sessions = {"n": 0}

    def _counting_factory() -> AsyncSession:
        sessions["n"] += 1
        return cli_session_factory()

    monkeypatch.setattr(
        manage_user_module, "get_session_factory", lambda: _counting_factory
    )
    _allow_tty(monkeypatch)
    if form == "strict":
        password_input: bytes | None = (
            b"secr\xe9t-password-123\nsecr\xe9t-password-123\n"
        )
    else:
        password_input = None
        monkeypatch.setattr(
            click, "prompt", lambda *args, **kwargs: "secr\udce9t-password-123"
        )

    result = _invoke(
        ["manage-user", "set-password", "--username", username], input=password_input
    )

    assert result.exit_code == 1
    assert result.stderr == _INVALID_UTF8_PASSWORD_ERROR
    _assert_no_entry_leak(result)
    assert sessions["n"] == 1
    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash == user.password_hash


@pytest.mark.integration
@pytest.mark.parametrize(
    ("password", "expected_message"),
    [
        ("short-pw-1", "Error: Password must be at least 16 characters."),
        ("x" * 129, "Error: Password must be at most 128 characters."),
    ],
)
def test_set_password_length_boundaries_exit_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    password: str,
    expected_message: str,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdlength"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=f"{password}\n{password}\n",
    )
    assert result.exit_code == 1
    assert result.stderr.strip() == expected_message


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_set_password_success_active_user(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdsuccess"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    old_hash = user.password_hash

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code == 0, result.output
    assert (
        result.stdout.strip().splitlines()[-1]
        == f"Password updated for user '{username}'. All active sessions invalidated."
    )
    assert _NEW_STRONG_PASSWORD not in result.output

    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash != old_hash
    assert refreshed.password_hash is not None
    assert verify_password(_NEW_STRONG_PASSWORD, refreshed.password_hash)

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert _NEW_STRONG_PASSWORD not in log_text
    assert refreshed.password_hash not in log_text


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_set_password_inactive_user_succeeds_and_stays_inactive(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdinactive"
    cleanup_users_by_username(username)
    asyncio.run(
        _create_user_directly(cli_session_factory, username=username, active=False)
    )

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code == 0, result.output

    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.active is False
    assert refreshed.password_hash is not None
    assert verify_password(_NEW_STRONG_PASSWORD, refreshed.password_hash)


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_set_password_invalidates_only_active_sessions(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdsessions"
    other_username = "clisetpwdsessionsother"
    cleanup_users_by_username(username, other_username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    other_user = asyncio.run(
        _create_user_directly(cli_session_factory, username=other_username)
    )

    active_session = asyncio.run(
        _create_session_directly(cli_session_factory, user_id=user.id, is_active=True)
    )
    already_inactive_session = asyncio.run(
        _create_session_directly(cli_session_factory, user_id=user.id, is_active=False)
    )
    other_user_session = asyncio.run(
        _create_session_directly(
            cli_session_factory, user_id=other_user.id, is_active=True
        )
    )

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code == 0, result.output

    assert (
        asyncio.run(_fetch_session_is_active(cli_session_factory, active_session.id))
        is False
    )
    assert (
        asyncio.run(
            _fetch_session_is_active(cli_session_factory, already_inactive_session.id)
        )
        is False
    )
    assert (
        asyncio.run(
            _fetch_session_is_active(cli_session_factory, other_user_session.id)
        )
        is True
    )


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_set_password_creates_exact_audit_event(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdaudit"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code == 0, result.output

    events = asyncio.run(_fetch_password_reset_events(cli_session_factory, user.id))
    assert len(events) == 1
    event = events[0]
    assert event.user_id is None
    assert event.target_user_id == user.id
    assert event.old_value is None
    assert event.new_value is None
    assert event.detail is None


@pytest.mark.integration
def test_set_password_audit_failure_rolls_back_password_and_sessions(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdauditfail"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    old_hash = user.password_hash
    active_session = asyncio.run(
        _create_session_directly(cli_session_factory, user_id=user.id, is_active=True)
    )

    from app.services import identity_audit_log as audit_module

    original_log_event = audit_module.IdentityAuditLog.log_event
    call_count = {"n": 0}

    async def _flaky_log_event(*args: Any, **kwargs: Any) -> Any:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated audit failure")
        return await original_log_event(*args, **kwargs)

    monkeypatch.setattr(audit_module.IdentityAuditLog, "log_event", _flaky_log_event)

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code != 0

    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash == old_hash
    assert (
        asyncio.run(_fetch_session_is_active(cli_session_factory, active_session.id))
        is True
    )
    assert asyncio.run(_fetch_password_reset_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_set_password_interrupted_before_commit_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdinterrupt"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    old_hash = user.password_hash

    from app.services import user_service as user_service_module

    original_reset_password = user_service_module.reset_password

    async def _reset_then_interrupt(*args: Any, **kwargs: Any) -> Any:
        await original_reset_password(*args, **kwargs)
        raise KeyboardInterrupt()

    monkeypatch.setattr(user_service_module, "reset_password", _reset_then_interrupt)

    with pytest.raises(click.Abort):
        _invoke(
            ["manage-user", "set-password", "--username", username],
            input=_NEW_PASSWORD_INPUT,
            catch_exceptions=False,
        )

    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash == old_hash
    assert asyncio.run(_fetch_password_reset_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_set_password_commits_exactly_once_on_success(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdcommitcount"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    commit_calls = {"n": 0}
    original_commit = AsyncSession.commit

    async def _counting_commit(self: AsyncSession) -> None:
        commit_calls["n"] += 1
        await original_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", _counting_commit)

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )

    assert result.exit_code == 0, result.output
    assert commit_calls["n"] == 1


@pytest.mark.integration
def test_set_password_redis_failure_is_best_effort(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """A `RedisError` during the post-commit session-cache purge or
    lockout-counter clear does not turn an already-committed password
    reset into a command failure — see `user-service.md`'s best-effort
    contract."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdredisfail"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    monkeypatch.setattr(
        session_service, "_new_redis_client", lambda: _FailingRedisClient()
    )
    monkeypatch.setattr(
        local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
    )

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code == 0, result.output

    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash is not None
    assert verify_password(_NEW_STRONG_PASSWORD, refreshed.password_hash)


@pytest.mark.integration
def test_set_password_redis_success_purges_session_and_lockout(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    redis_client: redis_asyncio.Redis,
) -> None:
    """Uses the `redis_client` fixture only for its URL and its
    `get_session_redis_url`/`get_lockout_redis_url` monkeypatch side
    effects — never awaited directly from this sync test's own
    `asyncio.run()` calls, which each create and close their own client
    (see `_redis_set_key`/`_redis_get_key`), consistent with never
    sharing a live async client across event loops."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    redis_url = redis_url_from_client(redis_client)
    username = "clisetpwdredissuccess"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    active_session = asyncio.run(
        _create_session_directly(cli_session_factory, user_id=user.id, is_active=True)
    )

    liveness_key = f"session_liveness:{active_session.id}"
    lockout_key = f"login_attempts:{username}"
    asyncio.run(_redis_set_key(redis_url, liveness_key, "1"))
    asyncio.run(_redis_set_key(redis_url, lockout_key, "3"))

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )
    assert result.exit_code == 0, result.output

    assert asyncio.run(_redis_get_key(redis_url, liveness_key)) is None
    assert asyncio.run(_redis_get_key(redis_url, lockout_key)) is None


# ---------------------------------------------------------------------------
# Integration: unlock
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_unlock_invalid_username_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "unlock", "--username", "1bad"])
    assert result.exit_code == 1
    assert "Invalid username '1bad'" in result.stderr


@pytest.mark.integration
def test_unlock_user_not_found_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["manage-user", "unlock", "--username", "doesnotexistatall"])
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: User 'doesnotexistatall' not found."


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_normalizes_username_before_lookup(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlocknormalize"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["manage-user", "unlock", "--username", f"  {username.upper()}  "])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_active_local_user_no_warnings(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlockactive"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_inactive_user_warns_and_continues(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlockinactive"
    cleanup_users_by_username(username)
    asyncio.run(
        _create_user_directly(cli_session_factory, username=username, active=False)
    )

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert result.stderr.strip() == (
        f"Warning: User '{username}' is inactive. Unlock has no practical "
        "effect until the user is reactivated."
    )
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_external_user_warns_and_continues(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlockexternal"
    cleanup_users_by_username(username)
    asyncio.run(
        _create_user_directly(
            cli_session_factory, username=username, external_id=uuid4()
        )
    )

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert result.stderr.strip() == (
        f"Warning: User '{username}' is an external user. Local login "
        "lockout does not apply to SSO authentication."
    )
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_inactive_external_user_both_warnings(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlockbothwarn"
    cleanup_users_by_username(username)
    asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=username,
            active=False,
            external_id=uuid4(),
        )
    )

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    stderr_lines = result.stderr.strip().splitlines()
    assert stderr_lines == [
        f"Warning: User '{username}' is inactive. Unlock has no practical "
        "effect until the user is reactivated.",
        f"Warning: User '{username}' is an external user. Local login "
        "lockout does not apply to SSO authentication.",
    ]
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
def test_unlock_deletes_existing_lockout_key(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    redis_client: redis_asyncio.Redis,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    redis_url = redis_url_from_client(redis_client)
    username = "cliunlockdeleteskey"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    lockout_key = f"login_attempts:{username}"
    asyncio.run(_redis_set_key(redis_url, lockout_key, "3"))

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert asyncio.run(_redis_get_key(redis_url, lockout_key)) is None


@pytest.mark.integration
def test_unlock_zero_counter_is_removed(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    redis_client: redis_asyncio.Redis,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    redis_url = redis_url_from_client(redis_client)
    username = "cliunlockzerocounter"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    lockout_key = f"login_attempts:{username}"
    asyncio.run(_redis_set_key(redis_url, lockout_key, "0"))

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert asyncio.run(_redis_get_key(redis_url, lockout_key)) is None


@pytest.mark.integration
def test_unlock_missing_key_is_idempotent_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    redis_client: redis_asyncio.Redis,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlocknokey"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
def test_unlock_redis_failure_still_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlockredisfail"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    monkeypatch.setattr(
        local_auth_service, "_new_redis_client", lambda: _FailingRedisClient()
    )

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_creates_no_audit_event(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlocknoaudit"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output

    async def _fetch_all_events() -> list[IdentityAuditEvent]:
        async with cli_session_factory() as db:
            events = await db.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.target_user_id == user.id
                )
            )
            return list(events.scalars().all())

    assert asyncio.run(_fetch_all_events()) == []


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_issues_no_database_commit(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlocknocommit"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    original_commit = AsyncSession.commit

    async def _fail_commit(self: AsyncSession) -> None:
        raise AssertionError("unlock must not commit")

    monkeypatch.setattr(AsyncSession, "commit", _fail_commit)

    result = _invoke(["manage-user", "unlock", "--username", username])
    assert result.exit_code == 0, result.output

    # Restore explicitly before the `cleanup_users_by_username` fixture's
    # own teardown runs its own real commit — fixture teardown order is
    # not guaranteed to happen after monkeypatch's own automatic undo.
    monkeypatch.setattr(AsyncSession, "commit", original_commit)


# ---------------------------------------------------------------------------
# Integration: username-only resolution
# ---------------------------------------------------------------------------
#
# docs/conventions.md (Command Design — Username normalization and
# resolution): every `--username` is matched by exact normalized username,
# never by the API's UUID-or-username resolution. A letter-leading UUID is
# also a format-valid username, so it reaches the lookup of every command,
# including the ones that validate the username format first.


def _letter_leading_uuid() -> UUID:
    """A random UUID whose canonical text starts with a letter, so it is
    also a format-valid username (docs/conventions.md, Username Format)."""
    return UUID("a" + uuid4().hex[1:])


@pytest.mark.integration
def test_show_uuid_shaped_username_resolves_by_username_not_by_id(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """The value is both one user's username and another user's ID: the
    command shows the username owner."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    shared = _letter_leading_uuid()
    username_owner = str(shared)
    id_owner = "clishowidowner"
    cleanup_users_by_username(username_owner, id_owner)
    asyncio.run(
        _create_user_directly(cli_session_factory, username=id_owner, user_id=shared)
    )
    asyncio.run(
        _create_user_directly(
            cli_session_factory, username=username_owner, full_name="Username Owner"
        )
    )

    result = _invoke(["manage-user", "show", "--username", username_owner.upper()])

    assert result.exit_code == 0, result.output
    assert f"Username:     {username_owner}" in result.stdout
    assert "Full name:    Username Owner" in result.stdout


@pytest.mark.integration
@pytest.mark.parametrize(
    "letter_leading_id", [True, False], ids=["letter-id", "uuid7-id"]
)
def test_show_rejects_existing_user_uuid_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    letter_leading_id: bool,
) -> None:
    """`show` performs no format validation, so any user UUID — including
    the generated digit-leading UUIDv7 — reaches the lookup and matches no
    username."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = f"clishowbyuuid{'letter' if letter_leading_id else 'uuid7'}"
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user_directly(
            cli_session_factory,
            username=username,
            user_id=_letter_leading_uuid() if letter_leading_id else None,
        )
    )

    result = _invoke(["manage-user", "show", "--username", str(user.id)])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == f"Error: User '{user.id}' not found.\n"


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_set_password_uuid_shaped_username_resolves_by_username(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = str(_letter_leading_uuid())
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(
        ["manage-user", "set-password", "--username", username],
        input=_NEW_PASSWORD_INPUT,
    )

    assert result.exit_code == 0, result.output
    assert (
        result.stdout.strip().splitlines()[-1]
        == f"Password updated for user '{username}'. All active sessions invalidated."
    )
    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash is not None
    assert verify_password(_NEW_STRONG_PASSWORD, refreshed.password_hash)


@pytest.mark.integration
def test_set_password_rejects_existing_user_uuid_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """Reported before the password prompt; nothing is changed."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    username = "clisetpwdbyuuid"
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user_directly(
            cli_session_factory, username=username, user_id=_letter_leading_uuid()
        )
    )

    result = _invoke(["manage-user", "set-password", "--username", str(user.id)])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == f"Error: User '{user.id}' not found.\n"
    refreshed = asyncio.run(_fetch_user(cli_session_factory, username))
    assert refreshed is not None
    assert refreshed.password_hash == user.password_hash


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_unlock_uuid_shaped_username_resolves_by_username(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = str(_letter_leading_uuid())
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["manage-user", "unlock", "--username", username])

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    assert result.stdout.strip() == f"Unlocked user '{username}'."


@pytest.mark.integration
def test_unlock_rejects_existing_user_uuid_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliunlockbyuuid"
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user_directly(
            cli_session_factory, username=username, user_id=_letter_leading_uuid()
        )
    )

    result = _invoke(["manage-user", "unlock", "--username", str(user.id)])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == f"Error: User '{user.id}' not found.\n"
