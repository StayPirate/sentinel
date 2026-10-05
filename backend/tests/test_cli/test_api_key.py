"""Tests for `sentinel api-key list/revoke`.

See docs/features/identity/api-key-management.md for the authoritative
per-command contract exercised here. Unit tests cover the pure rendering
helpers directly; integration tests exercise the full `CliRunner`-invoked
commands against the real PostgreSQL test database via the
`cli_session_factory`/`cleanup_users_by_username` fixtures (see
docs/features/platform/testing-strategy.md, Sync Entry-Point Tests) —
mirrors `test_manage_user.py`'s module docstring rationale: setup data is
created directly through `cli_session_factory` rather than through
`db_session`-based factories, which run in a separate connection.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import click
import pytest
from click.testing import CliRunner, Result
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.cli.api_key as api_key_module
from app.cli import cli
from app.core.enums import IdentityAuditEventType
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services.api_key_service import ApiKeyCliList


def _invoke(args: list[str], input: str | None = None, **extra: Any) -> Result:
    """Invoke the raw `cli` group with `standalone_mode=False`, mirroring
    exactly how production's `main()` invokes it — see the identical
    helper docstring in `test_main.py`/`test_manage_user.py`."""
    return CliRunner().invoke(cli, args, input=input, standalone_mode=False, **extra)


def _inject_session_factory(
    monkeypatch: pytest.MonkeyPatch,
    factory: async_sessionmaker[AsyncSession],
) -> None:
    monkeypatch.setattr(api_key_module, "get_session_factory", lambda: factory)


async def _create_user_directly(
    factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
    active: bool = True,
    user_id: UUID | None = None,
) -> User:
    """Insert and commit a `User` directly through `cli_session_factory`,
    bypassing `user_service` entirely. `user_id`, when given, overrides the
    generated primary key."""
    async with factory() as db:
        user = User(
            username=username,
            email=f"{username}@example.com",
            active=active,
            password_hash="$2b$12$" + "a" * 53,
        )
        if user_id is not None:
            user.id = user_id
        db.add(user)
        await db.commit()
        return user


async def _create_api_key_directly(
    factory: async_sessionmaker[AsyncSession],
    *,
    user_id: UUID,
    name: str,
    prefix: str = "sk-test-000",
    created_at: datetime | None = None,
    last_used_at: datetime | None = None,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
    revoked_by: UUID | None = None,
) -> ApiKey:
    """Insert and commit an `ApiKey` row directly through
    `cli_session_factory`, bypassing `api_key_service` entirely — used to
    set up fixtures for `api-key list`/`revoke` tests."""
    async with factory() as db:
        kwargs: dict[str, Any] = {
            "user_id": user_id,
            "key_hash": hashlib.sha256(uuid4().bytes).hexdigest(),
            "prefix": prefix,
            "name": name,
            "last_used_at": last_used_at,
            "expires_at": expires_at,
            "revoked_at": revoked_at,
            "revoked_by": revoked_by,
        }
        if created_at is not None:
            kwargs["created_at"] = created_at
        api_key = ApiKey(**kwargs)
        db.add(api_key)
        await db.commit()
        return api_key


async def _fetch_api_key(
    factory: async_sessionmaker[AsyncSession], key_id: UUID
) -> ApiKey | None:
    async with factory() as db:
        result: ApiKey | None = await db.scalar(
            select(ApiKey).where(ApiKey.id == key_id)
        )
        return result


async def _fetch_key_revoked_events(
    factory: async_sessionmaker[AsyncSession], key_id: UUID
) -> list[IdentityAuditEvent]:
    async with factory() as db:
        result = await db.execute(
            select(IdentityAuditEvent).where(
                IdentityAuditEvent.event_type
                == IdentityAuditEventType.API_KEY_REVOKED.value,
                IdentityAuditEvent.detail["key_id"].astext == str(key_id),
            )
        )
        return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Unit: rendering helpers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_format_utc_none_renders_em_dash() -> None:
    assert api_key_module._format_utc(None) == "—"


@pytest.mark.unit
def test_format_utc_converts_to_utc_display_format() -> None:
    value = datetime(2025, 3, 15, 10, 30, 0, tzinfo=UTC)
    assert api_key_module._format_utc(value) == "2025-03-15 10:30:00 UTC"


@pytest.mark.unit
def test_render_key_row_active_key_absent_last_used_and_expires() -> None:
    key_id = uuid4()
    api_key = ApiKey(
        id=key_id,
        user_id=uuid4(),
        key_hash="a" * 64,
        prefix="sk-abc123456",
        name="my-automation-bot",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
        last_used_at=None,
        expires_at=None,
        revoked_at=None,
    )
    row = api_key_module._render_key_row(api_key, datetime(2025, 6, 1, tzinfo=UTC))
    assert row == (
        str(key_id),
        "sk-abc123456",
        "my-automation-bot",
        "active",
        "2025-01-01 00:00:00 UTC",
        "—",
        "—",
    )


@pytest.mark.unit
def test_render_key_row_revoked_precedes_expired() -> None:
    """A key that is both revoked and expired renders `revoked`, not
    `expired` — precedence per `api-key-management.md` (Derived Status)."""
    now = datetime(2025, 6, 1, tzinfo=UTC)
    api_key = ApiKey(
        id=uuid4(),
        user_id=uuid4(),
        key_hash="a" * 64,
        prefix="sk-abc123456",
        name="expired-and-revoked",
        created_at=now - timedelta(days=10),
        expires_at=now - timedelta(days=1),
        revoked_at=now - timedelta(hours=1),
    )
    row = api_key_module._render_key_row(api_key, now)
    assert row[3] == "revoked"


@pytest.mark.unit
def test_render_key_table_empty_result_renders_header_only() -> None:
    result = ApiKeyCliList(items=[], evaluated_at=datetime.now(UTC))
    table = api_key_module._render_key_table(result)
    lines = table.splitlines()
    assert len(lines) == 1
    assert lines[0].split() == [
        "ID",
        "PREFIX",
        "NAME",
        "STATUS",
        "CREATED",
        "AT",
        "LAST",
        "USED",
        "AT",
        "EXPIRES",
        "AT",
    ]


@pytest.mark.unit
def test_render_key_table_dynamic_column_widths_no_truncation() -> None:
    """Column widths grow to fit the longest value — a long name is never
    truncated (`docs/features/identity/api-key-management.md`, `sentinel
    api-key list`)."""
    long_name = "a" * 128
    now = datetime(2025, 6, 1, tzinfo=UTC)
    api_key = ApiKey(
        id=uuid4(),
        user_id=uuid4(),
        key_hash="a" * 64,
        prefix="sk-abc123456",
        name=long_name,
        created_at=now,
    )
    result = ApiKeyCliList(items=[api_key], evaluated_at=now)
    table = api_key_module._render_key_table(result)
    assert long_name in table
    lines = table.splitlines()
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# Integration: list
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_keys_user_not_found_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["api-key", "list", "--username", "doesnotexistatall"])
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: User 'doesnotexistatall' not found."


@pytest.mark.integration
def test_list_keys_username_normalized(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistnormalize"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["api-key", "list", "--username", f"  {username.upper()}  "])
    assert result.exit_code == 0, result.output


def _letter_leading_uuid() -> UUID:
    """A random UUID whose canonical text starts with a letter, so it is
    also a format-valid username (docs/conventions.md, Username Format)."""
    return UUID("a" + uuid4().hex[1:])


@pytest.mark.integration
def test_list_keys_uuid_shaped_username_resolves_by_username(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """docs/conventions.md (Command Design — Username normalization and
    resolution): a valid username shaped like a UUID is an ordinary
    username."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = str(_letter_leading_uuid())
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(cli_session_factory, user_id=user.id, name="uuid-key")
    )

    result = _invoke(["api-key", "list", "--username", username])

    assert result.exit_code == 0, result.output
    assert str(api_key.id) in result.stdout


@pytest.mark.integration
def test_list_keys_rejects_existing_user_uuid_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """A user's UUID is never accepted in place of the username."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistbyuuid"
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user_directly(
            cli_session_factory, username=username, user_id=_letter_leading_uuid()
        )
    )

    result = _invoke(["api-key", "list", "--username", str(user.id)])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr.strip() == f"Error: User '{user.id}' not found."


@pytest.mark.integration
def test_list_keys_empty_result_prints_header_only(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistempty"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0].startswith("ID")


@pytest.mark.integration
def test_list_keys_inactive_user_still_lists_keys(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistinactiveuser"
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user_directly(cli_session_factory, username=username, active=False)
    )
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="retained-key"
        )
    )

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output
    assert "retained-key" in result.stdout


@pytest.mark.integration
def test_list_keys_orders_by_created_at_desc_then_id_desc(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistordering"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))

    now = datetime.now(UTC)
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="oldest-key",
            created_at=now - timedelta(days=2),
        )
    )
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="newest-key",
            created_at=now,
        )
    )

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output
    data_lines = [line for line in result.stdout.splitlines()[1:] if line.strip()]
    names_in_order = [line.split()[2] for line in data_lines]
    assert names_in_order == ["newest-key", "oldest-key"]


@pytest.mark.integration
def test_list_keys_exclusive_status_precedence(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyliststatus"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))

    now = datetime.now(UTC)
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="active-key"
        )
    )
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="expired-key",
            expires_at=now - timedelta(days=1),
        )
    )
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="revoked-key",
            revoked_at=now - timedelta(hours=1),
        )
    )
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="revoked-and-expired-key",
            expires_at=now - timedelta(days=1),
            revoked_at=now - timedelta(hours=1),
        )
    )

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output
    statuses = {
        line.split()[2]: line.split()[3]
        for line in result.stdout.splitlines()[1:]
        if line.strip()
    }
    assert statuses["active-key"] == "active"
    assert statuses["expired-key"] == "expired"
    assert statuses["revoked-key"] == "revoked"
    assert statuses["revoked-and-expired-key"] == "revoked"


@pytest.mark.integration
def test_list_keys_utc_rendering_converts_offset_to_utc(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistutc"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))

    # UTC+2 offset: 12:30 local == 10:30 UTC.
    from datetime import timezone

    offset_tz = timezone(timedelta(hours=2))
    created_at = datetime(2025, 3, 15, 12, 30, 0, tzinfo=offset_tz)
    asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="offset-key",
            created_at=created_at,
        )
    )

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output
    assert "2025-03-15 10:30:00 UTC" in result.stdout


@pytest.mark.integration
def test_list_keys_no_secret_or_hash_exposed(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistsecrecy"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="secrecy-key"
        )
    )

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output
    assert api_key.key_hash not in result.output
    assert str(user.id) not in result.output


@pytest.mark.integration
def test_list_keys_issues_no_database_commit(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeylistnocommit"
    cleanup_users_by_username(username)
    asyncio.run(_create_user_directly(cli_session_factory, username=username))

    original_commit = AsyncSession.commit

    async def _fail_commit(self: AsyncSession) -> None:
        raise AssertionError("list must not commit")

    monkeypatch.setattr(AsyncSession, "commit", _fail_commit)

    result = _invoke(["api-key", "list", "--username", username])
    assert result.exit_code == 0, result.output

    monkeypatch.setattr(AsyncSession, "commit", original_commit)


# ---------------------------------------------------------------------------
# Integration: revoke
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_revoke_malformed_uuid_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    result = _invoke(["api-key", "revoke", "--key-id", "not-a-uuid"])
    assert result.exit_code == 1
    assert isinstance(result.exception, click.UsageError)


@pytest.mark.integration
def test_revoke_rejects_username_option() -> None:
    """`api-key revoke` does not accept `--username` — the key UUID
    alone identifies the target regardless of owner."""
    result = _invoke(
        ["api-key", "revoke", "--key-id", str(uuid4()), "--username", "someuser"]
    )
    assert result.exit_code == 1
    assert isinstance(result.exception, click.UsageError)


@pytest.mark.integration
def test_revoke_missing_key_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    key_id = uuid4()
    result = _invoke(["api-key", "revoke", "--key-id", str(key_id)])
    assert result.exit_code == 1
    assert result.stderr.strip() == f"Error: API key '{key_id}' not found."


@pytest.mark.integration
def test_revoke_effective_revocation_sets_fields_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevokesuccess"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(cli_session_factory, user_id=user.id, name="revoke-me")
    )

    result = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == f"API key '{api_key.id}' is revoked."

    refreshed = asyncio.run(_fetch_api_key(cli_session_factory, api_key.id))
    assert refreshed is not None
    assert refreshed.revoked_at is not None
    assert refreshed.revoked_by is None


@pytest.mark.integration
def test_revoke_already_revoked_is_idempotent_noop_same_message(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevokenoop"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(
            cli_session_factory,
            user_id=user.id,
            name="already-revoked",
            revoked_at=datetime.now(UTC) - timedelta(hours=1),
        )
    )

    result = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == f"API key '{api_key.id}' is revoked."

    refreshed = asyncio.run(_fetch_api_key(cli_session_factory, api_key.id))
    assert refreshed is not None
    assert refreshed.revoked_at == api_key.revoked_at


@pytest.mark.integration
def test_revoke_creates_exact_audit_event(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevokeaudit"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(cli_session_factory, user_id=user.id, name="audit-key")
    )

    result = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert result.exit_code == 0, result.output

    events = asyncio.run(_fetch_key_revoked_events(cli_session_factory, api_key.id))
    assert len(events) == 1
    event = events[0]
    assert event.user_id is None
    assert event.target_user_id == user.id
    assert event.old_value == "audit-key"
    assert event.new_value is None
    assert event.detail == {"key_id": str(api_key.id)}


@pytest.mark.integration
def test_revoke_second_revoke_creates_no_additional_audit_event(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevoketwice"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="revoke-twice"
        )
    )

    first = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert first.exit_code == 0, first.output
    second = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert second.exit_code == 0, second.output
    assert second.stdout.strip() == first.stdout.strip()

    events = asyncio.run(_fetch_key_revoked_events(cli_session_factory, api_key.id))
    assert len(events) == 1


@pytest.mark.integration
def test_revoke_commits_exactly_once_on_success(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevokecommitcount"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="commit-count-key"
        )
    )

    commit_calls = {"n": 0}
    original_commit = AsyncSession.commit

    async def _counting_commit(self: AsyncSession) -> None:
        commit_calls["n"] += 1
        await original_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", _counting_commit)

    result = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])

    assert result.exit_code == 0, result.output
    assert commit_calls["n"] == 1


@pytest.mark.integration
def test_revoke_rolls_back_on_audit_failure(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevokeauditfail"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="audit-fail-key"
        )
    )

    from app.services import identity_audit_log as audit_module

    async def _raise_log_event(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr(audit_module.IdentityAuditLog, "log_event", _raise_log_event)

    result = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert result.exit_code != 0

    refreshed = asyncio.run(_fetch_api_key(cli_session_factory, api_key.id))
    assert refreshed is not None
    assert refreshed.revoked_at is None
    assert asyncio.run(_fetch_key_revoked_events(cli_session_factory, api_key.id)) == []


@pytest.mark.integration
def test_revoke_no_secret_or_hash_in_output(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = "cliapikeyrevokesecrecy"
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user_directly(cli_session_factory, username=username))
    api_key = asyncio.run(
        _create_api_key_directly(
            cli_session_factory, user_id=user.id, name="secrecy-revoke-key"
        )
    )

    result = _invoke(["api-key", "revoke", "--key-id", str(api_key.id)])
    assert result.exit_code == 0, result.output
    assert api_key.key_hash not in result.output
    assert "secrecy-revoke-key" not in result.output
