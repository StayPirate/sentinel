"""`sentinel api-key` command group: list and revoke.

See `docs/features/identity/api-key-management.md` (CLI Commands) for
the authoritative per-command contract (parameters, exact messages, exit
codes) this module implements, and
`docs/features/platform/cli-infrastructure.md` for the shared bootstrap,
session, and error-mapping mechanism it builds on.

Module-level imports are intentionally limited to Core-layer modules and
third-party libraries that do not instantiate `Settings` —
`app.services.api_key_service` (which transitively imports `app.config`)
is imported lazily, inside each command's own workflow, after
`app.cli._runtime.bootstrap()` has already validated `Settings`. This
preserves the requirement that `--help` at every level never loads
application settings or opens a database connection. Mirrors
`app.cli.manage_user`'s module docstring rationale.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import click

from app.cli._runtime import bootstrap, get_session_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.models.api_key import ApiKey
    from app.services.api_key_service import ApiKeyCliList

_LIST_HEADERS = (
    "ID",
    "PREFIX",
    "NAME",
    "STATUS",
    "CREATED AT",
    "LAST USED AT",
    "EXPIRES AT",
)


@click.group("api-key")
def api_key_group() -> None:
    """API key operator commands (listing and emergency revocation).

    This group callback is intentionally a no-op — see
    `app.cli.manage_user.manage_user_group`'s identical docstring
    rationale: Click invokes a group's own callback before creating its
    child command's context, including for a child's own `--help`, so
    bootstrap logic cannot live here.
    """


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@api_key_group.command("list")
@click.option("--username", required=True, help="Username of the key owner.")
def list_keys(username: str) -> None:
    """List every API key owned by a user.

    See `docs/features/identity/api-key-management.md`
    (`sentinel api-key list`) for the full behavioral contract.
    """
    bootstrap()

    normalized_username = username.strip().lower()
    result = asyncio.run(_list_keys_flow(get_session_factory(), normalized_username))
    click.echo(_render_key_table(result))


async def _list_keys_flow(
    session_factory: async_sessionmaker[AsyncSession], username: str
) -> ApiKeyCliList:
    """Read every key owned by `username` via
    `api_key_service.list_user_keys_for_cli()`.

    Read-only: opens a session, delegates the query, and issues no
    commit — see `docs/features/platform/cli-infrastructure.md`
    (Database Session Management). Translates `UserNotFoundError` into
    the command's exact not-found message and exit code.
    """
    from app.core.exceptions import UserNotFoundError
    from app.services import api_key_service

    async with session_factory() as db:
        try:
            return await api_key_service.list_user_keys_for_cli(db, username)
        except UserNotFoundError:
            click.echo(f"Error: User '{username}' not found.", err=True)
            raise SystemExit(1) from None


def _format_utc(value: datetime | None) -> str:
    """Render a timestamp as `YYYY-MM-DD HH:MM:SS UTC`, or `—` when absent.

    Duplicated from `app.cli.manage_user._format_utc` rather than
    imported: the two CLI command modules are independent leaves and
    importing a private helper across them would create an unnecessary
    coupling for a three-line function.
    """
    if value is None:
        return "—"
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _render_key_row(api_key: ApiKey, evaluated_at: datetime) -> tuple[str, ...]:
    """Build one `api-key list` row.

    Status is derived via `api_key_service.derive_api_key_status()` using
    the caller-supplied `evaluated_at` snapshot — never a fresh
    per-row `datetime.now()` — so every row in one invocation is
    classified against the exact same instant.
    """
    from app.services.api_key_service import derive_api_key_status

    status = derive_api_key_status(api_key, evaluated_at)
    return (
        str(api_key.id),
        api_key.prefix,
        api_key.name,
        status.value,
        _format_utc(api_key.created_at),
        _format_utc(api_key.last_used_at),
        _format_utc(api_key.expires_at),
    )


def _render_key_table(result: ApiKeyCliList) -> str:
    """Render the fixed-width `api-key list` table (header + rows).

    Each column's width is the maximum length across its header and
    every rendered value — no truncation, no wrapping (see
    `docs/features/identity/api-key-management.md`, `sentinel api-key
    list`). A user with no keys renders only the header line.
    """
    rows = [_render_key_row(key, result.evaluated_at) for key in result.items]
    all_rows = [_LIST_HEADERS, *rows]
    widths = [max(len(row[i]) for row in all_rows) for i in range(len(_LIST_HEADERS))]
    lines = [
        "  ".join(row[i].ljust(widths[i]) for i in range(len(_LIST_HEADERS))).rstrip()
        for row in all_rows
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


@api_key_group.command("revoke")
@click.option(
    "--key-id",
    "key_id",
    required=True,
    type=click.UUID,
    help="Globally unique API key UUID.",
)
def revoke(key_id: UUID) -> None:
    """Revoke the API key identified by its globally unique UUID.

    See `docs/features/identity/api-key-management.md`
    (`sentinel api-key revoke`) for the full behavioral contract. Does
    not accept or infer a username: `key_id` uniquely identifies the
    target key regardless of owner.
    """
    bootstrap()

    asyncio.run(_revoke_flow(get_session_factory(), key_id))
    click.echo(f"API key '{key_id}' is revoked.")


async def _revoke_flow(
    session_factory: async_sessionmaker[AsyncSession], key_id: UUID
) -> None:
    """Delegate to `api_key_service.revoke_key()` without an owner
    restriction and with `acting_user_id=None` (system action).

    Owns one database transaction: opens the session, invokes the
    service (which flushes but never commits), commits exactly once on
    success — including the already-revoked no-op path, which is still
    a successful call — and rolls back on any exception or interruption
    before commit. See
    `docs/features/platform/cli-infrastructure.md` (Database Session
    Management).
    """
    from app.services import api_key_service
    from app.services.api_key_service import ApiKeyNotFoundError

    async with session_factory() as db:
        try:
            await api_key_service.revoke_key(
                db, key_id, acting_user_id=None, owner_user_id=None
            )
            await db.commit()
        except ApiKeyNotFoundError:
            await db.rollback()
            click.echo(f"Error: API key '{key_id}' not found.", err=True)
            raise SystemExit(1) from None
        except BaseException:
            await db.rollback()
            raise
