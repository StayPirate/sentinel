"""`sentinel manage-user` command group: create, list, show, set-password,
and unlock.

See `docs/features/identity/user-management.md` for the authoritative
per-command contract (parameters, exact messages, exit codes) this module
implements, and `docs/features/platform/cli-infrastructure.md` for the
shared bootstrap, session, and error-mapping mechanism it builds on.

Module-level imports are intentionally limited to Core-layer modules and
third-party libraries that do not instantiate `Settings` — `app.config`,
`app.database`, and `app.services.user_service` (which transitively
imports `app.config`) are imported lazily, inside each command's own
workflow, after `app.cli._runtime.bootstrap()` has already validated
`Settings`. This preserves the requirement that `--help` at every level
never loads application settings or opens a database connection.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import click
from email_validator import EmailNotValidError, validate_email

from app.cli._prompts import is_interactive_terminal, prompt_password_with_confirmation
from app.cli._runtime import bootstrap, get_session_factory
from app.core.enums import Role, UserType
from app.core.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.core.permissions import role_from_wire, role_to_wire

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.models.user import User
    from app.models.user_role import UserRole

# Username Format (docs/conventions.md): 1-64 characters, starts with a
# letter, lowercase letters/numbers/dots/hyphens/underscores only. Mirrors
# the convention directly rather than importing user_service's private
# `_USERNAME_PATTERN`, since that name is internal to the service module.
_USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

# Fixed label-column width for `manage-user show`'s detail output — every
# label (including its trailing colon) is left-padded to this width before
# the value, matching the alignment in the command's spec example.
_SHOW_LABEL_WIDTH = 14

_LIST_HEADERS = ("USERNAME", "FULL NAME", "EMAIL", "TYPE", "STATUS", "ROLES")


@click.group("manage-user")
def manage_user_group() -> None:
    """User lifecycle management (local administrator bootstrap and
    recovery, directory listing, and detail lookup).

    This group callback is intentionally a no-op: Click invokes a group's
    own callback before creating its child command's context — including
    when the child's own `--help` triggered the invocation — so bootstrap
    logic cannot live here without also running for nested `--help`
    invocations. See `app.cli._runtime.bootstrap()`.
    """


def _valid_roles_list() -> str:
    """Comma-separated, alphabetically sorted list of valid role wire values."""
    return ", ".join(sorted(role_to_wire(role) for role in Role))


def _parse_roles_or_exit(role_values: tuple[str, ...]) -> list[Role]:
    """Convert CLI `--role` wire values to `Role`, or exit 1 on the first
    invalid value with the exact message shared by `create` and `list`."""
    parsed: list[Role] = []
    for value in role_values:
        try:
            parsed.append(role_from_wire(value))
        except ValueError:
            click.echo(
                f"Error: Invalid role '{value}'. Valid roles are: "
                f"{_valid_roles_list()}.",
                err=True,
            )
            raise SystemExit(1) from None
    return parsed


def _normalize_username_or_exit(username: str) -> str:
    """Trim/lowercase `username` and validate its format, or exit 1."""
    normalized = username.strip().lower()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        click.echo(
            f"Error: Invalid username '{normalized}'. Username must be "
            "1-64 characters, start with a letter, and contain only "
            "lowercase letters, numbers, dots, hyphens, and underscores.",
            err=True,
        )
        raise SystemExit(1)
    return normalized


def _normalize_email_or_exit(email: str) -> str:
    """Trim/lowercase `email` and validate its format, or exit 1."""
    normalized = email.strip().lower()
    try:
        validate_email(normalized, check_deliverability=False)
    except EmailNotValidError:
        click.echo(f"Error: Invalid email format '{normalized}'.", err=True)
        raise SystemExit(1) from None
    return normalized


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@manage_user_group.command("create")
@click.option("--username", required=True, help="Unique username for the account.")
@click.option("--email", required=True, help="Unique email address.")
@click.option("--full-name", default=None, help="Display name.")
@click.option(
    "--role",
    "roles",
    multiple=True,
    help=(
        "Role to assign: admin, vulnerability_analyst, restricted_analyst. Repeatable."
    ),
)
def create(
    username: str, email: str, full_name: str | None, roles: tuple[str, ...]
) -> None:
    """Create a new local user account with a password.

    See `docs/features/identity/user-management.md`
    (`sentinel manage-user create`) for the full behavioral contract.
    """
    bootstrap()

    normalized_username = _normalize_username_or_exit(username)
    parsed_roles = _parse_roles_or_exit(roles)
    normalized_email = _normalize_email_or_exit(email)

    if not is_interactive_terminal():
        click.echo(
            "Error: This command requires an interactive terminal (password input).",
            err=True,
        )
        raise SystemExit(1)

    password = prompt_password_with_confirmation()
    if password is None:
        click.echo("Error: Passwords do not match.", err=True)
        raise SystemExit(1)

    if len(password) < MIN_PASSWORD_LENGTH:
        click.echo(
            f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            err=True,
        )
        raise SystemExit(1)
    if len(password) > MAX_PASSWORD_LENGTH:
        click.echo(
            f"Error: Password must be at most {MAX_PASSWORD_LENGTH} characters.",
            err=True,
        )
        raise SystemExit(1)

    asyncio.run(
        _create_flow(
            get_session_factory(),
            username=normalized_username,
            email=normalized_email,
            full_name=full_name,
            roles=parsed_roles,
            password=password,
        )
    )


async def _create_flow(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
    email: str,
    full_name: str | None,
    roles: list[Role],
    password: str,
) -> None:
    """Delegate account creation to `user_service.create_user()`.

    Owns one database transaction: opens the session, invokes the
    service (which flushes but never commits), commits exactly once on
    success, and rolls back on any exception or interruption before
    commit — see `docs/features/platform/cli-infrastructure.md`
    (Database Session Management).
    """
    from app.services import user_service
    from app.services.user_service import UserConflictError

    async with session_factory() as db:
        try:
            await user_service.create_user(
                db,
                username=username,
                email=email,
                full_name=full_name,
                active=True,
                external_id=None,
                password=password,
                roles=[(role, "_manual") for role in roles],
                acting_user_id=None,
            )
            await db.commit()
        except UserConflictError as exc:
            await db.rollback()
            if exc.conflict_field == "username":
                click.echo(
                    f"Error: A user with username '{username}' already exists.",
                    err=True,
                )
            else:
                click.echo(
                    f"Error: A user with email '{email}' already exists.",
                    err=True,
                )
            raise SystemExit(1) from None
        except BaseException:
            await db.rollback()
            raise

    if roles:
        role_list = ", ".join(sorted(role_to_wire(role) for role in roles))
        click.echo(f"Created user '{username}' ({email}) with roles: {role_list}.")
    else:
        click.echo(f"Created user '{username}' ({email}) with no roles.")


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@manage_user_group.command("list")
@click.option("--active", is_flag=True, help="Show only active users.")
@click.option("--inactive", is_flag=True, help="Show only inactive users.")
@click.option(
    "--role",
    "roles",
    multiple=True,
    help=(
        "Filter by role: admin, vulnerability_analyst, restricted_analyst. "
        "Repeatable (OR)."
    ),
)
@click.option(
    "--type",
    "user_type_value",
    default=None,
    help="Filter by type: local or external.",
)
def list_users(
    active: bool, inactive: bool, roles: tuple[str, ...], user_type_value: str | None
) -> None:
    """List all users in the system with their key attributes.

    See `docs/features/identity/user-management.md`
    (`sentinel manage-user list`) for the full behavioral contract.
    """
    bootstrap()

    parsed_roles = _parse_roles_or_exit(roles)

    if active and inactive:
        click.echo("Error: --active and --inactive cannot be used together.", err=True)
        raise SystemExit(1)
    active_filter = True if active else (False if inactive else None)

    user_type: UserType | None = None
    if user_type_value is not None:
        if user_type_value == "local":
            user_type = UserType.LOCAL
        elif user_type_value == "external":
            user_type = UserType.EXTERNAL
        else:
            click.echo(
                f"Error: Invalid type '{user_type_value}'. Valid types are: "
                "local, external.",
                err=True,
            )
            raise SystemExit(1)

    users = asyncio.run(
        _list_users_flow(
            get_session_factory(),
            active=active_filter,
            roles=parsed_roles,
            user_type=user_type,
        )
    )

    if not users:
        click.echo("No users found matching the specified criteria.")
        return

    click.echo(_render_list_table(users))


async def _list_users_flow(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    active: bool | None,
    roles: list[Role],
    user_type: UserType | None,
) -> list[User]:
    """Read every matching user, paging through the full result set.

    Read-only: opens a session, delegates to `user_service.list_users()`
    across as many pages as needed to reach `UserPage.total`, and issues
    no commit — see `docs/features/platform/cli-infrastructure.md`
    (Database Session Management).
    """
    from app.core.enums import SortOrder, UserSortField
    from app.services import user_service

    batch_size = 100
    items: list[User] = []
    async with session_factory() as db:
        page = 1
        while True:
            result = await user_service.list_users(
                db,
                user_type=user_type,
                active=active,
                roles=roles or None,
                page=page,
                per_page=batch_size,
                sort_by=UserSortField.USERNAME,
                sort_order=SortOrder.ASC,
            )
            items.extend(result.items)
            if not result.items or len(items) >= result.total:
                break
            page += 1
    return items


def _render_list_table(users: list[User]) -> str:
    """Render the fixed-width `manage-user list` table (header + rows)."""
    rows = [_render_user_row(user) for user in users]
    all_rows = [_LIST_HEADERS, *rows]
    widths = [max(len(row[i]) for row in all_rows) for i in range(len(_LIST_HEADERS))]
    lines = [
        "  ".join(row[i].ljust(widths[i]) for i in range(len(_LIST_HEADERS))).rstrip()
        for row in all_rows
    ]
    return "\n".join(lines)


def _render_user_row(user: User) -> tuple[str, str, str, str, str, str]:
    """Build one `manage-user list` row: username, full name, email, type,
    status, and comma-separated roles (each rendered `—` when absent)."""
    full_name = user.full_name if user.full_name else "—"
    user_type = "external" if user.external_id is not None else "local"
    status = "active" if user.active else "inactive"
    role_values = sorted({role_to_wire(Role(ur.role)) for ur in user.roles})
    roles = ", ".join(role_values) if role_values else "—"
    return (user.username, full_name, user.email, user_type, status, roles)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@manage_user_group.command("show")
@click.option("--username", required=True, help="Username of the user to display.")
def show(username: str) -> None:
    """Display detailed information about a single user.

    See `docs/features/identity/user-management.md`
    (`sentinel manage-user show`) for the full behavioral contract.
    """
    bootstrap()

    normalized_username = username.strip().lower()
    user = asyncio.run(_show_flow(get_session_factory(), normalized_username))
    click.echo(_render_user_detail(user))


async def _show_flow(
    session_factory: async_sessionmaker[AsyncSession], username: str
) -> User:
    """Look up `username` via `user_service.get_user()`.

    Read-only: opens a session, delegates the lookup, and issues no
    commit. Translates `UserNotFoundError` into the command's exact
    not-found message and exit code.
    """
    from app.core.exceptions import UserNotFoundError
    from app.services import user_service

    async with session_factory() as db:
        try:
            return await user_service.get_user(db, username)
        except UserNotFoundError:
            click.echo(f"Error: User '{username}' not found.", err=True)
            raise SystemExit(1) from None


def _format_utc(value: datetime | None) -> str:
    """Render a timestamp as `YYYY-MM-DD HH:MM:SS UTC`, or `—` when absent."""
    if value is None:
        return "—"
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _render_roles_with_origins(roles: list[UserRole]) -> str:
    """Render each held role with its origin(s) in parentheses.

    Roles are ordered alphabetically by wire value. Within a role, the
    `manual` origin (from `group_name == "_manual"`) is listed first,
    followed by any external group names in alphabetical order — matching
    the command's spec example (`admin (manual, O SUSE Admins)`).
    """
    if not roles:
        return "—"
    grouped: dict[str, list[str]] = {}
    for user_role in roles:
        wire = role_to_wire(Role(user_role.role))
        origin = "manual" if user_role.group_name == "_manual" else user_role.group_name
        grouped.setdefault(wire, []).append(origin)

    parts = []
    for wire in sorted(grouped):
        origins = sorted(grouped[wire], key=lambda origin: (origin != "manual", origin))
        parts.append(f"{wire} ({', '.join(origins)})")
    return ", ".join(parts)


def _render_user_detail(user: User) -> str:
    """Render the full `manage-user show` detail block."""
    full_name = user.full_name if user.full_name else "—"
    user_type = "external" if user.external_id is not None else "local"
    status = "active" if user.active else "inactive"
    manager = user.manager.username if user.manager is not None else "—"

    fields = (
        ("Username:", user.username),
        ("Full name:", full_name),
        ("Email:", user.email),
        ("Type:", user_type),
        ("Status:", status),
        ("Roles:", _render_roles_with_origins(user.roles)),
        ("Created:", _format_utc(user.created_at)),
        ("Last login:", _format_utc(user.last_login_at)),
        ("Manager:", manager),
    )
    return "\n".join(f"{label:<{_SHOW_LABEL_WIDTH}}{value}" for label, value in fields)


# ---------------------------------------------------------------------------
# set-password
# ---------------------------------------------------------------------------


def _external_user_password_error_message(username: str) -> str:
    """Exact error text shared by the pre-check and the mutating call —
    both `set-password`'s own guard and a re-validation failure inside
    `user_service.reset_password()` produce this identical message."""
    return (
        f"Error: Cannot set password for external user '{username}'. "
        "External users authenticate via SSO."
    )


@manage_user_group.command("set-password")
@click.option(
    "--username",
    required=True,
    help="Username of the local user whose password is set.",
)
def set_password(username: str) -> None:
    """Set or reset the password for a local user.

    See `docs/features/identity/user-management.md`
    (`sentinel manage-user set-password`) for the full behavioral contract.
    """
    bootstrap()

    normalized_username = _normalize_username_or_exit(username)

    if not is_interactive_terminal():
        click.echo(
            "Error: This command requires an interactive terminal (password input).",
            err=True,
        )
        raise SystemExit(1)

    asyncio.run(_set_password_flow(get_session_factory(), username=normalized_username))


async def _set_password_flow(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
) -> None:
    """Resolve the user, prompt for a new password, and delegate the reset.

    Single async workflow (`docs/features/platform/cli-infrastructure.md`,
    Database Session Management): a read-only session resolves the user
    and rejects an external target before the hidden password prompt runs
    — an interactive prompt MUST NOT run while a database session is
    open. A second session then delegates the mutation to
    `user_service.reset_password()`, committing exactly once on success
    and rolling back on any exception or interruption before commit.
    `UserNotFoundError`/`ExternalUserPasswordError` are also caught around
    the mutating call because `reset_password()` re-validates both guards
    atomically against the locked row — a user deleted or converted to
    external between the pre-check and the mutation surfaces the exact
    same messages as the pre-check. After the commit succeeds, runs the
    session-cache purge and login lockout-counter clear from the returned
    `PasswordResetResult`, in that order, inside this same workflow.
    """
    from app.core.exceptions import UserNotFoundError
    from app.services import local_auth_service, session_service, user_service
    from app.services.user_service import ExternalUserPasswordError

    async with session_factory() as db:
        try:
            user = await user_service.get_user(db, username)
        except UserNotFoundError:
            click.echo(f"Error: User '{username}' not found.", err=True)
            raise SystemExit(1) from None
        if user.external_id is not None:
            click.echo(_external_user_password_error_message(username), err=True)
            raise SystemExit(1)

    password = prompt_password_with_confirmation()
    if password is None:
        click.echo("Error: Passwords do not match.", err=True)
        raise SystemExit(1)

    if len(password) < MIN_PASSWORD_LENGTH:
        click.echo(
            f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            err=True,
        )
        raise SystemExit(1)
    if len(password) > MAX_PASSWORD_LENGTH:
        click.echo(
            f"Error: Password must be at most {MAX_PASSWORD_LENGTH} characters.",
            err=True,
        )
        raise SystemExit(1)

    async with session_factory() as db:
        try:
            result = await user_service.reset_password(
                db, user.id, password, acting_user_id=None
            )
            await db.commit()
        except UserNotFoundError:
            await db.rollback()
            click.echo(f"Error: User '{username}' not found.", err=True)
            raise SystemExit(1) from None
        except ExternalUserPasswordError:
            await db.rollback()
            click.echo(_external_user_password_error_message(username), err=True)
            raise SystemExit(1) from None
        except BaseException:
            await db.rollback()
            raise

    await session_service.purge_session_cache(result.invalidated_session_ids)
    await local_auth_service.clear_login_attempts(result.username)

    click.echo(
        f"Password updated for user '{username}'. All active sessions invalidated."
    )


# ---------------------------------------------------------------------------
# unlock
# ---------------------------------------------------------------------------


@manage_user_group.command("unlock")
@click.option("--username", required=True, help="Username of the user to unlock.")
def unlock(username: str) -> None:
    """Clear the login lockout counter for a user.

    See `docs/features/identity/user-management.md`
    (`sentinel manage-user unlock`) for the full behavioral contract.
    """
    bootstrap()

    normalized_username = _normalize_username_or_exit(username)

    asyncio.run(_unlock_flow(get_session_factory(), username=normalized_username))


async def _unlock_flow(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
) -> None:
    """Resolve the user, emit independent lifecycle warnings, and delegate
    to `user_service.unlock_user()`.

    Read-only for PostgreSQL: `unlock_user()` mutates only ephemeral,
    best-effort Redis state and creates no audit event, so this workflow
    issues no database commit — see
    `docs/features/platform/cli-infrastructure.md` (Database Session
    Management). Both the inactive and external warnings are independent:
    an inactive external user receives both, and neither aborts the
    command.
    """
    from app.core.exceptions import UserNotFoundError
    from app.services import user_service

    async with session_factory() as db:
        try:
            user = await user_service.get_user(db, username)
        except UserNotFoundError:
            click.echo(f"Error: User '{username}' not found.", err=True)
            raise SystemExit(1) from None

        if not user.active:
            click.echo(
                f"Warning: User '{username}' is inactive. Unlock has no "
                "practical effect until the user is reactivated.",
                err=True,
            )
        if user.external_id is not None:
            click.echo(
                f"Warning: User '{username}' is an external user. Local "
                "login lockout does not apply to SSO authentication.",
                err=True,
            )

        await user_service.unlock_user(db, user.id, acting_user_id=None)

    click.echo(f"Unlocked user '{username}'.")
