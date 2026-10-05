"""Sentinel CLI package: root command group and shared bootstrap.

See `docs/features/platform/cli-infrastructure.md` for the full contract
this package implements: package entry point, root command group
assembly, error-to-exit-code mapping, and signal handling.
"""

from __future__ import annotations

import sys
from importlib.metadata import version as get_version

import click
import structlog
from redis.exceptions import RedisError
from sqlalchemy.exc import DBAPIError, OperationalError

from app.cli._runtime import install_signal_handlers
from app.cli.api_key import api_key_group
from app.cli.fetcher import fetcher_group
from app.cli.manage_user import manage_user_group
from app.core.exceptions import ServiceError

logger = structlog.get_logger(__name__)


def _print_version(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    """Eager `--version` callback: print the installed package version
    and exit 0, without loading application settings or opening any
    connection — see `docs/features/platform/cli-infrastructure.md`
    (Root Command Group & Bootstrap, step 1)."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(get_version("sentinel"))
    ctx.exit()


@click.group()
@click.option(
    "--version",
    is_flag=True,
    expose_value=False,
    is_eager=True,
    callback=_print_version,
    help="Show the version and exit.",
)
def cli() -> None:
    """Sentinel command-line interface.

    This callback is intentionally a no-op: Click invokes a group's own
    callback before creating its child command's context — including
    when the child's own `--help` triggered the invocation. Fail-fast
    `Settings` loading and CLI logging configuration therefore happen in
    `app.cli._runtime.bootstrap()`, called by each leaf command as its
    own first statement, not here — see `_runtime.bootstrap()` for the
    full rationale.
    """


cli.add_command(manage_user_group)
cli.add_command(api_key_group)
cli.add_command(fetcher_group)


def _arguments_are_utf8(arguments: list[str]) -> bool:
    """Whether every argument encodes as UTF-8.

    On POSIX, Python decodes undecodable argument bytes into lone
    surrogates (`surrogateescape`), which UTF-8 cannot encode; such a
    value would otherwise fail only at PostgreSQL as a system error.
    """
    try:
        for argument in arguments:
            argument.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def main() -> None:
    """Console-script entry point (`sentinel = "app.cli:main"`).

    Installs the `SIGINT`/`SIGTERM` handlers and rejects arguments that
    are not valid UTF-8 (exit 1, value not echoed; see
    `docs/features/platform/cli-infrastructure.md`, Root Command Group &
    Bootstrap — Argument encoding), then invokes the root group with
    `standalone_mode=False` so this function has full and exclusive
    control over exit codes and message formatting for every condition
    except Click's own broken-pipe handling — see
    `docs/features/platform/cli-infrastructure.md` (Error Handling &
    Exit Code Mapping).
    """
    install_signal_handlers()

    if not _arguments_are_utf8(sys.argv[1:]):
        click.echo("Error: Command-line arguments must be valid UTF-8.", err=True)
        sys.exit(1)

    try:
        cli.main(standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        sys.exit(1)
    except click.Abort:
        click.echo("Aborted.")
        sys.exit(0)
    except ServiceError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except (OperationalError, DBAPIError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except RedisError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:  # terminal catch-all mapper, see module docstring
        logger.error("cli_unhandled_exception", exc_info=exc)
        message = str(exc) or exc.__class__.__name__
        click.echo(f"Error: {message}", err=True)
        sys.exit(2)
