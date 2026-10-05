"""Shared CLI runtime: signal handling and the fail-fast bootstrap.

See `docs/features/platform/cli-infrastructure.md` (Root Command Group &
Bootstrap, Database Session Management, Signal Handling) for the
authoritative contract this module implements.
"""

from __future__ import annotations

import signal
from types import FrameType
from typing import TYPE_CHECKING

import click
from pydantic import ValidationError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def install_signal_handlers() -> None:
    """Install `SIGINT`/`SIGTERM` handlers producing exit codes 130/143.

    Called once, as the very first statement of the `main()` entry point,
    before Click parses any argument. This has no observable effect on a
    `--help`/`--version` invocation; it only arms process-level signal
    delivery ahead of the (possibly long-running) command that follows.
    See `docs/features/platform/cli-infrastructure.md` (Signal Handling).
    """

    def _on_sigint(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(130)

    def _on_sigterm(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(143)

    signal.signal(signal.SIGINT, _on_sigint)
    signal.signal(signal.SIGTERM, _on_sigterm)


def _load_settings() -> None:
    """Import `app.config`, instantiating and validating `Settings`.

    Extracted as its own function so tests can monkeypatch it to
    simulate a validation failure without touching the real
    `sys.modules` cache for `app.config` — other tests rely on it
    remaining a stable, already-validated singleton.
    """
    import app.config  # noqa: F401  (import alone validates Settings)


def _format_validation_error(exc: ValidationError) -> str:
    """Render a `pydantic.ValidationError` without leaking input values.

    Pydantic's default `str(exc)`/error rendering embeds a repr of the
    entire input mapping for some error types (e.g. a required field
    that is `missing`), which can include other, unrelated
    credential-bearing settings (`DATABASE_URL`, `NVD_API_KEY`,
    `IBS_PASSWORD`) that are still plain strings at validation time —
    before `SecretStr`/`repr=False` masking would otherwise apply. This
    renders only the failing field path and the validator's own message
    (`errors(include_input=False)`), which is exactly the safe subset
    already used by every custom validator in `app.config`.
    """
    parts = []
    for error in exc.errors(include_url=False, include_input=False):
        loc = ".".join(str(part) for part in error["loc"])
        parts.append(f"{loc}: {error['msg']}" if loc else error["msg"])
    return "; ".join(parts)


def bootstrap() -> None:
    """Fail-fast `Settings` load plus minimal CLI logging configuration.

    Per `docs/features/platform/cli-infrastructure.md` (Root Command Group
    & Bootstrap, steps 2 and 4), this MUST run before a real command's own
    logic executes, but MUST NOT run for a `--help`/`--version`
    invocation at any level.

    A Click `Group` callback cannot host this logic: Click invokes a
    group's own callback before creating its child command's context —
    including when the child's own `--help` is what triggered the
    invocation (verified empirically: `sentinel manage-user --help` runs
    the root group's callback before `manage-user`'s own eager `--help`
    is even parsed). Every leaf command callback therefore calls this
    function as its first statement instead, deferring the
    `app.config`/`app.core.logging` imports until that point so eager
    help/version handling never triggers them.

    Raises `SystemExit(2)` directly (bypassing the shared exception
    mapper in `app.cli.main()`) when `Settings` fails to load, printing a
    plain `Error: ...` message with no traceback — see
    cli-infrastructure.md, Root Command Group & Bootstrap, step 2. A
    `pydantic.ValidationError` is rendered via `_format_validation_error()`
    to avoid leaking credential-bearing settings values (see that
    function's docstring); any other exception is rendered via `str()`,
    which is safe because no other exception raised during `Settings`
    construction carries raw input values.
    """
    try:
        _load_settings()
    except ValidationError as exc:
        message = _format_validation_error(exc)
        click.echo(f"Error: Invalid configuration - {message}", err=True)
        raise SystemExit(2) from None
    except Exception as exc:  # fail-fast boundary, exits directly (see above)
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(2) from None

    from app.config import settings
    from app.core.logging import configure_cli_logging

    configure_cli_logging(settings)


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the production async session factory.

    Deferred import so `app.database` (which imports `app.config` and
    creates the async engine) is never imported before `bootstrap()` has
    already validated `Settings` — see Database Session Management.
    """
    from app.database import async_session_factory

    return async_session_factory
