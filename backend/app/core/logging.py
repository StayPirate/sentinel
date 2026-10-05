"""Structured logging configuration.

Configures `structlog` on top of the stdlib `logging` module so that
Sentinel's own code and third-party libraries (uvicorn, SQLAlchemy,
httpx, Celery) emit through the same pipeline, format, and output
stream. See `docs/features/platform/logging.md` for the full
specification this module implements.

This module governs the long-running runtime processes (API server,
Celery worker, git worker, Beat, IBS consumer). CLI (Click) processes
use `configure_cli_logging()` instead — see its docstring.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable
from typing import TYPE_CHECKING, TextIO
from urllib.parse import unquote, urlsplit

import structlog
from pydantic import SecretStr

if TYPE_CHECKING:
    from app.config import Settings

# Third-party loggers captured via the stdlib bridge. Explicitly reset
# to NOTSET + propagate=True so they defer to the root logger's level
# and handler uniformly — no per-logger overrides, no conditional pins.
# NOTE: both "sqlalchemy" (the parent) and "sqlalchemy.engine" (the
# child that actually gates SQL statement/parameter echoing) must be
# reset: SQLAlchemy's own `log.py` pins the parent "sqlalchemy" logger
# to WARNING at import time, which would otherwise cap the effective
# level of "sqlalchemy.engine" regardless of the root logger's level.
_THIRD_PARTY_LOGGERS = (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "sqlalchemy",
    "sqlalchemy.engine",
    "httpx",
    "httpcore",
    "celery",
)

# Shared processors applied to every log record regardless of origin:
# both structlog-originated calls (via `structlog.configure`) and
# stdlib-originated records captured by the bridge (via
# `foreign_pre_chain`). NOTE: `structlog.stdlib.filter_by_level` is
# deliberately NOT included here — it assumes a bound structlog logger
# instance and raises AttributeError when run against foreign (stdlib)
# records, where `logger` is None. Level filtering is instead performed
# by the stdlib logger's own `isEnabledFor()` check.
_TIMESTAMPER = structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp")

_SHARED_PROCESSORS: list[structlog.types.Processor] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    _TIMESTAMPER,
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]


def _bind_app_name(app_name: str) -> structlog.types.Processor:
    """Build a processor that stamps every event with the `app` field."""

    def processor(
        logger: object, method_name: str, event_dict: structlog.types.EventDict
    ) -> structlog.types.EventDict:
        event_dict["app"] = app_name
        return event_dict

    return processor


# Redaction processor (logging.md, Secrets and PII Discipline, Redaction
# Processor): best-effort defense-in-depth applied at the handler level,
# after exception/stack rendering and immediately before the renderer.
REDACTED = "***"

# Configured secret values shorter than this are never matched by exact
# value: a short value (e.g. the development database password) would
# also mask ordinary words, identifiers, and paths that coincide with it.
# Such values remain masked when they appear as URI userinfo.
_MIN_EXACT_SECRET_LENGTH = 12

# Userinfo of any URI with an authority, for any scheme. Greedy up to the
# last "@" of the authority, so an unencoded "@" inside a password is
# covered too. The character class excludes whitespace, the authority
# terminators "/?#", and characters RFC 3986 never allows in userinfo, so
# the match cannot cross into a path or out of surrounding quoting.
# NOTE: the lookbehind (rather than `\b`) lets a match start only at the
# beginning of a run of scheme characters; with `\b`, a run such as
# "a.a.a..." (e.g. a client-supplied request path in the access log) is
# rescanned from every word boundary, which is quadratic.
_URI_USERINFO_PATTERN = re.compile(
    r"(?P<scheme>(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://)"
    r"[^\s/?#\"<>\\\[\]{}|^`]+@"
)

# Credential following an Authorization/Proxy-Authorization header name,
# as rendered in header lines ("Authorization: Basic ...") or in dict/bytes
# reprs ("'authorization': b'Bearer ...'"). The authentication scheme
# token, when present, is preserved.
_AUTHORIZATION_PATTERN = re.compile(
    r"(?P<prefix>\b(?:proxy-)?authorization[\"']?\s*[:=]\s*(?:b?[\"'])?"
    r"(?:[A-Za-z][A-Za-z0-9_-]*\s+)?)[^\s\"',}]+",
    re.IGNORECASE,
)


def _collect_secret_values(settings: Settings) -> list[str]:
    """Return the non-empty configured secret values to mask exactly.

    Derived from the `Settings` field classification of
    `docs/conventions.md` (Secret Field Typing): the value of every
    `SecretStr` field, and the percent-decoded password component of
    every credential-bearing URL field (a `str` declared with
    `repr=False`). The length threshold is applied by
    `_build_redaction_processor()`.
    """
    values: set[str] = set()
    for name, field in type(settings).model_fields.items():
        value = getattr(settings, name)
        if isinstance(value, SecretStr):
            values.add(value.get_secret_value())
        elif not field.repr and isinstance(value, str):
            try:
                password = urlsplit(value).password
            except ValueError:
                # Malformed URL: the userinfo pattern still applies.
                continue
            if password:
                values.add(unquote(password))
    values.discard("")
    return sorted(values)


def _redact_text(text: str, exact_pattern: re.Pattern[str] | None) -> str:
    """Apply every redaction category to a single string."""
    if exact_pattern is not None:
        text = exact_pattern.sub(REDACTED, text)
    text = _URI_USERINFO_PATTERN.sub(rf"\g<scheme>{REDACTED}@", text)
    return _AUTHORIZATION_PATTERN.sub(rf"\g<prefix>{REDACTED}", text)


def _build_redaction_processor(
    secret_values: Iterable[str],
) -> structlog.types.Processor:
    """Build the redaction processor for the given configured secrets.

    Values shorter than `_MIN_EXACT_SECRET_LENGTH` (including empty
    ones) are not matched by exact value. Longer values are matched
    first so a secret containing another one is masked whole.

    Only top-level string values of the event dict are inspected. The
    processor never raises: a value whose redaction fails is replaced
    entirely with the placeholder, and the record is still emitted.
    """
    exact_values = sorted(
        {value for value in secret_values if len(value) >= _MIN_EXACT_SECRET_LENGTH},
        key=len,
        reverse=True,
    )
    exact_pattern = (
        re.compile("|".join(re.escape(value) for value in exact_values))
        if exact_values
        else None
    )

    def processor(
        logger: object, method_name: str, event_dict: structlog.types.EventDict
    ) -> structlog.types.EventDict:
        for key, value in event_dict.items():
            if isinstance(value, str):
                try:
                    event_dict[key] = _redact_text(value, exact_pattern)
                except Exception:  # fail closed: never drop the record
                    event_dict[key] = REDACTED
        return event_dict

    return processor


def resolve_log_format(log_format: str, *, stream: TextIO | None = None) -> str:
    """Resolve the effective log output format.

    `auto` resolves to `console` when the target stream is a TTY and to
    `json` otherwise. Explicit `json` or `console` values are returned
    unchanged. `log_format` is expected to already be validated/
    normalized (lowercase) by `Settings`.
    """
    if log_format != "auto":
        return log_format
    target = stream if stream is not None else sys.stdout
    return "console" if target.isatty() else "json"


def configure_logging(settings: Settings, *, stream: TextIO | None = None) -> None:
    """Configure the structlog + stdlib logging pipeline.

    Idempotent: safe to call multiple times — each call fully replaces
    the previous root logger handler/level and structlog configuration
    rather than layering on top of it (relevant for test invocations
    and any future re-configuration need).

    `stream` defaults to `sys.stdout` and is exposed only for testing
    (capturing output without relying on global stdout redirection).
    """
    target_stream = stream if stream is not None else sys.stdout
    log_format = resolve_log_format(settings.log_format, stream=target_stream)
    level: int = getattr(logging, settings.log_level)

    app_name_processor = _bind_app_name(settings.app_name)
    processors = [*_SHARED_PROCESSORS, app_name_processor]

    structlog.configure(
        processors=[
            *processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    renderer: structlog.types.Processor
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=target_stream.isatty())

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _build_redaction_processor(_collect_secret_values(settings)),
            renderer,
        ],
        foreign_pre_chain=processors,
    )

    handler = logging.StreamHandler(target_stream)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    for name in _THIRD_PARTY_LOGGERS:
        third_party_logger = logging.getLogger(name)
        third_party_logger.handlers.clear()
        third_party_logger.setLevel(logging.NOTSET)
        third_party_logger.propagate = True


def configure_cli_logging(settings: Settings) -> None:
    """Configure minimal logging for CLI (Click) processes.

    Per `docs/features/platform/logging.md` (Scope of this pipeline),
    CLI processes do not use the full structlog pipeline. When CLI code
    invokes shared service/utility code that logs via
    `structlog.get_logger()`, this configuration routes that output
    through stdlib logging to stderr, in plain text (not JSON, not
    colorized), at WARNING level or above — so DEBUG/INFO messages from
    service code do not pollute CLI output. stdout remains reserved
    exclusively for the CLI Output Contract. The same redaction
    processor as the runtime pipeline is applied, built from `settings`.

    Correlation IDs are not bound in CLI processes and are therefore
    omitted from any log records emitted this way.
    """
    processors = [
        *_SHARED_PROCESSORS,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _build_redaction_processor(_collect_secret_values(settings)),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        foreign_pre_chain=_SHARED_PROCESSORS,
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.WARNING)
