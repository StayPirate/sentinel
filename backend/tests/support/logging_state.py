"""Snapshot and restore of the process-wide logging configuration.

`configure_logging()` and `configure_cli_logging()` (`app.core.logging`)
replace the root logger's handlers and level, clear the third-party
loggers' handlers, and install a new structlog processor list. Tests
reach them through CLI commands (`app.cli._runtime.bootstrap()`), the
Celery `setup_logging` signal, and direct calls. The autouse
`_preserve_logging_state` fixture in `tests/conftest.py` wraps every
test in `preserved_logging_state()` so that none of this leaks into a
later test — see docs/features/platform/testing-strategy.md (Test
Independence).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog

from app.core.logging import _THIRD_PARTY_LOGGERS


@contextmanager
def preserved_logging_state() -> Iterator[None]:
    """Restore the logging configuration found on entry, on every exit.

    Restores the root logger's handlers and level; the handlers, level,
    and `propagate` flag of every logger in `_THIRD_PARTY_LOGGERS`; and
    the structlog configuration.

    The structlog processor list is restored as the same list object,
    refilled with the entries it held on entry. A logger cached on first
    use (`cache_logger_on_first_use=True`) keeps the list configured at
    that moment, and `structlog.testing.capture_logs()` captures by
    mutating the configured list in place: an equal but new list would
    leave every logger cached before the scope invisible to later
    captures.

    A logger first used while a configuration installed inside the scope
    is active stays bound to that configuration's list for the rest of
    the process; restoring the configuration cannot rebind it.
    """
    root = logging.getLogger()
    root_handlers = list(root.handlers)
    root_level = root.level
    third_party = {
        name: (
            logging.getLogger(name).level,
            logging.getLogger(name).propagate,
            list(logging.getLogger(name).handlers),
        )
        for name in _THIRD_PARTY_LOGGERS
    }
    structlog_config: dict[str, Any] = structlog.get_config()
    processors = structlog_config["processors"]
    processor_entries = list(processors)
    try:
        yield
    finally:
        root.handlers[:] = root_handlers
        root.setLevel(root_level)
        for name, (level, propagate, handlers) in third_party.items():
            logger = logging.getLogger(name)
            logger.setLevel(level)
            logger.propagate = propagate
            logger.handlers[:] = handlers
        processors[:] = processor_entries
        structlog.configure(**structlog_config)
