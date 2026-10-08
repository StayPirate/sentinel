"""Tests for the logging-state isolation helper
(`tests/support/logging_state.py`) and its autouse fixture
(`_preserve_logging_state` in `tests/conftest.py`).

See docs/features/platform/testing-strategy.md (Test Independence).
"""

from __future__ import annotations

import contextlib
import io
import logging
import sys
import types
from collections.abc import Callable

import pytest
import structlog
from celery.signals import setup_logging
from structlog.testing import capture_logs

from app.cli._runtime import bootstrap
from app.config import settings
from app.core.logging import _THIRD_PARTY_LOGGERS, configure_logging
from tests.support.logging_state import preserved_logging_state


def _bootstrap_cli_on_closed_stderr() -> None:
    """Run the CLI bootstrap as a command invoked through `main()` under
    `capsys` does: its root handler is bound to a stderr stream that is
    closed afterwards."""
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        bootstrap()
    stderr.close()


def _send_celery_setup_logging() -> None:
    """Dispatch Celery's `setup_logging` signal to Sentinel's receiver."""
    setup_logging.send(sender=None)


def _raise_inside_scope() -> None:
    with preserved_logging_state():
        configure_logging(settings, stream=io.StringIO())
        raise RuntimeError("simulated failure")


def _passthrough(
    logger: object, method_name: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    return event_dict


_RECONFIGURATIONS = [
    pytest.param(_bootstrap_cli_on_closed_stderr, id="cli-bootstrap"),
    pytest.param(_send_celery_setup_logging, id="celery-setup-logging"),
]


@pytest.mark.unit
class TestPreservedLoggingState:
    @pytest.mark.parametrize("reconfigure", _RECONFIGURATIONS)
    def test_reconfiguration_inside_scope_restores_root_handlers_and_level(
        self, reconfigure: Callable[[], None]
    ) -> None:
        """Regression: the root handler left behind by the CLI bootstrap was
        bound to a closed stderr, so every later record reported
        `ValueError: I/O operation on closed file`."""
        root = logging.getLogger()
        handlers = list(root.handlers)
        level = root.level

        with preserved_logging_state():
            reconfigure()
            assert root.handlers != handlers

        assert root.handlers == handlers
        assert root.level == level

    @pytest.mark.parametrize("reconfigure", _RECONFIGURATIONS)
    def test_reconfiguration_inside_scope_keeps_cached_logger_capturable(
        self, reconfigure: Callable[[], None]
    ) -> None:
        """Regression: after a reconfiguration, `capture_logs()` mutated the
        replacement processor list, so a logger cached on the original list
        was no longer captured."""
        logger = structlog.get_logger("tests.logging_state.cached")
        logger.debug("first_use")  # caches the logger on the current list
        processors = structlog.get_config()["processors"]

        with preserved_logging_state():
            reconfigure()
            assert structlog.get_config()["processors"] is not processors

        with capture_logs() as captured:
            logger.warning("after_scope")

        assert [entry["event"] for entry in captured] == ["after_scope"]

    @pytest.mark.parametrize("reconfigure", _RECONFIGURATIONS)
    def test_app_logger_first_used_inside_scope_is_capturable_afterwards(
        self, reconfigure: Callable[[], None], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: a module-level logger first used while a test's own
        configuration was active stayed bound to that configuration's
        processor list, so later `capture_logs()` assertions missed it."""
        module = types.ModuleType("app._logging_state_probe")
        logger = structlog.get_logger("tests.logging_state.probe")
        vars(module)["logger"] = logger
        monkeypatch.setitem(sys.modules, module.__name__, module)

        with preserved_logging_state():
            reconfigure()
            logger.debug("first_use")  # caches the logger on the scope's list

        with capture_logs() as captured:
            logger.warning("after_scope")

        assert [entry["event"] for entry in captured] == ["after_scope"]

    def test_processor_list_is_restored_as_same_object_with_its_entries(
        self,
    ) -> None:
        processors = structlog.get_config()["processors"]
        entries = list(processors)

        with preserved_logging_state():
            processors.insert(0, _passthrough)
            structlog.configure(processors=list(entries))

        assert structlog.get_config()["processors"] is processors
        assert processors == entries

    def test_runtime_configuration_inside_scope_restores_third_party_loggers(
        self,
    ) -> None:
        third_party = logging.getLogger(_THIRD_PARTY_LOGGERS[0])
        original = (third_party.level, third_party.propagate)
        original_handlers = list(third_party.handlers)
        handler = logging.NullHandler()
        third_party.addHandler(handler)
        third_party.setLevel(logging.ERROR)
        third_party.propagate = False
        try:
            with preserved_logging_state():
                configure_logging(settings, stream=io.StringIO())
                assert handler not in third_party.handlers

            assert third_party.handlers == [*original_handlers, handler]
            assert third_party.level == logging.ERROR
            assert third_party.propagate is False
        finally:
            third_party.removeHandler(handler)
            third_party.setLevel(original[0])
            third_party.propagate = original[1]

    def test_exception_inside_scope_still_restores_configuration(self) -> None:
        root = logging.getLogger()
        handlers = list(root.handlers)
        processors = structlog.get_config()["processors"]

        with pytest.raises(RuntimeError, match="simulated failure"):
            _raise_inside_scope()

        assert root.handlers == handlers
        assert structlog.get_config()["processors"] is processors

    def test_shared_fixture_is_active_without_being_requested(
        self, request: pytest.FixtureRequest
    ) -> None:
        assert "_preserve_logging_state" in request.fixturenames
