"""Tests for structured logging configuration (backend/app/core/logging.py).

See docs/features/platform/logging.md for the full specification.
"""

from __future__ import annotations

import io
import json
import logging
import time
from collections.abc import Iterator

import pytest
import structlog
from pydantic import Field, SecretStr

from app.config import Settings
from app.core import logging as core_logging
from app.core.logging import (
    _THIRD_PARTY_LOGGERS,
    REDACTED,
    _build_redaction_processor,
    _collect_secret_values,
    configure_cli_logging,
    configure_logging,
    resolve_log_format,
)


def _settings(**overrides: str) -> Settings:
    """Build a Settings instance for logging tests, bypassing the `.env`
    file. Environment variables still apply, so a test that depends on a
    field's value passes it explicitly."""
    defaults = {
        "jwt_secret_key": "a" * 32,
        "app_name": "sentinel-test",
        "log_level": "INFO",
        "log_format": "json",
    }
    defaults.update(overrides)
    # pydantic-settings' BaseSettings.__init__ exposes many strictly-typed
    # special init kwargs (_cli_settings_source, etc.) beyond the model's
    # own fields, so a **dict[str, str] spread cannot be matched precisely
    # against every possible parameter slot.
    return Settings(_env_file=None, **defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_logging_state() -> Iterator[None]:
    """Save/restore global logging state around every test.

    `configure_logging`/`configure_cli_logging` mutate the root logger
    and third-party logger objects, and reconfigure structlog globally.
    Without this fixture, tests would leak state into each other and
    into the rest of the test suite (which relies on `caplog` and the
    module-level `configure_logging(settings)` call already performed
    at `app.main` import time in conftest.py).

    Restores, in addition to root logger handlers/level: third-party
    logger **handlers** (not just level/propagate — `configure_logging`
    clears them on every call) and the global structlog configuration
    (`structlog.configure(...)` mutates process-wide state that
    `structlog.get_config()`/`structlog.configure(**config)` can
    snapshot and replay exactly).
    """
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level

    original_third_party = {
        name: (
            logging.getLogger(name).level,
            logging.getLogger(name).propagate,
            list(logging.getLogger(name).handlers),
        )
        for name in _THIRD_PARTY_LOGGERS
    }

    original_structlog_config = structlog.get_config()

    yield

    root_logger.handlers.clear()
    root_logger.handlers.extend(original_handlers)
    root_logger.setLevel(original_level)

    for name, (level, propagate, handlers) in original_third_party.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = propagate
        logger.handlers.clear()
        logger.handlers.extend(handlers)

    structlog.configure(**original_structlog_config)


class _FakeStream(io.StringIO):
    """A StringIO that can simulate being a TTY or not."""

    def __init__(self, *, isatty: bool = False) -> None:
        super().__init__()
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


@pytest.mark.unit
class TestResetLoggingStateFixture:
    """Regression coverage for the module's own `_reset_logging_state`
    autouse fixture. Exercises the fixture's generator function
    directly (bypassing pytest's fixture-resolution machinery) so the
    save/mutate/restore sequence can be asserted within a single test,
    proving the two behaviors this fixture is responsible for beyond
    root logger handlers/level: restoring third-party logger handlers
    and the global structlog configuration, both of which
    `configure_logging()` mutates on every call.

    NOTE: `_fixture_function` is pytest's internal attribute (verified
    against the pinned `pytest==9.1.1`) exposing the raw generator
    function behind `@pytest.fixture` — calling the decorated object
    itself is no longer supported directly. A future pytest major
    upgrade may relocate or remove this attribute, which would surface
    as an `AttributeError` here rather than silently passing.
    """

    def test_restores_third_party_logger_handlers(self) -> None:
        third_party_name = _THIRD_PARTY_LOGGERS[0]
        third_party_logger = logging.getLogger(third_party_name)
        pre_existing_handler = logging.NullHandler()
        third_party_logger.addHandler(pre_existing_handler)
        try:
            fixture_gen = _reset_logging_state._fixture_function()
            next(fixture_gen)  # enter: snapshot taken with the handler present

            configure_logging(_settings(), stream=_FakeStream())
            assert pre_existing_handler not in third_party_logger.handlers

            with pytest.raises(StopIteration):
                next(fixture_gen)  # exit: restore

            assert pre_existing_handler in third_party_logger.handlers
        finally:
            third_party_logger.removeHandler(pre_existing_handler)

    def test_restores_structlog_global_configuration(self) -> None:
        original_processors = structlog.get_config()["processors"]

        fixture_gen = _reset_logging_state._fixture_function()
        next(fixture_gen)  # enter: snapshot taken

        configure_logging(_settings(), stream=_FakeStream())
        assert structlog.get_config()["processors"] != original_processors

        with pytest.raises(StopIteration):
            next(fixture_gen)  # exit: restore

        assert structlog.get_config()["processors"] == original_processors


@pytest.mark.unit
class TestResolveLogFormat:
    """Pure function: auto-detection and explicit override behavior."""

    def test_auto_resolves_to_console_when_tty(self) -> None:
        stream = _FakeStream(isatty=True)
        assert resolve_log_format("auto", stream=stream) == "console"

    def test_auto_resolves_to_json_when_not_tty(self) -> None:
        stream = _FakeStream(isatty=False)
        assert resolve_log_format("auto", stream=stream) == "json"

    def test_explicit_json_overrides_tty_stream(self) -> None:
        stream = _FakeStream(isatty=True)
        assert resolve_log_format("json", stream=stream) == "json"

    def test_explicit_console_overrides_non_tty_stream(self) -> None:
        stream = _FakeStream(isatty=False)
        assert resolve_log_format("console", stream=stream) == "console"


@pytest.mark.unit
class TestConfigureLoggingJsonSchema:
    """JSON renderer output matches the Standard Log Record Schema."""

    def test_json_record_has_required_fields(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(log_format="json", app_name="sentinel-schema-test")
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.schema")
        log.info("schema_test_event")

        line = stream.getvalue().strip()
        record = json.loads(line)
        assert record["event"] == "schema_test_event"
        assert record["level"] == "info"
        assert record["logger"] == "app.test.schema"
        assert record["app"] == "sentinel-schema-test"
        assert record["timestamp"].endswith("Z")

    def test_level_values_are_lowercase(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(log_level="DEBUG")
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.level")
        log.warning("warn_event")

        record = json.loads(stream.getvalue().strip())
        assert record["level"] == "warning"

    def test_correlation_fields_omitted_when_not_bound(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings()
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.correlation")
        log.info("no_correlation_event")

        record = json.loads(stream.getvalue().strip())
        assert "request_id" not in record
        assert "celery_task_id" not in record
        assert "fetcher_run_id" not in record

    def test_correlation_field_present_when_bound(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings()
        configure_logging(settings, stream=stream)

        import structlog

        tokens = structlog.contextvars.bind_contextvars(request_id="req-123")
        try:
            log = structlog.get_logger("app.test.bound")
            log.info("bound_event")
        finally:
            structlog.contextvars.reset_contextvars(**tokens)

        record = json.loads(stream.getvalue().strip())
        assert record["request_id"] == "req-123"

    def test_exception_field_rendered_on_exception_log(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings()
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.exc")
        try:
            raise ValueError("boom")
        except ValueError:
            log.exception("operation_failed")

        record = json.loads(stream.getvalue().strip())
        assert "exception" in record
        assert "ValueError: boom" in record["exception"]
        assert record["level"] == "error"


@pytest.mark.unit
class TestConfigureLoggingConsole:
    """Console renderer produces human-readable, non-JSON output."""

    def test_console_output_is_not_json(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(log_format="console")
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.console")
        log.info("console_event")

        line = stream.getvalue().strip()
        with pytest.raises(json.JSONDecodeError):
            json.loads(line)
        assert "console_event" in line


@pytest.mark.unit
class TestConfigureLoggingLevel:
    """LOG_LEVEL controls all loggers uniformly; no per-logger pins."""

    def test_debug_below_configured_level_is_suppressed(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(log_level="INFO")
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.suppressed")
        log.debug("should_not_appear")

        assert stream.getvalue() == ""

    def test_level_at_or_above_configured_level_is_emitted(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(log_level="WARNING")
        configure_logging(settings, stream=stream)

        import structlog

        log = structlog.get_logger("app.test.emitted")
        log.warning("should_appear")

        assert "should_appear" in stream.getvalue()

    def test_third_party_loggers_deferred_to_root(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(log_level="ERROR")
        configure_logging(settings, stream=stream)

        for name in _THIRD_PARTY_LOGGERS:
            logger = logging.getLogger(name)
            assert logger.level == logging.NOTSET
            assert logger.propagate is True

    def test_sqlalchemy_parent_logger_does_not_cap_engine_level(self) -> None:
        """SQLAlchemy pins the parent "sqlalchemy" logger to WARNING at
        import time; it must also be reset so it doesn't cap the
        effective level of "sqlalchemy.engine" below the configured
        LOG_LEVEL (see docs/features/platform/logging.md, third-party
        logger integration)."""
        stream = _FakeStream(isatty=False)
        settings = _settings(log_level="DEBUG")
        configure_logging(settings, stream=stream)

        assert (
            logging.getLogger("sqlalchemy.engine").getEffectiveLevel() == logging.DEBUG
        )

    def test_third_party_logger_captured_in_same_pipeline(self) -> None:
        stream = _FakeStream(isatty=False)
        settings = _settings(
            log_level="INFO", log_format="json", app_name="sentinel-third-party"
        )
        configure_logging(settings, stream=stream)

        stdlib_logger = logging.getLogger("uvicorn.access")
        stdlib_logger.info("GET / HTTP/1.1 200")

        record = json.loads(stream.getvalue().strip())
        assert record["logger"] == "uvicorn.access"
        assert record["event"] == "GET / HTTP/1.1 200"
        assert record["level"] == "info"
        assert record["app"] == "sentinel-third-party"
        assert record["timestamp"].endswith("Z")


@pytest.mark.unit
class TestConfigureLoggingIdempotency:
    """Calling configure_logging multiple times must not duplicate output."""

    def test_second_call_replaces_handlers(self) -> None:
        stream1 = _FakeStream(isatty=False)
        stream2 = _FakeStream(isatty=False)
        settings = _settings()

        configure_logging(settings, stream=stream1)
        configure_logging(settings, stream=stream2)

        import structlog

        log = structlog.get_logger("app.test.idempotent")
        log.info("only_once")

        assert stream1.getvalue() == ""
        lines = [ln for ln in stream2.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 1


@pytest.mark.unit
class TestConfigureCliLogging:
    """CLI logging: stderr, plain text, WARNING threshold, no correlation."""

    def test_routes_to_stderr_not_stdout(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_cli_logging(_settings())

        logging.getLogger("app.test.cli").warning("cli_warning")

        captured = capsys.readouterr()
        assert captured.out == ""
        assert "cli_warning" in captured.err

    def test_info_below_warning_is_suppressed(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_cli_logging(_settings())

        logging.getLogger("app.test.cli.info").info("cli_info_should_not_appear")

        captured = capsys.readouterr()
        assert captured.err == ""

    def test_output_is_plain_text_not_json(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_cli_logging(_settings())

        logging.getLogger("app.test.cli.plain").warning("cli_plain_event")

        captured = capsys.readouterr()
        with pytest.raises(json.JSONDecodeError):
            json.loads(captured.err.strip())
        assert "cli_plain_event" in captured.err

    def test_cli_record_with_configured_secret_is_redacted(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_cli_logging(_settings(nvd_api_key=_NVD_SETTING_VALUE))

        logging.getLogger("app.test.cli.secret").warning(
            "request rejected for key %s", _NVD_SETTING_VALUE
        )

        captured = capsys.readouterr()
        assert _NVD_SETTING_VALUE not in captured.err
        assert f"request rejected for key {REDACTED}" in captured.err


# Fictional credential material used by the redaction tests.
_NVD_SETTING_VALUE = "fictional-nvd-key-0123456789"
_BROKER_URL_USERINFO_PART = "fictional-broker-pass-42"
_BROKER_URL = (
    f"amqps://svc-sentinel:{_BROKER_URL_USERINFO_PART}@rabbit.example.test:5671/"
)


def _redact(text: str, secret_values: tuple[str, ...] = ()) -> str:
    """Run a single string through a freshly built redaction processor."""
    processor = _build_redaction_processor(secret_values)
    event_dict = processor(None, "info", {"event": text})
    assert isinstance(event_dict, dict)
    value = event_dict["event"]
    assert isinstance(value, str)
    return value


@pytest.mark.unit
class TestRedactionProcessor:
    """Each masked category of logging.md (Redaction Processor), applied
    to a single string value."""

    def test_configured_secret_value_is_masked_everywhere(self) -> None:
        text = f"invalid key {_NVD_SETTING_VALUE}; retrying with {_NVD_SETTING_VALUE}"
        assert _redact(text, (_NVD_SETTING_VALUE,)) == (
            f"invalid key {REDACTED}; retrying with {REDACTED}"
        )

    def test_longer_secret_containing_shorter_one_is_masked_whole(self) -> None:
        shorter = "fictional-secret-part"
        longer = f"{shorter}-and-suffix"
        assert _redact(f"value={longer}", (shorter, longer)) == f"value={REDACTED}"

    @pytest.mark.parametrize("value", ["", "fict-pass", "a" * 11])
    def test_empty_or_short_secret_value_is_never_matched(self, value: str) -> None:
        text = f"connected as fict-pass to db aaaaaaaaaaa {value}"
        assert _redact(text, (value,)) == text

    def test_secret_value_at_minimum_length_is_masked(self) -> None:
        value = "fict-pass-12"
        assert len(value) == 12
        assert _redact(f"x {value} y", (value,)) == f"x {REDACTED} y"

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                "postgresql+asyncpg://svc:fict-pass@db.example.test:5432/db",
                f"postgresql+asyncpg://{REDACTED}@db.example.test:5432/db",
            ),
            (
                "rediss://:fict-pass@cache.example.test:6380/1",
                f"rediss://{REDACTED}@cache.example.test:6380/1",
            ),
            (
                "amqps://svc:fict@pass@rabbit.example.test//",
                f"amqps://{REDACTED}@rabbit.example.test//",
            ),
            (
                "Error: 'redis://svc-token@cache.example.test' refused",
                f"Error: 'redis://{REDACTED}@cache.example.test' refused",
            ),
            (
                "broker_url=x_redis://:fict-pass@cache.example.test",
                f"broker_url=x_redis://{REDACTED}@cache.example.test",
            ),
        ],
    )
    def test_uri_userinfo_is_masked_for_any_scheme(
        self, text: str, expected: str
    ) -> None:
        assert _redact(text) == expected

    def test_uri_userinfo_scan_of_scheme_like_run_is_linear(self) -> None:
        """Regression: a long client-controlled run such as "a.a.a..." (e.g.
        a request path in the access log) must not be rescanned from every
        word boundary. The quadratic pattern took ~20 s on this input."""
        text = "GET /" + "a." * 131072
        started = time.perf_counter()
        assert _redact(text) == text
        assert time.perf_counter() - started < 1.0

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                "Authorization: Bearer eyJfictional.payload.signature",
                f"Authorization: Bearer {REDACTED}",
            ),
            (
                "proxy-authorization=Basic ZmljdGlvbmFsOnBhc3M=",
                f"proxy-authorization=Basic {REDACTED}",
            ),
            (
                "{'authorization': b'Basic ZmljdGlvbmFsOnBhc3M=', 'accept': 'x'}",
                f"{{'authorization': b'Basic {REDACTED}', 'accept': 'x'}}",
            ),
            (
                '"Authorization": "fictional-raw-token"',
                f'"Authorization": "{REDACTED}"',
            ),
        ],
    )
    def test_authorization_header_credential_is_masked(
        self, text: str, expected: str
    ) -> None:
        assert _redact(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "CVE-2024-12345 affects package example-lib",
            "fetcher run 018f6c3e-8a4b-7c1d-9e2f-0123456789ab finished",
            "request_id=req-123 celery_task_id=0f4c1a2b-0000-4000-8000-000000000001",
            "GET https://nvd.example.test/rest/json/cves/2.0?cveId=CVE-2024-12345",
            "Error 111 connecting to cache.example.test:6379. Connection refused.",
            "contact owner@example.test or mailto:owner@example.test",
            '"http://host.example.test:80","owner@example.test"',
            "https://lists.example.test/archives?from=owner@example.test",
            "authorization failed for user fict-user",
        ],
    )
    def test_text_without_sensitive_content_is_unchanged(self, text: str) -> None:
        assert _redact(text, (_NVD_SETTING_VALUE,)) == text

    def test_non_string_values_are_left_untouched(self) -> None:
        processor = _build_redaction_processor((_NVD_SETTING_VALUE,))
        nested = {"key": _NVD_SETTING_VALUE}
        event_dict = processor(None, "info", {"event": "x", "count": 3, "d": nested})
        assert isinstance(event_dict, dict)
        assert event_dict["count"] == 3
        assert event_dict["d"] is nested

    def test_redaction_failure_masks_value_and_keeps_record(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _FailingPattern:
            def sub(self, repl: str, string: str) -> str:
                raise RuntimeError("simulated redaction failure")

        monkeypatch.setattr(core_logging, "_URI_USERINFO_PATTERN", _FailingPattern())
        processor = _build_redaction_processor(())

        event_dict = processor(None, "info", {"event": "some text", "level": "info"})

        assert event_dict == {"event": REDACTED, "level": REDACTED}


@pytest.mark.unit
class TestCollectSecretValues:
    """The exact-value set is derived from the Settings classification
    (docs/conventions.md, Secret Field Typing)."""

    def test_collects_secretstr_values_and_url_passwords(self) -> None:
        settings = _settings(
            jwt_secret_key="j" * 32,
            nvd_api_key=_NVD_SETTING_VALUE,
            ibs_password="fictional-ibs-password",
            database_url="postgresql+asyncpg://svc:fictional-db-pass@db.example.test/db",
            redis_url="redis://:fictional-redis-pass@cache.example.test:6379/0",
            celery_broker_url=_BROKER_URL,
        )

        values = _collect_secret_values(settings)

        assert set(values) == {
            "j" * 32,
            _NVD_SETTING_VALUE,
            "fictional-ibs-password",
            "fictional-db-pass",
            "fictional-redis-pass",
            _BROKER_URL_USERINFO_PART,
        }

    def test_values_are_derived_from_field_classification(self) -> None:
        """A new field classified per Secret Field Typing is covered
        without changes to the logging module."""

        class _ExtendedSettings(Settings):
            extra_token: SecretStr = SecretStr("fictional-extra-token-0001")
            extra_url: str = Field(
                default="amqps://svc:fictional-extra-pass@mq.example.test/",
                repr=False,
            )
            extra_public_url: str = "https://svc:public-userinfo@docs.example.test/"

        settings = _ExtendedSettings(_env_file=None, jwt_secret_key="a" * 32)

        values = _collect_secret_values(settings)

        assert "fictional-extra-token-0001" in values
        assert "fictional-extra-pass" in values
        assert "public-userinfo" not in values

    def test_url_password_is_percent_decoded(self) -> None:
        settings = _settings(
            database_url="postgresql+asyncpg://svc:fictional%40db%2Fpass@db.example.test/db"
        )
        assert "fictional@db/pass" in _collect_secret_values(settings)

    def test_empty_values_and_urls_without_password_are_skipped(self) -> None:
        settings = _settings(
            nvd_api_key="",
            ibs_password="",
            database_url="postgresql+asyncpg://svc@db.example.test/db",
            redis_url="redis://cache.example.test:6379/0",
            celery_broker_url="redis://cache.example.test:6379/1",
        )
        assert _collect_secret_values(settings) == ["a" * 32]

    def test_malformed_url_is_skipped(self) -> None:
        settings = _settings(redis_url="redis://svc:fict-pass@[::1/0")
        assert "fict-pass" not in _collect_secret_values(settings)


@pytest.mark.unit
class TestConfigureLoggingRedaction:
    """The redaction processor is wired into the runtime pipeline for
    application records, stdlib-bridged records, and rendered tracebacks."""

    def _configure(self, log_format: str = "json") -> _FakeStream:
        stream = _FakeStream(isatty=False)
        settings = _settings(
            log_format=log_format,
            nvd_api_key=_NVD_SETTING_VALUE,
            celery_broker_url=_BROKER_URL,
        )
        configure_logging(settings, stream=stream)
        return stream

    def test_application_record_is_redacted(self) -> None:
        stream = self._configure()

        structlog.get_logger("app.test.redact").warning(
            "nvd_request_rejected", detail=f"key {_NVD_SETTING_VALUE} rejected"
        )

        record = json.loads(stream.getvalue().strip())
        assert record["detail"] == f"key {REDACTED} rejected"
        assert record["event"] == "nvd_request_rejected"

    def test_third_party_record_is_redacted(self) -> None:
        stream = self._configure()

        logging.getLogger("celery").error("consumer: cannot connect to %s", _BROKER_URL)

        output = stream.getvalue()
        record = json.loads(output.strip())
        assert _BROKER_URL_USERINFO_PART not in output
        assert record["logger"] == "celery"
        assert record["event"] == (
            f"consumer: cannot connect to amqps://{REDACTED}@rabbit.example.test:5671/"
        )

    def test_third_party_exception_traceback_is_redacted(self) -> None:
        stream = self._configure()

        try:
            raise ConnectionError(f"[Errno 111] password={_BROKER_URL_USERINFO_PART}")
        except ConnectionError:
            logging.getLogger("celery").exception("task publication failed")

        output = stream.getvalue()
        record = json.loads(output.strip())
        assert _BROKER_URL_USERINFO_PART not in output
        assert (
            f"ConnectionError: [Errno 111] password={REDACTED}" in record["exception"]
        )

    def test_application_exception_traceback_is_redacted(self) -> None:
        stream = self._configure()

        try:
            raise ValueError(f"cannot reach {_BROKER_URL}")
        except ValueError:
            structlog.get_logger("app.test.redact.exc").exception("dispatch_failed")

        output = stream.getvalue()
        record = json.loads(output.strip())
        assert _BROKER_URL_USERINFO_PART not in output
        assert "amqps://***@rabbit.example.test" in record["exception"]

    def test_console_output_is_redacted(self) -> None:
        stream = self._configure(log_format="console")

        structlog.get_logger("app.test.redact.console").warning(
            "nvd_request_rejected", detail=_NVD_SETTING_VALUE
        )

        assert _NVD_SETTING_VALUE not in stream.getvalue()
        assert REDACTED in stream.getvalue()

    def test_default_short_database_password_does_not_mask_app_name(self) -> None:
        """Regression: the development/CI database password `sentinel`
        coincides with APP_NAME; the length threshold keeps the app field
        and ordinary text intact."""
        stream = _FakeStream(isatty=False)
        settings = _settings(
            app_name="sentinel",
            database_url="postgresql+asyncpg://sentinel:sentinel@db.example.test/db",
        )
        configure_logging(settings, stream=stream)

        structlog.get_logger("app.test.redact.default").info("sentinel_started")

        record = json.loads(stream.getvalue().strip())
        assert record["app"] == "sentinel"
        assert record["event"] == "sentinel_started"
