"""Tests for Settings startup validation (backend/app/config.py)."""

from __future__ import annotations

import functools
import json
import logging
import os
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any, Final

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import Field, SecretStr, ValidationError

from app.config import Settings, _split_comma
from tests.support.ibs_keys import (
    encode_settings_value,
    fictional_ed25519_key,
    fictional_settings_value,
    openssh_file,
)


@pytest.mark.unit
class TestJwtSecretKeyValidation:
    """JWT_SECRET_KEY startup validation."""

    def test_missing_jwt_secret_key_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        with pytest.raises(ValidationError, match="jwt_secret_key"):
            Settings(_env_file=None)

    def test_short_jwt_secret_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "short")
        with pytest.raises(ValidationError, match="at least 32 characters"):
            Settings(_env_file=None)

    def test_31_chars_jwt_secret_key_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 31)
        with pytest.raises(ValidationError, match="at least 32 characters"):
            Settings(_env_file=None)

    def test_exactly_32_chars_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        s = Settings(_env_file=None)
        assert s.jwt_secret_key.get_secret_value() == "a" * 32


@pytest.mark.unit
class TestJwtExpiryValidation:
    """JWT_EXPIRY_HOURS startup validation."""

    def test_zero_expiry_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("JWT_EXPIRY_HOURS", "0")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_negative_expiry_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("JWT_EXPIRY_HOURS", "-1")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_excessive_expiry_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("JWT_EXPIRY_HOURS", "721")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert ">720 hours" in caplog.text

    def test_720_does_not_warn(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("JWT_EXPIRY_HOURS", "720")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert ">720 hours" not in caplog.text

    def test_expiry_1_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("JWT_EXPIRY_HOURS", "1")
        s = Settings(_env_file=None)
        assert s.jwt_expiry_hours == 1


@pytest.mark.unit
class TestSessionMaxLifetimeValidation:
    """SESSION_MAX_LIFETIME_DAYS startup validation
    (docs/features/identity/authentication.md, Configuration bounds).
    """

    def test_zero_lifetime_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("SESSION_MAX_LIFETIME_DAYS", "0")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_negative_lifetime_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("SESSION_MAX_LIFETIME_DAYS", "-1")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_excessive_lifetime_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("SESSION_MAX_LIFETIME_DAYS", "366")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert ">365 days" in caplog.text

    def test_365_does_not_warn(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("SESSION_MAX_LIFETIME_DAYS", "365")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert ">365 days" not in caplog.text

    def test_lifetime_1_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("SESSION_MAX_LIFETIME_DAYS", "1")
        s = Settings(_env_file=None)
        assert s.session_max_lifetime_days == 1

    def test_default_is_30(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("SESSION_MAX_LIFETIME_DAYS", raising=False)
        s = Settings(_env_file=None)
        assert s.session_max_lifetime_days == 30


@pytest.mark.unit
class TestLoginMaxAttemptsValidation:
    """LOGIN_MAX_ATTEMPTS startup validation
    (docs/features/identity/local-authentication.md, Configuration bounds).
    """

    def test_zero_attempts_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "0")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_negative_attempts_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "-1")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_attempts_1_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "1")
        s = Settings(_env_file=None)
        assert s.login_max_attempts == 1

    def test_default_is_5(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("LOGIN_MAX_ATTEMPTS", raising=False)
        s = Settings(_env_file=None)
        assert s.login_max_attempts == 5


@pytest.mark.unit
class TestLoginLockoutMinutesValidation:
    """LOGIN_LOCKOUT_MINUTES startup validation
    (docs/features/identity/local-authentication.md, Configuration bounds).
    """

    def test_zero_minutes_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOGIN_LOCKOUT_MINUTES", "0")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_negative_minutes_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOGIN_LOCKOUT_MINUTES", "-1")
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(_env_file=None)

    def test_minutes_1_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOGIN_LOCKOUT_MINUTES", "1")
        s = Settings(_env_file=None)
        assert s.login_lockout_minutes == 1

    def test_default_is_10(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("LOGIN_LOCKOUT_MINUTES", raising=False)
        s = Settings(_env_file=None)
        assert s.login_lockout_minutes == 10


@pytest.mark.unit
class TestLogLevelValidation:
    """LOG_LEVEL startup validation (docs/features/platform/logging.md)."""

    @pytest.mark.parametrize("value", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    def test_valid_levels_accepted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        value: str,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_LEVEL", value)
        s = Settings(_env_file=None)
        assert s.log_level == value

    @pytest.mark.parametrize(
        ("input_value", "expected"),
        [
            ("debug", "DEBUG"),
            ("Debug", "DEBUG"),
            ("info", "INFO"),
            ("WARNING", "WARNING"),
            ("error", "ERROR"),
            ("Critical", "CRITICAL"),
        ],
    )
    def test_case_insensitive_normalization(
        self, monkeypatch: pytest.MonkeyPatch, input_value: str, expected: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_LEVEL", input_value)
        s = Settings(_env_file=None)
        assert s.log_level == expected

    def test_default_is_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        s = Settings(_env_file=None)
        assert s.log_level == "INFO"

    def test_invalid_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_LEVEL", "BOGUS")
        with pytest.raises(ValidationError, match="Invalid LOG_LEVEL"):
            Settings(_env_file=None)

    def test_empty_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_LEVEL", "")
        with pytest.raises(ValidationError, match="Invalid LOG_LEVEL"):
            Settings(_env_file=None)


@pytest.mark.unit
class TestLogFormatValidation:
    """LOG_FORMAT startup validation (docs/features/platform/logging.md)."""

    @pytest.mark.parametrize("value", ["auto", "json", "console"])
    def test_valid_formats_accepted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        value: str,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_FORMAT", value)
        s = Settings(_env_file=None)
        assert s.log_format == value

    @pytest.mark.parametrize(
        ("input_value", "expected"),
        [
            ("AUTO", "auto"),
            ("Json", "json"),
            ("CONSOLE", "console"),
        ],
    )
    def test_case_insensitive_normalization(
        self, monkeypatch: pytest.MonkeyPatch, input_value: str, expected: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_FORMAT", input_value)
        s = Settings(_env_file=None)
        assert s.log_format == expected

    def test_default_is_auto(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("LOG_FORMAT", raising=False)
        s = Settings(_env_file=None)
        assert s.log_format == "auto"

    def test_invalid_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_FORMAT", "xml")
        with pytest.raises(ValidationError, match="Invalid LOG_FORMAT"):
            Settings(_env_file=None)


_BACKEND_DIR: Final = Path(__file__).resolve().parents[1]
_INHERITED_OS_ENV_KEYS: Final = ("PATH", "LANG", "LC_ALL", "TZ")
# Fictional JWT secret — never a real credential (AGENTS.md Guardrail 23).
_STARTUP_JWT_SECRET_KEY: Final = "startup-test-jwt-secret-key-not-for-production"

_STARTUP_SCRIPT: Final = """\
import runpy
import socket
import sys


def _refuse(*args, **kwargs):
    raise AssertionError("the process opened a connection")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.create_connection = _refuse

sys.argv = {argv!r}
runpy.run_module({module!r}, run_name="__main__", alter_sys=True)
"""

_RUNTIME_ENTRY_POINTS: Final = {
    "api": (
        "uvicorn",
        ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "0"],
    ),
    # `-A` is resolved before the subcommand, so this is also the startup
    # path of the Git worker and Beat.
    "celery": (
        "celery",
        ["celery", "-A", "app.celery_app", "worker", "--pool=prefork"],
    ),
    "ibs-consumer": ("app.ibs_consumer", ["python"]),
}


def _start(
    module: str, argv: list[str], variable: str, home: Path
) -> subprocess.CompletedProcess[str]:
    """Start an entry point with `variable=bogus` in a hermetic interpreter:
    outbound connections refused, an explicit minimal environment, and
    `cwd` `home`, so the relative `backend/.env` is never read."""
    env = {key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ}
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(_BACKEND_DIR)
    env["JWT_SECRET_KEY"] = _STARTUP_JWT_SECRET_KEY
    env["LOG_FORMAT"] = "json"
    env[variable] = "bogus"
    return subprocess.run(
        [sys.executable, "-c", _STARTUP_SCRIPT.format(argv=argv, module=module)],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _is_json_object(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


@pytest.mark.unit
class TestInvalidLoggingSettingsFailProcessStartup:
    """An invalid `LOG_LEVEL` or `LOG_FORMAT` stops every process role with
    a plain-text stderr message, not through the structured renderer
    (docs/features/platform/logging.md, Startup Validation; Testing), and
    the CLI with its documented `Error: ...` line and exit 2
    (docs/features/platform/cli-infrastructure.md, Root Command Group &
    Bootstrap, step 3)."""

    @pytest.mark.parametrize("variable", ["LOG_LEVEL", "LOG_FORMAT"])
    @pytest.mark.parametrize("role", list(_RUNTIME_ENTRY_POINTS))
    def test_runtime_process_exits_with_a_plain_text_error(
        self, role: str, variable: str, tmp_path: Path
    ) -> None:
        module, argv = _RUNTIME_ENTRY_POINTS[role]

        result = _start(module, argv, variable, tmp_path)

        assert result.returncode != 0, result.stderr
        assert result.stdout == ""
        assert f"Invalid {variable}: 'bogus'" in result.stderr
        assert not [
            line for line in result.stderr.splitlines() if _is_json_object(line)
        ]

    @pytest.mark.parametrize("variable", ["LOG_LEVEL", "LOG_FORMAT"])
    def test_cli_exits_2_with_an_error_line_and_no_traceback(
        self, variable: str, tmp_path: Path
    ) -> None:
        result = _start("app.cli", ["sentinel", "fetcher", "list"], variable, tmp_path)

        assert result.returncode == 2, result.stderr
        assert result.stdout == ""
        assert result.stderr.startswith(
            f"Error: Invalid configuration - {variable.lower()}:"
        )
        assert f"Invalid {variable}: 'bogus'" in result.stderr
        assert "Traceback" not in result.stderr


@pytest.mark.unit
class TestDebugLogLevelOrthogonality:
    """DEBUG and LOG_LEVEL are fully independent configuration axes."""

    def test_debug_true_does_not_change_log_level(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("DEBUG", "true")
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        s = Settings(_env_file=None)
        assert s.log_level == "INFO"
        assert s.debug is True

    def test_log_level_debug_does_not_change_debug_flag(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.delenv("DEBUG", raising=False)
        s = Settings(_env_file=None)
        assert s.log_level == "DEBUG"
        assert s.debug is False


@pytest.mark.unit
class TestIbsCredentialWarning:
    """IBS API credential startup warning
    (docs/features/integrations/ibs-integration.md, IBS API Credentials): the
    application starts and the warning names only the empty settings."""

    @pytest.mark.parametrize(
        ("username", "key_configured", "expected"),
        [
            ("", False, "IBS_USERNAME / IBS_SSH_PRIVATE_KEY empty"),
            ("", True, "IBS_USERNAME empty"),
            ("jdoe", False, "IBS_SSH_PRIVATE_KEY empty"),
        ],
        ids=["both_empty", "username_empty", "key_empty"],
    )
    def test_empty_credentials_warn_naming_the_empty_settings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        username: str,
        key_configured: bool,
        expected: str,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", username)
        key = fictional_settings_value() if key_configured else ""
        monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", key)
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert f"IBS credentials not configured ({expected})" in caplog.text
        if key_configured:
            assert key not in caplog.text

    def test_unset_credentials_warn(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("IBS_USERNAME", raising=False)
        monkeypatch.delenv("IBS_SSH_PRIVATE_KEY", raising=False)
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert (
            "IBS credentials not configured (IBS_USERNAME / IBS_SSH_PRIVATE_KEY empty)"
            in caplog.text
        )

    def test_configured_ibs_credentials_no_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", "jdoe")
        monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", fictional_settings_value())
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert "IBS credentials not configured" not in caplog.text


@pytest.mark.unit
class TestIbsUsernameValidation:
    """`IBS_USERNAME` (docs/features/integrations/ibs-integration.md, IBS API
    Credentials): a non-empty value consists only of U+0021 to U+007E other
    than `"` and `\\`; any other value fails startup naming the variable."""

    @pytest.mark.parametrize(
        "value", ["jdoe", "svc-sentinel_01", "a.b@c", "!~#$%&'()*+,-./:;<=>?[]^`{|}"]
    )
    def test_admissible_value_is_accepted_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", value)
        assert Settings(_env_file=None).ibs_username == value

    def test_empty_value_is_not_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", "")
        assert Settings(_env_file=None).ibs_username == ""

    @pytest.mark.parametrize(
        "value",
        [
            'jdoe"',
            "jdoe\\",
            "j doe",
            " jdoe",
            "jdoe\n",
            "jdoe\t",
            "jdoe\x00",
            "jdoe\x7f",
            "jdo\u00e9",
            "jdoe\u00a0",
        ],
        ids=[
            "double_quote",
            "backslash",
            "inner_space",
            "leading_space",
            "trailing_newline",
            "tab",
            "nul",
            "del",
            "non_ascii",
            "no_break_space",
        ],
    )
    def test_inadmissible_value_fails_startup(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        with pytest.raises(ValidationError) as raised:
            Settings(_env_file=None, ibs_username=value)
        [error] = raised.value.errors(include_url=False, include_input=False)
        assert error["loc"] == ("ibs_username",)
        assert "Invalid IBS_USERNAME:" in error["msg"]
        assert "input_value" not in _rendered(raised.value)


_KEY_MARKER = "FictionalKeyMarker"
"""Text embedded in rejected key values; never rendered in an error."""


def _key_file() -> bytes:
    return openssh_file(fictional_ed25519_key())


@functools.cache
def _rejected_key_values() -> dict[str, str]:
    """Every rejected `IBS_SSH_PRIVATE_KEY` shape, by case id."""
    data = _key_file()
    body = data[:-1]
    begin, *_, end = body.split(b"\n")
    marker = _KEY_MARKER.encode()
    valid = encode_settings_value(data)
    other_key = openssh_file(fictional_ed25519_key("sentinel-other-fictional-key"))
    return {
        "invalid_base64": f"{_KEY_MARKER}!!",
        "missing_padding": _padded_encoding(data).rstrip("="),
        "non_canonical_padding_bits": _with_non_canonical_bits(data),
        "trailing_newline": valid + "\n",
        "line_wrapped": valid[:64] + "\n" + valid[64:],
        "leading_space": " " + valid,
        "non_ascii": valid + "\u00e9",
        "multi_line_file_not_encoded": data.decode("ascii"),
        "text_before_armor": encode_settings_value(marker + b"\n" + data),
        "text_after_armor": encode_settings_value(data + marker + b"\n"),
        "two_keys": encode_settings_value(data + other_key),
        "two_final_line_feeds": encode_settings_value(data + b"\n"),
        "crlf_separators": encode_settings_value(data.replace(b"\n", b"\r\n")),
        "no_final_line_feed_but_cr": encode_settings_value(body + b"\r"),
        "armor_only": encode_settings_value(begin + b"\n" + end + b"\n"),
        "corrupt_body": encode_settings_value(
            begin + b"\n" + marker + b"\n" + end + b"\n"
        ),
        "pem_private_key": encode_settings_value(
            fictional_ed25519_key().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
        "encrypted": encode_settings_value(
            openssh_file(fictional_ed25519_key(), passphrase=b"fictional-passphrase")
        ),
        "ecdsa": encode_settings_value(
            openssh_file(ec.generate_private_key(ec.SECP256R1()))
        ),
        "rsa": encode_settings_value(
            openssh_file(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        ),
    }


def _padded_encoding(data: bytes) -> str:
    """The encoding of `data`, or of the same key file without its final LF,
    whichever ends with base64 padding; both files are valid."""
    encoded = encode_settings_value(data)
    return encoded if encoded.endswith("=") else encode_settings_value(data[:-1])


def _with_non_canonical_bits(data: bytes) -> str:
    """A valid key file encoded with non-zero unused bits in its last base64
    symbol, which a lenient decoder accepts as the same bytes."""
    encoded = _padded_encoding(data)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    stem = encoded.rstrip("=")
    last = alphabet.index(stem[-1])
    return stem[:-1] + alphabet[last | 1] + encoded[len(stem) :]


@pytest.mark.unit
class TestIbsSshPrivateKeyValidation:
    """`IBS_SSH_PRIVATE_KEY` (docs/features/integrations/ibs-integration.md,
    IBS API Credentials): the one-line standard padded base64 encoding of
    exactly one unencrypted OpenSSH Ed25519 private-key file. Any other
    non-empty value fails startup naming only the variable, never trimmed,
    and the error carries no part of the value or a parser detail."""

    def test_valid_value_is_accepted_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        value = fictional_settings_value()
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", value)
        key = Settings(_env_file=None).ibs_ssh_private_key
        assert isinstance(key, SecretStr)
        assert key.get_secret_value() == value

    def test_file_without_final_line_feed_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        value = encode_settings_value(_key_file()[:-1])
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", value)
        assert Settings(_env_file=None).ibs_ssh_private_key.get_secret_value() == value

    @pytest.mark.parametrize("unset", [True, False], ids=["unset", "empty"])
    def test_empty_or_unset_is_not_configured(
        self, monkeypatch: pytest.MonkeyPatch, unset: bool
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        if unset:
            monkeypatch.delenv("IBS_SSH_PRIVATE_KEY", raising=False)
        else:
            monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", "")
        assert Settings(_env_file=None).ibs_ssh_private_key.get_secret_value() == ""

    @pytest.mark.parametrize("case", sorted(_rejected_key_values()))
    def test_invalid_value_fails_startup_without_rendering_it(
        self, monkeypatch: pytest.MonkeyPatch, case: str
    ) -> None:
        value = _rejected_key_values()[case]
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        with pytest.raises(ValidationError) as raised:
            Settings(_env_file=None, ibs_ssh_private_key=value)

        [error] = raised.value.errors(include_url=False, include_input=False)
        assert error["loc"] == ("ibs_ssh_private_key",)
        assert error["msg"] == (
            "Value error, Invalid IBS_SSH_PRIVATE_KEY: must be the one-line "
            "base64 encoding of one unencrypted OpenSSH Ed25519 private-key file."
        )
        rendered = _rendered(raised.value)
        assert "input_value" not in rendered
        assert _KEY_MARKER not in rendered
        assert value not in rendered
        for fragment in (value[:16], value[-16:]):
            assert fragment not in rendered
        assert "password" not in rendered.lower()

    def test_value_read_from_the_environment_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The realistic path: an encoded file with a trailing newline."""
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", fictional_settings_value() + "\n")
        with pytest.raises(ValidationError, match="Invalid IBS_SSH_PRIVATE_KEY:"):
            Settings(_env_file=None)

    def test_not_listed_in_env_example(self) -> None:
        env_example = Path(__file__).resolve().parents[1] / ".env.example"
        text = env_example.read_text(encoding="utf-8")
        assert "IBS_SSH_PRIVATE_KEY" not in text
        assert "IBS_PASSWORD" not in text

    def test_ibs_password_setting_no_longer_exists(self) -> None:
        assert "ibs_password" not in Settings.model_fields


@pytest.mark.unit
class TestIbsDownloadBaseUrlValidation:
    """`IBS_DOWNLOAD_BASE_URL` startup validation and canonicalization
    (`docs/features/packages/ibs-product-release-detection.md`,
    Download Origin and Repository Paths -> `IBS_DOWNLOAD_BASE_URL`).

    Every case builds the real `Settings` object so the Pydantic validator
    runs on the application's actual startup path. A valid `JWT_SECRET_KEY`
    is supplied so only the IBS field is under test. Values are provided
    through the environment where possible; the NUL character cannot be
    represented in `os.environ`, so the control-character cases are passed
    directly to the constructor, which exercises the identical validator.
    """

    def test_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("IBS_DOWNLOAD_BASE_URL", raising=False)
        s = Settings(_env_file=None)
        assert s.ibs_download_base_url == "https://download.suse.de/ibs"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (
                "https://mirror.example.test/ibs/products",
                "https://mirror.example.test/ibs/products",
            ),
            (
                "https://mirror.example.test/ibs/products/",
                "https://mirror.example.test/ibs/products",
            ),
            ("https://mirror.example.test/", "https://mirror.example.test"),
            (
                "https://mirror.example.test:8443/ibs",
                "https://mirror.example.test:8443/ibs",
            ),
            (
                "https://mirror.example.test:8443/ibs/products",
                "https://mirror.example.test:8443/ibs/products",
            ),
            (
                "https://mirror.example.test:8443/ibs/products/",
                "https://mirror.example.test:8443/ibs/products",
            ),
            (
                "https://mirror.example.test:8443/",
                "https://mirror.example.test:8443",
            ),
            ("HTTPS://mirror.example.test/ibs", "HTTPS://mirror.example.test/ibs"),
        ],
    )
    def test_accepted_values_are_canonicalized(
        self,
        monkeypatch: pytest.MonkeyPatch,
        value: str,
        expected: str,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        s = Settings(_env_file=None)
        assert s.ibs_download_base_url == expected

    @pytest.mark.parametrize(
        "value",
        [
            "http://mirror.example.test/ibs",
            "ftp://mirror.example.test/ibs",
            "mirror.example.test/ibs",
            "//mirror.example.test/ibs",
            "/var/lib/mirror/ibs",
            "https://mirror.example.test",
            "https://mirror.example.test:8443",
            "https:///ibs",
            "https://",
            "https://:8443/ibs",
        ],
    )
    def test_rejected_scheme_authority_or_path_names_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://[::1/ibs",
            "https://]mirror[.example.test/ibs",
        ],
    )
    def test_rejected_malformed_authority_names_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://user@mirror.example.test/ibs",
            "https://user:password@mirror.example.test/ibs",
            "https://:password@mirror.example.test/ibs",
            "https://@mirror.example.test/ibs",
        ],
    )
    def test_rejected_user_information_names_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://mirror.example.test/ibs?view=full",
            "https://mirror.example.test/ibs?",
            "https://mirror.example.test/ibs#section",
            "https://mirror.example.test/ibs#",
            "https://mirror.example.test/ibs?view=full#section",
        ],
    )
    def test_rejected_query_or_fragment_names_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://mirror.example.test//ibs",
            "https://mirror.example.test/ibs//products",
            "https://mirror.example.test/./ibs",
            "https://mirror.example.test/../ibs",
            "https://mirror.example.test/ibs/./products",
            "https://mirror.example.test/ibs/../products",
            "https://mirror.example.test/ibs/.",
            "https://mirror.example.test/ibs/..",
            "https://mirror.example.test/ibs//",
            "https://mirror.example.test/ibs//products/",
            "https://mirror.example.test//",
            "https://mirror.example.test/%2e%2e/ibs",
            "https://mirror.example.test/ibs%2Fproducts",
            "https://mirror.example.test/ibs%",
            "https://mirror.example.test/ibs\\products",
        ],
    )
    def test_rejected_unsafe_path_names_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            " https://mirror.example.test/ibs",
            "https://mirror.example.test/ibs ",
            "https://mirror.example.test /ibs",
            "https://mirror.example.test/ib s",
            "https://mirror.example.test/ibs\u00a0",
        ],
    )
    def test_rejected_whitespace_names_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "character",
        [chr(code) for code in range(0x20)] + [chr(0x7F)],
        ids=[f"U+{code:04X}" for code in range(0x20)] + ["U+007F"],
    )
    def test_rejected_control_characters_name_setting(
        self, monkeypatch: pytest.MonkeyPatch, character: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        value = f"https://mirror.example.test/ibs{character}/products"
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None, ibs_download_base_url=value)

    @pytest.mark.parametrize(
        "value",
        [
            "https://mirror.example.test:not-a-port/ibs",
            "https://mirror.example.test:65536/ibs",
            "https://mirror.example.test:-1/ibs",
            "https://mirror.example.test:/ibs",
        ],
    )
    def test_rejected_ports_name_setting(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_DOWNLOAD_BASE_URL", value)
        with pytest.raises(ValidationError, match="IBS_DOWNLOAD_BASE_URL"):
            Settings(_env_file=None)


@pytest.mark.unit
class TestHttpsApiPrefixValidation:
    """`SMELT_API_URL`, `AIMAAS_API_URL`, and `IBS_API_URL` startup validation
    and canonicalization (`docs/features/packages/product-catalog.md`, SMELT
    Integration and AIMAAS Integration -> Origin, Authentication, and
    Pagination; Configuration; `docs/features/integrations/ibs-integration.md`,
    Origins and Authentication).

    The settings follow the same rules, so every case runs for each:
    HTTPS, a hostname, no user information, query, or fragment, a permitted
    non-default port, and trailing-slash removal, plus malformed-URL
    rejection. The stricter `IBS_DOWNLOAD_BASE_URL` path rules are
    deliberately not mirrored.
    """

    @pytest.fixture(
        params=[
            ("SMELT_API_URL", "smelt_api_url", "https://smelt.suse.de/api"),
            ("AIMAAS_API_URL", "aimaas_api_url", "https://aimaas.suse.de/api"),
            ("IBS_API_URL", "ibs_api_url", "https://api.suse.de"),
        ],
        ids=["smelt", "aimaas", "ibs_api"],
    )
    def setting(self, request: pytest.FixtureRequest) -> tuple[str, str, str]:
        """`(environment variable, Settings attribute, default)`."""
        value: tuple[str, str, str] = request.param
        return value

    def test_default_when_unset(
        self, monkeypatch: pytest.MonkeyPatch, setting: tuple[str, str, str]
    ) -> None:
        variable, attribute, default = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv(variable, raising=False)
        s = Settings(_env_file=None)
        assert getattr(s, attribute) == default

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://service.example.test/api", "https://service.example.test/api"),
            ("https://service.example.test/api/", "https://service.example.test/api"),
            ("https://service.example.test/api//", "https://service.example.test/api"),
            ("https://service.example.test", "https://service.example.test"),
            ("https://service.example.test/", "https://service.example.test"),
            (
                "https://service.example.test:8443/api",
                "https://service.example.test:8443/api",
            ),
            (
                "https://service.example.test:8443/api/",
                "https://service.example.test:8443/api",
            ),
            ("HTTPS://service.example.test/api", "HTTPS://service.example.test/api"),
        ],
    )
    def test_accepted_values_are_canonicalized(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        value: str,
        expected: str,
    ) -> None:
        variable, attribute, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        s = Settings(_env_file=None)
        assert getattr(s, attribute) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "http://service.example.test/api",
            "ftp://service.example.test/api",
            "service.example.test/api",
            "//service.example.test/api",
            "",
        ],
    )
    def test_rejected_non_https_scheme_names_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        value: str,
    ) -> None:
        variable, _, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        with pytest.raises(ValidationError, match=variable):
            Settings(_env_file=None)

    @pytest.mark.parametrize("value", ["https://", "https:///api", "https://:8443/api"])
    def test_rejected_missing_hostname_names_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        value: str,
    ) -> None:
        variable, _, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        with pytest.raises(ValidationError, match=variable):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://user@service.example.test/api",
            "https://user:password@service.example.test/api",
            "https://:password@service.example.test/api",
            "https://@service.example.test/api",
        ],
    )
    def test_rejected_user_information_names_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        value: str,
    ) -> None:
        variable, _, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        with pytest.raises(ValidationError, match=variable):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://service.example.test/api?page_size=100",
            "https://service.example.test/api?",
            "https://service.example.test/api#section",
            "https://service.example.test/api#",
        ],
    )
    def test_rejected_query_or_fragment_names_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        value: str,
    ) -> None:
        variable, _, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        with pytest.raises(ValidationError, match=variable):
            Settings(_env_file=None)

    @pytest.mark.parametrize(
        "value",
        [
            "https://[::1/api",
            "https://]smelt[.example.test/api",
            "https://service.example.test:not-a-port/api",
            "https://service.example.test:65536/api",
            "https://service.example.test:/api",
            " https://service.example.test/api",
            "https://service.example.test /api",
        ],
    )
    def test_rejected_malformed_values_name_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        value: str,
    ) -> None:
        variable, _, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        with pytest.raises(ValidationError, match=variable):
            Settings(_env_file=None)

    @pytest.mark.parametrize("character", ["\x00", "\t", "\n", "\x7f"])
    def test_rejected_control_characters_name_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        setting: tuple[str, str, str],
        character: str,
    ) -> None:
        variable, attribute, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        overrides: dict[str, Any] = {
            attribute: f"https://service.example.test/api{character}/v"
        }
        with pytest.raises(ValidationError, match=variable):
            Settings(_env_file=None, **overrides)

    def test_not_listed_in_env_example(self, setting: tuple[str, str, str]) -> None:
        variable, _, _ = setting
        env_example = Path(__file__).resolve().parents[1] / ".env.example"
        assert variable not in env_example.read_text(encoding="utf-8")


@pytest.mark.unit
class TestGithubToken:
    """`GITHUB_TOKEN` (docs/configuration.md, External APIs): a `SecretStr`
    whose empty default means "not configured". Every test sets or removes
    the variable explicitly, independent of the developer environment."""

    def test_default_when_unset_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        s = Settings(_env_file=None)
        assert isinstance(s.github_token, SecretStr)
        assert s.github_token.get_secret_value() == ""

    def test_empty_value_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("GITHUB_TOKEN", "")
        s = Settings(_env_file=None)
        assert s.github_token.get_secret_value() == ""

    def test_not_listed_in_env_example(self) -> None:
        env_example = Path(__file__).resolve().parents[1] / ".env.example"
        assert "GITHUB_TOKEN" not in env_example.read_text(encoding="utf-8")


def _rendered(error: ValidationError) -> str:
    """Every rendering a process may print or log for `error`: its message,
    its repr, and the traceback an uncaught startup failure prints."""
    return "\n".join(
        [str(error), repr(error), "".join(traceback.format_exception(error))]
    )


_HEADER_SECRET_MARKER = "Fictional-Header-Secret"
"""A fragment of every rejected header-secret value below; never rendered."""


@pytest.mark.unit
class TestHeaderSecretValidation:
    """`NVD_API_KEY` and `GITHUB_TOKEN` are sent verbatim as HTTP header
    values (`docs/conventions.md`, Secret Field Typing; docs/configuration.md,
    External APIs): a non-empty value must be printable ASCII without
    whitespace, otherwise startup fails with an error that names the
    variable and never renders the value. Empty or unset stays valid."""

    @pytest.fixture(
        params=[("NVD_API_KEY", "nvd_api_key"), ("GITHUB_TOKEN", "github_token")],
        ids=["nvd", "github"],
    )
    def setting(self, request: pytest.FixtureRequest) -> tuple[str, str]:
        """`(environment variable, Settings attribute)`."""
        value: tuple[str, str] = request.param
        return value

    @pytest.mark.parametrize(
        "value",
        [
            "00000000-0000-4000-8000-000000000000",
            "ghp_Fictional0000000000000000000000000000",
            "github_pat_Fictional_0000000000",
            "!~",
            "x",
        ],
    )
    def test_valid_value_is_accepted_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, setting: tuple[str, str], value: str
    ) -> None:
        variable, attribute = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        secret = getattr(Settings(_env_file=None), attribute)
        assert secret.get_secret_value() == value

    @pytest.mark.parametrize("unset", [True, False], ids=["unset", "empty"])
    def test_empty_or_unset_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, setting: tuple[str, str], unset: bool
    ) -> None:
        variable, attribute = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        if unset:
            monkeypatch.delenv(variable, raising=False)
        else:
            monkeypatch.setenv(variable, "")
        assert getattr(Settings(_env_file=None), attribute).get_secret_value() == ""

    @pytest.mark.parametrize(
        "value",
        [
            f"{_HEADER_SECRET_MARKER}\n",
            f"{_HEADER_SECRET_MARKER}\r\n",
            f"{_HEADER_SECRET_MARKER}\r",
            f" {_HEADER_SECRET_MARKER}",
            f"{_HEADER_SECRET_MARKER} ",
            f"{_HEADER_SECRET_MARKER} 0000",
            f"{_HEADER_SECRET_MARKER}\t",
            f"{_HEADER_SECRET_MARKER}\u00a0",
            f"{_HEADER_SECRET_MARKER}-\u00e9",
            f"{_HEADER_SECRET_MARKER}\x00",
            f"{_HEADER_SECRET_MARKER}\x1b",
            f"{_HEADER_SECRET_MARKER}\x7f",
        ],
        ids=[
            "trailing_newline",
            "trailing_crlf",
            "trailing_cr",
            "leading_space",
            "trailing_space",
            "inner_space",
            "tab",
            "no_break_space",
            "non_ascii",
            "nul",
            "escape",
            "del",
        ],
    )
    def test_invalid_value_fails_startup_without_rendering_it(
        self, monkeypatch: pytest.MonkeyPatch, setting: tuple[str, str], value: str
    ) -> None:
        variable, attribute = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        overrides: dict[str, Any] = {attribute: value}
        with pytest.raises(ValidationError) as raised:
            Settings(_env_file=None, **overrides)

        [error] = raised.value.errors(include_url=False, include_input=False)
        assert error["loc"] == (attribute,)
        assert f"Invalid {variable}:" in error["msg"]
        rendered = _rendered(raised.value)
        assert _HEADER_SECRET_MARKER not in rendered
        assert "input_value" not in rendered

    def test_value_read_from_the_environment_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch, setting: tuple[str, str]
    ) -> None:
        """The realistic path: a file-based secret with a trailing newline."""
        variable, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, f"{_HEADER_SECRET_MARKER}\n")
        with pytest.raises(ValidationError, match=f"Invalid {variable}:") as raised:
            Settings(_env_file=None)
        assert _HEADER_SECRET_MARKER not in _rendered(raised.value)

    @pytest.mark.parametrize("value", [" ", "\n", "\t"])
    def test_whitespace_only_value_fails_startup(
        self, monkeypatch: pytest.MonkeyPatch, setting: tuple[str, str], value: str
    ) -> None:
        variable, _ = setting
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(variable, value)
        with pytest.raises(ValidationError, match=f"Invalid {variable}:"):
            Settings(_env_file=None)


def _fictional(name: str) -> str:
    """A fictional secret value, built at run time so that no credential-like
    literal appears in the source."""
    return f"fictional-{name}-value"


_CONFIGURED_SECRETS: dict[str, str] = {
    "DATABASE_URL": f"postgresql+asyncpg://sentinel:{_fictional('db')}@db/sentinel",
    "REDIS_URL": f"redis://:{_fictional('redis')}@redis:6379/0",
    "CELERY_BROKER_URL": f"redis://:{_fictional('broker')}@redis:6379/1",
    "IBS_SSH_PRIVATE_KEY": fictional_settings_value(),
    "NVD_API_KEY": _fictional("nvd"),
    "GITHUB_TOKEN": _fictional("github"),
}
_SHORT_JWT_SECRET_KEY = _fictional("jwt")
"""Shorter than the 32-character minimum."""
_SECRET_FRAGMENTS = (
    *(_fictional(name) for name in ("db", "redis", "broker", "nvd", "github", "jwt")),
    _CONFIGURED_SECRETS["IBS_SSH_PRIVATE_KEY"][:24],
    _CONFIGURED_SECRETS["IBS_SSH_PRIVATE_KEY"][-24:],
)


@pytest.mark.unit
class TestValidationErrorsHideInput:
    """`Settings` declares `hide_input_in_errors` (`docs/conventions.md`,
    Secret Field Typing): no startup failure renders a received value. A
    missing required setting or a model-level validator failure would
    otherwise render the whole input mapping, which holds every configured
    secret as a plain string. One case per error mechanism."""

    @pytest.mark.parametrize(
        "failure",
        [
            {"JWT_SECRET_KEY": None},
            {"JWT_SECRET_KEY": _SHORT_JWT_SECRET_KEY},
            {"JWT_EXPIRY_HOURS": "not-a-number"},
            {"GIT_CLONE_BASE_DIR": "relative/git"},
        ],
        ids=[
            "missing_required_setting",
            "model_validator",
            "type_parsing",
            "field_validator",
        ],
    )
    def test_startup_failure_never_renders_a_configured_secret(
        self, monkeypatch: pytest.MonkeyPatch, failure: dict[str, str | None]
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        for variable, value in {**_CONFIGURED_SECRETS, **failure}.items():
            if value is None:
                monkeypatch.delenv(variable, raising=False)
            else:
                monkeypatch.setenv(variable, value)

        with pytest.raises(ValidationError) as raised:
            Settings(_env_file=None)

        rendered = _rendered(raised.value)
        assert "input_value" not in rendered
        for fragment in _SECRET_FRAGMENTS:
            assert fragment not in rendered


@pytest.mark.unit
class TestGitCloneBaseDir:
    """`GIT_CLONE_BASE_DIR` (docs/configuration.md, Git-Based Fetchers;
    git-fetcher-infrastructure.md, Environment Configuration): an absolute
    path, validated at startup because clones are deleted under it."""

    def test_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("GIT_CLONE_BASE_DIR", raising=False)
        assert Settings(_env_file=None).git_clone_base_dir == "/var/lib/sentinel/git"

    def test_absolute_override_accepted_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("GIT_CLONE_BASE_DIR", "/srv/example/git clones/")
        s = Settings(_env_file=None)
        assert s.git_clone_base_dir == "/srv/example/git clones/"

    @pytest.mark.parametrize(
        "value", ["", "relative/git", "./git", "../git", "~/git", "git"]
    )
    def test_empty_or_relative_value_fails_startup(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("GIT_CLONE_BASE_DIR", value)
        with pytest.raises(ValidationError, match="Invalid GIT_CLONE_BASE_DIR"):
            Settings(_env_file=None)

    def test_nul_character_fails_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        with pytest.raises(ValidationError, match="Invalid GIT_CLONE_BASE_DIR"):
            Settings(_env_file=None, git_clone_base_dir="/var/lib/\x00git")

    def test_listed_in_env_example_with_an_absolute_value(self) -> None:
        env_example = Path(__file__).resolve().parents[1] / ".env.example"
        lines = env_example.read_text(encoding="utf-8").splitlines()
        values = [
            line.split("=", 1)[1]
            for line in lines
            if line.startswith("GIT_CLONE_BASE_DIR=")
        ]
        assert len(values) == 1
        assert values[0].startswith("/")


@pytest.mark.unit
class TestSecretFieldRedaction:
    """Secret field redaction, covering two distinct mechanisms:

    - `SecretStr` fields (`jwt_secret_key`, `ibs_ssh_private_key`,
      `nvd_api_key`, `github_token`):
      masked in both `repr()`/`str()` AND `model_dump()`/`model_dump_json()`.
    - `Field(..., repr=False)` URL fields (`database_url`, `redis_url`,
      `celery_broker_url`): the field is entirely excluded from `repr()`,
      but the plain value IS still returned by `model_dump()` (repr=False
      only affects repr, not serialization).
    """

    def test_repr_does_not_expose_jwt_secret_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_value = "x" * 32
        monkeypatch.setenv("JWT_SECRET_KEY", secret_value)
        s = Settings(_env_file=None)
        assert secret_value not in repr(s)
        assert secret_value not in str(s)

    def test_repr_and_dump_do_not_expose_ibs_ssh_private_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_value = fictional_settings_value()
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_SSH_PRIVATE_KEY", secret_value)
        s = Settings(_env_file=None)
        for rendered in (repr(s), str(s), s.model_dump_json()):
            assert secret_value[:24] not in rendered

    def test_repr_does_not_expose_nvd_api_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_value = "super-secret-nvd-api-key"
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("NVD_API_KEY", secret_value)
        s = Settings(_env_file=None)
        assert secret_value not in repr(s)

    def test_repr_and_dump_do_not_expose_github_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_value = "fictional-github-token-0000000000"
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("GITHUB_TOKEN", secret_value)
        s = Settings(_env_file=None)
        assert secret_value not in repr(s)
        assert secret_value not in str(s)
        assert secret_value not in s.model_dump_json()
        assert s.github_token.get_secret_value() == secret_value

    def test_repr_does_not_expose_database_url_credentials(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql+asyncpg://sentinel_user:sentinel_pw@db:5432/sentinel",
        )
        s = Settings(_env_file=None)
        assert "sentinel_pw" not in repr(s)
        assert "database_url" not in repr(s)

    def test_repr_does_not_expose_redis_url_credentials(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(
            "REDIS_URL",
            "redis://:redis_secret_pw@redis:6379/0",
        )
        s = Settings(_env_file=None)
        assert "redis_secret_pw" not in repr(s)
        assert "redis_url" not in repr(s)

    def test_repr_does_not_expose_celery_broker_url_credentials(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv(
            "CELERY_BROKER_URL",
            "redis://:celery_secret_pw@redis:6379/1",
        )
        s = Settings(_env_file=None)
        assert "celery_secret_pw" not in repr(s)
        assert "celery_broker_url" not in repr(s)

    def test_repr_exposes_non_secret_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-secret fields must remain visible in repr() — guards against
        over-broad redaction being applied by mistake in the future."""
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("APP_NAME", "sentinel-test-instance")
        s = Settings(_env_file=None)
        assert "sentinel-test-instance" in repr(s)

    def test_model_dump_masks_secret_str_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_value = "x" * 32
        monkeypatch.setenv("JWT_SECRET_KEY", secret_value)
        s = Settings(_env_file=None)
        dumped = s.model_dump()
        assert dumped["jwt_secret_key"].get_secret_value() == secret_value
        assert secret_value not in repr(dumped["jwt_secret_key"])
        assert secret_value not in str(dumped)

    def test_model_dump_json_masks_secret_str_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_value = "x" * 32
        monkeypatch.setenv("JWT_SECRET_KEY", secret_value)
        s = Settings(_env_file=None)
        dumped_json = s.model_dump_json()
        assert secret_value not in dumped_json

    def test_model_dump_exposes_plain_repr_false_url_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`repr=False` only affects repr(); model_dump() must still return
        the plain string value for these fields (no masking on dump)."""
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        db_url = "postgresql+asyncpg://sentinel_user:sentinel_pw@db:5432/sentinel"
        monkeypatch.setenv("DATABASE_URL", db_url)
        s = Settings(_env_file=None)
        dumped = s.model_dump()
        assert dumped["database_url"] == db_url


# Fictional credential material used by the secret value tests.
_NVD_SETTING_VALUE = "fictional-nvd-key-0123456789"
_GITHUB_TOKEN_VALUE = "fictional-github-token-0123456789"
_IBS_KEY_SETTING_VALUE = fictional_settings_value()
_BROKER_URL_USERINFO_PART = "fictional-broker-pass-42"


def _secret_settings(**overrides: Any) -> Settings:
    """Build a Settings instance bypassing the `.env` file. Environment
    variables still apply, so a test that depends on a field's value
    passes it explicitly."""
    return Settings(_env_file=None, **{"jwt_secret_key": "a" * 32, **overrides})


@pytest.mark.unit
class TestSecretValues:
    """`Settings.secret_values()`, the configured secret values the
    Redaction Processor masks exactly (docs/features/platform/logging.md,
    Redaction Processor), is derived from the field classification of
    docs/conventions.md (Secret Field Typing)."""

    def test_collects_secretstr_values_and_url_passwords(self) -> None:
        settings = _secret_settings(
            jwt_secret_key="j" * 32,
            nvd_api_key=_NVD_SETTING_VALUE,
            ibs_ssh_private_key=_IBS_KEY_SETTING_VALUE,
            database_url="postgresql+asyncpg://svc:fictional-db-pass@db.example.test/db",
            redis_url="redis://:fictional-redis-pass@cache.example.test:6379/0",
            celery_broker_url=(
                f"amqps://svc-sentinel:{_BROKER_URL_USERINFO_PART}"
                "@rabbit.example.test:5671/"
            ),
            ibs_rabbitmq_url="amqps://svc:fictional-mq-pass@mq.example.test",
        )

        values = settings.secret_values()

        assert set(values) == {
            "j" * 32,
            _NVD_SETTING_VALUE,
            _IBS_KEY_SETTING_VALUE,
            "fictional-db-pass",
            "fictional-redis-pass",
            _BROKER_URL_USERINFO_PART,
            "fictional-mq-pass",
        }

    def test_values_are_derived_from_field_classification(self) -> None:
        """A new field classified per Secret Field Typing is covered
        without further changes."""

        class _ExtendedSettings(Settings):
            extra_token: SecretStr = SecretStr("fictional-extra-token-0001")
            extra_url: str = Field(
                default="amqps://svc:fictional-extra-pass@mq.example.test/",
                repr=False,
            )
            extra_public_url: str = "https://svc:public-userinfo@docs.example.test/"

        settings = _ExtendedSettings(_env_file=None, jwt_secret_key="a" * 32)

        values = settings.secret_values()

        assert "fictional-extra-token-0001" in values
        assert "fictional-extra-pass" in values
        assert "public-userinfo" not in values

    def test_url_password_is_percent_decoded(self) -> None:
        settings = _secret_settings(
            database_url="postgresql+asyncpg://svc:fictional%40db%2Fpass@db.example.test/db"
        )
        assert "fictional@db/pass" in settings.secret_values()

    def test_github_token_is_collected(self) -> None:
        settings = _secret_settings(github_token=_GITHUB_TOKEN_VALUE)
        assert _GITHUB_TOKEN_VALUE in settings.secret_values()

    def test_empty_values_and_urls_without_password_are_skipped(self) -> None:
        settings = _secret_settings(
            nvd_api_key="",
            github_token="",
            ibs_ssh_private_key="",
            database_url="postgresql+asyncpg://svc@db.example.test/db",
            redis_url="redis://cache.example.test:6379/0",
            celery_broker_url="redis://cache.example.test:6379/1",
            ibs_rabbitmq_url="amqps://mq.example.test",
        )
        assert settings.secret_values() == ["a" * 32]

    def test_malformed_url_is_skipped(self) -> None:
        settings = _secret_settings(redis_url="redis://svc:fict-pass@[::1/0")
        assert "fict-pass" not in settings.secret_values()


@pytest.mark.unit
class TestCorsOriginsParsing:
    """CORS_ORIGINS comma-separated parsing (`docs/conventions.md`,
    Configuration Management -> List-type environment variables).

    Exercises both the pure `_split_comma()` helper directly (fast,
    exhaustive edge cases) and the full `Settings.cors_origins` field
    end-to-end via the environment variable (the real application
    contract)."""

    def test_split_comma_single_value(self) -> None:
        assert _split_comma("http://localhost:5173") == ["http://localhost:5173"]

    def test_split_comma_multiple_values(self) -> None:
        assert _split_comma("http://a.com,http://b.com") == [
            "http://a.com",
            "http://b.com",
        ]

    def test_split_comma_strips_whitespace_around_values(self) -> None:
        assert _split_comma(" http://a.com , http://b.com ") == [
            "http://a.com",
            "http://b.com",
        ]

    def test_split_comma_drops_empty_elements(self) -> None:
        assert _split_comma("http://a.com,,http://b.com") == [
            "http://a.com",
            "http://b.com",
        ]

    def test_split_comma_empty_string_yields_empty_list(self) -> None:
        assert _split_comma("") == []

    def test_split_comma_passes_through_already_typed_list(self) -> None:
        already_typed = ["http://a.com", "http://b.com"]
        assert _split_comma(already_typed) is already_typed

    def test_settings_cors_origins_env_var_single_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")
        s = Settings(_env_file=None)
        assert s.cors_origins == ["http://localhost:5173"]

    def test_settings_cors_origins_env_var_multiple_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("CORS_ORIGINS", "http://a.com,http://b.com")
        s = Settings(_env_file=None)
        assert s.cors_origins == ["http://a.com", "http://b.com"]

    def test_settings_cors_origins_env_var_empty_yields_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("CORS_ORIGINS", "")
        s = Settings(_env_file=None)
        assert s.cors_origins == []

    def test_settings_cors_origins_default_when_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.delenv("CORS_ORIGINS", raising=False)
        s = Settings(_env_file=None)
        assert s.cors_origins == ["http://localhost:5173"]


_MQ_PASSWORD = "mq-password-not-for-production"


def _mq_settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
    for name in (
        "IBS_RABBITMQ_URL",
        "IBS_RABBITMQ_ENABLED",
        "IBS_RABBITMQ_RECONNECT_INITIAL",
        "IBS_RABBITMQ_RECONNECT_MAX",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)


@pytest.mark.unit
class TestIbsRabbitmqSettings:
    """The IBS RabbitMQ consumer settings
    (docs/features/integrations/ibs-rabbitmq-integration.md, Configuration;
    docs/configuration.md, IBS RabbitMQ Consumer). Every role shares
    `Settings`, so an invalid value fails startup of every role even when
    the consumer is disabled."""

    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        s = _mq_settings(monkeypatch)

        assert s.ibs_rabbitmq_url == "amqps://suse:suse@rabbit.suse.de"
        assert s.ibs_rabbitmq_enabled is True
        assert s.ibs_rabbitmq_reconnect_initial == 5
        assert s.ibs_rabbitmq_reconnect_max == 300

    def test_url_is_excluded_from_the_representation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url = f"amqps://svc:{_MQ_PASSWORD}@mq.example.test"
        s = _mq_settings(monkeypatch, IBS_RABBITMQ_URL=url)

        assert _MQ_PASSWORD not in repr(s)
        assert not Settings.model_fields["ibs_rabbitmq_url"].repr

    def test_fixed_constants_have_no_setting(self) -> None:
        assert {
            name for name in Settings.model_fields if name.startswith("ibs_rabbitmq_")
        } == {
            "ibs_rabbitmq_url",
            "ibs_rabbitmq_enabled",
            "ibs_rabbitmq_reconnect_initial",
            "ibs_rabbitmq_reconnect_max",
        }

    @pytest.mark.parametrize(
        "url",
        [
            "amqps://suse:suse@rabbit.suse.de",
            "amqps://rabbit.suse.de",
            "AMQPS://rabbit.suse.de",
            "amqps://svc:p%40ss@mq.example.test:5671",
            "amqps://svc:pass@mq.example.test:5671/",
            "amqps://svc:pass@mq.example.test/example-vhost",
            "amqps://svc@[2001:db8::1]:5671",
        ],
    )
    def test_accepted_urls_are_kept_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, url: str
    ) -> None:
        assert _mq_settings(monkeypatch, IBS_RABBITMQ_URL=url).ibs_rabbitmq_url == url

    @pytest.mark.parametrize(
        "url",
        [
            "amqp://mq.example.test",
            "https://mq.example.test",
            "mq.example.test",
            "",
            "amqps://",
            "amqps://:5671",
            f"amqps://svc:{_MQ_PASSWORD}@",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test?heartbeat=0",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test/?no_verify_ssl=1",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test#fragment",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test:notaport",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test:99999",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test:",
            f"amqps://svc:{_MQ_PASSWORD}@[::1",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test /vhost",
            f" amqps://svc:{_MQ_PASSWORD}@mq.example.test",
            f"amqps://svc:{_MQ_PASSWORD}@mq.example.test\n",
        ],
    )
    def test_rejected_url_names_only_the_variable(
        self, monkeypatch: pytest.MonkeyPatch, url: str
    ) -> None:
        with pytest.raises(ValidationError, match="IBS_RABBITMQ_URL") as raised:
            _mq_settings(monkeypatch, IBS_RABBITMQ_URL=url)

        rendered = str(raised.value) + "".join(traceback.format_exception(raised.value))
        assert _MQ_PASSWORD not in rendered

    def test_control_character_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="IBS_RABBITMQ_URL"):
            Settings(
                _env_file=None,
                jwt_secret_key="a" * 32,
                ibs_rabbitmq_url="amqps://mq.example.test\x00",
            )

    @pytest.mark.parametrize(
        ("initial", "maximum"),
        [("5", "300"), ("1", "1"), ("300", "300"), ("7", "8")],
    )
    def test_accepted_reconnect_pairs(
        self, monkeypatch: pytest.MonkeyPatch, initial: str, maximum: str
    ) -> None:
        s = _mq_settings(
            monkeypatch,
            IBS_RABBITMQ_RECONNECT_INITIAL=initial,
            IBS_RABBITMQ_RECONNECT_MAX=maximum,
        )

        assert (s.ibs_rabbitmq_reconnect_initial, s.ibs_rabbitmq_reconnect_max) == (
            int(initial),
            int(maximum),
        )

    @pytest.mark.parametrize(
        ("initial", "maximum", "variable"),
        [
            ("0", "300", "IBS_RABBITMQ_RECONNECT_INITIAL"),
            ("-5", "300", "IBS_RABBITMQ_RECONNECT_INITIAL"),
            ("5", "0", "IBS_RABBITMQ_RECONNECT_MAX"),
            ("5", "-1", "IBS_RABBITMQ_RECONNECT_MAX"),
            ("10", "9", "IBS_RABBITMQ_RECONNECT_MAX"),
        ],
    )
    def test_rejected_reconnect_pairs_name_the_variable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        initial: str,
        maximum: str,
        variable: str,
    ) -> None:
        with pytest.raises(ValidationError, match=variable):
            _mq_settings(
                monkeypatch,
                IBS_RABBITMQ_RECONNECT_INITIAL=initial,
                IBS_RABBITMQ_RECONNECT_MAX=maximum,
            )

    def test_invalid_value_fails_even_when_the_consumer_is_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with pytest.raises(ValidationError, match="IBS_RABBITMQ_URL"):
            _mq_settings(
                monkeypatch,
                IBS_RABBITMQ_ENABLED="false",
                IBS_RABBITMQ_URL="amqp://mq.example.test",
            )

    def test_disabled_flag_is_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert (
            _mq_settings(monkeypatch, IBS_RABBITMQ_ENABLED="false").ibs_rabbitmq_enabled
            is False
        )
