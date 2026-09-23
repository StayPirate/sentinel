"""Tests for Settings startup validation (backend/app/config.py)."""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from app.config import Settings, _split_comma


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
    """IBS credential startup warning."""

    def test_empty_ibs_credentials_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", "")
        monkeypatch.setenv("IBS_PASSWORD", "")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert "IBS credentials not configured" in caplog.text

    def test_only_username_empty_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", "")
        monkeypatch.setenv("IBS_PASSWORD", "secret")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert "IBS credentials not configured" in caplog.text

    def test_only_password_empty_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", "jdoe")
        monkeypatch.setenv("IBS_PASSWORD", "")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert "IBS credentials not configured" in caplog.text

    def test_configured_ibs_credentials_no_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_USERNAME", "jdoe")
        monkeypatch.setenv("IBS_PASSWORD", "secret-password-here")
        with caplog.at_level(logging.WARNING):
            Settings(_env_file=None)
        assert "IBS credentials not configured" not in caplog.text


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
class TestSecretFieldRedaction:
    """Secret field redaction, covering two distinct mechanisms:

    - `SecretStr` fields (`jwt_secret_key`, `ibs_password`, `nvd_api_key`):
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

    def test_repr_does_not_expose_ibs_password(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_value = "super-secret-ibs-password"
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("IBS_PASSWORD", secret_value)
        s = Settings(_env_file=None)
        assert secret_value not in repr(s)

    def test_repr_does_not_expose_nvd_api_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_value = "super-secret-nvd-api-key"
        monkeypatch.setenv("JWT_SECRET_KEY", "a" * 32)
        monkeypatch.setenv("NVD_API_KEY", secret_value)
        s = Settings(_env_file=None)
        assert secret_value not in repr(s)

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
