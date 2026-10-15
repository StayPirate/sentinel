"""Application configuration using pydantic-settings."""

from __future__ import annotations

import logging
import re
from pathlib import PurePosixPath
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import (
    BeforeValidator,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.ibs_ssh_key import (
    INVALID_USERNAME_MESSAGE,
    is_valid_ibs_username,
    load_ibs_ssh_private_key,
)

logger = logging.getLogger(__name__)


def _split_comma(value: Any) -> Any:
    """Split a comma-separated string into a list of stripped, non-empty items."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


CommaSeparated = Annotated[list[str], NoDecode, BeforeValidator(_split_comma)]


def _validate_https_api_prefix(value: str, variable: str) -> str:
    """Validate and canonicalize an HTTPS API prefix setting.

    Enforces the prefix rules of docs/features/packages/product-catalog.md
    (Configuration) and docs/features/integrations/ibs-integration.md
    (Origins and Authentication): HTTPS; a hostname; no user information,
    query, or fragment; a non-default port permitted; any trailing slash
    removed.
    Malformed values (including whitespace or control characters and an
    invalid port) are rejected. Every message names `variable`.
    """
    prefix = f"Invalid {variable}"

    if any(character.isspace() or not character.isprintable() for character in value):
        msg = f"{prefix}: malformed URL."
        raise ValueError(msg)
    if "?" in value or "#" in value:
        msg = f"{prefix}: query or fragment components are not permitted."
        raise ValueError(msg)

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        msg = f"{prefix}: malformed URL."
        raise ValueError(msg) from None
    if port is None and parsed.netloc.endswith(":"):
        msg = f"{prefix}: malformed URL."
        raise ValueError(msg)

    if parsed.scheme.lower() != "https":
        msg = f"{prefix}: the scheme must be HTTPS."
        raise ValueError(msg)
    if not hostname:
        msg = f"{prefix}: a non-empty hostname is required."
        raise ValueError(msg)
    if username is not None or password is not None:
        msg = f"{prefix}: user information is not permitted."
        raise ValueError(msg)

    return value.rstrip("/")


_HEADER_VALUE = re.compile(r"[\x21-\x7e]*")
"""Printable ASCII without whitespace; empty means "not configured"."""

_HEADER_SECRET_FIELDS = ("nvd_api_key", "github_token")
"""Secret settings sent verbatim as an HTTP header value
(docs/conventions.md, Secret Field Typing)."""


_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_VALID_LOG_FORMATS = ("auto", "json", "console")


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # `hide_input_in_errors`: a validation error never renders a received
    # value, which may be a secret (docs/conventions.md, Secret Field Typing).
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        hide_input_in_errors=True,
    )

    # Application
    app_name: str = "sentinel"
    debug: bool = False

    # Logging
    log_level: str = "INFO"
    log_format: str = "auto"

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel",
        repr=False,
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", repr=False)

    # Celery
    celery_broker_url: str = Field(default="redis://localhost:6379/1", repr=False)
    celery_timezone: str = "UTC"
    celery_enable_utc: bool = True

    # CORS
    cors_origins: CommaSeparated = ["http://localhost:5173"]

    # IBS Integration
    ibs_api_url: str = "https://api.suse.de"
    ibs_username: str = ""
    ibs_ssh_private_key: SecretStr = SecretStr("")
    ibs_download_base_url: str = "https://download.suse.de/ibs"

    # IBS RabbitMQ consumer (credential-bearing URL: docs/conventions.md,
    # Secret Field Typing)
    ibs_rabbitmq_url: str = Field(
        default="amqps://suse:suse@rabbit.suse.de", repr=False
    )
    ibs_rabbitmq_enabled: bool = True
    ibs_rabbitmq_reconnect_initial: int = 5
    ibs_rabbitmq_reconnect_max: int = 300

    # SMELT / AIMAAS
    smelt_api_url: str = "https://smelt.suse.de/api"
    aimaas_api_url: str = "https://aimaas.suse.de/api"

    # NVD API
    nvd_api_key: SecretStr = SecretStr("")

    # GitHub Advisory Database (sync_ghsa_advisories)
    github_token: SecretStr = SecretStr("")

    # Git-based fetchers
    git_clone_base_dir: str = "/var/lib/sentinel/git"

    # Security
    jwt_secret_key: SecretStr
    jwt_expiry_hours: int = 72
    session_max_lifetime_days: int = 30
    login_max_attempts: int = 5
    login_lockout_minutes: int = 10

    # TLS / Networking
    suse_ca_cert_path: str = "certs/SUSE_Trust_Root.crt"

    @field_validator("log_level", mode="before")
    @classmethod
    def _validate_log_level(cls, value: Any) -> Any:
        """Normalize and validate LOG_LEVEL (case-insensitive)."""
        if isinstance(value, str):
            normalized = value.upper()
            if normalized not in _VALID_LOG_LEVELS:
                msg = (
                    f"Invalid LOG_LEVEL: {value!r}. Must be one of "
                    f"{', '.join(_VALID_LOG_LEVELS)} (case-insensitive)."
                )
                raise ValueError(msg)
            return normalized
        return value

    @field_validator("log_format", mode="before")
    @classmethod
    def _validate_log_format(cls, value: Any) -> Any:
        """Normalize and validate LOG_FORMAT (case-insensitive)."""
        if isinstance(value, str):
            normalized = value.lower()
            if normalized not in _VALID_LOG_FORMATS:
                msg = (
                    f"Invalid LOG_FORMAT: {value!r}. Must be one of "
                    f"{', '.join(_VALID_LOG_FORMATS)} (case-insensitive)."
                )
                raise ValueError(msg)
            return normalized
        return value

    @model_validator(mode="after")
    def _validate_security_settings(self) -> Settings:
        """Fail fast on invalid security configuration."""
        jwt_secret_key_length = len(self.jwt_secret_key.get_secret_value())
        if jwt_secret_key_length < 32:
            msg = (
                f"Invalid JWT_SECRET_KEY: must be at least 32 characters "
                f"(got: {jwt_secret_key_length})"
            )
            raise ValueError(msg)
        if self.jwt_expiry_hours < 1:
            msg = (
                f"Invalid JWT_EXPIRY_HOURS: must be >= 1 (got: {self.jwt_expiry_hours})"
            )
            raise ValueError(msg)
        if self.jwt_expiry_hours > 720:
            logger.warning(
                "JWT_EXPIRY_HOURS is set to %d (>720 hours). "
                "Long-lived tokens increase the window of exposure "
                "if a token is compromised.",
                self.jwt_expiry_hours,
            )
        if self.session_max_lifetime_days < 1:
            msg = (
                "Invalid SESSION_MAX_LIFETIME_DAYS: must be >= 1 "
                f"(got: {self.session_max_lifetime_days})"
            )
            raise ValueError(msg)
        if self.session_max_lifetime_days > 365:
            logger.warning(
                "SESSION_MAX_LIFETIME_DAYS is set to %d (>365 days). "
                "Long-lived sessions increase exposure if a session is "
                "compromised.",
                self.session_max_lifetime_days,
            )
        if self.login_max_attempts < 1:
            msg = (
                "Invalid LOGIN_MAX_ATTEMPTS: must be >= 1 "
                f"(got: {self.login_max_attempts})"
            )
            raise ValueError(msg)
        if self.login_lockout_minutes < 1:
            msg = (
                "Invalid LOGIN_LOCKOUT_MINUTES: must be >= 1 "
                f"(got: {self.login_lockout_minutes})"
            )
            raise ValueError(msg)
        return self

    @field_validator(*_HEADER_SECRET_FIELDS)
    @classmethod
    def _validate_header_secret(
        cls, value: SecretStr, info: ValidationInfo
    ) -> SecretStr:
        """Reject a secret that is not a valid HTTP header value at startup.

        The value is rejected, never trimmed, and the message names only the
        variable. See docs/conventions.md (Secret Field Typing).
        """
        if _HEADER_VALUE.fullmatch(value.get_secret_value()) is None:
            variable = (info.field_name or "").upper()
            msg = (
                f"Invalid {variable}: must be printable ASCII without whitespace "
                "(it is sent as an HTTP header value)."
            )
            raise ValueError(msg)
        return value

    @field_validator("ibs_download_base_url")
    @classmethod
    def _validate_ibs_download_base_url(cls, value: str) -> str:
        """Validate and canonicalize IBS_DOWNLOAD_BASE_URL at startup.

        See docs/features/packages/ibs-product-release-detection.md
        (Download Origin and Repository Paths).
        """
        prefix = "Invalid IBS_DOWNLOAD_BASE_URL"

        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            msg = f"{prefix}: control characters are not permitted."
            raise ValueError(msg)
        if any(character.isspace() for character in value):
            msg = f"{prefix}: whitespace is not permitted."
            raise ValueError(msg)
        if "\\" in value:
            msg = f"{prefix}: backslashes are not permitted."
            raise ValueError(msg)
        if "%" in value:
            msg = f"{prefix}: percent-encoded values are not permitted."
            raise ValueError(msg)
        if "?" in value or "#" in value:
            msg = f"{prefix}: query or fragment components are not permitted."
            raise ValueError(msg)

        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            username = parsed.username
            password = parsed.password
        except ValueError:
            msg = f"{prefix}: malformed URL."
            raise ValueError(msg) from None

        if parsed.scheme.lower() != "https":
            msg = f"{prefix}: the scheme must be HTTPS."
            raise ValueError(msg)
        if not parsed.netloc or not hostname:
            msg = f"{prefix}: a non-empty hostname is required."
            raise ValueError(msg)
        if username is not None or password is not None:
            msg = f"{prefix}: user information is not permitted."
            raise ValueError(msg)

        try:
            port = parsed.port
        except ValueError:
            msg = f"{prefix}: the port is invalid."
            raise ValueError(msg) from None
        if port is None and parsed.netloc.endswith(":"):
            msg = f"{prefix}: the port is invalid."
            raise ValueError(msg)

        path = parsed.path
        if not path.startswith("/"):
            msg = f"{prefix}: the path must be absolute."
            raise ValueError(msg)
        if path == "/":
            return value[:-1]

        remainder = path[1:]
        if remainder.endswith("/"):
            remainder = remainder[:-1]
        if any(segment in ("", ".", "..") for segment in remainder.split("/")):
            msg = f"{prefix}: the path is not safe."
            raise ValueError(msg)

        return value[:-1] if path.endswith("/") else value

    @field_validator("ibs_api_url")
    @classmethod
    def _validate_ibs_api_url(cls, value: str) -> str:
        """Validate and canonicalize IBS_API_URL at startup.

        See docs/features/integrations/ibs-integration.md (Origins and
        Authentication).
        """
        return _validate_https_api_prefix(value, "IBS_API_URL")

    @field_validator("ibs_rabbitmq_url")
    @classmethod
    def _validate_ibs_rabbitmq_url(cls, value: str) -> str:
        """Validate IBS_RABBITMQ_URL at startup.

        AMQPS with a non-empty host and a valid port; no query or fragment,
        so URL parameters cannot override the consumer's fixed constants
        (heartbeat, TLS options); user information and a virtual host path
        are permitted. See docs/features/integrations/ibs-rabbitmq-integration.md
        (Configuration). The value may embed credentials: every message
        names only the variable.
        """
        prefix = "Invalid IBS_RABBITMQ_URL"

        if any(char.isspace() or not char.isprintable() for char in value):
            msg = f"{prefix}: malformed URL."
            raise ValueError(msg)
        if "?" in value or "#" in value:
            msg = f"{prefix}: query or fragment components are not permitted."
            raise ValueError(msg)

        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            msg = f"{prefix}: malformed URL."
            raise ValueError(msg) from None
        if port is None and parsed.netloc.endswith(":"):
            msg = f"{prefix}: malformed URL."
            raise ValueError(msg)

        if parsed.scheme.lower() != "amqps":
            msg = f"{prefix}: the scheme must be amqps."
            raise ValueError(msg)
        if not hostname:
            msg = f"{prefix}: a non-empty hostname is required."
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _validate_ibs_rabbitmq_reconnect(self) -> Settings:
        """Validate the IBS RabbitMQ reconnect delays at startup.

        Both are positive seconds and the cap is not below the initial
        delay (docs/features/integrations/ibs-rabbitmq-integration.md,
        Configuration). Every role fails startup on an invalid pair, even
        when the consumer is disabled.
        """
        if self.ibs_rabbitmq_reconnect_initial < 1:
            msg = (
                "Invalid IBS_RABBITMQ_RECONNECT_INITIAL: must be a positive "
                "number of seconds."
            )
            raise ValueError(msg)
        if self.ibs_rabbitmq_reconnect_max < 1:
            msg = (
                "Invalid IBS_RABBITMQ_RECONNECT_MAX: must be a positive number "
                "of seconds."
            )
            raise ValueError(msg)
        if self.ibs_rabbitmq_reconnect_max < self.ibs_rabbitmq_reconnect_initial:
            msg = (
                "Invalid IBS_RABBITMQ_RECONNECT_MAX: must be greater than or "
                "equal to IBS_RABBITMQ_RECONNECT_INITIAL."
            )
            raise ValueError(msg)
        return self

    @field_validator("ibs_username")
    @classmethod
    def _validate_ibs_username(cls, value: str) -> str:
        """Reject a non-empty IBS_USERNAME that cannot be a `keyId`.

        See docs/features/integrations/ibs-integration.md (IBS API
        Credentials). Empty means "not configured".
        """
        if value and not is_valid_ibs_username(value):
            raise ValueError(INVALID_USERNAME_MESSAGE)
        return value

    @field_validator("ibs_ssh_private_key")
    @classmethod
    def _validate_ibs_ssh_private_key(cls, value: SecretStr) -> SecretStr:
        """Reject a non-empty IBS_SSH_PRIVATE_KEY that is not one unencrypted
        Ed25519 OpenSSH key in its one-line base64 form.

        See docs/features/integrations/ibs-integration.md (IBS API
        Credentials). The message names only the variable.
        """
        encoded = value.get_secret_value()
        if encoded:
            load_ibs_ssh_private_key(encoded)
        return value

    @field_validator("git_clone_base_dir")
    @classmethod
    def _validate_git_clone_base_dir(cls, value: str) -> str:
        """Validate GIT_CLONE_BASE_DIR at startup.

        Clones are created and recursively deleted under this directory, so
        it must be absolute. See
        docs/features/platform/git-fetcher-infrastructure.md (Environment
        Configuration).
        """
        if "\x00" in value:
            msg = "Invalid GIT_CLONE_BASE_DIR: U+0000 is not permitted."
            raise ValueError(msg)
        if not PurePosixPath(value).is_absolute():
            msg = "Invalid GIT_CLONE_BASE_DIR: an absolute path is required."
            raise ValueError(msg)
        return value

    @field_validator("smelt_api_url")
    @classmethod
    def _validate_smelt_api_url(cls, value: str) -> str:
        """Validate and canonicalize SMELT_API_URL at startup.

        See docs/features/packages/product-catalog.md (SMELT Integration,
        Origin, Authentication, and Pagination).
        """
        return _validate_https_api_prefix(value, "SMELT_API_URL")

    @field_validator("aimaas_api_url")
    @classmethod
    def _validate_aimaas_api_url(cls, value: str) -> str:
        """Validate and canonicalize AIMAAS_API_URL at startup.

        See docs/features/packages/product-catalog.md (AIMAAS Integration,
        Origin, Authentication, and Pagination).
        """
        return _validate_https_api_prefix(value, "AIMAAS_API_URL")

    @model_validator(mode="after")
    def _validate_ibs_settings(self) -> Settings:
        """Warn if the IBS API credentials are not configured.

        See docs/features/integrations/ibs-integration.md (IBS API
        Credentials); the warning names only the empty settings.
        """
        empty = [
            name
            for name, configured in (
                ("IBS_USERNAME", bool(self.ibs_username)),
                (
                    "IBS_SSH_PRIVATE_KEY",
                    bool(self.ibs_ssh_private_key.get_secret_value()),
                ),
            )
            if not configured
        ]
        if empty:
            logger.warning(
                "IBS credentials not configured (%s empty). Credentialed IBS "
                "API operations will fail at runtime.",
                " / ".join(empty),
            )
        return self


settings = Settings()
