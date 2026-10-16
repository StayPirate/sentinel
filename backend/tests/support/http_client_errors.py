"""Shared HTTP client configuration errors for fetcher tests.

`create_http_client()` (backend/app/services/http_client.py) fails when a
proxy variable holds an unsupported URL (`ValueError`, naming the variable,
never the value; docs/features/platform/networking.md, Proxy Configuration)
or when `SUSE_CA_CERT_PATH` is corrupt (`TLSConfigurationError`, naming the
path; networking.md, TLS Trust Store Configuration). `break_shared_client()`
causes one of them through the real configuration, so the production factory
raises it. The proxy URL carries a fictional credential that no message may
contain.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

import pytest

from app.config import settings
from app.core.exceptions import TLSConfigurationError

ConfigurationError = Literal["invalid-proxy", "corrupt-ca"]

CONFIGURATION_ERRORS: Final[tuple[ConfigurationError, ...]] = (
    "invalid-proxy",
    "corrupt-ca",
)

PROXY_SECRET: Final = "fictional-proxy-secret"


@dataclass(frozen=True)
class BrokenClient:
    """What client creation raises, and a text its message names."""

    error: type[Exception]
    named: str


def break_shared_client(
    kind: ConfigurationError, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> BrokenClient:
    """Make every later `create_http_client()` call raise `kind`."""
    if kind == "invalid-proxy":
        monkeypatch.setenv(
            "HTTPS_PROXY",
            f"socks5://fictional-user:{PROXY_SECRET}@proxy.example.test:1080",
        )
        return BrokenClient(ValueError, "HTTPS_PROXY")
    corrupt = tmp_path / "corrupt-ca.crt"
    corrupt.write_text("this is not a certificate")
    monkeypatch.setattr(settings, "suse_ca_cert_path", str(corrupt))
    return BrokenClient(TLSConfigurationError, str(corrupt))
