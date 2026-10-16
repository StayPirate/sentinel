"""Pytest fixtures for `IBSClient` tests.

Load with `pytest_plugins = ["tests.support.ibs_client_fixtures"]` and
create clients with `tests.support.ibs_api.ibs_client()`. Every client is a
real `create_http_client` client: only the network transport is replaced by
the fake IBS API of `tests/support/ibs_api.py`, so the shared retry
transport, the authentication flow, and the cookie jar are the production
ones. Retry backoff sleeps are recorded, not awaited.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from app.services import http_client
from tests.support.ibs_api import IBSServer
from tests.support.ibs_keys import fictional_ed25519_key


@pytest.fixture
def sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Records the shared transport's retry backoff sleeps."""
    recorded = AsyncMock()
    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=recorded))
    return recorded


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch, sleep: AsyncMock) -> IBSServer:
    """The fake IBS API behind every client the test creates."""
    fake = IBSServer(public_key=fictional_ed25519_key().public_key())
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: fake.transport())
    return fake
