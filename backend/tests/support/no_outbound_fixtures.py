"""The `no_outbound` pytest fixture.

A pytest plugin: consumers list `"tests.support.no_outbound_fixtures"`
in their module-level `pytest_plugins` and never import this module, so
that pytest imports it first and rewrites its assertions (the pattern of
`tests/support/ticket_mutation_fixtures.py`). The guard itself, its
exception, and its attempt record live in `tests/support/no_outbound.py`,
which consumers import directly; its module docstring documents the
guarded boundaries and the database allowance.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.support.no_outbound import DatabaseEndpoint, OutboundGuard


@pytest.fixture
def no_outbound(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> OutboundGuard:
    """Fail and record every outbound lookup, connection, or HTTP send.

    When the test already depends on the shared test engine (directly or
    through `db_session` and the factory fixtures), the guard allows only
    that engine's PostgreSQL endpoint, so database access keeps working
    whatever the fixture order. A test without database access allows no
    endpoint at all and never starts the database.
    """
    allowed: tuple[DatabaseEndpoint, ...] = ()
    if "_engine" in request.fixturenames:
        engine: AsyncEngine = request.getfixturevalue("_engine")
        allowed = (DatabaseEndpoint.from_url(engine.url),)
    return OutboundGuard(allowed).install(monkeypatch)
