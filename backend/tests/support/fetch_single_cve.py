"""Shared harness of the on-demand single-CVE fetch tests: the database-free
publication `cve_service.trigger_on_demand_fetch()` and the
`fetch_single_cve` workflow `cve_service.run_fetch_single_cve()` with its
task wrapper (`app.tasks.cve_tasks`).

Consumers:

- `tests/test_services/test_cve_on_demand_publication.py` (format guard,
  token marker writer, fail-open publication, queue routing, the four
  `FetchDispatchResult` lists, and agreement with the source-status
  overlay);
- `tests/test_services/test_fetch_single_cve_workflow.py` (payload
  validation, the terminal matrix, token ownership, HTTP teardown, audit,
  and log privacy against real PostgreSQL and the worker Redis database);
- `tests/test_tasks/test_fetch_single_cve_task.py` (the synchronous wrapper
  and its async boundary: one `asyncio.run()` and one engine disposal per
  attempt, native retry, and task registration);
- `tests/test_api/test_cve_refetch.py`,
  `tests/test_api/test_ticket_freshness_refresh.py`, and
  `tests/test_services/test_ticket_freshness_composition.py` (the refetch
  endpoint and the create/associate freshness refresh).

Provided here:

- marker helpers that build the `fetch_pending:{cve_id}:{source}` key and
  the 43-character URL-safe token grammar literally, never through the
  module under test;
- `ScriptedRedis`, a deterministic substitute for the pending-marker client
  returned by `cve_service._new_redis_client()`: it records every command,
  answers `SET` per key (or raises), and can make `EVAL` or `aclose()`
  raise;
- `NoDatabaseAccess`, which records every SQL statement and pool checkout
  of any engine in the process while it is active;
- `assert_private_logs()`, the log-privacy assertion shared by every
  consumer;
- `FetchSingleHarness`, which installs recording substitutes for the
  workflow session factory, the isolated status sessions
  (`base_cve_fetcher.async_session_factory`), `task_publication.publish_task`,
  and the Ticket convergence drain, and owns committed `FetcherConfig`
  rows and token markers of one workflow test.

Test-only CVE fetchers come from `tests/support/cve_catch_up.py`
(`define_cve_fetcher()`), so consumers request `isolated_fetcher_registries`.
Nothing here computes an expectation with the module under test. All
identifiers are fictional.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Final, cast

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import Engine, event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.pool import Pool

from app.core.enums import CVESourceType
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import (
    base_cve_fetcher,
    cve_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.cve_service import FetchSingleRetry
from tests.support.cve_catch_up import (
    SOURCE,
    CVEProbe,
    Publications,
    RecordingSessions,
    define_cve_fetcher,
    delete_fetcher_rows,
    seed_fetcher_config,
)

TASK: Final = "fetch_single_cve"
"""The explicit registered task name, spelled literally."""

PENDING_TTL: Final = 600
"""The fixed marker TTL in seconds."""

TOKEN_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{43}")
"""`secrets.token_urlsafe(32)`: 43 URL-safe base64 characters."""

PAYLOAD_INVALID: Final = "fetch_single_cve_payload_invalid"
UNKNOWN_FETCHER: Final = "fetch_single_cve_unknown_fetcher"
TARGET_MISMATCH: Final = "fetch_single_cve_target_mismatch"
CONFIG_MISSING: Final = "fetch_single_cve_config_missing"
FETCHER_DISABLED: Final = "fetch_single_cve_fetcher_disabled"
CVE_MISSING: Final = "fetch_single_cve_cve_missing"
RETRY_SCHEDULED: Final = "fetch_single_cve_retry_scheduled"
COMPLETED: Final = "fetch_single_cve_completed"
FAILED: Final = "fetch_single_cve_failed"
MARKER_UNAVAILABLE: Final = "fetch_pending_marker_unavailable"
MARKER_OPERATION_FAILED: Final = "fetch_pending_marker_operation_failed"

SECRET_DETAIL: Final = "Example-Secret-Detail https://cve-source.example.invalid/item"
"""Exception text that must never reach a log record."""

LogEntry = dict[str, Any]


def pending_key(cve_id: str, source: str = SOURCE.value) -> str:
    return f"fetch_pending:{cve_id}:{source}"


def new_token() -> str:
    """A fresh well-formed ownership token."""
    return secrets.token_urlsafe(32)


def fictional_cve_id() -> str:
    """A well-formed CVE-ID that no committed row uses."""
    return f"CVE-2099-{uuid.uuid4().int % 10**9:09d}"


def events_named(logs: Iterable[Mapping[str, Any]], event_name: str) -> list[Any]:
    return [entry for entry in logs if entry["event"] == event_name]


def levels(logs: Iterable[Mapping[str, Any]], level: str) -> list[Any]:
    return [entry for entry in logs if entry["log_level"] == level]


# ---------------------------------------------------------------------------
# Log privacy
# ---------------------------------------------------------------------------

ALLOWED_LOG_KEYS: Final = frozenset(
    {
        "event",
        "log_level",
        "cve_id",
        "source",
        "fetcher_name",
        "cause",
        "invalid_fields",
        "stage",
        "outcome",
        "retries",
        "countdown",
        "operation",
        "status",
        "celery_task_id",
        "sources_failed",
        "trigger",
    }
)
"""Structured fields the on-demand paths may emit: canonical identifiers,
closed causes or class names, and correlation (logging.md, Secrets and PII
Discipline; Correlation IDs). `sources_failed` and `trigger` are the
canonical source list and closed workflow name of the preparation events
`cve_fetch_no_eligible_source` and `cve_fetch_publication_unconfirmed`."""


def assert_private_logs(logs: Iterable[Mapping[str, Any]], *forbidden: str) -> None:
    """Every record carries only allowed keys and never a URL or any of the
    `forbidden` fragments (tokens, exception text, payload values)."""
    for entry in logs:
        assert set(entry) <= ALLOWED_LOG_KEYS, entry
        rendered = repr(entry)
        assert "://" not in rendered, entry
        for fragment in forbidden:
            assert fragment not in rendered, entry


# ---------------------------------------------------------------------------
# Redis substitutes
# ---------------------------------------------------------------------------


class ScriptedRedis:
    """Deterministic substitute of the pending-marker Redis client.

    `set_results` maps a key to the `SET` answer (`True`/`None`) or an
    exception to raise; other keys answer `True`. `eval_error` and
    `aclose_error` make those calls raise. `commands` records every call
    as `(command, key, value-or-args)`.
    """

    def __init__(
        self,
        *,
        set_results: Mapping[str, bool | Exception | None] | None = None,
        eval_error: Exception | None = None,
        aclose_error: Exception | None = None,
    ) -> None:
        self.set_results = dict(set_results or {})
        self.eval_error = eval_error
        self.aclose_error = aclose_error
        self.commands: list[tuple[str, str, object]] = []
        self.set_options: list[dict[str, object]] = []
        self.closed = 0

    async def set(self, key: str, value: str, **options: object) -> bool | None:
        self.commands.append(("set", key, value))
        self.set_options.append(options)
        result = self.set_results.get(key, True)
        if isinstance(result, Exception):
            raise result
        return result

    async def eval(self, script: str, numkeys: int, key: str, *args: str) -> int:
        self.commands.append(("eval", key, args))
        if self.eval_error is not None:
            raise self.eval_error
        return 1

    async def aclose(self) -> None:
        self.closed += 1
        if self.aclose_error is not None:
            raise self.aclose_error

    def install(self, monkeypatch: pytest.MonkeyPatch) -> list[int]:
        """Return this client from `_new_redis_client()`; the returned
        one-element list counts the clients created."""
        created = [0]

        def factory() -> ScriptedRedis:
            created[0] += 1
            return self

        monkeypatch.setattr(cve_service, "_new_redis_client", factory)
        return created

    def values(self, command: str) -> list[object]:
        return [value for name, _, value in self.commands if name == command]


def forbid_redis(monkeypatch: pytest.MonkeyPatch) -> Callable[[], int]:
    """Make any pending-marker client creation fail the test; returns a
    counter of attempted creations."""
    attempts = [0]

    def factory() -> redis_asyncio.Redis:
        attempts[0] += 1
        raise AssertionError("no Redis client may be created")

    monkeypatch.setattr(cve_service, "_new_redis_client", factory)
    return lambda: attempts[0]


def count_redis_clients(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count the real pending-marker clients created (one-element list)."""
    real = cve_service._new_redis_client
    created = [0]

    def factory() -> redis_asyncio.Redis:
        created[0] += 1
        return real()

    monkeypatch.setattr(cve_service, "_new_redis_client", factory)
    return created


async def wait_until_expired(
    redis: redis_asyncio.Redis, key: str, *, within: float = 1.0
) -> None:
    """Poll until `key` no longer exists (Redis expires lazily on access)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while await redis.exists(key):
        assert loop.time() < deadline, f"{key} did not expire"
        await asyncio.sleep(0.01)


# ---------------------------------------------------------------------------
# Database-access observation
# ---------------------------------------------------------------------------


class NoDatabaseAccess:
    """Records every SQL statement and connection-pool checkout of every
    engine and pool in the process while active."""

    def __init__(self) -> None:
        self.statements: list[str] = []
        self.checkouts = 0

    def _statement(self, *args: Any) -> None:
        self.statements.append(str(args[2]))

    def _checkout(self, *args: Any) -> None:
        self.checkouts += 1

    def __enter__(self) -> NoDatabaseAccess:
        event.listen(Engine, "before_cursor_execute", self._statement)
        event.listen(Pool, "checkout", self._checkout)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        event.remove(Engine, "before_cursor_execute", self._statement)
        event.remove(Pool, "checkout", self._checkout)


# ---------------------------------------------------------------------------
# Workflow harness
# ---------------------------------------------------------------------------

DrainHook = Callable[[], Awaitable[None]]


@dataclass
class FetchSingleHarness:
    """The substitutes of one `run_fetch_single_cve` test sharing `events`.

    `sessions` is the workflow `session_factory` argument, `status` replaces
    `base_cve_fetcher.async_session_factory` (recorded with the `status:`
    prefix), `published` replaces `task_publication.publish_task`, and the
    real Ticket convergence drain appends `drain` and first awaits
    `on_drain` when set. `fetcher()` defines a probe and commits its
    `FetcherConfig`; `cleanup()` deletes every committed row it created.
    """

    factory: async_sessionmaker[AsyncSession]
    redis: redis_asyncio.Redis
    events: list[str]
    sessions: RecordingSessions
    status: RecordingSessions
    published: Publications
    on_drain: DrainHook | None = None
    names: list[str] = field(default_factory=list)

    async def fetcher(
        self,
        *,
        enabled: bool | None = True,
        source: CVESourceType = SOURCE,
        supports: bool = True,
    ) -> CVEProbe:
        """A registered test-only CVE fetcher; `enabled=None` commits no
        `FetcherConfig` row."""
        probe = define_cve_fetcher(self.events, source=source, supports=supports)
        if enabled is not None:
            self.names.append(probe.name)
            await seed_fetcher_config(self.factory, probe.name, enabled=enabled)
        return probe

    async def marker(
        self,
        cve_id: str,
        source: str = SOURCE.value,
        *,
        token: str | None = None,
        ttl_ms: int | None = None,
    ) -> str:
        """Write a token marker as the publisher does; `ttl_ms` then
        shortens its remaining TTL."""
        value = token or new_token()
        key = pending_key(cve_id, source)
        assert await self.redis.set(key, value, nx=True, ex=PENDING_TTL)
        if ttl_ms is not None:
            await self.redis.pexpire(key, ttl_ms)
        return value

    async def marker_value(self, cve_id: str, source: str = SOURCE.value) -> str | None:
        value: str | None = await self.redis.get(pending_key(cve_id, source))
        return value

    async def marker_ttl(self, cve_id: str, source: str = SOURCE.value) -> int:
        ttl: int = await self.redis.ttl(pending_key(cve_id, source))
        return ttl

    async def run(
        self,
        fetcher_name: object,
        cve_id: object,
        source: object,
        token: object,
        *,
        attempt: int = 0,
    ) -> FetchSingleRetry | None:
        return await cve_service.run_fetch_single_cve(
            fetcher_name,
            cve_id,
            source,
            token,
            attempt=attempt,
            session_factory=cast(async_sessionmaker[AsyncSession], self.sessions),
        )

    async def cleanup(self) -> None:
        await delete_fetcher_rows(self.factory, self.names)


def install_fetch_single_harness(
    monkeypatch: pytest.MonkeyPatch,
    factory: async_sessionmaker[AsyncSession],
    redis: redis_asyncio.Redis,
) -> FetchSingleHarness:
    """Install every `FetchSingleHarness` substitute."""
    events: list[str] = []
    harness = FetchSingleHarness(
        factory=factory,
        redis=redis,
        events=events,
        sessions=RecordingSessions(factory, events),
        status=RecordingSessions(factory, events, label="status:"),
        published=Publications(events),
    )
    harness.status.install(monkeypatch, base_cve_fetcher)
    monkeypatch.setattr(task_publication, "publish_task", harness.published)
    real_drain = ticket_convergence_publication.drain_ticket_convergence

    async def drain(session: AsyncSession) -> None:
        events.append("drain")
        if harness.on_drain is not None:
            await harness.on_drain()
        await real_drain(session)

    monkeypatch.setattr(
        ticket_convergence_publication, "drain_ticket_convergence", drain
    )
    return harness


async def ticket_audit_event_count(
    factory: async_sessionmaker[AsyncSession], ticket_id: uuid.UUID
) -> int:
    async with factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id == ticket_id)
        )
    return int(count or 0)
