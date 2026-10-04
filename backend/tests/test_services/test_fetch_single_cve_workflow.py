"""Tests for the `fetch_single_cve` workflow
`cve_service.run_fetch_single_cve()` (backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve —
  Task Classification and Orchestrator Behavior, including the terminal
  matrix, token ownership, Redis degradation, and resource lifecycle;
  Caller Validation Responsibility, "Background task (non-fetcher)" row;
  Transaction Ownership);
- docs/features/platform/cve-fetcher-infrastructure.md (`fetch_single`
  Signaling Convention; Retry Policy for `fetch_single` and its Enabled
  checks; Error Categorization; Isolated status commit);
- docs/features/platform/fetcher-infrastructure.md (`fetch_single()` and
  `catch_up()` Lifecycle: HTTP Client Ownership Rule and teardown);
- docs/features/tickets/ticket-audit-log.md (no Ticket event for dispatch
  outcomes) and docs/features/platform/logging.md (Secrets and PII
  Discipline; Correlation IDs);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch; Redis
  Strategy; Application-Owned Redis Operations; Concurrency Testing:
  explicit cleanup of committed rows);
- issue #799 decisions D4 (payload grammar), D5 (compare-by-token
  scripts), D6 (bounded outcomes and their levels), D7 (retry signal), and
  D8 (one `fetch_single_cve_failed` ERROR per terminal error).

The workflow runs against real PostgreSQL: its `session_factory` argument
and the isolated status sessions (`base_cve_fetcher.async_session_factory`)
are `RecordingSessions` over `real_session_factory`, sharing one ordered
event list with the publication substitute and the real Ticket convergence
drain (`tests/support/fetch_single_cve.py`). Committed CVE, Ticket, and
`FetcherConfig` rows are deleted explicitly at teardown. Markers live in the
worker Redis database (`redis_client` redirects the pending-marker URL);
Redis failures replace the `_new_redis_client` boundary. Test-only fetchers
are registered under `isolated_fetcher_registries`; their scripted
`fetch_single()` performs one fetch's writes: a `success` source status, an
optional Ticket convergence registration, and, last, an unflushed CVE
description change. The synchronous wrapper, the engine disposal, and the
cross-loop regression are covered in `tests/test_tasks/`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import SoftTimeLimitExceeded
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services import cve_service
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    ISOLATED_STATUS_CVE_MISSING_EVENT,
    ISOLATED_STATUS_WRITE_FAILED_EVENT,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.cve_ingest import PostIngestTasks, UpsertAction
from app.services.cve_service import FetchSingleRetry, _PendingMarker
from app.services.fetcher_execution import FetcherConfigMissingError
from app.services.ticket_convergence_registry import register_ticket_convergence
from tests.support.cve_catch_up import (
    CONVERGE,
    RESOLVE,
    SOURCE,
    CVEProbe,
    FakeHttpClient,
    Step,
    counters,
    fetcher_run_count,
    source_state,
)
from tests.support.fetch_single_cve import (
    COMPLETED,
    CONFIG_MISSING,
    CVE_MISSING,
    FAILED,
    FETCHER_DISABLED,
    MARKER_OPERATION_FAILED,
    PAYLOAD_INVALID,
    PENDING_TTL,
    RETRY_SCHEDULED,
    SECRET_DETAIL,
    TARGET_MISMATCH,
    UNKNOWN_FETCHER,
    FetchSingleHarness,
    ScriptedRedis,
    assert_private_logs,
    count_redis_clients,
    events_named,
    fictional_cve_id,
    forbid_redis,
    install_fetch_single_harness,
    levels,
    new_token,
    pending_key,
    ticket_audit_event_count,
    wait_until_expired,
)
from tests.support.suse_cvss_races import CommittedWorld

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NVD = SOURCE.value
_DESCRIPTION = "Example refreshed description"
_CPE = "cpe:2.3:a:example_vendor:example_product:1.0:*:*:*:*:*:*:*"


class _CommitFailureError(Exception):
    """An injected commit failure."""


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://cve-source.example.invalid/item")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {status_code} {SECRET_DETAIL}", request=request, response=response
    )


_RETRYABLE_ERRORS = [
    pytest.param(lambda: httpx.ConnectError(SECRET_DETAIL), id="connect-error"),
    pytest.param(lambda: httpx.ReadTimeout(SECRET_DETAIL), id="read-timeout"),
    pytest.param(lambda: _http_status_error(503), id="http-503"),
    pytest.param(lambda: _http_status_error(429), id="http-429"),
]

_NON_RETRYABLE_ERRORS = [
    pytest.param(lambda: ValueError(SECRET_DETAIL), id="value-error"),
    pytest.param(lambda: _http_status_error(404), id="http-404"),
    pytest.param(lambda: _http_status_error(403), id="http-403"),
]

_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]


def _context(fetcher_name: str, cve_id: str, source: str = NVD) -> dict[str, str]:
    return {"fetcher_name": fetcher_name, "cve_id": cve_id, "source": source}


# ---------------------------------------------------------------------------
# Scripted per-CVE writes
# ---------------------------------------------------------------------------


async def _write(
    session: AsyncSession, cve_id: str, *, register: uuid.UUID | None = None
) -> None:
    """One fetch's writes; the description change stays unflushed."""
    cve = (await session.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one()
    await cve_service.record_source_status(
        session, cve.id, SOURCE, CVESourceFetchStatus.SUCCESS
    )
    if register is not None:
        register_ticket_convergence(session, register)
    cve.description = _DESCRIPTION


def _succeeds(
    *,
    register: uuid.UUID | None = None,
    post_ingest: PostIngestTasks | None = None,
    before: Callable[[], Awaitable[None]] | None = None,
) -> Step:
    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        if before is not None:
            await before()
        await _write(session, cve_id, register=register)
        return CVEFetchResult(action=UpsertAction.UPDATED, post_ingest=post_ingest)

    return step


def _raises(
    error: BaseException,
    *,
    register: uuid.UUID | None = None,
    before: Callable[[], Awaitable[None]] | None = None,
) -> Step:
    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        if before is not None:
            await before()
        await _write(session, cve_id, register=register)
        raise error

    return step


def _flush_fails() -> Step:
    """Writes, then adds a duplicate CVE row that the caller's flush rejects."""

    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        await _write(session, cve_id)
        session.add(CVE(cve_id=cve_id))
        return CVEFetchResult(action=UpsertAction.UPDATED, post_ingest=None)

    return step


def _handoff(ticket_id: uuid.UUID) -> PostIngestTasks:
    return PostIngestTasks(
        ticket_id=str(ticket_id),
        cpe_matches=[],
        affected_cpes=[_CPE],
        vendor_products=[],
        resolved_packages=["example-package"],
    )


def _use_http_client(probe: CVEProbe) -> Callable[[], Awaitable[None]]:
    """A `before` hook touching the lazy `http_client` of the fetching
    instance, as a real `fetch_single()` does."""

    async def before() -> None:
        assert probe.fetcher.http_client is not None

    return before


async def _description(
    factory: async_sessionmaker[AsyncSession], cve_id: uuid.UUID
) -> str | None:
    async with factory() as session:
        value: str | None = await session.scalar(
            select(CVE.description).where(CVE.id == cve_id)
        )
    return value


async def _seed_success(factory: async_sessionmaker[AsyncSession], cve: CVE) -> None:
    async with factory() as session:
        await cve_service.record_source_status(
            session, cve.id, SOURCE, CVESourceFetchStatus.SUCCESS
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def harness(
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FetchSingleHarness]:
    installed = install_fetch_single_harness(
        monkeypatch, real_session_factory, redis_client
    )
    try:
        yield installed
    finally:
        await installed.cleanup()


@pytest.fixture
def http_client(monkeypatch: pytest.MonkeyPatch) -> FakeHttpClient:
    """The client every lazy `http_client` access creates."""
    client = FakeHttpClient(AsyncMock())
    monkeypatch.setattr(base_fetcher_module, "create_http_client", lambda **_: client)
    return client


@dataclass
class _Target:
    """A committed published CVE and its Ticket."""

    cve: CVE
    ticket: Ticket

    @property
    def cve_id(self) -> str:
        return self.cve.cve_id


async def _target(world: CommittedWorld) -> _Target:
    cve = await world.cve()
    return _Target(cve, await world.ticket(cve_id=cve.id))


# ---------------------------------------------------------------------------
# Outcome scenarios shared by the ownership, teardown, audit, and privacy
# tests
# ---------------------------------------------------------------------------


@dataclass
class _Scenario:
    """One arranged attempt: its payload values, attempt index, and the
    expected exception type (`None` for a normal return)."""

    fetcher_name: str
    cve_id: str
    target: _Target | None
    probe: CVEProbe | None
    attempt: int = 0
    raises: type[BaseException] | None = None

    async def run(
        self, harness: FetchSingleHarness, token: str
    ) -> FetchSingleRetry | None:
        if self.raises is None:
            return await harness.run(
                self.fetcher_name, self.cve_id, NVD, token, attempt=self.attempt
            )
        with pytest.raises(self.raises):
            await harness.run(
                self.fetcher_name, self.cve_id, NVD, token, attempt=self.attempt
            )
        return None


_OUTCOMES = [
    "success",
    "unknown-fetcher",
    "target-mismatch",
    "config-missing",
    "disabled",
    "cve-missing",
    "not-in-source",
    "retry",
    "exhausted",
    "non-retryable",
    "commit-failure",
    "post-commit-failure",
]


async def _arrange(
    outcome: str,
    harness: FetchSingleHarness,
    world: CommittedWorld,
    *,
    use_http_client: bool = False,
) -> _Scenario:
    """Arrange `outcome` for a committed CVE with a Ticket (none for
    `cve-missing`). Exceptions carry `SECRET_DETAIL` as their text."""
    if outcome == "unknown-fetcher":
        target = await _target(world)
        return _Scenario("fictional_unknown_fetcher", target.cve_id, target, None)
    if outcome == "target-mismatch":
        target = await _target(world)
        probe = await harness.fetcher(source=CVESourceType.GHSA)
        return _Scenario(probe.name, target.cve_id, target, probe)
    if outcome == "config-missing":
        target = await _target(world)
        probe = await harness.fetcher(enabled=None)
        return _Scenario(
            probe.name, target.cve_id, target, probe, raises=FetcherConfigMissingError
        )
    if outcome == "disabled":
        target = await _target(world)
        probe = await harness.fetcher(enabled=False)
        return _Scenario(probe.name, target.cve_id, target, probe)
    if outcome == "cve-missing":
        probe = await harness.fetcher()
        return _Scenario(probe.name, fictional_cve_id(), None, probe)

    target = await _target(world)
    probe = await harness.fetcher()
    before = _use_http_client(probe) if use_http_client else None
    scenario = _Scenario(probe.name, target.cve_id, target, probe)
    if outcome == "success":
        probe.step = _succeeds(register=target.ticket.id, before=before)
    elif outcome == "not-in-source":
        probe.step = _raises(CVENotInSource(), register=target.ticket.id, before=before)
    elif outcome in {"retry", "exhausted"}:
        error = httpx.ConnectError(SECRET_DETAIL)
        probe.step = _raises(error, register=target.ticket.id, before=before)
        if outcome == "exhausted":
            scenario.attempt = 3
            scenario.raises = httpx.ConnectError
    elif outcome == "non-retryable":
        probe.step = _raises(ValueError(SECRET_DETAIL), before=before)
        scenario.raises = ValueError
    elif outcome == "commit-failure":
        probe.step = _succeeds(register=target.ticket.id, before=before)
        harness.sessions.failures["commit"] = _CommitFailureError(SECRET_DETAIL)
        scenario.raises = _CommitFailureError
    else:
        assert outcome == "post-commit-failure"
        probe.step = _succeeds(register=target.ticket.id, before=before)

        async def drain_fails() -> None:
            raise RuntimeError(SECRET_DETAIL)

        harness.on_drain = drain_fails
        scenario.raises = RuntimeError
    return scenario


# ---------------------------------------------------------------------------
# Payload validation (Caller Validation Responsibility: background task)
# ---------------------------------------------------------------------------

_WELL_FORMED_NAME = "fictional_valid_fetcher"

_MALFORMED_FIELDS = [
    pytest.param("fetcher_name", 42, id="fetcher-name-integer"),
    pytest.param("fetcher_name", None, id="fetcher-name-none"),
    pytest.param("fetcher_name", "Fictional_Fetcher", id="fetcher-name-uppercase"),
    pytest.param("fetcher_name", "f" * 101, id="fetcher-name-101-characters"),
    pytest.param("fetcher_name", "", id="fetcher-name-empty"),
    pytest.param("fetcher_name", "1fictional", id="fetcher-name-leading-digit"),
    pytest.param("fetcher_name", "fictional-fetcher", id="fetcher-name-hyphen"),
    pytest.param("cve_id", "cve-2099-0001", id="cve-id-lowercase"),
    pytest.param("cve_id", "CVE-2099-" + "1" * 12, id="cve-id-overlength"),
    pytest.param("cve_id", None, id="cve-id-none"),
    pytest.param("source", "fictional_source", id="source-unknown"),
    pytest.param("source", "NVD", id="source-uppercase"),
    pytest.param("source", 7, id="source-integer"),
    pytest.param("token", "fictional-short-token", id="token-short"),
    pytest.param("token", "!" * 43, id="token-wrong-alphabet"),
    pytest.param("token", "A" * 44, id="token-44-characters"),
    pytest.param("token", None, id="token-none"),
]


@pytest.mark.integration
class TestPayloadValidation:
    @pytest.mark.parametrize(("field", "value"), _MALFORMED_FIELDS)
    async def test_malformed_field_logs_one_warning_and_skips_without_fetch(
        self,
        harness: FetchSingleHarness,
        monkeypatch: pytest.MonkeyPatch,
        field: str,
        value: object,
    ) -> None:
        """A bounded skip: one WARNING naming only the field, no fetch,
        session, status write, or retry. The matching marker is owner-
        deleted only when CVE-ID, source, and token are well-formed."""
        cve_id = fictional_cve_id()
        token = await harness.marker(cve_id)
        payload: dict[str, object] = {
            "fetcher_name": _WELL_FORMED_NAME,
            "cve_id": cve_id,
            "source": NVD,
            "token": token,
        }
        payload[field] = value
        created = count_redis_clients(monkeypatch)

        with capture_logs() as logs:
            outcome = await harness.run(
                payload["fetcher_name"],
                payload["cve_id"],
                payload["source"],
                payload["token"],
            )

        assert outcome is None
        assert logs == [
            {
                "event": PAYLOAD_INVALID,
                "log_level": "warning",
                "invalid_fields": [field],
            }
        ]
        assert harness.sessions.opened == []
        assert harness.status.opened == []
        assert harness.published.calls == []
        if field == "fetcher_name":
            assert await harness.marker_value(cve_id) is None
            assert created == [1]
        else:
            assert await harness.marker_value(cve_id) == token
            assert 0 < await harness.marker_ttl(cve_id) <= PENDING_TTL
            assert created == [0]

    async def test_every_malformed_field_is_named_in_a_fixed_order(
        self, harness: FetchSingleHarness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs:
            outcome = await harness.run(
                "Fictional-Secret-Name", "cve-2099-0001", "fictional_source", "x"
            )

        assert outcome is None
        assert logs == [
            {
                "event": PAYLOAD_INVALID,
                "log_level": "warning",
                "invalid_fields": ["fetcher_name", "cve_id", "source", "token"],
            }
        ]
        assert attempts() == 0

    async def test_malformed_payload_warning_is_correlated_by_celery_task_id(
        self, harness: FetchSingleHarness
    ) -> None:
        celery_task_id = str(uuid.uuid4())
        secret_name = "Fictional-Secret-Name"
        token = new_token()
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                await harness.run(secret_name, fictional_cve_id(), NVD, token)
        finally:
            unbind_contextvars("celery_task_id")

        assert logs == [
            {
                "event": PAYLOAD_INVALID,
                "log_level": "warning",
                "invalid_fields": ["fetcher_name"],
                "celery_task_id": celery_task_id,
            }
        ]
        assert_private_logs(logs, secret_name, token)

    async def test_fetcher_name_of_100_characters_is_well_formed(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        """The `FetcherConfig.fetcher_name` length bound is inclusive: a
        100-character unregistered name is the unknown-target row."""
        target = await _target(world)
        name = "f" * 100
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs:
            await harness.run(name, target.cve_id, NVD, token)

        assert [entry["event"] for entry in logs] == [UNKNOWN_FETCHER]
        assert await harness.marker_value(target.cve_id) is None


# ---------------------------------------------------------------------------
# Bounded orchestration outcomes (never invoke the external fetcher)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBoundedOutcomes:
    @pytest.mark.parametrize("kind", ["unknown", "deregistered"])
    async def test_unknown_or_deregistered_fetcher_logs_error_and_releases_marker(
        self, world: CommittedWorld, harness: FetchSingleHarness, kind: str
    ) -> None:
        target = await _target(world)
        if kind == "deregistered":
            probe = await harness.fetcher()
            FETCHER_REGISTRY.pop(probe.name)
            _CVE_SOURCE_TYPE_MAP.pop(SOURCE)
            name = probe.name
        else:
            name = "fictional_unknown_fetcher"
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs:
            outcome = await harness.run(name, target.cve_id, NVD, token)

        assert outcome is None
        assert logs == [
            {
                "event": UNKNOWN_FETCHER,
                "log_level": "error",
                **_context(name, target.cve_id),
            }
        ]
        assert await harness.marker_value(target.cve_id) is None
        assert harness.sessions.opened == []
        assert harness.status.opened == []
        assert await source_state(harness.factory, target.cve.id) is None

    @pytest.mark.parametrize(
        "kind", ["source-mismatch", "not-fetch-single-capable", "not-a-cve-fetcher"]
    )
    async def test_mismatched_target_logs_error_and_releases_marker_without_fetch(
        self, world: CommittedWorld, harness: FetchSingleHarness, kind: str
    ) -> None:
        target = await _target(world)
        source = NVD
        fetched: list[str] = []
        if kind == "source-mismatch":
            probe = await harness.fetcher(source=CVESourceType.NVD)
            name, source = probe.name, CVESourceType.GHSA.value
            fetched = probe.fetched
        elif kind == "not-fetch-single-capable":
            probe = await harness.fetcher(supports=False)
            name, fetched = probe.name, probe.fetched
        else:
            plain_name = f"test_plain_fetcher_{uuid.uuid4().hex[:12]}"

            class _PlainFetcher(BaseFetcher):
                name = plain_name
                description = "Test-only non-CVE fetcher"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    raise AssertionError("never executed")

            name = _PlainFetcher.name
            assert FETCHER_REGISTRY[name] is _PlainFetcher
        token = await harness.marker(target.cve_id, source)

        with capture_logs() as logs:
            outcome = await harness.run(name, target.cve_id, source, token)

        assert outcome is None
        assert logs == [
            {
                "event": TARGET_MISMATCH,
                "log_level": "error",
                **_context(name, target.cve_id, source),
            }
        ]
        assert await harness.marker_value(target.cve_id, source) is None
        assert fetched == []
        assert harness.sessions.opened == []
        assert harness.status.opened == []

    async def test_missing_fetcher_config_raises_after_error_and_marker_release(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher(enabled=None)
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(FetcherConfigMissingError):
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert logs == [
            {
                "event": CONFIG_MISSING,
                "log_level": "error",
                **_context(probe.name, target.cve_id),
            }
        ]
        assert await harness.marker_value(target.cve_id) is None
        assert probe.fetched == []
        assert len(harness.sessions.opened) == 1
        assert harness.status.opened == []
        assert await source_state(harness.factory, target.cve.id) is None

    async def test_fetcher_disabled_after_preparation_logs_info_and_skips(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher(enabled=False)
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs:
            outcome = await harness.run(probe.name, target.cve_id, NVD, token)

        assert outcome is None
        assert logs == [
            {
                "event": FETCHER_DISABLED,
                "log_level": "info",
                **_context(probe.name, target.cve_id),
            }
        ]
        assert await harness.marker_value(target.cve_id) is None
        assert probe.fetched == []
        # The read-only precheck transaction is ended; nothing else runs.
        assert harness.events == ["rollback"]
        assert harness.status.opened == []
        assert await source_state(harness.factory, target.cve.id) is None

    async def test_missing_cve_logs_warning_and_skips(
        self, harness: FetchSingleHarness
    ) -> None:
        probe = await harness.fetcher()
        cve_id = fictional_cve_id()
        token = await harness.marker(cve_id)

        with capture_logs() as logs:
            outcome = await harness.run(probe.name, cve_id, NVD, token)

        assert outcome is None
        assert logs == [
            {
                "event": CVE_MISSING,
                "log_level": "warning",
                **_context(probe.name, cve_id),
            }
        ]
        assert await harness.marker_value(cve_id) is None
        assert probe.fetched == []
        assert harness.events == ["rollback"]
        assert harness.status.opened == []


# ---------------------------------------------------------------------------
# Success: flush, then the finalizer's sole commit, then marker release
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSuccess:
    async def test_success_flushes_finalizes_once_then_releases_the_marker(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        handoff = _handoff(target.ticket.id)
        probe.step = _succeeds(register=target.ticket.id, post_ingest=handoff)
        token = await harness.marker(target.cve_id)
        held_during_finalization: list[str | None] = []

        async def on_drain() -> None:
            held_during_finalization.append(await harness.marker_value(target.cve_id))

        harness.on_drain = on_drain

        with capture_logs() as logs:
            outcome = await harness.run(probe.name, target.cve_id, NVD, token)

        assert outcome is None
        assert probe.fetched == [target.cve_id]
        assert harness.events == [
            "rollback",
            "fetch_single",
            "flush",
            "commit_and_dispatch",
            "commit",
            "drain",
            f"publish:{CONVERGE}",
            f"publish:{RESOLVE}",
        ]
        assert probe.flushed_at_finalization == [True]
        assert harness.published.published(CONVERGE) == [
            {"ticket_id": str(target.ticket.id)}
        ]
        assert len(harness.published.published(RESOLVE)) == 1
        # The marker is released only after finalization.
        assert held_during_finalization == [token]
        assert await harness.marker_value(target.cve_id) is None
        # Committed and visible from a fresh session.
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _description(harness.factory, target.cve.id) == _DESCRIPTION
        # One session and fetcher instance; no FetcherRun metric or row.
        assert len(harness.sessions.opened) == 1
        assert len(probe.instances) == 1
        assert counters(probe.fetcher) == (0, 0, 0, 0)
        assert await fetcher_run_count(harness.factory, probe.name) == 0
        assert harness.status.opened == []
        assert logs == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "updated",
                **_context(probe.name, target.cve_id),
            }
        ]


# ---------------------------------------------------------------------------
# CVENotInSource, retry, and pre-finalization failures
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPreFinalizationOutcomes:
    async def test_not_in_source_rolls_back_writes_isolated_missing_and_releases(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _raises(CVENotInSource(), register=target.ticket.id)
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs:
            outcome = await harness.run(probe.name, target.cve_id, NVD, token)

        assert outcome is None
        assert harness.events == [
            "rollback",
            "fetch_single",
            "rollback",
            "status:commit",
        ]
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert await _description(harness.factory, target.cve.id) is None
        assert harness.published.calls == []
        assert await harness.marker_value(target.cve_id) is None
        assert logs == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "missing",
                **_context(probe.name, target.cve_id),
            }
        ]

    @pytest.mark.parametrize(
        ("make_error", "attempt", "countdown"),
        [
            *(
                pytest.param(*error.values, 0, 5, id=f"{error.id}-attempt-0")
                for error in _RETRYABLE_ERRORS
            ),
            pytest.param(
                *_RETRYABLE_ERRORS[0].values, 1, 10, id="connect-error-attempt-1"
            ),
            pytest.param(
                *_RETRYABLE_ERRORS[0].values, 2, 20, id="connect-error-attempt-2"
            ),
        ],
    )
    async def test_retryable_exception_within_budget_renews_marker_and_signals_retry(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        make_error: Callable[[], Exception],
        attempt: int,
        countdown: int,
    ) -> None:
        """Rolled back with nothing committed; the marker, whose TTL ran
        down during the attempt, is renewed to 600 seconds before the retry
        signal."""
        target = await _target(world)
        probe = await harness.fetcher()
        error = make_error()
        token = await harness.marker(target.cve_id)

        async def time_passes() -> None:
            await harness.redis.pexpire(pending_key(target.cve_id), 60000)

        probe.step = _raises(error, register=target.ticket.id, before=time_passes)

        with capture_logs() as logs:
            outcome = await harness.run(
                probe.name, target.cve_id, NVD, token, attempt=attempt
            )

        assert outcome == FetchSingleRetry(countdown=countdown, cause=error)
        assert outcome is not None
        assert outcome.cause is error
        assert harness.events == ["rollback", "fetch_single", "rollback"]
        assert harness.status.opened == []
        assert harness.published.calls == []
        assert await source_state(harness.factory, target.cve.id) is None
        assert await _description(harness.factory, target.cve.id) is None
        assert await harness.marker_value(target.cve_id) == token
        assert PENDING_TTL - 5 < await harness.marker_ttl(target.cve_id) <= PENDING_TTL
        assert logs == [
            {
                "event": RETRY_SCHEDULED,
                "log_level": "warning",
                "cause": type(error).__name__,
                "retries": attempt,
                "countdown": countdown,
                **_context(probe.name, target.cve_id),
            }
        ]
        assert_private_logs(logs, token, SECRET_DETAIL)

    @pytest.mark.parametrize("make_error", _RETRYABLE_ERRORS[:1])
    async def test_retryable_exception_after_exhaustion_writes_failure_and_raises(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        make_error: Callable[[], Exception],
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        error = make_error()
        probe.step = _raises(error, register=target.ticket.id)
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await harness.run(probe.name, target.cve_id, NVD, token, attempt=3)

        assert raised.value is error
        assert harness.events == [
            "rollback",
            "fetch_single",
            "rollback",
            "status:commit",
        ]
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _description(harness.factory, target.cve.id) is None
        assert harness.published.calls == []
        assert await harness.marker_value(target.cve_id) is None
        assert logs == [
            {
                "event": FAILED,
                "log_level": "error",
                "stage": "pre_finalization",
                "cause": type(error).__name__,
                "retries": 3,
                **_context(probe.name, target.cve_id),
            }
        ]

    @pytest.mark.parametrize("make_error", _NON_RETRYABLE_ERRORS)
    async def test_non_retryable_exception_writes_failure_releases_and_raises(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        make_error: Callable[[], Exception],
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        error = make_error()
        probe.step = _raises(error, register=target.ticket.id)
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert raised.value is error
        assert harness.events == [
            "rollback",
            "fetch_single",
            "rollback",
            "status:commit",
        ]
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert harness.published.calls == []
        assert await harness.marker_value(target.cve_id) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert logs == [
            {
                "event": FAILED,
                "log_level": "error",
                "stage": "pre_finalization",
                "cause": type(error).__name__,
                "retries": 0,
                **_context(probe.name, target.cve_id),
            }
        ]

    async def test_non_retryable_failure_writes_no_status_for_a_deleted_cve(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        cve = await world.cve()
        probe = await harness.fetcher()
        error = ValueError(SECRET_DETAIL)

        async def delete_cve() -> None:
            async with harness.factory() as session:
                await session.execute(delete(CVE).where(CVE.id == cve.id))
                await session.commit()

        async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
            await delete_cve()
            raise error

        probe.step = step
        token = await harness.marker(cve.cve_id)

        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match="Example-Secret-Detail") as raised,
        ):
            await harness.run(probe.name, cve.cve_id, NVD, token)

        assert raised.value is error
        assert harness.events == ["rollback", "fetch_single", "rollback"]
        assert len(harness.status.opened) == 1
        assert len(events_named(logs, ISOLATED_STATUS_CVE_MISSING_EVENT)) == 1
        assert await source_state(harness.factory, cve.id) is None
        assert await harness.marker_value(cve.cve_id) is None
        assert [entry["event"] for entry in levels(logs, "error")] == [FAILED]

    async def test_flush_failure_is_a_pre_finalization_failure(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        """A non-retryable flush failure (unique violation) rolls back,
        writes an isolated `failure`, and propagates."""
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _flush_fails()
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(IntegrityError):
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert harness.events == [
            "rollback",
            "fetch_single",
            "flush",
            "rollback",
            "status:commit",
        ]
        assert probe.flushed_at_finalization == []
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await harness.marker_value(target.cve_id) is None
        [failed] = events_named(logs, FAILED)
        assert failed["stage"] == "pre_finalization"
        assert failed["cause"] == "IntegrityError"

    async def test_retryable_flush_failure_signals_retry(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        """Retry classification applies to the flush: an injected
        retryable flush failure requests the first retry."""
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _succeeds()
        error = httpx.ReadTimeout(SECRET_DETAIL)
        harness.sessions.failures["flush"] = error
        token = await harness.marker(target.cve_id)

        outcome = await harness.run(probe.name, target.cve_id, NVD, token)

        assert outcome == FetchSingleRetry(countdown=5, cause=error)
        assert harness.events == ["rollback", "fetch_single", "flush", "rollback"]
        assert await source_state(harness.factory, target.cve.id) is None
        assert await harness.marker_value(target.cve_id) == token


# ---------------------------------------------------------------------------
# Commit and post-commit failures (outside the pre-finalization handler)
# ---------------------------------------------------------------------------


def _ambiguous_commit(session: AsyncSession) -> None:
    """Make the (recorded) commit succeed, then raise: an ambiguous
    outcome whose commit actually happened."""
    committed = session.commit

    async def commit() -> None:
        await committed()
        raise _CommitFailureError(SECRET_DETAIL)

    setattr(session, "commit", commit)  # noqa: B010


@pytest.mark.integration
class TestFinalizationFailures:
    @pytest.mark.parametrize("kind", ["definite", "ambiguous"])
    async def test_commit_exception_propagates_without_isolated_status(
        self, world: CommittedWorld, harness: FetchSingleHarness, kind: str
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _succeeds(
            register=target.ticket.id, post_ingest=_handoff(target.ticket.id)
        )
        if kind == "definite":
            harness.sessions.failures["commit"] = _CommitFailureError(SECRET_DETAIL)
        else:
            harness.sessions.hooks.append(_ambiguous_commit)
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(_CommitFailureError):
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert harness.events == [
            "rollback",
            "fetch_single",
            "flush",
            "commit_and_dispatch",
            "commit",
        ]
        assert harness.status.opened == []
        assert harness.published.calls == []
        state = await source_state(harness.factory, target.cve.id)
        if kind == "definite":
            assert state is None
        else:
            # The committed success is kept, never reclassified.
            assert state is not None
            assert state.status == CVESourceFetchStatus.SUCCESS
        assert await harness.marker_value(target.cve_id) is None
        assert await fetcher_run_count(harness.factory, probe.name) == 0
        assert logs == [
            {
                "event": FAILED,
                "log_level": "error",
                "stage": "finalization",
                "cause": "_CommitFailureError",
                "retries": 0,
                **_context(probe.name, target.cve_id),
            }
        ]

    async def test_post_commit_exception_keeps_committed_success(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _succeeds(register=target.ticket.id)
        error = RuntimeError(SECRET_DETAIL)

        async def drain_fails() -> None:
            raise error

        harness.on_drain = drain_fails
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await harness.run(probe.name, target.cve_id, NVD, token, attempt=1)

        assert raised.value is error
        assert harness.events == [
            "rollback",
            "fetch_single",
            "flush",
            "commit_and_dispatch",
            "commit",
            "drain",
        ]
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _description(harness.factory, target.cve.id) == _DESCRIPTION
        assert harness.status.opened == []
        assert await harness.marker_value(target.cve_id) is None
        assert logs == [
            {
                "event": FAILED,
                "log_level": "error",
                "stage": "finalization",
                "cause": "RuntimeError",
                "retries": 1,
                **_context(probe.name, target.cve_id),
            }
        ]


# ---------------------------------------------------------------------------
# Control signals: propagate without forced cleanup
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestControlSignals:
    @pytest.mark.parametrize("make_signal", _SIGNALS)
    async def test_signal_from_fetch_propagates_and_keeps_the_marker(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        http_client: FakeHttpClient,
        make_signal: Callable[[], BaseException],
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        signal = make_signal()
        probe.step = _raises(
            signal, register=target.ticket.id, before=_use_http_client(probe)
        )
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert raised.value is signal
        assert harness.events == ["rollback", "fetch_single"]
        assert await harness.marker_value(target.cve_id) == token
        assert harness.status.opened == []
        assert await source_state(harness.factory, target.cve.id) is None
        http_client.aclose.assert_awaited_once_with()
        assert probe.fetcher._http_client is None
        assert levels(logs, "error") == []

    @pytest.mark.parametrize("make_signal", _SIGNALS)
    async def test_signal_from_commit_propagates_and_keeps_the_marker(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        make_signal: Callable[[], BaseException],
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _succeeds()
        signal = make_signal()
        harness.sessions.failures["commit"] = signal
        token = await harness.marker(target.cve_id)

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert raised.value is signal
        assert await harness.marker_value(target.cve_id) == token
        assert harness.status.opened == []
        assert levels(logs, "error") == []

    async def test_marker_of_a_killed_attempt_expires_and_is_never_recreated(
        self, world: CommittedWorld, harness: FetchSingleHarness
    ) -> None:
        """TTL recovery: an interrupted attempt leaves its marker; once it
        expires, a later delivery with the same token runs normally and
        recreates nothing."""
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _raises(SoftTimeLimitExceeded())
        token = await harness.marker(target.cve_id)
        key = pending_key(target.cve_id)
        with pytest.raises(SoftTimeLimitExceeded):
            await harness.run(probe.name, target.cve_id, NVD, token)
        assert await harness.marker_value(target.cve_id) == token

        await harness.redis.pexpire(key, 1)
        await wait_until_expired(harness.redis, key)
        probe.step = _succeeds()
        outcome = await harness.run(probe.name, target.cve_id, NVD, token, attempt=1)

        assert outcome is None
        assert await harness.redis.exists(key) == 0
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS


# ---------------------------------------------------------------------------
# Isolated status-write failure
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIsolatedStatusWriteFailure:
    @pytest.mark.parametrize("kind", ["not-in-source", "non-retryable", "exhausted"])
    async def test_status_write_error_is_suppressed_and_keeps_the_original_outcome(
        self, world: CommittedWorld, harness: FetchSingleHarness, kind: str
    ) -> None:
        target = await _target(world)
        await _seed_success(harness.factory, target.cve)
        before = await source_state(harness.factory, target.cve.id)
        probe = await harness.fetcher()
        error: Exception = {
            "not-in-source": CVENotInSource(),
            "non-retryable": ValueError(SECRET_DETAIL),
            "exhausted": httpx.ConnectError(SECRET_DETAIL),
        }[kind]
        probe.step = _raises(error)
        harness.status.failures["commit"] = RuntimeError("fictional status failure")
        token = await harness.marker(target.cve_id)
        attempt = 3 if kind == "exhausted" else 0

        with capture_logs() as logs:
            if kind == "not-in-source":
                outcome = await harness.run(probe.name, target.cve_id, NVD, token)
                assert outcome is None
            else:
                with pytest.raises(type(error)) as raised:
                    await harness.run(
                        probe.name, target.cve_id, NVD, token, attempt=attempt
                    )
                assert raised.value is error

        [suppressed] = events_named(logs, ISOLATED_STATUS_WRITE_FAILED_EVENT)
        assert suppressed["cause"] == "RuntimeError"
        expected = "missing" if kind == "not-in-source" else "failure"
        assert suppressed["status"] == expected
        assert len(harness.status.opened) == 1
        assert await source_state(harness.factory, target.cve.id) == before
        assert await harness.marker_value(target.cve_id) is None


# ---------------------------------------------------------------------------
# Token ownership
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTokenOwnership:
    @pytest.mark.parametrize("marker", ["matching", "newer-owner", "absent"])
    async def test_attempt_start_renews_only_a_matching_marker(
        self, world: CommittedWorld, harness: FetchSingleHarness, marker: str
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        key = pending_key(target.cve_id)
        token = new_token()
        stored: str | None = None
        if marker == "matching":
            stored = await harness.marker(target.cve_id, token=token, ttl_ms=60000)
        elif marker == "newer-owner":
            stored = await harness.marker(target.cve_id, ttl_ms=60000)
        seen: list[tuple[str | None, int]] = []

        async def observe() -> None:
            seen.append((await harness.redis.get(key), await harness.redis.pttl(key)))

        probe.step = _succeeds(before=observe)

        await harness.run(probe.name, target.cve_id, NVD, token)

        [(value, pttl)] = seen
        assert value == stored
        if marker == "matching":
            assert pttl > (PENDING_TTL - 5) * 1000
            assert await harness.redis.exists(key) == 0
        elif marker == "newer-owner":
            assert 0 < pttl <= 60000
            assert await harness.marker_value(target.cve_id) == stored
            assert 0 < await harness.redis.pttl(key) <= 60000
        else:
            assert pttl == -2
            assert await harness.redis.exists(key) == 0

    @pytest.mark.parametrize("outcome", _OUTCOMES)
    async def test_old_task_neither_extends_nor_deletes_a_newer_marker(
        self, world: CommittedWorld, harness: FetchSingleHarness, outcome: str
    ) -> None:
        scenario = await _arrange(outcome, harness, world)
        newer = await harness.marker(scenario.cve_id, ttl_ms=60000)
        old_token = new_token()

        await scenario.run(harness, old_token)

        assert await harness.marker_value(scenario.cve_id) == newer
        assert 0 < await harness.redis.pttl(pending_key(scenario.cve_id)) <= 60000

    @pytest.mark.parametrize("outcome", ["retry", "success"])
    async def test_absent_marker_is_never_recreated(
        self, world: CommittedWorld, harness: FetchSingleHarness, outcome: str
    ) -> None:
        scenario = await _arrange(outcome, harness, world)

        await scenario.run(harness, new_token())

        assert await harness.redis.keys("*") == []

    @pytest.mark.parametrize(
        ("outcome", "operations"),
        [
            pytest.param("success", ["renew", "release"], id="success"),
            pytest.param("disabled", ["renew", "release"], id="disabled"),
            pytest.param("retry", ["renew", "renew"], id="retry"),
            pytest.param("non-retryable", ["renew", "release"], id="non-retryable"),
            pytest.param("commit-failure", ["renew", "release"], id="commit-failure"),
        ],
    )
    async def test_redis_error_in_renewal_or_release_is_best_effort(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        monkeypatch: pytest.MonkeyPatch,
        outcome: str,
        operations: list[str],
    ) -> None:
        """Each failed compare-by-token operation logs one bounded WARNING;
        the database outcome and the retry classification are unchanged,
        and a failing client close is suppressed."""
        error = RedisConnectionError(f"fictional refusal {SECRET_DETAIL}")
        client = ScriptedRedis(eval_error=error, aclose_error=RedisConnectionError())
        created = client.install(monkeypatch)
        scenario = await _arrange(outcome, harness, world)
        token = new_token()

        with capture_logs() as logs:
            result = await scenario.run(harness, token)

        assert created == [1]
        assert client.closed == 1
        assert events_named(logs, MARKER_OPERATION_FAILED) == [
            {
                "event": MARKER_OPERATION_FAILED,
                "log_level": "warning",
                "operation": operation,
                "cve_id": scenario.cve_id,
                "source": NVD,
                "cause": "ConnectionError",
            }
            for operation in operations
        ]
        assert_private_logs(logs, token, SECRET_DETAIL)
        assert scenario.target is not None
        state = await source_state(harness.factory, scenario.target.cve.id)
        if outcome == "success":
            assert result is None
            assert state is not None
            assert state.status == CVESourceFetchStatus.SUCCESS
        elif outcome == "retry":
            assert isinstance(result, FetchSingleRetry)
            assert result.countdown == 5
            assert state is None
        elif outcome == "non-retryable":
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE
        else:
            assert state is None

    async def test_unused_marker_close_creates_no_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts = forbid_redis(monkeypatch)
        marker = _PendingMarker(fictional_cve_id(), NVD, new_token())

        await marker.aclose()

        assert attempts() == 0


# ---------------------------------------------------------------------------
# Wrapper-owned HTTP client teardown
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHttpClientTeardown:
    @pytest.mark.parametrize(
        "outcome",
        [
            "success",
            "not-in-source",
            "retry",
            "exhausted",
            "non-retryable",
            "commit-failure",
            "post-commit-failure",
        ],
    )
    async def test_http_client_is_closed_by_the_workflow_on_every_outcome(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        http_client: FakeHttpClient,
        outcome: str,
    ) -> None:
        scenario = await _arrange(outcome, harness, world, use_http_client=True)

        await scenario.run(harness, new_token())

        assert scenario.probe is not None
        assert len(scenario.probe.instances) == 1
        http_client.aclose.assert_awaited_once_with()
        assert scenario.probe.fetcher._http_client is None

    async def test_bounded_outcome_creates_no_http_client(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        create = MagicMock(side_effect=AssertionError("must not create a client"))
        monkeypatch.setattr(base_fetcher_module, "create_http_client", create)
        scenario = await _arrange("disabled", harness, world)

        await scenario.run(harness, new_token())

        create.assert_not_called()

    async def test_failing_http_client_close_does_not_mask_the_primary_exception(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        http_client: FakeHttpClient,
    ) -> None:
        http_client.aclose.side_effect = RuntimeError("fictional close failure")
        target = await _target(world)
        probe = await harness.fetcher()
        error = ValueError(SECRET_DETAIL)
        probe.step = _raises(error, before=_use_http_client(probe))

        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match="Example-Secret-Detail") as raised,
        ):
            await harness.run(probe.name, target.cve_id, NVD, new_token())

        assert raised.value is error
        http_client.aclose.assert_awaited_once_with()
        assert probe.fetcher._http_client is None
        assert len(events_named(logs, "fetcher_http_client_close_failed")) == 1


# ---------------------------------------------------------------------------
# Audit and log privacy
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditAndPrivacy:
    @pytest.mark.parametrize(
        "outcome", [o for o in _OUTCOMES if o not in {"cve-missing"}]
    )
    async def test_dispatch_outcome_creates_no_ticket_audit_event(
        self, world: CommittedWorld, harness: FetchSingleHarness, outcome: str
    ) -> None:
        scenario = await _arrange(outcome, harness, world)
        assert scenario.target is not None
        ticket_id = scenario.target.ticket.id
        assert await ticket_audit_event_count(harness.factory, ticket_id) == 0

        await scenario.run(harness, await harness.marker(scenario.cve_id))

        assert await ticket_audit_event_count(harness.factory, ticket_id) == 0

    @pytest.mark.parametrize("outcome", _OUTCOMES)
    async def test_logs_carry_only_canonical_identity_and_closed_causes(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        http_client: FakeHttpClient,
        outcome: str,
    ) -> None:
        """Every record of the outcome carries only allowed fields and the
        task-bound `celery_task_id`; never the token, exception text, or a
        URL."""
        scenario = await _arrange(outcome, harness, world, use_http_client=True)
        token = await harness.marker(scenario.cve_id)
        celery_task_id = str(uuid.uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                await scenario.run(harness, token)
        finally:
            unbind_contextvars("celery_task_id")

        assert logs
        assert all(entry["celery_task_id"] == celery_task_id for entry in logs)
        assert_private_logs(logs, token, SECRET_DETAIL)
        for entry in logs:
            if "cve_id" in entry:
                assert entry["cve_id"] == scenario.cve_id
            if "source" in entry:
                assert entry["source"] == NVD

    async def test_isolated_status_and_redis_failure_logs_stay_private(
        self,
        world: CommittedWorld,
        harness: FetchSingleHarness,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client = ScriptedRedis(eval_error=RedisConnectionError(SECRET_DETAIL))
        client.install(monkeypatch)
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _raises(ValueError(SECRET_DETAIL))
        harness.status.failures["commit"] = RuntimeError(SECRET_DETAIL)
        token = new_token()

        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match="Example-Secret-Detail"),
        ):
            await harness.run(probe.name, target.cve_id, NVD, token)

        assert {entry["event"] for entry in logs} == {
            MARKER_OPERATION_FAILED,
            ISOLATED_STATUS_WRITE_FAILED_EVENT,
            FAILED,
        }
        assert_private_logs(logs, token, SECRET_DETAIL)
