"""Server-global Redis tests of the all-CVE CVSS recalculation runner
(`run_cvss_derived_state_recalculation()`,
backend/app/services/cvss_recalculation.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Renewal
  Checkpoints; Ownership Loss; Cleanup and Recovery Matrix, rows "Redis
  restart" and "cleanup Redis failure");
- docs/deployment.md (CVSS Recalculation Coordination and Redis Loss;
  Persistence is Disabled by Design);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner, Coordination server-global Redis tests; Redis Strategy, Worker
  and Test Isolation);
- issue #835 decision T7 (no client-side retry): a lease client reused
  across a restart either raises `RedisError` or reconnects and observes
  the lost lease, depending on whether its event loop saw the server's
  close before the command.

Every test runs against its own Redis 8 container
(`tests.support.redis.dedicated_redis_container`), reached by the workflow
through the replaceable URL provider `get_cvss_recalculation_redis_url()`;
the workflow runs on the harness's borrowed fenced connection on the worker
test database.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from functools import partial
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.enums import Severity
from app.models.cve import CVE
from app.services import cvss_recalculation, cvss_recalculation_coordination
from app.services.cvss_recalculation import (
    ADOPTED_EVENT,
    CLEANUP_FAILED_EVENT,
    OWNERSHIP_LOST_EVENT,
    OWNERSHIP_LOST_MESSAGE,
    RENEWAL_FAILED_EVENT,
    STARTED_EVENT,
)
from app.services.cvss_recalculation_coordination import (
    LEASE_KEY,
    LeaseDeleteOutcome,
)
from tests.support.cvss_chain import Assessment, cve_severity
from tests.support.cvss_recalculation import (
    TARGET,
    ChainSpy,
    RecalculationHarness,
    capture_events,
    counters,
    recalculation_harness,
    runner_events,
)
from tests.support.redis import DedicatedRedisContainer, dedicated_redis_container

pytestmark = pytest.mark.integration

SUSE_31_CRITICAL = Assessment("9.8")
"""Seeded as `Low`; the 3.1 default resolves `Critical` (`changed`)."""


@pytest.fixture
def dedicated_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[DedicatedRedisContainer]:
    """A Redis 8 container for this test only, with the lease URL provider
    redirected to it."""
    with dedicated_redis_container() as container:
        monkeypatch.setattr(
            cvss_recalculation_coordination,
            "get_cvss_recalculation_redis_url",
            lambda: container.url,
        )
        yield container


@pytest.fixture
async def h(
    _engine: AsyncEngine,
    dedicated_redis: DedicatedRedisContainer,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RecalculationHarness]:
    """The runner harness whose admission and observation client targets
    the dedicated container."""
    client = redis_asyncio.Redis.from_url(dedicated_redis.url, decode_responses=True)
    try:
        async with recalculation_harness(_engine.url, client, monkeypatch) as harness:
            yield harness
    finally:
        await client.aclose()


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> ChainSpy:
    return ChainSpy(monkeypatch)


class _DeleteSpy:
    """Records each terminal compare-and-delete: its outcome, or the
    `RedisError` it raised."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.results: list[LeaseDeleteOutcome | RedisError] = []
        original = cvss_recalculation_coordination.compare_and_delete_lease

        async def _delete(client: redis_asyncio.Redis, **kwargs: Any) -> Any:
            try:
                outcome = await original(client, **kwargs)
            except RedisError as exc:
                self.results.append(exc)
                raise
            self.results.append(outcome)
            return outcome

        monkeypatch.setattr(cvss_recalculation, "compare_and_delete_lease", _delete)


async def _population(h: RecalculationHarness, count: int) -> list[CVE]:
    cves = [
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        for _ in range(count)
    ]
    return sorted(cves, key=lambda cve: cve.id)


async def _severities(h: RecalculationHarness, cves: list[CVE]) -> list[str | None]:
    return [await h.world.read(partial(cve_severity, cve_id=cve.id)) for cve in cves]


async def _escape(h: RecalculationHarness, task_id: str) -> BaseException:
    try:
        await h.run(task_id)
    except BaseException as exc:  # the escape is the proof
        return exc
    raise AssertionError("no exception escaped the workflow")


def _event(name: str, task_id: str, **fields: Any) -> dict[str, Any]:
    level = "info" if name in (ADOPTED_EVENT, STARTED_EVENT) else "warning"
    return {
        "event": name,
        "log_level": level,
        "celery_task_id": task_id,
        "target_version": TARGET,
        **fields,
    }


class TestRedisLossDuringActiveUnit:
    async def test_redis_restart_during_an_active_unit_terminates_safely(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        dedicated_redis: DedicatedRedisContainer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Cleanup and Recovery Matrix, "Redis restart": the active unit
        commits and keeps its classification, the next checkpoint blocks
        the next unit, and the delivery terminates `ownership_lost` after
        an attempted compare-and-delete and the fence release. Which of
        the two conservative checkpoint results the reused lease client
        observes is not prescribed (#835 T7)."""
        cves = await _population(h, 3)
        deletes = _DeleteSpy(monkeypatch)

        async def restart(_index: int) -> None:
            # Inside the first unit's transaction, after its chain.
            await asyncio.to_thread(dedicated_redis.restart)
            h.clock.advance(60)

        chain.after[0] = restart
        task_id = await h.admit()

        with capture_events() as logs:
            escaped = await _escape(h, task_id)

        events = runner_events(logs)
        cause = events[-1].get("cause")
        assert cause in ("infrastructure", "interrupted"), events
        if cause == "infrastructure":
            assert isinstance(escaped, RedisError)
            reason = "redis_error"
        else:
            assert type(escaped) is RuntimeError
            assert str(escaped) == OWNERSHIP_LOST_MESSAGE
            reason = "lease_absent"
        # The restart lost the lease (persistence disabled): an attempted
        # owner-safe delete finds it absent or fails, which only adds a
        # cleanup failure and changes no outcome.
        assert len(deletes.results) == 1
        cleanup = []
        if isinstance(deletes.results[0], RedisError):
            cleanup = [_event(CLEANUP_FAILED_EVENT, task_id, reason="redis_error")]
        else:
            assert deletes.results[0] is LeaseDeleteOutcome.ABSENT
        watermark = {"watermark": str(cves[-1].id)}
        assert events == [
            _event(ADOPTED_EVENT, task_id),
            _event(STARTED_EVENT, task_id, **watermark, **counters()),
            _event(RENEWAL_FAILED_EVENT, task_id, reason=reason),
            *cleanup,
            _event(
                OWNERSHIP_LOST_EVENT,
                task_id,
                **watermark,
                **counters(changed=1),
                phase="control",
                cause=cause,
            ),
        ]

        assert len(chain.calls) == 1
        assert await _severities(h, cves) == ["Critical", "Low", "Low"]
        assert await h.lease() is None
        assert await h.fence_holders() == []
        assert not h.connection.invalidated
        assert not h.connection.in_transaction()

    async def test_redis_unavailable_at_the_checkpoint_still_releases_the_fence(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        dedicated_redis: DedicatedRedisContainer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Renewal against a stopped server: `ownership_lost`/
        `infrastructure` with the `RedisError` escaping; the terminal
        compare-and-delete fails (`cleanup_failed`, `redis_error`) and the
        fence is still released."""
        cves = await _population(h, 2)
        deletes = _DeleteSpy(monkeypatch)

        async def stop(_index: int) -> None:
            await asyncio.to_thread(dedicated_redis.stop)
            h.clock.advance(60)

        chain.after[0] = stop
        task_id = await h.admit()

        with capture_events() as logs:
            escaped = await _escape(h, task_id)

        assert isinstance(escaped, RedisError)
        assert len(deletes.results) == 1
        assert isinstance(deletes.results[0], RedisError)
        watermark = {"watermark": str(cves[-1].id)}
        assert runner_events(logs) == [
            _event(ADOPTED_EVENT, task_id),
            _event(STARTED_EVENT, task_id, **watermark, **counters()),
            _event(RENEWAL_FAILED_EVENT, task_id, reason="redis_error"),
            _event(CLEANUP_FAILED_EVENT, task_id, reason="redis_error"),
            _event(
                OWNERSHIP_LOST_EVENT,
                task_id,
                **watermark,
                **counters(changed=1),
                phase="control",
                cause="infrastructure",
            ),
        ]
        assert len(chain.calls) == 1
        assert await _severities(h, cves) == ["Critical", "Low"]
        assert await h.fence_holders() == []
        assert not h.connection.invalidated

        # The lease stays to its TTL; with persistence disabled, the server
        # that comes back holds none.
        await asyncio.to_thread(dedicated_redis.start)
        assert await h.redis.exists(LEASE_KEY) == 0
