"""Hard process loss of the all-CVE CVSS recalculation runner
(`run_cvss_derived_state_recalculation()`,
backend/app/services/cvss_recalculation.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Retry, Rerun,
  and Recovery; Execution Fence; Timeout and Cancellation; Cleanup and
  Recovery Matrix, row "hard kill");
- docs/deployment.md (CVSS Recalculation Recovery);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner: Coordination task and process tests, "hard process loss" and "no
  test presumes cleanup after a hard kill"; Process lifecycle, "recovery
  after an unterminated process");
- issue #836 decision U8; umbrella #833 P19.

A child process (tests/support/cvss_recalculation_process.py) runs the real
workflow on the worker test database and the worker Redis logical database
against a lease this test admitted, pauses at a unit boundary after the
k-th unit's commit, close, and drain, and is killed with SIGKILL. Nothing
here asserts or relies on a cleanup by the killed process: the fence is
released only by the closure of its backend connection, and the lease
remains until its TTL or an owner-safe removal.
"""

from __future__ import annotations

import asyncio
import signal
import uuid
from collections.abc import AsyncIterator
from functools import partial
from pathlib import Path

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.enums import Severity
from app.models.cve import CVE
from app.services.cvss_recalculation import (
    ADOPTED_EVENT,
    STARTED_EVENT,
)
from app.services.cvss_recalculation_coordination import (
    LEASE_KEY,
    LEASE_TTL_SECONDS,
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    LeaseAcquireOutcome,
    LeaseDeleteOutcome,
    acquire_lease,
    compare_and_delete_lease,
    encode_lease_value,
    release_execution_fence,
    try_acquire_execution_fence,
)
from tests.support.cvss_chain import Assessment, cve_severity
from tests.support.cvss_recalculation import (
    TARGET,
    RecalculationHarness,
    capture_events,
    completed_run,
    connection_pid,
    non_advisory_locks,
    recalculation_harness,
    runner_events,
    wait_until_fence_free,
)
from tests.support.cvss_recalculation_process import (
    RecalculationProcess,
    recalculation_process,
)
from tests.support.redis import redis_url_from_client

pytestmark = pytest.mark.integration

_POPULATION = 4
_PAUSE_AFTER = 2

SUSE_31_CRITICAL = Assessment("9.8")
"""Every seeded CVE stores `Low`; the 3.1 default resolves `Critical`, so
each unit classifies `changed` on its first run."""


@pytest.fixture
async def h(
    _engine: AsyncEngine,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RecalculationHarness]:
    async with recalculation_harness(_engine.url, redis_client, monkeypatch) as harness:
        yield harness


async def _population(h: RecalculationHarness) -> list[CVE]:
    cves = [
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        for _ in range(_POPULATION)
    ]
    return sorted(cves, key=lambda cve: cve.id)


async def _severities(h: RecalculationHarness, cves: list[CVE]) -> list[str | None]:
    return [await h.world.read(partial(cve_severity, cve_id=cve.id)) for cve in cves]


def _converged(count: int) -> list[str | None]:
    """The committed severities after `count` converged units."""
    severities: list[str | None] = ["Critical"] * count
    return severities + ["Low"] * (_POPULATION - count)


async def _kill_at_unit_boundary(
    h: RecalculationHarness,
    cves: list[CVE],
    process: RecalculationProcess,
) -> None:
    """Wait until the child paused after `_PAUSE_AFTER` units, prove the
    pause state, then SIGKILL its process group and reap it."""
    marker = await process.wait_paused()
    assert marker.strip() == f"PAUSED {_PAUSE_AFTER}"

    holders = await h.fence_holders()
    own = {h.pid, connection_pid(h.observer)}
    assert len(holders) == 1, process.tail_log()
    assert holders[0] not in own
    # A unit boundary: the fenced backend holds no transaction-level lock.
    assert await non_advisory_locks(h.observer, holders[0]) == []
    assert await _severities(h, cves) == _converged(_PAUSE_AFTER)

    assert process.kill() == -signal.SIGKILL


async def _assert_fresh_fence_acquisition(h: RecalculationHarness) -> None:
    """The killed backend's closure released the fence: a fresh session
    acquires it non-blockingly (then releases it again)."""
    await wait_until_fence_free(h.engine)
    async with h.engine.connect() as fresh:
        assert await try_acquire_execution_fence(fresh) is FenceAcquireOutcome.ACQUIRED
        assert await release_execution_fence(fresh) is FenceReleaseOutcome.RELEASED
    assert await h.fence_holders() == []


async def _wait_until_lease_absent(h: RecalculationHarness) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 5.0
    while await h.redis.exists(LEASE_KEY):
        assert loop.time() < deadline, "the lease did not expire"
        await asyncio.sleep(0.01)


class TestHardProcessLoss:
    async def test_sigkill_at_unit_boundary_leaves_no_terminal_event_and_the_lease(
        self,
        h: RecalculationHarness,
        tmp_path: Path,
    ) -> None:
        """Cleanup and Recovery Matrix, "hard kill": no compare-and-delete,
        the fence released automatically on connection closure, no
        terminal event, and the lease left to its TTL."""
        cves = await _population(h)
        task_id = await h.admit()

        with recalculation_process(
            database_url=h.engine.url.render_as_string(hide_password=False),
            redis_url=redis_url_from_client(h.redis),
            task_id=task_id,
            target_version=TARGET,
            pause_after=_PAUSE_AFTER,
            run_dir=tmp_path,
        ) as process:
            await _kill_at_unit_boundary(h, cves, process)
            events = runner_events(process.events())
            log = process.tail_log()

        # Adopted and started, then nothing: no renewal failure, cleanup
        # failure, or terminal event of any outcome.
        assert [event["event"] for event in events] == [
            ADOPTED_EVENT,
            STARTED_EVENT,
        ], log
        assert all(event["celery_task_id"] == task_id for event in events)
        assert events[1]["watermark"] == str(cves[-1].id)

        # The lease is neither removed nor changed, with a running TTL.
        assert await h.lease() == encode_lease_value(task_id, TARGET)
        assert 0 < await h.redis.ttl(LEASE_KEY) <= LEASE_TTL_SECONDS

        await _assert_fresh_fence_acquisition(h)

        # Committed units stay committed; later CVEs are untouched.
        assert await _severities(h, cves) == _converged(_PAUSE_AFTER)
        # The surviving lease still blocks a new admission until its TTL.
        assert (
            await acquire_lease(
                h.redis, task_id=str(uuid.uuid4()), target_version=TARGET
            )
            is LeaseAcquireOutcome.NOT_ACQUIRED
        )
        assert await h.lease() == encode_lease_value(task_id, TARGET)

    @pytest.mark.parametrize("lease_release", ["owner_safe_delete", "ttl_expiry"])
    async def test_recovery_after_an_unterminated_process_is_a_fresh_complete_run(
        self,
        h: RecalculationHarness,
        tmp_path: Path,
        lease_release: str,
    ) -> None:
        """Retry, Rerun, and Recovery: after the killed run's lease is
        removed owner-safely or has expired (never by an unconditional
        delete), a new admission runs from the beginning; the units the
        killed run committed reclassify `unchanged`."""
        cves = await _population(h)
        killed = await h.admit()

        with recalculation_process(
            database_url=h.engine.url.render_as_string(hide_password=False),
            redis_url=redis_url_from_client(h.redis),
            task_id=killed,
            target_version=TARGET,
            pause_after=_PAUSE_AFTER,
            run_dir=tmp_path,
        ) as process:
            await _kill_at_unit_boundary(h, cves, process)

        await _assert_fresh_fence_acquisition(h)
        if lease_release == "owner_safe_delete":
            assert (
                await compare_and_delete_lease(
                    h.redis, task_id=killed, target_version=TARGET
                )
                is LeaseDeleteOutcome.DELETED
            )
        else:
            # Stands in for the elapsed 900-second TTL of the exact value.
            assert await h.lease() == encode_lease_value(killed, TARGET)
            assert await h.redis.pexpire(LEASE_KEY, 1)
            await _wait_until_lease_absent(h)
        assert await h.lease() is None

        rerun = await h.admit()
        with capture_events() as logs:
            assert await h.run(rerun) is None

        assert runner_events(logs) == completed_run(
            rerun,
            cves[-1].id,
            changed=_POPULATION - _PAUSE_AFTER,
            unchanged=_PAUSE_AFTER,
        )
        assert await _severities(h, cves) == _converged(_POPULATION)
        assert await h.lease() is None
        assert await h.fence_holders() == []
