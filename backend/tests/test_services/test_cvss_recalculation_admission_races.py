"""Coordination integration tests of the manual CVSS recalculation
admission `admit_cvss_recalculation()`
(backend/app/services/cvss_recalculation_admission.py) against independent
connections and the real runner
(`run_cvss_derived_state_recalculation()`,
backend/app/services/cvss_recalculation.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Complete-Run
  Coordination: Run Identity, Coordination Resources, Execution Fence,
  Admission Ordering, Manual Admission Service, Task Adoption, Lifecycle
  Phases, Publication Uncertainty, Cleanup and Recovery Matrix,
  Coordination Logging);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner: Coordination integration tests, the admission bullets, and
  Coordination API tests "a task actually accepted despite the 503 can
  still run and adopt" and "a task actually not accepted leaves the lease
  to expire by its TTL"; Concurrency Testing; Lock-Wait Observation);
- issue #837, acceptance criteria "Coordination integration" and decision
  V8 (`PEXPIRE` instead of waiting 900 seconds).

Every admission runs on its own borrowed connection of the shared
recalculation harness (tests/support/cvss_recalculation.py), supplied in
call order through the `get_cvss_admission_bind()` patch point, and is
observed by the shared `AdmissionSpy`
(tests/support/cvss_recalculation_admission.py), whose recorder stands in
for the broker. The runner is the real workflow on the harness's fenced
connection. Interleavings are forced with one-shot `asyncio.Event` gates at
named boundaries (inside the fenced setting read, after the lease, at the
publisher, at a runner unit boundary); these are waits on application
boundaries, not lock-serialization evidence, so every wait is bounded and
no ordering relies on a sleep. The only poll waits for a Redis TTL to
elapse. The populations are ticketless, so the runner publishes nothing.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from kombu.exceptions import (  # type: ignore[import-untyped]
    OperationalError as BrokerOperationalError,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.core.enums import Severity
from app.services import cvss_recalculation_admission as admission
from app.services.cvss_recalculation import (
    ADOPTED_EVENT,
    ADOPTION_REJECTED_EVENT,
    RECALCULATE_CVSS_DERIVED_STATE_TASK,
    STALE_EVENT,
)
from app.services.cvss_recalculation_admission import (
    ADMISSION_REJECTED_EVENT,
    ADMITTED_EVENT,
    PUBLICATION_UNCONFIRMED_EVENT,
    SUBMITTED_EVENT,
    CVSSRecalculationAdmission,
    CVSSRecalculationBrokerUnavailableError,
    admit_cvss_recalculation,
)
from app.services.cvss_recalculation_coordination import (
    LEASE_KEY,
    LEASE_TTL_SECONDS,
)
from app.services.settings import CVSSRecalculationAlreadyInProgressError
from tests.support.cvss_chain import Assessment, cve_severity
from tests.support.cvss_recalculation import (
    LEAK_MARKER,
    TARGET,
    ChainSpy,
    DrainSpy,
    RecalculationHarness,
    capture_events,
    completed_run,
    connection_pid,
    recalculation_harness,
    runner_events,
)
from tests.support.cvss_recalculation_admission import (
    WAIT,
    AdmissionSpy,
    Gate,
    finish,
)

pytestmark = pytest.mark.integration

_POLL_INTERVAL = 0.01


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def h(
    _engine: AsyncEngine,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RecalculationHarness]:
    async with recalculation_harness(_engine.url, redis_client, monkeypatch) as harness:
        yield harness


@pytest.fixture
def spy(h: RecalculationHarness, monkeypatch: pytest.MonkeyPatch) -> AdmissionSpy:
    """The spy, installed after the harness, with the harness's fenced
    connection as the default admission bind."""
    installed = AdmissionSpy(monkeypatch)
    monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: h.connection)
    return installed


@pytest.fixture
def drain(monkeypatch: pytest.MonkeyPatch) -> DrainSpy:
    return DrainSpy(monkeypatch)


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> ChainSpy:
    return ChainSpy(monkeypatch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bind_in_order(
    monkeypatch: pytest.MonkeyPatch, *connections: AsyncConnection
) -> None:
    """Supply one borrowed connection per admission, in call order: the
    bind is read synchronously at admission entry, before any await."""
    pending = list(connections)
    monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: pending.pop(0))


def _admission_event(name: str, level: str, **fields: str) -> dict[str, Any]:
    return {"event": name, "log_level": level, **fields}


def _admitted(target: str = TARGET) -> dict[str, Any]:
    return _admission_event(ADMITTED_EVENT, "info", target_version=target)


def _submitted(target: str = TARGET) -> dict[str, Any]:
    return _admission_event(SUBMITTED_EVENT, "info", target_version=target)


def _rejected(reason: str, target: str | None = TARGET) -> dict[str, Any]:
    if target is None:
        return _admission_event(ADMISSION_REJECTED_EVENT, "warning", reason=reason)
    return _admission_event(
        ADMISSION_REJECTED_EVENT, "warning", reason=reason, target_version=target
    )


def _token(task_id: str, target: str = TARGET) -> str:
    return f"v1:{task_id}:{target}"


def _assert_no_transaction(*connections: AsyncConnection) -> None:
    for connection in connections:
        assert connection.closed is False
        assert connection.invalidated is False
        assert connection.in_transaction() is False


async def _wait_until_absent(client: redis_asyncio.Redis, key: str) -> None:
    """Bounded poll until the key's TTL has elapsed (a wait on Redis
    expiry, not on a lock)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + WAIT
    while await client.exists(key):
        assert loop.time() < deadline, f"{key} never expired"
        await asyncio.sleep(_POLL_INTERVAL)


async def _rejected_by_paused_runner(
    h: RecalculationHarness,
    spy: AdmissionSpy,
    drain: DrainSpy,
    monkeypatch: pytest.MonkeyPatch,
    lose_redis_state: Callable[[], Awaitable[object]],
) -> None:
    """Start the real runner on an admitted lease, pause it at its first
    unit boundary (fence held, no open transaction), lose the Redis state,
    and prove that an admission on another connection is `fence_busy`
    without creating a lease client, writing a lease, or publishing. The
    runner then completes: the controlled clock is never advanced, so no
    renewal checkpoint observes the lost lease, and its terminal
    compare-and-delete is an `absent` no-op."""
    ids = await h.world.bulk_cves(2)
    task_id = await h.admit()
    other = (await h.borrow()).connection
    _bind_in_order(monkeypatch, other)
    gate = Gate()
    drain.after[0] = gate.pause

    with capture_events() as logs:
        run = asyncio.create_task(h.run(task_id))
        try:
            await gate.wait_reached()
            assert await h.fence_holders() == [h.pid]
            await lose_redis_state()
            assert await h.lease() is None
            steps = len(spy.sequence)

            with pytest.raises(CVSSRecalculationAlreadyInProgressError):
                await asyncio.wait_for(admit_cvss_recalculation(), WAIT)

            assert spy.sequence[steps:] == ["fence"]
            assert spy.fence_pids == [connection_pid(other)]
            assert spy.clients == 0
            assert spy.published == []
            assert await h.lease() is None
            assert await h.fence_holders() == [h.pid]
            gate.release()
            assert await asyncio.wait_for(run, WAIT) is None
        finally:
            await finish(run, gate)

    expected = completed_run(task_id, ids[-1], unchanged=2)
    expected.insert(2, _rejected("fence_busy", target=None))
    assert runner_events(logs) == expected
    assert await h.fence_holders() == []
    assert await h.lease() is None
    assert spy.published == []
    _assert_no_transaction(h.connection, other)


# ---------------------------------------------------------------------------
# Two concurrent admissions
# ---------------------------------------------------------------------------


class TestConcurrentAdmissions:
    async def test_second_admission_meets_the_first_admissions_fence(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Lifecycle phase `admitted`: admission A holds the fence and is
        paused inside its fenced setting read; admission B on another
        connection finds the fence busy and is `409` before any setting
        read or lease attempt. A then completes alone: exactly one owner,
        one publication, and the lease carries A's token."""
        second = (await h.borrow()).connection
        _bind_in_order(monkeypatch, h.connection, second)
        gate = Gate()
        spy.before_setting = gate.pause

        with capture_events() as logs:
            first = asyncio.create_task(admit_cvss_recalculation())
            try:
                await gate.wait_reached()
                assert await h.fence_holders() == [h.pid]

                with pytest.raises(CVSSRecalculationAlreadyInProgressError):
                    await asyncio.wait_for(admit_cvss_recalculation(), WAIT)

                assert spy.task_ids == []
                assert spy.published == []
                assert await h.lease() is None
                gate.release()
                result = await asyncio.wait_for(first, WAIT)
            finally:
                await finish(first, gate)

        assert result == CVSSRecalculationAdmission(
            outcome="submitted", target_version=TARGET
        )
        assert spy.fence_pids == [h.pid, connection_pid(second)]
        assert spy.sequence == [
            "fence",
            "setting",
            "fence",
            "lease",
            "release",
            "publish",
        ]
        owner = spy.task_id
        assert [call.task_id for call in spy.published] == [owner]
        assert await h.lease() == _token(owner)
        assert await h.fence_holders() == []
        _assert_no_transaction(h.connection, second)
        assert runner_events(logs) == [
            _rejected("fence_busy", target=None),
            _admitted(),
            _submitted(),
        ]

    async def test_second_admission_meets_the_first_admissions_lease(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Lifecycle phase `publication attempted`: admission A has
        acquired the lease, released the fence, and is paused at the
        publisher; admission B acquires the free fence, reads the setting,
        and finds the lease held (`lease_held` `409`), releasing the fence.
        Exactly one publication occurs and the lease still carries A's
        token."""
        second = (await h.borrow()).connection
        _bind_in_order(monkeypatch, h.connection, second)
        gate = Gate()

        async def _pause_at_publisher(_call: object) -> None:
            await gate.pause()

        spy.on_publish = _pause_at_publisher

        with capture_events() as logs:
            first = asyncio.create_task(admit_cvss_recalculation())
            try:
                await gate.wait_reached()
                assert await h.fence_holders() == []
                owner = spy.task_ids[0]
                assert await h.lease() == _token(owner)

                with pytest.raises(CVSSRecalculationAlreadyInProgressError):
                    await asyncio.wait_for(admit_cvss_recalculation(), WAIT)

                assert await h.fence_holders() == []
                gate.release()
                result = await asyncio.wait_for(first, WAIT)
            finally:
                await finish(first, gate)

        assert result.outcome == "submitted"
        assert spy.fence_pids == [h.pid, connection_pid(second)]
        assert spy.sequence == [
            "fence",
            "setting",
            "lease",
            "release",
            "publish",
            "fence",
            "setting",
            "lease",
            "release",
        ]
        assert len(spy.task_ids) == 2
        assert spy.task_ids[1] != owner
        assert len(spy.published) == 1
        assert spy.published[0].task_id == owner
        assert spy.published[0].task_name == RECALCULATE_CVSS_DERIVED_STATE_TASK
        assert await h.lease() == _token(owner)
        assert await h.fence_holders() == []
        _assert_no_transaction(h.connection, second)
        assert runner_events(logs) == [
            _admitted(),
            _rejected("lease_held"),
            _submitted(),
        ]


# ---------------------------------------------------------------------------
# The fenced setting read
# ---------------------------------------------------------------------------


class TestFencedSettingRead:
    async def test_setting_committed_after_the_fence_and_before_the_read_is_published(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        """The pre-fence value is `3.1`; a change to `4.0` committed on an
        independent connection after the admission acquired the fence and
        before its setting read is the version the admission publishes and
        writes into the lease, never the pre-fence observation."""
        assert await h.world.setting() == TARGET
        observed: dict[str, list[int]] = {}

        async def _commit_before_read() -> None:
            observed["fence"] = await h.fence_holders()
            await h.world.set_setting("4.0")

        spy.before_setting = _commit_before_read

        result = await admit_cvss_recalculation()

        assert observed["fence"] == [h.pid]
        assert result == CVSSRecalculationAdmission(
            outcome="submitted", target_version="4.0"
        )
        assert [call.kwargs for call in spy.published] == [{"target_version": "4.0"}]
        assert await h.lease() == _token(spy.task_id, "4.0")

    async def test_setting_committed_after_the_read_is_not_published(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        """The mirror: a change committed after the fenced read (here while
        the admission still holds the fence, after its lease; a direct
        write that requests no fence) does not alter the admitted target.
        The read is the run's only target source; the delivery later
        observes the newer setting and terminates `stale` (Admission
        Ordering), removing its lease."""

        async def _commit_after_read() -> None:
            assert await h.fence_holders() == [h.pid]
            await h.world.set_setting("4.0")

        spy.after_lease = _commit_after_read

        result = await admit_cvss_recalculation()

        assert result.target_version == TARGET
        assert [call.kwargs for call in spy.published] == [{"target_version": TARGET}]
        task_id = spy.task_id
        assert await h.lease() == _token(task_id)

        with capture_events() as logs:
            await h.run(task_id)

        assert [entry["event"] for entry in runner_events(logs)] == [
            ADOPTED_EVENT,
            STALE_EVENT,
        ]
        assert await h.lease() is None
        assert await h.fence_holders() == []


# ---------------------------------------------------------------------------
# The fence of an active runner
# ---------------------------------------------------------------------------


class TestActiveRunnerFence:
    async def test_active_runner_fence_rejects_an_admission_without_a_lease(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The lease key alone is removed while the runner is mid-run."""

        async def _delete_lease() -> object:
            return await h.redis.delete(LEASE_KEY)

        await _rejected_by_paused_runner(h, spy, drain, monkeypatch, _delete_lease)

    async def test_free_lease_with_a_held_fence_after_redis_loss_admits_no_run(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simulated Redis data loss: `FLUSHDB` on the worker Redis
        database empties every key while the runner holds the fence."""

        async def _flush() -> object:
            return await h.redis.flushdb()

        await _rejected_by_paused_runner(h, spy, drain, monkeypatch, _flush)


# ---------------------------------------------------------------------------
# Publication uncertainty
# ---------------------------------------------------------------------------


class TestPublicationUncertainty:
    async def test_task_accepted_despite_the_503_adopts_the_retained_lease(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        """ "Publishing after raising": the recorder captures the task ID
        and kwargs (the broker accepted the task), then raises
        `kombu.exceptions.OperationalError`. The admission reports `503`
        and retains the lease; the delivery of the recorded task adopts
        that lease, runs, completes, and removes it."""
        ids = await h.world.bulk_cves(1)
        spy.publish_error = BrokerOperationalError(LEAK_MARKER)

        with (
            capture_events() as logs,
            pytest.raises(CVSSRecalculationBrokerUnavailableError),
        ):
            await admit_cvss_recalculation()

        [accepted] = spy.published
        task_id = accepted.task_id
        assert task_id is not None
        target = accepted.kwargs["target_version"]
        assert isinstance(target, str)
        assert await h.lease() == _token(task_id, target)
        assert runner_events(logs) == [
            _admitted(),
            _admission_event(
                PUBLICATION_UNCONFIRMED_EVENT, "error", target_version=TARGET
            ),
        ]

        with capture_events() as logs:
            assert await h.run(task_id, target_version=target) is None

        assert runner_events(logs) == completed_run(task_id, ids[-1], unchanged=1)
        assert await h.lease() is None
        assert await h.fence_holders() == []

    async def test_task_not_accepted_leaves_the_lease_to_expire_then_admits(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        """The publication raised and nothing was delivered: the retained
        lease blocks the next admission (`lease_held`) until its TTL
        elapses, after which an admission succeeds with a new run identity
        and no manual key deletion. The TTL is shortened with `PEXPIRE`
        (issue #837 V8) instead of waiting 900 seconds."""
        spy.publish_error = BrokerOperationalError(LEAK_MARKER)

        with capture_events() as logs:
            with pytest.raises(CVSSRecalculationBrokerUnavailableError):
                await admit_cvss_recalculation()
            unconfirmed = spy.task_ids[0]
            assert await h.lease() == _token(unconfirmed)
            assert 0 < await h.redis.ttl(LEASE_KEY) <= LEASE_TTL_SECONDS

            with pytest.raises(CVSSRecalculationAlreadyInProgressError):
                await admit_cvss_recalculation()
            assert len(spy.published) == 1
            assert await h.lease() == _token(unconfirmed)

            assert await h.redis.pexpire(LEASE_KEY, 50) is True
            await _wait_until_absent(h.redis, LEASE_KEY)
            spy.publish_error = None

            result = await admit_cvss_recalculation()

        assert result.outcome == "submitted"
        assert len(spy.task_ids) == 3
        retried = spy.task_ids[2]
        assert len({unconfirmed, spy.task_ids[1], retried}) == 3
        assert [call.task_id for call in spy.published] == [unconfirmed, retried]
        assert await h.lease() == _token(retried)
        assert 0 < await h.redis.ttl(LEASE_KEY) <= LEASE_TTL_SECONDS
        assert await h.fence_holders() == []
        assert runner_events(logs) == [
            _admitted(),
            _admission_event(
                PUBLICATION_UNCONFIRMED_EVENT, "error", target_version=TARGET
            ),
            _rejected("lease_held"),
            _admitted(),
            _submitted(),
        ]


# ---------------------------------------------------------------------------
# Two deliveries of one admitted token
# ---------------------------------------------------------------------------


class TestDuplicateDelivery:
    async def test_second_delivery_of_an_admitted_token_mutates_nothing(
        self, h: RecalculationHarness, spy: AdmissionSpy, chain: ChainSpy
    ) -> None:
        """The token comes from a real admission. The first delivery adopts
        it, converges the stale severity, and removes the lease; the second
        delivery of the same task ID is rejected at adoption
        (`lease_absent`) and begins no unit."""
        cve = await h.world.scored_cve(Assessment("9.8"), severity=Severity.MEDIUM)
        await admit_cvss_recalculation()
        task_id = spy.task_id
        assert [call.task_id for call in spy.published] == [task_id]

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert chain.cve_ids == [cve.id]
        assert await h.lease() is None

        with capture_events() as logs:
            assert await h.run(task_id) is None

        assert runner_events(logs) == [
            {
                "event": ADOPTION_REJECTED_EVENT,
                "log_level": "warning",
                "celery_task_id": task_id,
                "reason": "lease_absent",
                "target_version": TARGET,
            }
        ]
        assert chain.cve_ids == [cve.id]
        assert await h.world.read(lambda db: cve_severity(db, cve.id)) == "Critical"
        assert await h.lease() is None
        assert await h.fence_holders() == []
        assert len(spy.published) == 1
