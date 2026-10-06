"""End-to-end tests of `GET /api/v1/admin/settings/default-cvss-version/impact`
while an all-CVE CVSS recalculation is admitted, queued, or running, and of
the preview no-op's independence from the manual trigger
(`POST /api/v1/admin/settings/default-cvss-version/recalculate`).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Default-CVSS
  Impact Preview: Preview Service, No-op Proposal, Consistency and
  Staleness, Active Recalculation Run; API Endpoints: Get Default-CVSS
  Impact Preview, Error responses, and Trigger CVSS Recalculation;
  Complete-Run Coordination: Lifecycle Phases);
- docs/features/platform/testing-strategy.md (Default-CVSS Impact Preview:
  the last integration bullet, availability during a recalculation, and
  the regression bullet "the preview no-op remains distinct from the manual
  recalculation operation");
- issue #837, acceptance criteria "Preview obligations deferred from #834".

The preview runs through the request `DatabaseSession`, which the e2e
`client` binds to the savepoint-wrapped `db_session`. That outer
transaction is `READ COMMITTED`, so each preview statement observes the
rows that the recalculation harness (tests/support/cvss_recalculation.py)
commits on independent connections, and the runner's unit commits
between two requests. The admission and the real runner use the harness's
fenced connection; the admission's broker call is the shared
`AdmissionSpy` recorder (tests/support/cvss_recalculation_admission.py),
so a `queued` task is one that was recorded and never delivered. Phases
are held at named boundaries with one-shot `asyncio.Event` gates. Every
population is ticketless, so the runner publishes nothing.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from types import ModuleType
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis
import redis.asyncio as redis_asyncio
import redis.asyncio.connection as redis_asyncio_connection
import redis.connection as redis_connection
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.api import dependencies
from app.core.enums import Role, Severity
from app.models.api_key import ApiKey
from app.models.cve import CVE
from app.models.user import User
from app.models.user_role import UserRole
from app.services import cvss_impact_preview, cvss_recalculation, task_publication
from app.services import cvss_recalculation_admission as admission
from app.services import cvss_recalculation_coordination as coordination
from app.services.cvss_recalculation_admission import admit_cvss_recalculation
from tests.support.cvss_chain import Assessment, cve_severity
from tests.support.cvss_recalculation import (
    TARGET,
    DrainSpy,
    RecalculationHarness,
    recalculation_harness,
)
from tests.support.cvss_recalculation_admission import (
    WAIT,
    AdmissionSpy,
    Gate,
    finish,
)
from tests.support.ticket_mutations import StatementRecorder

pytestmark = pytest.mark.e2e

_IMPACT = "/api/v1/admin/settings/default-cvss-version/impact"
_TRIGGER = "/api/v1/admin/settings/default-cvss-version/recalculate"
_PROPOSE_4_0 = {"proposed_version": "4.0"}

# A canonical SUSE 3.1 assessment of 9.8: `Critical` under the persisted
# `3.1`, and `Critical` under a proposed `4.0`, whose cascade takes the
# canonical SUSE assessment at another accepted version (cvss-scoring.md,
# Severity Resolution Cascade). Persisted `Medium` is therefore stale for
# both versions until a unit converges it.
_SUSE_31_CRITICAL = Assessment("9.8")


def _impact(
    *, evaluated: int, severity_changes: int, observed: str = TARGET
) -> dict[str, Any]:
    """The expected `4.0` preview of a ticketless population, whose only
    projectable effect is severity."""
    return {
        "data": {
            "observed_default_cvss_version": observed,
            "proposed_default_cvss_version": "4.0",
            "no_op": False,
            "cves_evaluated": evaluated,
            "cve_severity_changes": severity_changes,
            "product_eligibility_changes": 0,
            "product_eligibility_override_skips": 0,
            "resolved_ticket_regressions": 0,
        }
    }


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
    """The admission spy, installed after the harness, with the harness's
    fenced connection as the admission bind."""
    installed = AdmissionSpy(monkeypatch)
    monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: h.connection)
    return installed


@pytest.fixture
def drain(monkeypatch: pytest.MonkeyPatch) -> DrainSpy:
    return DrainSpy(monkeypatch)


@pytest_asyncio.fixture
async def admin_api_key_client(
    client: AsyncClient,
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
    api_key_factory: Callable[..., Awaitable[ApiKey]],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncClient:
    """The shared `client`, authenticated as an admin by an API key. Unlike
    a JWT session, whose liveness cache is in Redis, API-key
    authentication touches no Redis, so a request-wide Redis spy observes
    the preview alone. Mirrors the identical fixture in
    `tests/test_api/test_settings_impact_preview.py`."""
    user = await user_factory()
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    await api_key_factory(user_id=user.id, key_hash=digest)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    client.headers["Authorization"] = f"Bearer {token}"
    return client


class IOSpy:
    """Records every Redis command (asynchronous and synchronous clients,
    including pipelines, at the connection's send), every broker
    publication, every call into the recalculation coordination module,
    the admission, and the runner, and every preview invocation; each
    wrapper delegates to the original."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[str] = []
        self.previews = 0
        self._patch = monkeypatch
        self._wrap(redis_asyncio.Redis, "execute_command", "redis")
        self._wrap(redis.Redis, "execute_command", "redis")
        self._wrap(redis_asyncio_connection.AbstractConnection, "send_packed_command")
        self._wrap(redis_connection.AbstractConnection, "send_packed_command")
        self._wrap(task_publication, "publish_task", "publish_task")
        for name, value in vars(coordination).items():
            if (
                inspect.isfunction(value)
                and value.__module__ == coordination.__name__
                and not name.startswith("_")
            ):
                self._wrap(coordination, name, f"coordination.{name}")
        self._wrap(admission, "admit_cvss_recalculation", "admission")
        self._wrap(cvss_recalculation, "run_cvss_derived_state_recalculation", "runner")
        preview = cvss_impact_preview.get_default_cvss_version_impact

        async def _preview(*args: Any, **kwargs: Any) -> Any:
            self.previews += 1
            return await preview(*args, **kwargs)

        monkeypatch.setattr(
            cvss_impact_preview, "get_default_cvss_version_impact", _preview
        )

    def _wrap(
        self, owner: type | ModuleType, name: str, label: str = "redis-send"
    ) -> None:
        original = getattr(owner, name)
        if inspect.iscoroutinefunction(original):

            async def _async(*args: Any, **kwargs: Any) -> Any:
                self.calls.append(label)
                return await original(*args, **kwargs)

            self._patch.setattr(owner, name, _async)
        else:

            def _sync(*args: Any, **kwargs: Any) -> Any:
                self.calls.append(label)
                return original(*args, **kwargs)

            self._patch.setattr(owner, name, _sync)


@pytest.fixture
def io(spy: AdmissionSpy, monkeypatch: pytest.MonkeyPatch) -> IOSpy:
    """Installed after the admission spy, so it wraps its recorder."""
    return IOSpy(monkeypatch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _preview(client: AsyncClient, proposed: str = "4.0") -> Response:
    return await client.get(_IMPACT, params={"proposed_version": proposed})


async def _assert_available(client: AsyncClient, phase: str) -> dict[str, Any]:
    """The preview answers `200` with a complete aggregate, never
    `409 CVSS_RECALC_ALREADY_IN_PROGRESS`."""
    response = await _preview(client)
    assert response.status_code == 200, (phase, response.text)
    assert "CVSS_RECALC_ALREADY_IN_PROGRESS" not in response.text, phase
    body: dict[str, Any] = response.json()
    assert body["data"]["observed_default_cvss_version"] == TARGET, phase
    assert body["data"]["no_op"] is False, phase
    return body


async def _stale_population(h: RecalculationHarness) -> list[uuid.UUID]:
    """Two ticketless CVEs whose persisted `Medium` is stale; their IDs in
    the runner's ascending unit order."""
    created: list[CVE] = [
        await h.world.scored_cve(_SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        for _ in range(2)
    ]
    return sorted(cve.id for cve in created)


async def _severities(h: RecalculationHarness, ids: list[uuid.UUID]) -> list[Any]:
    async def _read(db: AsyncSession) -> list[Any]:
        return [await cve_severity(db, cve_id) for cve_id in ids]

    return await h.world.read(_read)


def _token(task_id: str, target: str = TARGET) -> str:
    return f"v1:{task_id}:{target}"


# ---------------------------------------------------------------------------
# Availability in every run phase
# ---------------------------------------------------------------------------


class TestAvailabilityDuringRecalculation:
    async def test_preview_is_200_while_admitted_queued_and_running(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        drain: DrainSpy,
        admin_client: AsyncClient,
    ) -> None:
        """One run is walked through its phases (Lifecycle Phases), and the
        preview is requested in each:

        - `admitted`: the admission holds the fence and the lease (paused
          right after its lease acquisition);
        - `queued`: the admission returned `submitted`; the lease is held,
          the fence is free, and the recorded task was never delivered;
        - `running`: the runner adopted the lease and holds the fence,
          paused at its first unit boundary.

        The run then completes and removes its lease."""
        ids = await _stale_population(h)
        admitted = Gate()
        spy.after_lease = admitted.pause

        trigger = asyncio.create_task(admit_cvss_recalculation())
        try:
            await admitted.wait_reached()
            assert await h.fence_holders() == [h.pid]
            assert await h.lease() == _token(spy.task_id)
            await _assert_available(admin_client, "admitted")
            admitted.release()
            result = await asyncio.wait_for(trigger, WAIT)
        finally:
            await finish(trigger, admitted)

        assert result.outcome == "submitted"
        task_id = spy.task_id
        assert [call.task_id for call in spy.published] == [task_id]
        assert await h.fence_holders() == []
        assert await h.lease() == _token(task_id)
        await _assert_available(admin_client, "queued")

        running = Gate()
        drain.after[0] = running.pause
        run = asyncio.create_task(h.run(task_id))
        try:
            await running.wait_reached()
            assert await h.fence_holders() == [h.pid]
            assert await h.lease() == _token(task_id)
            await _assert_available(admin_client, "running")
            running.release()
            assert await asyncio.wait_for(run, WAIT) is None
        finally:
            await finish(run, running)

        assert await h.lease() is None
        assert await h.fence_holders() == []
        assert await _severities(h, ids) == ["Critical", "Critical"]

    async def test_counts_taken_mid_run_mix_converged_and_unconverged_units(
        self,
        h: RecalculationHarness,
        drain: DrainSpy,
        admin_client: AsyncClient,
    ) -> None:
        """Two CVEs with stale persisted `Medium`; the runner targets the
        persisted `3.1` and converges each to `Critical`. A `4.0` preview
        compares the projected `Critical` with the persisted severity:

        - before the run, both units are unconverged: 2 changes;
        - with the runner paused after its first unit, one unit is
          converged and one is not: 1 change, differing from both the
          pre-run and the post-run result;
        - after the run, both are converged: 0 changes.

        The mid-run count reports neither progress nor remaining work; it
        is the advisory projection of the state committed when each unit
        was read (Active Recalculation Run; Consistency and Staleness)."""
        ids = await _stale_population(h)
        task_id = await h.admit()

        before = await _preview(admin_client)

        gate = Gate()
        drain.after[0] = gate.pause
        run = asyncio.create_task(h.run(task_id))
        try:
            await gate.wait_reached()
            assert await _severities(h, ids) == ["Critical", "Medium"]
            during = await _preview(admin_client)
            gate.release()
            assert await asyncio.wait_for(run, WAIT) is None
        finally:
            await finish(run, gate)

        after = await _preview(admin_client)

        assert [before.status_code, during.status_code, after.status_code] == [
            200,
            200,
            200,
        ]
        assert before.json() == _impact(evaluated=2, severity_changes=2)
        assert during.json() == _impact(evaluated=2, severity_changes=1)
        assert after.json() == _impact(evaluated=2, severity_changes=0)


# ---------------------------------------------------------------------------
# No Redis, task-state, or coordination access
# ---------------------------------------------------------------------------


class TestNoCoordinationAccess:
    async def test_preview_reads_no_redis_task_state_or_coordination(
        self,
        h: RecalculationHarness,
        drain: DrainSpy,
        io: IOSpy,
        admin_api_key_client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """Requested while a runner is mid-run (an admitted lease in Redis,
        the fence held), the complete request, authentication included,
        issues no Redis command on any client, publishes nothing, calls no
        coordination, admission, or runner function, and requests no
        advisory lock or row lock. A Redis read afterwards proves the spy
        observes Redis commands."""
        await _stale_population(h)
        task_id = await h.admit()
        gate = Gate()
        drain.after[0] = gate.pause
        run = asyncio.create_task(h.run(task_id))
        try:
            await gate.wait_reached()
            observed = len(io.calls)

            with StatementRecorder(db_session) as recorder:
                response = await _preview(admin_api_key_client)

            assert response.status_code == 200
            assert io.previews == 1
            assert io.calls[observed:] == []
            assert recorder.statements
            assert [s for s in recorder.statements if "advisory" in s] == []
            assert recorder.row_locks() == []
            gate.release()
            assert await asyncio.wait_for(run, WAIT) is None
        finally:
            await finish(run, gate)

        observed = len(io.calls)
        assert await h.lease() is None
        assert "redis" in io.calls[observed:]


# ---------------------------------------------------------------------------
# The no-op is distinct from the manual trigger
# ---------------------------------------------------------------------------


class TestNoOpDistinctFromTrigger:
    async def test_no_op_preview_admits_nothing_and_the_trigger_still_admits(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        io: IOSpy,
        admin_api_key_client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """A preview proposing the persisted `3.1` is the no-op: every
        count `0`, and no admission, fence, lease, or publication. Neither
        it nor a non-no-op preview has any bearing on the manual trigger,
        which still admits and publishes a complete run for the persisted
        version (No-op Proposal)."""
        await _stale_population(h)
        observed = len(io.calls)

        with StatementRecorder(db_session) as recorder:
            no_op = await _preview(admin_api_key_client, TARGET)

        assert no_op.status_code == 200
        assert no_op.json() == {
            "data": {
                "observed_default_cvss_version": TARGET,
                "proposed_default_cvss_version": TARGET,
                "no_op": True,
                "cves_evaluated": 0,
                "cve_severity_changes": 0,
                "product_eligibility_changes": 0,
                "product_eligibility_override_skips": 0,
                "resolved_ticket_regressions": 0,
            }
        }
        assert io.previews == 1
        assert io.calls[observed:] == []
        assert [s for s in recorder.statements if "advisory" in s] == []
        assert spy.sequence == []
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []

        proposal = await _preview(admin_api_key_client)
        assert proposal.json() == _impact(evaluated=2, severity_changes=2)
        assert spy.published == []

        triggered = await admin_api_key_client.post(_TRIGGER)

        assert triggered.status_code == 202
        assert triggered.json() == {
            "data": {
                "message": "Recalculation batch enqueued",
                "default_cvss_version": TARGET,
                "scope": "all_cves",
            }
        }
        assert spy.sequence == ["fence", "setting", "lease", "release", "publish"]
        assert [call.kwargs for call in spy.published] == [{"target_version": TARGET}]
        assert await h.lease() == _token(spy.task_id)
        assert await h.world.setting() == TARGET
