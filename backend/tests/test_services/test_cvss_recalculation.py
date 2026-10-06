"""Integration tests of the all-CVE default-version recalculation workflow
`run_cvss_derived_state_recalculation()`
(backend/app/services/cvss_recalculation.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (All-CVE
  Recalculation Runner: Input Validation and Stale Delivery, Watermark and
  Keyset Pagination, Concurrent-Change Semantics, Per-CVE Transactional
  Unit, Outcome Classification, Error Taxonomy, Logging; Retry, Rerun, and
  Recovery; Complete-Run Coordination: Execution Fence, Task Adoption,
  Renewal Checkpoints, Ownership Loss, Timeout and Cancellation, Cleanup
  and Recovery Matrix, Coordination Logging);
- docs/features/tickets/ticket-service.md (Ticket Convergence >
  Publication policies, all-CVE recalculation runner; Publication failure
  logging);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner; Ticket Convergence Publication Handoff, all-CVE runner rows;
  Concurrency Testing; Audit Trail Testing);
- issue #836 decisions U3 (borrowed connection), U5 (closed terminal
  classification), U6 (cleanup failures), U7 (correlation), and U9
  (renewal clock); umbrella #833 P8 and P9.

The workflow runs on a borrowed connection of a dedicated engine with a
committed population (tests/support/cvss_recalculation.py); the owned
(engine-bound) path is covered for its connection and disposal contract
only. The task wrapper and its cross-loop regression, the concurrency and
domain-matrix suites, the server-global Redis restart, and hard process
loss are covered by their own modules.

Expected values are transcribed from the specifications; the
`succeeded`/`processed` identities in `_counters()` are the specified
derivations.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from typing import Any, cast

import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import SoftTimeLimitExceeded, WorkerShutdown, WorkerTerminate
from kombu.exceptions import (  # type: ignore[import-untyped]
    EncodeError,
    SerializerNotInstalled,
)
from kombu.exceptions import OperationalError as BrokerOperationalError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy import event, func, select
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from structlog.typing import EventDict, WrappedLogger

from app.core.enums import Severity, TicketStatus
from app.models.cve import CVE
from app.models.setting_audit_event import SettingAuditEvent
from app.models.ticket import Ticket
from app.services import cvss_recalculation
from app.services import cvss_recalculation_coordination as coordination
from app.services import settings as settings_service
from app.services.cvss_recalculation import (
    ADOPTED_EVENT,
    ADOPTION_REJECTED_EVENT,
    CANCELLED_EVENT,
    CLEANUP_FAILED_EVENT,
    COMPLETED_EVENT,
    CVE_FAILED_EVENT,
    CVE_PAGE_SIZE,
    ENGINE_DISPOSE_FAILED_EVENT,
    FAILED_EVENT,
    OWNERSHIP_LOST_EVENT,
    OWNERSHIP_LOST_MESSAGE,
    PARTIAL_EVENT,
    RENEWAL_FAILED_EVENT,
    STALE_EVENT,
    STARTED_EVENT,
)
from app.services.cvss_recalculation_coordination import (
    LEASE_KEY,
    FenceReleaseOutcome,
)
from app.services.ticket_convergence_publication import PUBLICATION_FAILED_EVENT
from app.services.ticket_mutations import CVSSChainMode
from tests.support.cvss_chain import (
    Assessment,
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    subjects,
    ticket_state,
    total_ticket_events,
)
from tests.support.cvss_recalculation import (
    LEAK_MARKER,
    TARGET,
    ChainSpy,
    ConnectionStatements,
    DrainSpy,
    RecalculationHarness,
    capture_events,
    connection_pid,
    database_error,
    deadlock,
    fence_holders,
    non_advisory_locks,
    recalculation_harness,
    runner_events,
    terminate_backend,
    wait_until_fence_free,
)
from tests.support.database import assert_lock_wait
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
    unassigned_event,
)

pytestmark = pytest.mark.integration

SUSE_31_CRITICAL = Assessment("9.8")
"""A canonical SUSE 3.1 assessment: `Critical` when 3.1 is the default."""

SUSE_40_MEDIUM = Assessment("5.3", version="4.0")
"""A canonical SUSE 4.0 assessment: `Medium` when 4.0 is the default."""

_LOW_ID = "00000000-0000-7000-8000-000000000001"
"""A CVE row ID below every generated UUIDv7: inserted after the cursor
passed it."""


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
def chain(monkeypatch: pytest.MonkeyPatch) -> ChainSpy:
    return ChainSpy(monkeypatch)


@pytest.fixture
def drain(monkeypatch: pytest.MonkeyPatch) -> DrainSpy:
    return DrainSpy(monkeypatch)


# ---------------------------------------------------------------------------
# Expected events (default-cvss-version-operations.md, Logging; Coordination
# Logging)
# ---------------------------------------------------------------------------

_TERMINAL = {
    "completed": (COMPLETED_EVENT, "info"),
    "partial": (PARTIAL_EVENT, "warning"),
    "stale": (STALE_EVENT, "info"),
    "cancelled": (CANCELLED_EVENT, "warning"),
    "ownership_lost": (OWNERSHIP_LOST_EVENT, "warning"),
    "failed": (FAILED_EVENT, "error"),
}

_PHASES = {"setting_read", "enumeration", "unit", "publication", "control"}
_CAUSES = {
    "database",
    "domain",
    "programming",
    "infrastructure",
    "interrupted",
    "unexpected",
}
_REASONS = {
    "task_id_invalid",
    "fence_busy",
    "lease_absent",
    "lease_mismatch",
    "redis_error",
    "fence_release_failed",
}
_ALLOWED_FIELDS = {
    "event",
    "log_level",
    "celery_task_id",
    "target_version",
    "watermark",
    "changed",
    "unchanged",
    "skipped",
    "failed",
    "succeeded",
    "processed",
    "phase",
    "cause",
    "reason",
    "cve_id",
}


def _counters(
    changed: int = 0, unchanged: int = 0, skipped: int = 0, failed: int = 0
) -> dict[str, int]:
    succeeded = changed + unchanged
    return {
        "changed": changed,
        "unchanged": unchanged,
        "skipped": skipped,
        "failed": failed,
        "succeeded": succeeded,
        "processed": succeeded + skipped + failed,
    }


def _event(name: str, level: str, task_id: str, **fields: Any) -> dict[str, Any]:
    return {"event": name, "log_level": level, "celery_task_id": task_id, **fields}


def _run_fields(target: str, watermark: object) -> dict[str, Any]:
    fields: dict[str, Any] = {"target_version": target}
    if watermark is not None:
        fields["watermark"] = str(watermark)
    return fields


def _adopted(task_id: str, target: str = TARGET) -> dict[str, Any]:
    return _event(ADOPTED_EVENT, "info", task_id, target_version=target)


def _rejected(task_id: str, reason: str, target: str = TARGET) -> dict[str, Any]:
    return _event(
        ADOPTION_REJECTED_EVENT,
        "warning",
        task_id,
        reason=reason,
        target_version=target,
    )


def _renewal_failed(task_id: str, reason: str) -> dict[str, Any]:
    return _event(
        RENEWAL_FAILED_EVENT, "warning", task_id, reason=reason, target_version=TARGET
    )


def _cleanup_failed(task_id: str, reason: str) -> dict[str, Any]:
    return _event(
        CLEANUP_FAILED_EVENT, "warning", task_id, reason=reason, target_version=TARGET
    )


def _started(task_id: str, watermark: object, target: str = TARGET) -> dict[str, Any]:
    return _event(
        STARTED_EVENT,
        "info",
        task_id,
        **_run_fields(target, watermark),
        **_counters(),
    )


def _cve_failed(task_id: str, cve_identifier: str) -> dict[str, Any]:
    return _event(
        CVE_FAILED_EVENT,
        "warning",
        task_id,
        cve_id=cve_identifier,
        target_version=TARGET,
        phase="unit",
        cause="database",
    )


def _terminal(
    outcome: str,
    task_id: str,
    watermark: object,
    *,
    target: str = TARGET,
    phase: str | None = None,
    cause: str | None = None,
    **counts: int,
) -> dict[str, Any]:
    name, level = _TERMINAL[outcome]
    fields = {**_run_fields(target, watermark), **_counters(**counts)}
    if phase is not None:
        fields.update(phase=phase, cause=cause)
    return _event(name, level, task_id, **fields)


def _assert_sanitized(logs: list[EventDict], task_id: str) -> None:
    """Every runner and coordination event carries only the allowed bounded
    fields and closed vocabularies; no captured event carries an injected
    exception text, a vector, SQL, the lease token, or Ticket content."""
    for entry in runner_events(logs):
        assert set(entry) <= _ALLOWED_FIELDS, entry
        assert entry.get("phase", "unit") in _PHASES
        assert entry.get("cause", "database") in _CAUSES
        assert entry.get("reason", "redis_error") in _REASONS
    forbidden = (
        LEAK_MARKER,
        "CVSS:",
        "SELECT",
        "UPDATE",
        f"v1:{task_id}",
        "fictional-recalc-",
        "Example:Codestream",
        "cpe:/",
        "Traceback",
    )
    for captured in logs:
        assert "exc_info" not in captured
        rendered = repr(dict(captured))
        assert not [marker for marker in forbidden if marker in rendered], captured


# ---------------------------------------------------------------------------
# Readers and injection helpers
# ---------------------------------------------------------------------------


async def _severity(h: RecalculationHarness, cve_id: Any) -> str | None:
    return await h.world.read(lambda db: cve_severity(db, cve_id))


async def _ticket_events(h: RecalculationHarness, ticket: Ticket) -> list[EventRow]:
    return await h.world.read(lambda db: ticket_events_by_id(db, ticket.id))


async def _setting_audit_events(h: RecalculationHarness) -> int:
    async def _count(db: AsyncSession) -> int:
        return (
            await db.execute(select(func.count()).select_from(SettingAuditEvent))
        ).scalar_one()

    return await h.world.read(_count)


def _raise(error: BaseException) -> Callable[[int], Any]:
    async def _hook(_index: int) -> None:
        raise error

    return _hook


def _unit_session(chain: ChainSpy, index: int) -> Callable[[AsyncSession], bool]:
    def _is(session: AsyncSession) -> bool:
        return len(chain.sessions) > index and session is chain.sessions[index]

    return _is


def _fail_session_method(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    target: Callable[[AsyncSession], bool],
    error: BaseException,
    *,
    after_delegating: bool = False,
) -> None:
    """Make `AsyncSession.<method>` raise `error` for the target session,
    before the real call or after it completed (an ambiguous outcome)."""
    original = getattr(AsyncSession, method)

    async def _replacement(self: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        if not target(self):
            return await original(self, *args, **kwargs)
        if after_delegating:
            await original(self, *args, **kwargs)
        raise error

    monkeypatch.setattr(AsyncSession, method, _replacement)


def _fail_statement(
    monkeypatch: pytest.MonkeyPatch, marker: str, error: BaseException
) -> None:
    """Make every `AsyncSession.execute()` of a statement whose SQL contains
    `marker` raise `error`."""
    original = AsyncSession.execute

    async def _execute(
        self: AsyncSession, statement: Any, *args: Any, **kw: Any
    ) -> Any:
        if marker in str(statement):
            raise error
        return await original(self, statement, *args, **kw)

    monkeypatch.setattr(AsyncSession, "execute", _execute)


class _RenewSpy:
    """Wraps the runner's `compare_and_renew_lease`, recording before which
    unit each renewal ran; `errors[i]` makes renewal `i` raise (after the
    real command when `after_send`)."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, chain: ChainSpy | None = None
    ) -> None:
        self.positions: list[int] = []
        self.errors: dict[int, BaseException] = {}
        self.after_send = False
        original = coordination.compare_and_renew_lease

        async def _renew(client: Any, **kwargs: Any) -> Any:
            index = len(self.positions)
            self.positions.append(len(chain.calls) if chain is not None else -1)
            error = self.errors.get(index)
            if error is None:
                return await original(client, **kwargs)
            if self.after_send:
                await original(client, **kwargs)
            raise error

        monkeypatch.setattr(cvss_recalculation, "compare_and_renew_lease", _renew)


async def _advance_clock(h: RecalculationHarness, seconds: float) -> None:
    h.clock.advance(seconds)


async def _escape(awaitable: Awaitable[object]) -> BaseException:
    """Await and return the exception that escapes, without prescribing
    its class; fail when nothing escapes."""
    try:
        await awaitable
    except BaseException as exc:  # any escape is the proof
        return exc
    raise AssertionError("no exception escaped the workflow")


# ---------------------------------------------------------------------------
# Pagination and population
# ---------------------------------------------------------------------------


class TestPaginationAndPopulation:
    async def test_empty_table_completes_with_zero_counters_and_no_unit_session(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        task_id = await h.admit()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert chain.calls == []
        # The setting read and the watermark read only: no page or unit.
        assert len(h.factory.created) == 2
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, None),
            _terminal("completed", task_id, None),
        ]
        assert h.published.calls == []
        assert await h.world.read(total_ticket_events) == 0
        assert await h.lease() is None
        assert await h.fence_holders() == []

    @pytest.mark.parametrize("count", [1, 499, 500, 501])
    async def test_population_is_processed_in_full_with_500_per_page(
        self, h: RecalculationHarness, chain: ChainSpy, count: int
    ) -> None:
        ids = await h.world.bulk_cves(count)
        task_id = await h.admit()

        with ConnectionStatements(h.connection) as recorder, capture_events() as logs:
            await h.run(task_id)

        assert chain.cve_ids == ids
        pages = recorder.pages()
        # 500 is a per-page maximum: a full page is followed by another read.
        assert len(pages) == count // CVE_PAGE_SIZE + 1
        assert all(parameters[-1] == CVE_PAGE_SIZE for _, parameters in pages)
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, ids[-1]),
            _terminal("completed", task_id, ids[-1], unchanged=count),
        ]

    async def test_full_pages_and_partial_page_use_the_keyset_cursor_ascending(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        ids = await h.world.bulk_cves(2 * CVE_PAGE_SIZE + 7)
        task_id = await h.admit()

        with ConnectionStatements(h.connection) as recorder:
            await h.run(task_id)

        assert chain.cve_ids == ids
        pages = recorder.pages()
        assert len(pages) == 3
        first, second, third = pages
        # `last_id < CVE.id <= watermark`: the cursor is the last identity
        # of the previous page; there is no offset arithmetic.
        assert "cve.id >" not in first[0]
        assert first[1] == (ids[-1], CVE_PAGE_SIZE)
        assert second[1] == (ids[-1], ids[CVE_PAGE_SIZE - 1], CVE_PAGE_SIZE)
        assert third[1] == (ids[-1], ids[2 * CVE_PAGE_SIZE - 1], CVE_PAGE_SIZE)
        assert not [s for s, _ in recorder.statements if "OFFSET" in s.upper()]

    async def test_rows_beyond_the_watermark_or_behind_the_cursor_wait_for_a_rerun(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        """A CVE above the captured watermark is excluded; a CVE inside it
        that becomes visible after the cursor passed its key is deferred.
        The watermark is never returned or stored in Redis."""
        ids = await h.world.bulk_cves(CVE_PAGE_SIZE + 1)
        late: list[Any] = []

        async def insert_late(_index: int) -> None:
            above = await h.world.scored_cve()
            behind = await h.world.scored_cve(cve_uuid=uuid.UUID(_LOW_ID))
            late.extend([behind.id, above.id])

        chain.after[0] = insert_late
        task_id = await h.admit()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert chain.cve_ids == ids
        assert runner_events(logs)[-1] == _terminal(
            "completed", task_id, ids[-1], unchanged=len(ids)
        )
        assert await h.redis.keys("*") == []

        rerun = await h.admit()
        with capture_events() as logs:
            await h.run(rerun)

        assert chain.cve_ids[len(ids) :] == [late[0], *ids, late[1]]
        assert runner_events(logs)[-1] == _terminal(
            "completed", rerun, late[1], unchanged=len(ids) + 2
        )

    async def test_no_transaction_spans_the_fence_pages_or_units(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each page read completes in its own session before its units
        begin; the connection has no open transaction directly after fence
        acquisition, before every page and unit session, and after every
        commit (observed at the post-close drain)."""
        ids = await h.world.bulk_cves(CVE_PAGE_SIZE + 1)
        after_fence: list[bool] = []
        at_drain: list[bool] = []
        acquire = coordination.try_acquire_execution_fence

        async def _acquire(connection: AsyncConnection) -> Any:
            outcome = await acquire(connection)
            after_fence.append(connection.in_transaction())
            return outcome

        async def _drained(_index: int) -> None:
            at_drain.append(h.connection.in_transaction())

        monkeypatch.setattr(cvss_recalculation, "try_acquire_execution_fence", _acquire)
        drain.before.update(dict.fromkeys(range(len(ids)), _drained))
        task_id = await h.admit()

        await h.run(task_id)

        kinds = [
            "unit" if chain.is_unit(session) else "read"
            for session, _ in h.factory.created
        ]
        assert kinds == (["read"] * 3 + ["unit"] * CVE_PAGE_SIZE + ["read"] + ["unit"])
        assert [open_ for _, open_ in h.factory.created] == [False] * len(kinds)
        assert after_fence == [False]
        assert at_drain == [False] * len(ids)


# ---------------------------------------------------------------------------
# Recalculation part of carried-in line 1
# ---------------------------------------------------------------------------


class _SettingReads:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.count = 0
        original = settings_service.get_default_cvss_version

        async def _read(session: AsyncSession) -> str:
            self.count += 1
            return await original(session)

        monkeypatch.setattr(settings_service, "get_default_cvss_version", _read)


class TestTargetVersion:
    async def test_every_unit_uses_the_target_in_default_version_mode(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await h.world.set_setting("4.0")
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, SUSE_40_MEDIUM) for _ in range(3)
        ]
        reads = _SettingReads(monkeypatch)
        task_id = await h.admit("4.0")

        with capture_events() as logs:
            await h.run(task_id, target_version="4.0")

        assert chain.calls == [
            {
                "cve_id": cve.id,
                "mode": CVSSChainMode.DEFAULT_VERSION,
                "default_cvss_version": "4.0",
                "evaluation_date": EVAL,
            }
            for cve in cves
        ]
        # The stale check only; no unit reads the setting.
        assert reads.count == 1
        assert [await _severity(h, cve.id) for cve in cves] == ["Medium"] * 3
        assert runner_events(logs)[-1] == _terminal(
            "completed", task_id, cves[-1].id, target="4.0", changed=3
        )

    async def test_setting_written_after_the_stale_check_changes_no_resolution(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, SUSE_40_MEDIUM) for _ in range(3)
        ]

        async def change_setting(_index: int) -> None:
            await h.world.set_setting("4.0")

        chain.before[0] = change_setting
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert await h.world.setting() == "4.0"
        assert [call["default_cvss_version"] for call in chain.calls] == [TARGET] * 3
        assert [await _severity(h, cve.id) for cve in cves] == ["Critical"] * 3
        assert runner_events(logs)[-1] == _terminal(
            "completed", task_id, cves[-1].id, changed=3
        )


# ---------------------------------------------------------------------------
# Complete-run coordination, task side
# ---------------------------------------------------------------------------


class TestAdoption:
    @pytest.mark.parametrize(
        ("make_error", "after_send"),
        [
            pytest.param(RedisTimeoutError, False, id="timeout"),
            pytest.param(RedisTimeoutError, True, id="timeout-after-send"),
            pytest.param(RedisConnectionError, False, id="connection-error"),
        ],
    )
    async def test_initial_renew_redis_error_only_rejects_adoption(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
        make_error: type[Exception],
        after_send: bool,
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        renew = _RenewSpy(monkeypatch)
        renew.errors[0] = make_error(LEAK_MARKER)
        renew.after_send = after_send
        task_id = await h.admit()
        lease = await h.lease()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert runner_events(logs) == [_rejected(task_id, "redis_error")]
        _assert_sanitized(logs, task_id)
        assert chain.calls == []
        assert h.factory.created == []
        assert await _severity(h, cve.id) == "Low"
        # No ownership was confirmed: no compare-and-delete, fence released.
        assert await h.lease() == lease
        assert await h.fence_holders() == []
        assert h.connection.in_transaction() is False
        assert h.connection.invalidated is False

    async def test_database_error_during_fence_acquisition_propagates_silently(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL)
        error = database_error()

        async def _acquire(_connection: AsyncConnection) -> Any:
            raise error

        monkeypatch.setattr(cvss_recalculation, "try_acquire_execution_fence", _acquire)
        task_id = await h.admit()
        lease = await h.lease()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert runner_events(logs) == []
        assert chain.calls == []
        assert await h.lease() == lease
        assert await h.fence_holders() == []

    async def test_sequential_deliveries_of_one_token_adopt_once(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        task_id = await h.admit()
        await h.run(task_id)
        await h.world.set_cve_severity(cve.id, Severity.LOW.value)

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert runner_events(logs) == [_rejected(task_id, "lease_absent")]
        assert len(chain.calls) == 1
        assert await _severity(h, cve.id) == "Low"
        assert await h.fence_holders() == []

    async def test_concurrent_delivery_of_one_token_finds_the_fence_busy(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        paused, resume = asyncio.Event(), asyncio.Event()

        async def hold(_index: int) -> None:
            paused.set()
            await resume.wait()

        drain.after[0] = hold
        task_id = await h.admit()
        second = await h.borrow()

        with capture_events() as logs:
            first = asyncio.create_task(h.run(task_id))
            try:
                await asyncio.wait_for(paused.wait(), timeout=5)
                mark = len(logs)
                result = await asyncio.wait_for(
                    h.run(task_id, factory=second), timeout=5
                )
                duplicate = runner_events(logs[mark:])
                holders = await h.fence_holders()
            finally:
                resume.set()
                await asyncio.wait_for(first, timeout=10)

        assert result is None
        assert duplicate == [_rejected(task_id, "fence_busy")]
        assert holders == [h.pid]
        assert second.created == []
        assert second.connection.in_transaction() is False
        assert second.connection.invalidated is False
        assert chain.cve_ids == [cve.id for cve in cves]
        assert runner_events(logs)[-1] == _terminal(
            "completed", task_id, cves[-1].id, changed=2
        )

    async def test_old_token_against_a_newer_owner_mutates_nothing(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        newer = await h.admit()
        old = str(uuid.uuid4())

        with capture_events() as logs:
            result = await h.run(old)

        assert result is None
        assert runner_events(logs) == [_rejected(old, "lease_mismatch")]
        assert chain.calls == []
        assert await _severity(h, cve.id) == "Low"
        assert await h.lease() == f"v1:{newer}:{TARGET}"
        assert await h.fence_holders() == []

    async def test_delayed_old_delivery_after_the_newer_owner_completed(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        old = await h.admit()
        await h.redis.delete(LEASE_KEY)  # expired, then a newer admission
        newer = await h.admit()
        await h.run(newer)
        await h.world.set_cve_severity(cve.id, Severity.LOW.value)

        with capture_events() as logs:
            result = await h.run(old)

        assert result is None
        assert runner_events(logs) == [_rejected(old, "lease_absent")]
        assert len(chain.calls) == 1
        assert await _severity(h, cve.id) == "Low"
        assert await h.lease() is None


class TestRenewalCheckpoints:
    async def test_renewal_runs_at_the_60_second_boundary_and_never_before(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await h.world.bulk_cves(4)
        renew = _RenewSpy(monkeypatch, chain)
        drain.after[0] = lambda _i: _advance_clock(h, 59.5)
        drain.after[1] = lambda _i: _advance_clock(h, 0.5)  # exactly 60 s
        drain.after[2] = lambda _i: _advance_clock(h, 59.75)
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        # The adoption renewal before any unit, then one checkpoint before
        # the third unit; none at 59.5 s or 59.75 s after a renewal.
        assert renew.positions == [0, 2]
        assert runner_events(logs)[-1]["event"] == COMPLETED_EVENT

    async def test_checkpoint_redis_error_is_ownership_lost_infrastructure(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        renew = _RenewSpy(monkeypatch, chain)
        error = RedisConnectionError(LEAK_MARKER)
        renew.errors[1] = error
        drain.after[0] = lambda _i: _advance_clock(h, 60)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(RedisConnectionError) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _renewal_failed(task_id, "redis_error"),
            _terminal(
                "ownership_lost",
                task_id,
                cves[-1].id,
                phase="control",
                cause="infrastructure",
                changed=1,
            ),
        ]
        _assert_sanitized(logs, task_id)
        assert len(chain.calls) == 1
        assert await _severity(h, cves[1].id) == "Low"
        assert await h.lease() is None
        assert await h.fence_holders() == []

    async def test_lease_expiry_between_units_blocks_the_next_unit(
        self, h: RecalculationHarness, chain: ChainSpy, drain: DrainSpy
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(3)
        ]

        async def expire(_index: int) -> None:
            await h.redis.pexpire(LEASE_KEY, 1)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 5
            while await h.redis.exists(LEASE_KEY):
                assert loop.time() < deadline
                await asyncio.sleep(0.005)
            h.clock.advance(60)

        drain.after[0] = expire
        task_id = await h.admit()

        with capture_events() as logs:
            await _escape(h.run(task_id))

        assert runner_events(logs)[-2:] == [
            _renewal_failed(task_id, "lease_absent"),
            _terminal(
                "ownership_lost",
                task_id,
                cves[-1].id,
                phase="control",
                cause="interrupted",
                changed=1,
            ),
        ]
        assert len(chain.calls) == 1
        assert [await _severity(h, cve.id) for cve in cves[1:]] == ["Low", "Low"]
        assert await h.fence_holders() == []

    async def test_checkpoint_mismatch_terminates_and_the_newer_lease_survives(
        self, h: RecalculationHarness, chain: ChainSpy, drain: DrainSpy
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        newer = f"v1:{uuid.uuid4()}:{TARGET}"

        async def replace(_index: int) -> None:
            await h.redis.set(LEASE_KEY, newer, ex=900)
            h.clock.advance(60)

        drain.after[0] = replace
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(RuntimeError) as raised:
            await h.run(task_id)

        # The service contract (Q6): the built-in RuntimeError with the
        # fixed message; the wrapper-level tests assert only the escape.
        assert type(raised.value) is RuntimeError
        assert str(raised.value) == OWNERSHIP_LOST_MESSAGE
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _renewal_failed(task_id, "lease_mismatch"),
            _terminal(
                "ownership_lost",
                task_id,
                cves[-1].id,
                phase="control",
                cause="interrupted",
                changed=1,
            ),
        ]
        assert len(chain.calls) == 1
        # Compare-and-delete against the newer value is a mismatch no-op.
        assert await h.lease() == newer
        assert await h.fence_holders() == []


class TestFencedConnectionLoss:
    async def test_terminated_fenced_backend_fails_the_run_without_mutation(
        self, h: RecalculationHarness, chain: ChainSpy, drain: DrainSpy
    ) -> None:
        """`pg_terminate_backend()` on the fenced backend only, at a unit
        boundary: the next unit's session fails at its first statement and
        the run terminates `failed`/`database` with no further unit, a
        compare-and-delete attempt, and the fence released by the closure.
        The workflow never reconnects: no new backend connection is opened
        after the loss, and no explicit release is attempted on it."""
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(3)
        ]
        drain.after[0] = lambda _i: terminate_backend(h.observer, h.pid)
        task_id = await h.admit()
        connects: list[object] = []

        def _record_connect(dbapi_connection: object, _record: object) -> None:
            connects.append(dbapi_connection)

        event.listen(h.engine.sync_engine, "connect", _record_connect)
        try:
            with capture_events() as logs:
                escaped = await _escape(h.run(task_id))
        finally:
            event.remove(h.engine.sync_engine, "connect", _record_connect)

        assert connects == []

        assert getattr(escaped, "connection_invalidated", False) is True
        events = runner_events(logs)
        assert events[:2] == [_adopted(task_id), _started(task_id, cves[-1].id)]
        assert events[-1] == _terminal(
            "failed",
            task_id,
            cves[-1].id,
            phase="unit",
            cause="database",
            changed=1,
        )
        assert events[2:-1] == []
        # The second unit failed at its first statement; no third unit.
        assert len(chain.calls) == 2
        assert all(session.bind is h.connection for session in chain.sessions)
        assert [await _severity(h, cve.id) for cve in cves] == [
            "Critical",
            "Low",
            "Low",
        ]
        assert await h.lease() is None
        await wait_until_fence_free(h.engine)


class TestCoordinationIsolation:
    async def test_no_redis_or_broker_io_runs_under_a_transaction_or_row_lock(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        for _ in range(2):
            await h.world.regressing_ticket()
        observed: list[tuple[str, bool, list[str]]] = []

        async def observe(name: str) -> None:
            observed.append(
                (
                    name,
                    h.connection.in_transaction(),
                    await non_advisory_locks(h.observer, h.pid),
                )
            )

        for name in ("compare_and_renew_lease", "compare_and_delete_lease"):
            original = getattr(cvss_recalculation, name)

            async def _wrapped(
                client: Any, *, _name: str = name, _original: Any = original, **kw: Any
            ) -> Any:
                await observe(_name)
                return await _original(client, **kw)

            monkeypatch.setattr(cvss_recalculation, name, _wrapped)

        async def on_publish(_ticket_id: str) -> None:
            await observe("publish")

        h.published.on_call = on_publish
        drain.after[0] = lambda _i: _advance_clock(h, 60)
        task_id = await h.admit()

        await h.run(task_id)

        assert observed == [
            ("compare_and_renew_lease", False, []),
            ("publish", False, []),
            ("compare_and_renew_lease", False, []),
            ("publish", False, []),
            ("compare_and_delete_lease", False, []),
        ]

    @pytest.mark.parametrize(
        "path",
        ["completed", "partial", "stale", "cancelled", "failed", "ownership_lost"],
    )
    async def test_every_terminal_path_closes_deletes_releases_then_reports(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
    ) -> None:
        for _ in range(2):
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        sequence: list[str] = []
        fenced_at_delete: list[list[int]] = []
        close = AsyncSession.close

        async def _close(self: AsyncSession) -> None:
            if chain.is_unit(self):
                sequence.append(f"close:{chain.sessions.index(self)}")
            await close(self)

        delete_lease = coordination.compare_and_delete_lease
        release = coordination.release_execution_fence

        async def _delete(client: Any, **kwargs: Any) -> Any:
            sequence.append("delete")
            fenced_at_delete.append(await fence_holders(h.observer))
            return await delete_lease(client, **kwargs)

        async def _release(connection: AsyncConnection) -> Any:
            sequence.append("release")
            return await release(connection)

        def _record(
            _logger: WrappedLogger, _method: str, entry: EventDict
        ) -> EventDict:
            name = str(entry["event"])
            if name.startswith("cvss_recalculation_"):
                sequence.append(name.removeprefix("cvss_recalculation_"))
            return entry

        monkeypatch.setattr(AsyncSession, "close", _close)
        monkeypatch.setattr(cvss_recalculation, "compare_and_delete_lease", _delete)
        monkeypatch.setattr(cvss_recalculation, "release_execution_fence", _release)
        expected_tail: list[str]
        if path == "partial":
            chain.after[0] = _raise(deadlock())
            expected_tail = ["close:0", "cve_failed", "close:1"]
        elif path == "stale":
            await h.world.set_setting("4.0")
            expected_tail = []
        elif path == "cancelled":
            chain.after[0] = _raise(asyncio.CancelledError())
            expected_tail = ["close:0"]
        elif path == "failed":
            chain.after[0] = _raise(TypeError(LEAK_MARKER))
            expected_tail = ["close:0"]
        elif path == "ownership_lost":

            async def replace(_index: int) -> None:
                await h.redis.set(LEASE_KEY, f"v1:{uuid.uuid4()}:{TARGET}")
                h.clock.advance(60)

            drain.after[0] = replace
            expected_tail = ["close:0", "renewal_failed"]
        else:
            expected_tail = ["close:0", "close:1"]
        task_id = await h.admit()

        with capture_events(_record), suppress(BaseException):
            await h.run(task_id)

        prefix = ["adopted"] if path == "stale" else ["adopted", "started"]
        assert sequence == [*prefix, *expected_tail, "delete", "release", path]
        assert fenced_at_delete == [[h.pid]]
        assert await h.fence_holders() == []

    async def test_cleanup_redis_error_still_releases_and_leaves_the_lease_to_ttl(
        self, h: RecalculationHarness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)

        async def _delete(_client: Any, **_kwargs: Any) -> Any:
            raise RedisConnectionError(LEAK_MARKER)

        monkeypatch.setattr(cvss_recalculation, "compare_and_delete_lease", _delete)
        task_id = await h.admit()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cve.id),
            _cleanup_failed(task_id, "redis_error"),
            _terminal("completed", task_id, cve.id, changed=1),
        ]
        _assert_sanitized(logs, task_id)
        assert await h.fence_holders() == []
        assert await h.lease() == f"v1:{task_id}:{TARGET}"
        assert 0 < await h.redis.ttl(LEASE_KEY) <= 900


def _fail_release_statement(
    monkeypatch: pytest.MonkeyPatch, signal: BaseException
) -> list[AsyncConnection]:
    """Run the real `release_execution_fence()`, whose unlock statement
    raises `signal`: the helper invalidates the connection and re-raises.
    Returns the connections passed to the release."""
    release = coordination.release_execution_fence
    execute = AsyncConnection.execute
    releasing: list[AsyncConnection] = []

    async def _release(connection: AsyncConnection) -> Any:
        releasing.append(connection)
        return await release(connection)

    async def _execute(self: AsyncConnection, *args: Any, **kwargs: Any) -> Any:
        if releasing and self is releasing[0]:
            raise signal
        return await execute(self, *args, **kwargs)

    monkeypatch.setattr(cvss_recalculation, "release_execution_fence", _release)
    monkeypatch.setattr(AsyncConnection, "execute", _execute)
    return releasing


class TestCleanupSignals:
    """Decision U6: a signal raised by a cleanup step lets the remaining
    steps and the terminal event run; the original whole-run exception
    keeps precedence, otherwise the signal propagates afterwards."""

    @pytest.mark.parametrize(
        "make_signal",
        [
            pytest.param(lambda: asyncio.CancelledError(LEAK_MARKER), id="cancel"),
            pytest.param(lambda: MemoryError(LEAK_MARKER), id="memory"),
        ],
    )
    async def test_signal_during_the_initial_renew_releases_and_propagates_silently(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        signal = make_signal()
        renew = _RenewSpy(monkeypatch)
        renew.errors[0] = signal
        task_id = await h.admit()
        lease = await h.lease()

        with capture_events() as logs, pytest.raises(type(signal)) as raised:
            await h.run(task_id)

        # No adoption outcome is reached: no event, no counters, no unit.
        assert raised.value is signal
        assert runner_events(logs) == []
        assert chain.calls == []
        assert await h.lease() == lease
        assert await h.fence_holders() == []

    @pytest.mark.parametrize("step", ["delete", "release"])
    async def test_cleanup_signal_after_an_ordinary_outcome_propagates_last(
        self,
        h: RecalculationHarness,
        monkeypatch: pytest.MonkeyPatch,
        step: str,
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        signal = asyncio.CancelledError(LEAK_MARKER)
        releasing: list[AsyncConnection] = []
        if step == "delete":

            async def _delete(_client: Any, **_kwargs: Any) -> Any:
                raise signal

            monkeypatch.setattr(cvss_recalculation, "compare_and_delete_lease", _delete)
        else:
            releasing = _fail_release_statement(monkeypatch, signal)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(asyncio.CancelledError) as raised:
            await h.run(task_id)

        assert raised.value is signal
        cleanup = (
            []
            if step == "delete"
            else [_cleanup_failed(task_id, "fence_release_failed")]
        )
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cve.id),
            *cleanup,
            _terminal("completed", task_id, cve.id, changed=1),
        ]
        if step == "delete":
            # The fence release still ran; the lease is left to its TTL.
            assert await h.fence_holders() == []
            assert await h.lease() == f"v1:{task_id}:{TARGET}"
        else:
            # The release helper invalidated the connection (U3): its
            # closure releases the fence.
            assert releasing == [h.connection]
            assert h.connection.invalidated is True
            assert await h.lease() is None
            await wait_until_fence_free(h.engine)

    @pytest.mark.parametrize("step", ["close", "delete", "release"])
    async def test_cleanup_signal_never_replaces_the_whole_run_exception(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
        step: str,
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = TypeError(LEAK_MARKER)
        signal = asyncio.CancelledError(LEAK_MARKER)
        chain.after[0] = _raise(error)
        if step == "close":
            # The signal arrives once the real close ended the transaction.
            _fail_session_method(
                monkeypatch,
                "close",
                _unit_session(chain, 0),
                signal,
                after_delegating=True,
            )
        elif step == "delete":

            async def _delete(_client: Any, **_kwargs: Any) -> Any:
                raise signal

            monkeypatch.setattr(cvss_recalculation, "compare_and_delete_lease", _delete)
        else:
            _fail_release_statement(monkeypatch, signal)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(TypeError) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert runner_events(logs)[-1] == _terminal(
            "failed", task_id, cve.id, phase="unit", cause="programming"
        )
        assert await h.lease() == (
            f"v1:{task_id}:{TARGET}" if step == "delete" else None
        )
        await wait_until_fence_free(h.engine)


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


class TestTransactions:
    async def test_one_fresh_session_and_one_transaction_per_cve(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        for _ in range(3):
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        sequence: list[str] = []
        after_commit: list[bool] = []
        unflushed_at_commit: list[bool] = []
        sync_connection = h.connection.sync_connection
        assert sync_connection is not None
        listeners = {
            name: (lambda *_args, _name=name: sequence.append(_name))
            for name in ("begin", "commit", "rollback")
        }
        commit = AsyncSession.commit

        async def _commit(self: AsyncSession) -> None:
            # Step 5: every mutation is flushed before finalization.
            unflushed_at_commit.append(bool(self.new or self.dirty or self.deleted))
            await commit(self)
            after_commit.append(h.connection.in_transaction())

        original_call = h.factory.__class__.__call__

        def _created(self: Any, **kw: Any) -> AsyncSession:
            sequence.append("session")
            return original_call(self, **kw)

        async def _chain_started(_index: int) -> None:
            sequence.append("chain")

        chain.before.update(dict.fromkeys(range(3), _chain_started))
        monkeypatch.setattr(AsyncSession, "commit", _commit)
        monkeypatch.setattr(h.factory.__class__, "__call__", _created)
        for name, listener in listeners.items():
            event.listen(sync_connection, name, listener)
        task_id = await h.admit()
        try:
            await h.run(task_id)
        finally:
            for name, listener in listeners.items():
                event.remove(sync_connection, name, listener)

        read = ["session", "begin", "rollback"]
        unit = ["session", "chain", "begin", "commit"]
        assert sequence == [
            *["begin", "commit"],  # fence acquisition
            *read,  # setting
            *read,  # watermark
            *read,  # page
            *unit,
            *unit,
            *unit,
            *["begin", "commit"],  # fence release
        ]
        assert len({id(session) for session in chain.sessions}) == 3
        assert after_commit == [False] * 3
        assert unflushed_at_commit == [False] * 3
        assert [await _severity(h, cve_id) for cve_id in chain.cve_ids] == [
            "Critical"
        ] * 3

    async def test_committed_sibling_survives_a_later_failure(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        error = TypeError(LEAK_MARKER)
        chain.after[1] = _raise(error)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(TypeError) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert runner_events(logs)[-1] == _terminal(
            "failed",
            task_id,
            cves[-1].id,
            phase="unit",
            cause="programming",
            changed=1,
        )
        assert [await _severity(h, cve.id) for cve in cves] == ["Critical", "Low"]

    @pytest.mark.parametrize("point", ["after-chain-writes", "at-flush"])
    async def test_isolated_deadlock_rolls_back_the_entire_unit(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
        point: str,
    ) -> None:
        """Severity, Product eligibility, assignment, status, priority, and
        every audit event of the unit roll back; its registered effect is
        never drained; the next CVE commits."""
        cve, ticket, _ = await h.world.regressing_ticket(assignee_active=False)
        sibling = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        before = (
            await h.world.read(lambda db: ticket_state(db, ticket.id)),
            await h.world.read(lambda db: eligibility(db, ticket.id)),
        )
        if point == "after-chain-writes":
            chain.after[0] = _raise(deadlock())
        else:
            _fail_session_method(
                monkeypatch,
                "flush",
                _unit_session(chain, 0),
                deadlock(),
                after_delegating=True,
            )
        task_id = await h.admit()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, sibling.id),
            _cve_failed(task_id, cve.cve_id),
            _terminal("partial", task_id, sibling.id, changed=1, failed=1),
        ]
        assert await _severity(h, cve.id) == "Medium"
        assert (
            await h.world.read(lambda db: ticket_state(db, ticket.id)),
            await h.world.read(lambda db: eligibility(db, ticket.id)),
        ) == before
        assert await _ticket_events(h, ticket) == []
        assert drain.calls == 1
        assert h.published.calls == []
        assert await _severity(h, sibling.id) == "Critical"

    async def test_real_deadlock_against_a_ticket_first_transaction_is_isolated(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        """An independent transaction holds the unit's Ticket, the unit
        holds the CVE and waits for the Ticket, then the independent
        transaction requests the CVE: PostgreSQL aborts the unit, which
        waited first, with `40P01`."""
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        ticket = await h.world.ticket(cve_id=cve.id, status=TicketStatus.ANALYSIS)
        sibling = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        holder = await h.world.open_session()
        await holder.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )
        task_id = await h.admit()
        waiter = AsyncSession(bind=h.connection)

        with capture_events() as logs:
            run = asyncio.create_task(h.run(task_id))
            await assert_lock_wait(run, waiter=waiter, blocked_by=holder)
            conflict = h.world.start(
                holder,
                holder.execute(
                    select(CVE.id).where(CVE.id == cve.id).with_for_update()
                ),
            )
            await asyncio.wait_for(asyncio.shield(run), timeout=10)
            await asyncio.wait_for(conflict, timeout=5)
            await holder.rollback()
        await waiter.close()

        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, sibling.id),
            _cve_failed(task_id, cve.cve_id),
            _terminal("partial", task_id, sibling.id, changed=1, failed=1),
        ]
        assert await _severity(h, cve.id) == "Low"
        assert await _ticket_events(h, ticket) == []
        assert await _severity(h, sibling.id) == "Critical"

    @pytest.mark.parametrize("ambiguous", [False, True], ids=["failed", "ambiguous"])
    async def test_failed_or_ambiguous_commit_publishes_nothing(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
        ambiguous: bool,
    ) -> None:
        cve, ticket, _ = await h.world.regressing_ticket()
        sibling = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = database_error()
        _fail_session_method(
            monkeypatch,
            "commit",
            _unit_session(chain, 0),
            error,
            after_delegating=ambiguous,
        )
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        # Counter treatment follows the commit boundary: an ambiguous
        # commit is never classified, even though it became durable.
        assert runner_events(logs)[-1] == _terminal(
            "failed", task_id, sibling.id, phase="unit", cause="database"
        )
        _assert_sanitized(logs, task_id)
        assert len(chain.calls) == 1
        assert drain.calls == 0
        assert h.published.calls == []
        assert await _severity(h, cve.id) == ("Critical" if ambiguous else "Medium")
        assert (await _ticket_events(h, ticket) != []) is ambiguous

    async def test_effects_are_drained_once_after_commit_and_close_before_the_next_unit(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tickets = [(await h.world.regressing_ticket())[1] for _ in range(2)]
        sequence: list[str] = []
        commit, close = AsyncSession.commit, AsyncSession.close

        async def _commit(self: AsyncSession) -> None:
            await commit(self)
            if chain.is_unit(self):
                sequence.append(f"commit:{chain.sessions.index(self)}")

        async def _close(self: AsyncSession) -> None:
            await close(self)
            if chain.is_unit(self):
                sequence.append(f"close:{chain.sessions.index(self)}")

        async def _chain_started(index: int) -> None:
            sequence.append(f"chain:{index}")

        async def on_publish(ticket_id: str) -> None:
            # Locks are released: the Ticket is lockable without waiting.
            await h.observer.execute(
                select(Ticket.id)
                .where(Ticket.id == uuid.UUID(ticket_id))
                .with_for_update(nowait=True)
            )
            sequence.append(f"publish:{tickets.index(_by_id(tickets, ticket_id))}")

        monkeypatch.setattr(AsyncSession, "commit", _commit)
        monkeypatch.setattr(AsyncSession, "close", _close)
        chain.before.update(dict.fromkeys(range(2), _chain_started))
        h.published.on_call = on_publish
        task_id = await h.admit()

        await h.run(task_id)

        assert sequence == [
            *["chain:0", "commit:0", "close:0", "publish:0"],
            *["chain:1", "commit:1", "close:1", "publish:1"],
        ]
        assert h.published.calls == [str(ticket.id) for ticket in tickets]


def _by_id(tickets: list[Ticket], ticket_id: str) -> Ticket:
    return next(ticket for ticket in tickets if str(ticket.id) == ticket_id)


# ---------------------------------------------------------------------------
# Ticket Convergence Publication Handoff (all-CVE runner rows)
# ---------------------------------------------------------------------------

_DRAIN_EXCEPTIONS = [
    pytest.param(
        lambda: asyncio.CancelledError(LEAK_MARKER),
        "cancelled",
        "interrupted",
        id="cancel",
    ),
    pytest.param(
        lambda: WorkerShutdown(LEAK_MARKER),
        "cancelled",
        "interrupted",
        id="worker-shutdown",
    ),
    pytest.param(
        lambda: SoftTimeLimitExceeded(LEAK_MARKER),
        "failed",
        "interrupted",
        id="soft-time-limit",
    ),
    pytest.param(lambda: MemoryError(LEAK_MARKER), "failed", "unexpected", id="memory"),
    pytest.param(
        lambda: EncodeError(LEAK_MARKER), "failed", "programming", id="encode"
    ),
    pytest.param(
        lambda: SerializerNotInstalled(LEAK_MARKER),
        "failed",
        "programming",
        id="serializer-not-installed",
    ),
    pytest.param(
        lambda: TypeError(LEAK_MARKER), "failed", "programming", id="contract"
    ),
    pytest.param(
        lambda: RuntimeError(LEAK_MARKER), "failed", "unexpected", id="runtime"
    ),
]


class TestPublicationHandoff:
    async def test_regressed_resolved_ticket_is_published_once_after_its_unit(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cve, ticket, assignee = await h.world.regressing_ticket(assignee_active=False)
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert h.published.calls == [str(ticket.id)]
        assert await h.world.read(lambda db: ticket_state(db, ticket.id)) == (
            TicketStatus.ANALYZED,
            None,
            "P2",
            None,
            None,
        )
        detail = await h.world.read(lambda db: subjects(db, ticket.id))
        assert await _ticket_events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
            unassigned_event(assignee.username, "inactive assignee"),
            status_event(TicketStatus.RESOLVED, TicketStatus.ANALYZED),
        ]
        assert runner_events(logs)[-1] == _terminal(
            "completed", task_id, cve.id, changed=1
        )
        _assert_sanitized(logs, task_id)

    async def test_broker_operational_error_is_logged_once_and_changes_nothing(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        _, ticket, _ = await h.world.regressing_ticket()
        sibling = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        h.published.errors[str(ticket.id)] = BrokerOperationalError(
            f"redis://fictional-user:{LEAK_MARKER}@broker.example.test:6379"
        )
        task_id = await h.admit()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert [e for e in logs if e["event"] == PUBLICATION_FAILED_EVENT] == [
            {
                "event": PUBLICATION_FAILED_EVENT,
                "log_level": "error",
                "ticket_id": str(ticket.id),
                "cause": "broker_operational_error",
                "celery_task_id": task_id,
            }
        ]
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, sibling.id),
            _terminal("completed", task_id, sibling.id, changed=2),
        ]
        _assert_sanitized(logs, task_id)
        assert len(chain.calls) == 2

    @pytest.mark.parametrize(("make_error", "outcome", "cause"), _DRAIN_EXCEPTIONS)
    async def test_non_operational_drain_exception_keeps_the_committed_unit(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        make_error: Callable[[], BaseException],
        outcome: str,
        cause: str,
    ) -> None:
        cve, ticket, _ = await h.world.regressing_ticket()
        sibling = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = make_error()
        h.published.errors[str(ticket.id)] = error
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert [e for e in logs if e["event"] == PUBLICATION_FAILED_EVENT] == []
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, sibling.id),
            _terminal(
                outcome,
                task_id,
                sibling.id,
                phase="publication",
                cause=cause,
                changed=1,
            ),
        ]
        _assert_sanitized(logs, task_id)
        assert await _severity(h, cve.id) == "Critical"
        assert len(chain.calls) == 1
        assert await _severity(h, sibling.id) == "Low"
        assert await h.fence_holders() == []


# ---------------------------------------------------------------------------
# Idempotency and recovery
# ---------------------------------------------------------------------------


class TestIdempotencyAndRecovery:
    async def test_complete_rerun_and_duplicate_delivery_create_nothing_new(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        _, ticket, _ = await h.world.regressing_ticket()
        stale = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        converged = await h.world.scored_cve(
            SUSE_31_CRITICAL, severity=Severity.CRITICAL
        )
        first = await h.admit()
        with capture_events() as logs:
            await h.run(first)
        assert runner_events(logs)[-1] == _terminal(
            "completed", first, converged.id, changed=2, unchanged=1
        )
        events = await _ticket_events(h, ticket)
        assert len(events) == 4

        rerun = await h.admit()
        with capture_events() as logs:
            await h.run(rerun)
        assert runner_events(logs)[-1] == _terminal(
            "completed", rerun, converged.id, unchanged=3
        )

        with capture_events() as logs:
            await h.run(rerun)
        assert runner_events(logs) == [_rejected(rerun, "lease_absent")]

        assert await _ticket_events(h, ticket) == events
        assert h.published.calls == [str(ticket.id)]
        assert await _severity(h, stale.id) == "Critical"
        assert len(chain.calls) == 6

    async def test_setting_changed_before_adoption_terminates_stale(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cve, _, _ = await h.world.regressing_ticket()
        task_id = await h.admit()
        await h.world.set_setting("4.0")
        ticket_events_before = await h.world.read(total_ticket_events)
        setting_events_before = await _setting_audit_events(h)

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert runner_events(logs) == [
            _adopted(task_id),
            _terminal("stale", task_id, None),
        ]
        assert chain.calls == []
        assert len(h.factory.created) == 1  # the setting read only
        assert await h.world.read(total_ticket_events) == ticket_events_before
        assert await _setting_audit_events(h) == setting_events_before == 0
        assert await _severity(h, cve.id) == "Medium"
        assert h.published.calls == []
        assert await h.lease() is None
        assert await h.fence_holders() == []


# ---------------------------------------------------------------------------
# Errors and control signals
# ---------------------------------------------------------------------------


def _inject_unit_failure(
    case: str,
    h: RecalculationHarness,
    chain: ChainSpy,
    monkeypatch: pytest.MonkeyPatch,
) -> BaseException:
    """Install the whole-run failure `case` on the second unit; returns the
    injected exception."""
    unit = _unit_session(chain, 1)
    if case == "integrity":
        error: BaseException = database_error(IntegrityError, sqlstate="23505")
        chain.after[1] = _raise(error)
    elif case == "data":
        error = database_error(DataError, sqlstate="22001")
        chain.after[1] = _raise(error)
    elif case == "programming":
        error = TypeError(LEAK_MARKER)
        chain.after[1] = _raise(error)
    elif case == "invalidated":
        error = deadlock(invalidated=True)
        chain.after[1] = _raise(error)
    elif case in ("commit", "ambiguous-commit"):
        error = database_error()
        _fail_session_method(
            monkeypatch,
            "commit",
            unit,
            error,
            after_delegating=case == "ambiguous-commit",
        )
    elif case == "rollback":
        error = database_error()
        chain.after[1] = _raise(deadlock())
        _fail_session_method(monkeypatch, "rollback", unit, error)
    elif case == "session-cleanup":
        error = database_error()
        chain.after[1] = _raise(deadlock())
        _fail_session_method(monkeypatch, "close", unit, error)
    else:
        raise AssertionError(case)
    return error


_UNIT_FAILURES = [
    pytest.param("integrity", "programming", id="integrity-error"),
    pytest.param("data", "programming", id="data-error"),
    pytest.param("programming", "programming", id="pre-commit-programming-error"),
    pytest.param("invalidated", "database", id="invalidated-connection"),
    pytest.param("commit", "database", id="commit-failure"),
    pytest.param("ambiguous-commit", "database", id="ambiguous-commit"),
    pytest.param("rollback", "database", id="rollback-failure"),
    pytest.param("session-cleanup", "database", id="pre-commit-session-cleanup"),
]

_SIGNALS = [
    pytest.param(
        lambda: asyncio.CancelledError(LEAK_MARKER),
        "cancelled",
        "interrupted",
        id="cancel",
    ),
    pytest.param(
        lambda: WorkerShutdown(LEAK_MARKER),
        "cancelled",
        "interrupted",
        id="worker-shutdown",
    ),
    pytest.param(
        lambda: WorkerTerminate(LEAK_MARKER),
        "cancelled",
        "interrupted",
        id="worker-terminate",
    ),
    pytest.param(
        lambda: SoftTimeLimitExceeded(LEAK_MARKER),
        "failed",
        "interrupted",
        id="soft-time-limit",
    ),
    pytest.param(lambda: MemoryError(LEAK_MARKER), "failed", "unexpected", id="memory"),
]


class TestErrorsAndControlSignals:
    async def test_isolable_deadlock_counts_failed_once_and_continues(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(3)
        ]
        chain.after[1] = _raise(deadlock())
        task_id = await h.admit()

        with capture_events() as logs:
            result = await h.run(task_id)

        assert result is None
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _cve_failed(task_id, cves[1].cve_id),
            _terminal("partial", task_id, cves[-1].id, changed=2, failed=1),
        ]
        _assert_sanitized(logs, task_id)
        assert [await _severity(h, cve.id) for cve in cves] == [
            "Critical",
            "Low",
            "Critical",
        ]

    @pytest.mark.parametrize(("case", "cause"), _UNIT_FAILURES)
    async def test_whole_run_unit_failure_never_touches_the_unit_counters(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        cause: str,
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(3)
        ]
        error = _inject_unit_failure(case, h, chain, monkeypatch)
        task_id = await h.admit()

        with capture_events() as logs:
            escaped = await _escape(h.run(task_id))

        assert escaped is error
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _terminal(
                "failed", task_id, cves[-1].id, phase="unit", cause=cause, changed=1
            ),
        ]
        _assert_sanitized(logs, task_id)
        assert len(chain.calls) == 2
        assert await _severity(h, cves[2].id) == "Low"
        assert await h.fence_holders() == []

    async def test_unsupported_persisted_assessment_version_fails_the_run(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        first = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        broken = await h.world.scored_cve(Assessment("9.8", version="9.9"))
        last = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(ValueError):  # noqa: PT011
            await h.run(task_id)

        assert runner_events(logs)[-1] == _terminal(
            "failed", task_id, last.id, phase="unit", cause="programming", changed=1
        )
        assert chain.cve_ids == [first.id, broken.id]
        assert await _severity(h, last.id) == "Low"

    @pytest.mark.parametrize(
        ("marker", "captured"),
        [
            pytest.param("ORDER BY cve.id DESC", False, id="watermark"),
            pytest.param("cve.cve_id \nFROM cve", True, id="page"),
        ],
    )
    async def test_enumeration_failure_terminates_failed(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
        marker: str,
        captured: bool,
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = database_error()
        _fail_statement(monkeypatch, marker, error)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        watermark = cve.id if captured else None
        assert runner_events(logs) == [
            _adopted(task_id),
            *([_started(task_id, watermark)] if captured else []),
            _terminal(
                "failed", task_id, watermark, phase="enumeration", cause="database"
            ),
        ]
        assert chain.calls == []

    async def test_missing_setting_is_failed_setting_read_domain(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        await h.world.delete_setting()
        task_id = await h.admit()

        with (
            capture_events() as logs,
            pytest.raises(settings_service.RequiredSystemSettingMissingError),
        ):
            await h.run(task_id)

        assert runner_events(logs) == [
            _adopted(task_id),
            _terminal("failed", task_id, None, phase="setting_read", cause="domain"),
        ]
        assert chain.calls == []
        assert await h.lease() is None

    @pytest.mark.parametrize(
        ("point", "phase", "cause"),
        [
            pytest.param("close", "unit", "database", id="close-after-commit"),
            pytest.param("drain", "publication", "unexpected", id="drain"),
        ],
    )
    async def test_post_commit_failure_preserves_the_unit_classification(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
        point: str,
        phase: str,
        cause: str,
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        error: BaseException
        if point == "close":
            error = database_error()
            _fail_session_method(monkeypatch, "close", _unit_session(chain, 0), error)
        else:
            error = RuntimeError(LEAK_MARKER)
            drain.before[0] = _raise(error)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert runner_events(logs)[-1] == _terminal(
            "failed", task_id, cves[-1].id, phase=phase, cause=cause, changed=1
        )
        assert len(chain.calls) == 1
        assert [await _severity(h, cve.id) for cve in cves] == ["Critical", "Low"]

    @pytest.mark.parametrize(("make_signal", "outcome", "cause"), _SIGNALS)
    @pytest.mark.parametrize(
        ("point", "phase"),
        [
            pytest.param("between-units", "control", id="between-units"),
            pytest.param("before-commit", "unit", id="before-commit"),
            pytest.param("after-commit", "publication", id="after-commit"),
        ],
    )
    async def test_control_signal_terminates_with_its_outcome_and_propagates(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        drain: DrainSpy,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
        outcome: str,
        cause: str,
        point: str,
        phase: str,
    ) -> None:
        """Adversarial: a broad catch would turn each signal into `failed`
        or `partial`; the `failed` counter stays zero, a unit interrupted
        before its commit rolls back, and a committed unit keeps its
        classification."""
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(3)
        ]
        signal = make_signal()
        if point == "between-units":
            renew = _RenewSpy(monkeypatch, chain)
            renew.errors[1] = signal
            drain.after[0] = lambda _i: _advance_clock(h, 60)
            committed, attempted = 1, 1
        elif point == "before-commit":
            chain.after[1] = _raise(signal)
            committed, attempted = 1, 2
        else:
            drain.before[0] = _raise(signal)
            committed, attempted = 1, 1
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(signal)) as raised:
            await h.run(task_id)

        assert raised.value is signal
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _terminal(
                outcome,
                task_id,
                cves[-1].id,
                phase=phase,
                cause=cause,
                changed=committed,
            ),
        ]
        _assert_sanitized(logs, task_id)
        assert len(chain.calls) == attempted
        assert [await _severity(h, cve.id) for cve in cves] == [
            "Critical",
            "Low",
            "Low",
        ]
        assert await h.lease() is None
        assert await h.fence_holders() == []

    @pytest.mark.parametrize(
        ("make_error", "cause"),
        [
            pytest.param(
                lambda: deadlock(invalidated=True), "database", id="40P01-invalidated"
            ),
            pytest.param(
                lambda: database_error(sqlstate="40001"),
                "database",
                id="serialization-failure",
            ),
            pytest.param(
                lambda: _SqlstateCarrierError("40P01"),
                "unexpected",
                id="non-dbapi-40P01",
            ),
        ],
    )
    async def test_only_a_valid_connection_deadlock_is_isolable(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        make_error: Callable[[], BaseException],
        cause: str,
    ) -> None:
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        error = make_error()
        chain.after[0] = _raise(error)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        assert runner_events(logs) == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _terminal("failed", task_id, cves[-1].id, phase="unit", cause=cause),
        ]
        assert len(chain.calls) == 1

    async def test_deadlock_whose_rollback_invalidates_the_connection_is_whole_run(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The rollback and close succeed, but the fenced connection is
        invalidated by then: the `40P01` is not isolable."""
        cves = [
            await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
            for _ in range(2)
        ]
        error = deadlock()
        chain.after[0] = _raise(error)
        rollback = AsyncSession.rollback
        unit = _unit_session(chain, 0)

        async def _rollback(self: AsyncSession) -> None:
            await rollback(self)
            if unit(self):
                await h.connection.invalidate()

        monkeypatch.setattr(AsyncSession, "rollback", _rollback)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            await h.run(task_id)

        assert raised.value is error
        events = runner_events(logs)
        # No isolated failure and no explicit release on the invalidated
        # connection (its closure released the fence).
        assert events == [
            _adopted(task_id),
            _started(task_id, cves[-1].id),
            _terminal("failed", task_id, cves[-1].id, phase="unit", cause="database"),
        ]
        assert len(chain.calls) == 1
        await wait_until_fence_free(h.engine)


class _SqlstateCarrierError(Exception):
    """Not a `DBAPIError`, although it carries SQLSTATE `40P01`."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(LEAK_MARKER)
        self.sqlstate = sqlstate


# ---------------------------------------------------------------------------
# Counters and logging
# ---------------------------------------------------------------------------


class TestCountersAndLogging:
    async def test_counters_follow_each_classification_and_logs_stay_bounded(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        stale = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        converged = await h.world.scored_cve(
            SUSE_31_CRITICAL, severity=Severity.CRITICAL
        )
        vanished = await h.world.scored_cve(SUSE_31_CRITICAL)
        failing = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)

        async def delete_candidate(_index: int) -> None:
            await h.world.delete_cve(vanished.id)

        chain.before[2] = delete_candidate
        chain.after[3] = _raise(deadlock())
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert chain.cve_ids == [stale.id, converged.id, vanished.id, failing.id]
        terminal = runner_events(logs)[-1]
        assert terminal == {
            "event": PARTIAL_EVENT,
            "log_level": "warning",
            "celery_task_id": task_id,
            "target_version": TARGET,
            "watermark": str(failing.id),
            "changed": 1,
            "unchanged": 1,
            "skipped": 1,
            "failed": 1,
            "succeeded": 2,
            "processed": 4,
        }
        # One warning per isolated unit; no per-CVE INFO and no failure
        # event for the skipped candidate.
        assert [e["event"] for e in logs if e["log_level"] == "info"] == [
            ADOPTED_EVENT,
            STARTED_EVENT,
        ]
        assert [e["event"] for e in logs if e["log_level"] == "warning"] == [
            CVE_FAILED_EVENT,
            PARTIAL_EVENT,
        ]
        assert [e for e in logs if e["event"] == CVE_FAILED_EVENT] == [
            _cve_failed(task_id, failing.cve_id)
        ]
        _assert_sanitized(logs, task_id)
        assert await h.world.read(total_ticket_events) == 0


# ---------------------------------------------------------------------------
# Connection ownership: borrowed and owned paths
# ---------------------------------------------------------------------------


class _LifecycleCalls:
    """Counts `close()`, `invalidate()`, and `dispose()` on given objects."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        connection: AsyncConnection,
        engine: AsyncEngine,
    ) -> None:
        self.calls: list[str] = []
        for cls, method, target in (
            (AsyncConnection, "close", connection),
            (AsyncConnection, "invalidate", connection),
            (AsyncEngine, "dispose", engine),
        ):
            original = getattr(cls, method)

            async def _wrapped(
                self_: Any,
                *args: Any,
                _target: Any = target,
                _method: str = method,
                _original: Any = original,
                **kwargs: Any,
            ) -> Any:
                if self_ is _target:
                    self.calls.append(_method)
                return await _original(self_, *args, **kwargs)

            monkeypatch.setattr(cls, method, _wrapped)


class TestBorrowedConnection:
    @pytest.mark.parametrize("fails", [False, True], ids=["success", "failure"])
    async def test_workflow_never_closes_invalidates_or_disposes_the_borrowed_bind(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        monkeypatch: pytest.MonkeyPatch,
        fails: bool,
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        if fails:
            chain.after[0] = _raise(TypeError(LEAK_MARKER))
        lifecycle = _LifecycleCalls(monkeypatch, h.connection, h.engine)
        task_id = await h.admit()

        with suppress(BaseException):
            await h.run(task_id)

        assert lifecycle.calls == []
        assert h.connection.closed is False
        assert h.connection.invalidated is False
        assert h.connection.in_transaction() is False
        assert await h.fence_holders() == []

    @pytest.mark.parametrize(
        "make_factory",
        [
            pytest.param(lambda h: async_sessionmaker(), id="unbound"),
            pytest.param(
                lambda h: async_sessionmaker(bind=cast(Any, h.engine.sync_engine)),
                id="sync-engine",
            ),
        ],
    )
    async def test_factory_bound_to_neither_raises_type_error_before_io(
        self,
        h: RecalculationHarness,
        monkeypatch: pytest.MonkeyPatch,
        make_factory: Callable[
            [RecalculationHarness], async_sessionmaker[AsyncSession]
        ],
    ) -> None:
        clients: list[str] = []

        def _client() -> redis_asyncio.Redis:
            clients.append("created")
            raise AssertionError("no Redis client may be created")

        monkeypatch.setattr(
            cvss_recalculation, "new_cvss_recalculation_redis_client", _client
        )
        task_id = await h.admit()
        lease = await h.lease()

        with capture_events() as logs, pytest.raises(TypeError):
            await h.run(task_id, factory=make_factory(h))

        assert clients == []
        assert logs == []
        assert await h.lease() == lease
        assert await h.fence_holders() == []


@pytest.fixture
async def owned(
    h: RecalculationHarness, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[_OwnedEngine]:
    engine = create_async_engine(h.engine.url, pool_size=1, max_overflow=0)
    real_dispose = AsyncEngine.dispose
    owned_engine = _OwnedEngine(h, engine, monkeypatch)
    try:
        yield owned_engine
    finally:
        await real_dispose(engine)


class _OwnedEngine:
    """A one-connection pooled engine as the factory bind (the owned
    path). Before its real `dispose()`, each counted disposal checks out
    the pool's connection: the workflow's own backend when it was closed
    back to the pool, a new one when it was invalidated."""

    def __init__(
        self,
        h: RecalculationHarness,
        engine: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self.engine = engine
        self.factory = async_sessionmaker(engine, expire_on_commit=False)
        self.disposals = 0
        self.dispose_error: BaseException | None = None
        self.workflow_pids: list[int] = []
        self.pooled_pids: list[int] = []
        self.holders_at_dispose: list[list[int]] = []
        acquire = coordination.try_acquire_execution_fence
        dispose = AsyncEngine.dispose

        async def _acquire(connection: AsyncConnection) -> Any:
            self.workflow_pids.append(connection_pid(connection))
            return await acquire(connection)

        async def _dispose(engine_: AsyncEngine, close: bool = True) -> None:
            if engine_ is not engine:
                return await dispose(engine_, close)
            self.disposals += 1
            self.holders_at_dispose.append(await fence_holders(h.observer))
            async with engine.connect() as pooled:
                self.pooled_pids.append(connection_pid(pooled))
            await dispose(engine_, close)
            if self.dispose_error is not None:
                raise self.dispose_error
            return None

        monkeypatch.setattr(cvss_recalculation, "try_acquire_execution_fence", _acquire)
        monkeypatch.setattr(AsyncEngine, "dispose", _dispose)


class TestOwnedConnection:
    @pytest.mark.parametrize("fails", [False, True], ids=["success", "failure"])
    async def test_confirmed_unlock_returns_the_connection_and_disposes_once(
        self,
        h: RecalculationHarness,
        owned: _OwnedEngine,
        chain: ChainSpy,
        fails: bool,
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = TypeError(LEAK_MARKER)
        if fails:
            chain.after[0] = _raise(error)
        task_id = await h.admit()

        with capture_events() as logs:
            if fails:
                with pytest.raises(TypeError) as raised:
                    await h.run(task_id, factory=owned.factory)
                assert raised.value is error
            else:
                assert await h.run(task_id, factory=owned.factory) is None

        assert owned.disposals == 1
        assert owned.holders_at_dispose == [[]]
        # Closed back to the pool only after the confirmed unlock: the
        # one-connection pool hands out the workflow's own backend.
        assert owned.pooled_pids == owned.workflow_pids
        assert runner_events(logs)[-1]["event"] == (
            FAILED_EVENT if fails else COMPLETED_EVENT
        )

    @pytest.mark.parametrize("mode", ["raises", "not-confirmed"])
    async def test_release_failure_invalidates_and_never_returns_the_connection(
        self,
        h: RecalculationHarness,
        owned: _OwnedEngine,
        monkeypatch: pytest.MonkeyPatch,
        mode: str,
    ) -> None:
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        release = coordination.release_execution_fence
        execute = AsyncConnection.execute
        failing: list[AsyncConnection] = []

        async def _release(connection: AsyncConnection) -> Any:
            failing.append(connection)
            if mode == "not-confirmed":
                # What the helper does on a definitive `false` unlock.
                await connection.invalidate()
                return FenceReleaseOutcome.NOT_CONFIRMED
            return await release(connection)

        async def _execute(self: AsyncConnection, *args: Any, **kwargs: Any) -> Any:
            if failing and self is failing[0]:
                raise database_error()
            return await execute(self, *args, **kwargs)

        monkeypatch.setattr(cvss_recalculation, "release_execution_fence", _release)
        monkeypatch.setattr(AsyncConnection, "execute", _execute)
        task_id = await h.admit()

        with capture_events() as logs:
            assert await h.run(task_id, factory=owned.factory) is None

        assert failing[0].invalidated is True
        assert owned.disposals == 1
        # The invalidated backend never returned to the one-connection
        # pool: the pool opened a new one.
        assert owned.pooled_pids != owned.workflow_pids
        assert runner_events(logs)[-2:] == [
            _cleanup_failed(task_id, "fence_release_failed"),
            _terminal("completed", task_id, cve.id, changed=1),
        ]
        await wait_until_fence_free(h.engine)

    async def test_dispose_failure_never_masks_the_primary_exception(
        self,
        h: RecalculationHarness,
        owned: _OwnedEngine,
        chain: ChainSpy,
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = TypeError(LEAK_MARKER)
        chain.after[0] = _raise(error)
        owned.dispose_error = RuntimeError(LEAK_MARKER)
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(TypeError) as raised:
            await h.run(task_id, factory=owned.factory)

        assert raised.value is error
        assert owned.disposals == 1
        assert [e for e in logs if e["event"] == ENGINE_DISPOSE_FAILED_EVENT] == [
            _event(ENGINE_DISPOSE_FAILED_EVENT, "warning", task_id)
        ]
        _assert_sanitized(logs, task_id)

    async def test_dispose_failure_after_success_propagates(
        self, h: RecalculationHarness, owned: _OwnedEngine
    ) -> None:
        await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        error = RuntimeError(LEAK_MARKER)
        owned.dispose_error = error
        task_id = await h.admit()

        with capture_events() as logs, pytest.raises(RuntimeError) as raised:
            await h.run(task_id, factory=owned.factory)

        assert raised.value is error
        assert owned.disposals == 1
        assert runner_events(logs)[-1]["event"] == COMPLETED_EVENT
        assert ENGINE_DISPOSE_FAILED_EVENT not in [e["event"] for e in logs]
