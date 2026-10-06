"""Tests of the manual CVSS recalculation admission
`admit_cvss_recalculation()`
(backend/app/services/cvss_recalculation_admission.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (API
  Endpoints > Trigger CVSS Recalculation; Complete-Run Coordination: Run
  Identity, Coordination Resources, Atomic Lease Operations, Execution
  Fence, Admission Ordering, Manual Admission Service, Publication
  Uncertainty, Cleanup and Recovery Matrix, Coordination Logging);
- docs/features/platform/system-settings.md (Service Exceptions:
  `CVSSRecalculationAlreadyInProgressError`);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner: Complete-run coordination, Coordination integration tests, the
  admission rows of Coordination API tests; Redis Strategy; Concurrency
  Testing);
- issue #837 decisions V2 (own-or-borrow bind), V3 (Redis client
  lifetime), V4 (cleanup precedence), V5 (event fields), and V7 (result and
  run identity); umbrella #833 P9 and P11.

The admission runs on the borrowed fenced connection of the shared
recalculation harness (tests/support/cvss_recalculation.py), observed by
the shared `AdmissionSpy` (tests/support/cvss_recalculation_admission.py)
and supplied through the `get_cvss_admission_bind()` patch point; the
owned path uses a dedicated one-connection pooled engine. The lease lives
in the worker Redis
database (`redis_client` redirects the lease URL provider). The broker call
`task_publication.publish_task` is replaced by the spy's recorder. Failures
are injected through the real helpers wherever feasible: a backend
termination, an extra unlock that makes the real `pg_advisory_unlock`
return `false`, or a failing statement inside the real helper, so the
helpers' own invalidation contract (issue #836 U3) is exercised. The
two-admission race, the setting change before the fenced read, and the
runner interplay are covered by their own modules.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from kombu.exceptions import (  # type: ignore[import-untyped]
    EncodeError,
    SerializerNotInstalled,
)
from kombu.exceptions import OperationalError as BrokerOperationalError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy import BigInteger, func, literal, select
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.pool import QueuePool
from structlog.contextvars import bound_contextvars

from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.setting_audit_event import SettingAuditEvent
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import cvss_recalculation_admission as admission
from app.services import settings as settings_service
from app.services.cvss_recalculation import RECALCULATE_CVSS_DERIVED_STATE_TASK
from app.services.cvss_recalculation_admission import (
    ADMISSION_REJECTED_EVENT,
    ADMITTED_EVENT,
    BROKER_UNAVAILABLE_MESSAGE,
    CLEANUP_FAILED_EVENT,
    FENCE_RELEASE_NOT_CONFIRMED_MESSAGE,
    PUBLICATION_UNCONFIRMED_EVENT,
    REDIS_UNAVAILABLE_MESSAGE,
    SUBMITTED_EVENT,
    CVSSRecalculationAdmission,
    CVSSRecalculationBrokerUnavailableError,
    CVSSRecalculationRedisUnavailableError,
    admit_cvss_recalculation,
)
from app.services.cvss_recalculation_coordination import (
    EXECUTION_FENCE_ID,
    LEASE_KEY,
    LEASE_TTL_SECONDS,
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    LeaseDeleteOutcome,
    compare_and_delete_lease,
    is_canonical_task_id,
    release_execution_fence,
    try_acquire_execution_fence,
)
from app.services.settings import (
    CVSS_RECALCULATION_IN_PROGRESS_MESSAGE,
    CVSSRecalculationAlreadyInProgressError,
    RequiredSystemSettingMissingError,
    SettingsServiceError,
)
from tests.support.cvss_recalculation import (
    LEAK_MARKER,
    TARGET,
    RecalculationHarness,
    capture_events,
    connection_pid,
    database_error,
    recalculation_harness,
    runner_events,
    terminate_backend,
    wait_until_fence_free,
)
from tests.support.cvss_recalculation_admission import AdmissionSpy, Publication

REQUEST_ID = "req-fictional-0837"
"""A fictional bound `request_id`: the admission events' only correlation."""

_ALLOWED_FIELDS = {"event", "log_level", "reason", "target_version", "request_id"}
_REJECTION_REASONS = {"fence_busy", "lease_held", "redis_error"}
_CLEANUP_REASONS = {"redis_error", "fence_release_failed"}
_ADMISSION_EVENTS = {
    ADMITTED_EVENT,
    ADMISSION_REJECTED_EVENT,
    SUBMITTED_EVENT,
    PUBLICATION_UNCONFIRMED_EVENT,
    CLEANUP_FAILED_EVENT,
}

_UNLOCK = select(func.pg_advisory_unlock(literal(EXECUTION_FENCE_ID, BigInteger)))


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
    """The spy, installed after the harness (so its recorder replaces the
    harness's convergence publisher), with the borrowed harness connection
    as the admission bind."""
    installed = AdmissionSpy(monkeypatch)
    monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: h.connection)
    return installed


@pytest.fixture
async def pooled(
    h: RecalculationHarness, monkeypatch: pytest.MonkeyPatch, spy: AdmissionSpy
) -> AsyncIterator[AsyncEngine]:
    """A dedicated one-connection pooled engine as the owned bind."""
    engine = create_async_engine(h.engine.url, pool_size=1, max_overflow=0)
    monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: engine)
    try:
        yield engine
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(name: str, level: str, **fields: str) -> dict[str, Any]:
    return {"event": name, "log_level": level, **fields}


def _admitted(target: str = TARGET) -> dict[str, Any]:
    return _event(ADMITTED_EVENT, "info", target_version=target)


def _rejected(reason: str, target: str | None = TARGET) -> dict[str, Any]:
    if target is None:
        return _event(ADMISSION_REJECTED_EVENT, "warning", reason=reason)
    return _event(
        ADMISSION_REJECTED_EVENT, "warning", reason=reason, target_version=target
    )


def _cleanup_failed(reason: str, target: str = TARGET) -> dict[str, Any]:
    return _event(CLEANUP_FAILED_EVENT, "warning", reason=reason, target_version=target)


def _assert_private(events: list[dict[str, Any]], *secrets: str) -> None:
    """Admission events use only the bounded fields and closed reasons and
    never carry a task ID, the lease token, or raw exception text."""
    for entry in events:
        assert entry["event"] in _ADMISSION_EVENTS
        assert set(entry) <= _ALLOWED_FIELDS, entry
        if entry["event"] == ADMISSION_REJECTED_EVENT:
            assert entry["reason"] in _REJECTION_REASONS
        elif entry["event"] == CLEANUP_FAILED_EVENT:
            assert entry["reason"] in _CLEANUP_REASONS
        else:
            assert "reason" not in entry
        rendered = repr(entry)
        assert LEAK_MARKER not in rendered
        assert "v1:" not in rendered
        for secret in secrets:
            assert secret not in rendered


def _assert_borrowed_intact(h: RecalculationHarness) -> None:
    """Admission never closes or invalidates a borrowed connection and
    leaves no open transaction on it."""
    assert h.connection.closed is False
    assert h.connection.invalidated is False
    assert h.connection.in_transaction() is False


async def _unlock_once(connection: AsyncConnection) -> None:
    """Release the fence once ahead of the admission's own unlock, which
    then returns the definitive `false` of a session holding nothing."""
    released: bool = (await connection.execute(_UNLOCK)).scalar_one()
    await connection.commit()
    assert released is True


async def _admission_error() -> BaseException:
    """Run the admission and return what it raised, whatever its class
    (a backend termination raises a driver-specific class)."""
    try:
        await admit_cvss_recalculation()
    except BaseException as exc:
        return exc
    raise AssertionError("the admission did not raise")


async def _audit_counts(session: AsyncSession) -> dict[str, int]:
    models = (
        SettingAuditEvent,
        TicketAuditEvent,
        IdentityAuditEvent,
        FetcherAuditEvent,
    )
    return {
        model.__name__: (
            await session.execute(select(func.count()).select_from(model))
        ).scalar_one()
        for model in models
    }


# ---------------------------------------------------------------------------
# Ordering and success
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSubmitted:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    async def test_submits_the_persisted_target_with_a_fresh_canonical_task_id(
        self, h: RecalculationHarness, spy: AdmissionSpy, target: str
    ) -> None:
        await h.world.set_setting(target)

        with capture_events() as logs:
            result = await admit_cvss_recalculation()

        assert result == CVSSRecalculationAdmission(
            outcome="submitted", target_version=target
        )
        assert dataclasses.asdict(result) == {
            "outcome": "submitted",
            "target_version": target,
        }
        assert len(spy.published) == 1
        publication = spy.published[0]
        assert publication.task_name == RECALCULATE_CVSS_DERIVED_STATE_TASK
        assert publication.task_name == "recalculate_cvss_derived_state"
        assert publication.kwargs == {"target_version": target}
        assert publication.queue is None
        task_id = publication.task_id
        assert task_id is not None
        assert is_canonical_task_id(task_id)
        assert uuid.UUID(task_id).version == 4
        assert task_id == spy.task_id
        assert await h.lease() == f"v1:{task_id}:{target}"
        ttl = await h.redis.ttl(LEASE_KEY)
        assert 0 < ttl <= LEASE_TTL_SECONDS
        assert task_id not in repr(result)
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        assert spy.clients == 1
        events = runner_events(logs)
        assert events == [
            _admitted(target),
            _event(SUBMITTED_EVENT, "info", target_version=target),
        ]
        _assert_private(events, task_id)

    async def test_steps_run_in_the_normative_order(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        """Admission Ordering: the setting is read only under the acquired
        fence, the lease is acquired while it is still held, and the
        publisher runs only after its confirmed release, with the lease in
        place."""
        observed: dict[str, Any] = {}
        setting = settings_service.get_default_cvss_version

        async def _observe_setting(session: AsyncSession) -> str:
            observed["setting"] = await h.fence_holders()
            return await setting(session)

        async def _observe_lease() -> None:
            observed["lease"] = await h.fence_holders()

        async def _observe_publish(call: Publication) -> None:
            observed["publish"] = (await h.fence_holders(), await h.lease())

        spy.after_lease = _observe_lease
        spy.on_publish = _observe_publish
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                settings_service, "get_default_cvss_version", _observe_setting
            )
            await admit_cvss_recalculation()

        assert spy.sequence == ["fence", "setting", "lease", "release", "publish"]
        assert observed["setting"] == [h.pid]
        assert observed["lease"] == [h.pid]
        assert observed["publish"] == ([], f"v1:{spy.task_id}:{TARGET}")

    async def test_each_admission_allocates_a_new_run_identity(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        await admit_cvss_recalculation()
        first = spy.task_ids[0]
        deleted = await compare_and_delete_lease(
            h.redis, task_id=first, target_version=TARGET
        )
        assert deleted is LeaseDeleteOutcome.DELETED

        await admit_cvss_recalculation()

        assert len(spy.task_ids) == 2
        second = spy.task_ids[1]
        assert first != second
        assert all(is_canonical_task_id(task_id) for task_id in spy.task_ids)
        assert [call.task_id for call in spy.published] == [first, second]
        assert await h.lease() == f"v1:{second}:{TARGET}"

    async def test_creates_no_audit_record_and_leaves_the_setting_unchanged(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        before = await h.world.read(_audit_counts)

        await admit_cvss_recalculation()

        assert await h.world.read(_audit_counts) == before
        assert await h.world.setting() == TARGET


# ---------------------------------------------------------------------------
# Rejections
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRejected:
    async def test_busy_fence_is_409_without_setting_read_redis_or_publication(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        holder = (await h.borrow()).connection
        holder_pid = connection_pid(holder)
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        with (
            capture_events() as logs,
            pytest.raises(CVSSRecalculationAlreadyInProgressError) as excinfo,
        ):
            await asyncio.wait_for(admit_cvss_recalculation(), 5.0)

        assert str(excinfo.value) == CVSS_RECALCULATION_IN_PROGRESS_MESSAGE
        assert spy.sequence == ["fence"]
        assert spy.clients == 0
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == [holder_pid]
        _assert_borrowed_intact(h)
        events = runner_events(logs)
        assert events == [_rejected("fence_busy", target=None)]
        _assert_private(events)
        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED

    @pytest.mark.parametrize(
        "stored",
        [
            pytest.param(None, id="other-owner"),
            pytest.param("fictional-garbage", id="malformed"),
        ],
    )
    async def test_held_lease_is_409_releases_the_fence_and_keeps_the_lease(
        self, h: RecalculationHarness, spy: AdmissionSpy, stored: str | None
    ) -> None:
        if stored is None:
            other = await h.admit()
            stored = f"v1:{other}:{TARGET}"
        else:
            await h.redis.set(LEASE_KEY, stored, ex=LEASE_TTL_SECONDS)

        with (
            capture_events() as logs,
            pytest.raises(CVSSRecalculationAlreadyInProgressError),
        ):
            await admit_cvss_recalculation()

        assert spy.sequence == ["fence", "setting", "lease", "release"]
        assert spy.published == []
        assert await h.lease() == stored
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        events = runner_events(logs)
        assert events == [_rejected("lease_held")]
        _assert_private(events, spy.task_id)

    @pytest.mark.parametrize(
        "after_write",
        [pytest.param(False, id="before-write"), pytest.param(True, id="after-write")],
    )
    async def test_redis_error_on_acquire_is_503_and_never_publishes(
        self, h: RecalculationHarness, spy: AdmissionSpy, after_write: bool
    ) -> None:
        """An uncertain acquire (a timeout after the write landed) never
        proceeds to publication, and the possibly written key is left to
        expire by its TTL rather than deleted."""
        spy.lease_error = (
            RedisTimeoutError(LEAK_MARKER)
            if after_write
            else RedisConnectionError(LEAK_MARKER)
        )
        spy.lease_error_after_write = after_write

        with (
            capture_events() as logs,
            pytest.raises(CVSSRecalculationRedisUnavailableError) as excinfo,
        ):
            await admit_cvss_recalculation()

        assert str(excinfo.value) == REDIS_UNAVAILABLE_MESSAGE
        assert LEAK_MARKER not in str(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert spy.sequence == ["fence", "setting", "lease", "release"]
        assert spy.published == []
        if after_write:
            assert await h.lease() == f"v1:{spy.task_id}:{TARGET}"
            assert await h.redis.ttl(LEASE_KEY) > 0
        else:
            assert await h.lease() is None
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        events = runner_events(logs)
        assert events == [_rejected("redis_error")]
        _assert_private(events, spy.task_id)


# ---------------------------------------------------------------------------
# Pre-lease failures
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPreLeaseFailures:
    async def test_missing_setting_propagates_and_releases_the_fence(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        await h.world.delete_setting()

        with capture_events() as logs, pytest.raises(RequiredSystemSettingMissingError):
            await admit_cvss_recalculation()

        assert spy.sequence == ["fence", "setting", "release"]
        assert spy.clients == 0
        assert spy.task_ids == []
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        assert runner_events(logs) == []

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(database_error, id="database-error"),
            pytest.param(asyncio.CancelledError, id="cancelled"),
        ],
    )
    async def test_setting_read_error_propagates_unchanged_and_releases_the_fence(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        make_error: Callable[[], BaseException],
    ) -> None:
        error = make_error()
        spy.setting_error = error

        with capture_events() as logs, pytest.raises(type(error)) as excinfo:
            await admit_cvss_recalculation()

        assert excinfo.value is error
        assert spy.sequence == ["fence", "setting", "release"]
        assert spy.clients == 0
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        assert runner_events(logs) == []

    async def test_redis_client_creation_error_propagates_and_releases_the_fence(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Step 3: a failure to create the lease client, after the fenced
        setting read and before any lease attempt, releases the fence and
        propagates unchanged; nothing is acquired or published."""
        error = RuntimeError(LEAK_MARKER)

        def _client() -> redis_asyncio.Redis:
            spy.sequence.append("client")
            raise error

        monkeypatch.setattr(admission, "new_cvss_recalculation_redis_client", _client)

        with capture_events() as logs, pytest.raises(RuntimeError) as excinfo:
            await admit_cvss_recalculation()

        assert excinfo.value is error
        assert spy.sequence == ["fence", "setting", "client", "release"]
        assert spy.task_ids == []
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        assert runner_events(logs) == []

    async def test_fence_database_error_propagates_unchanged_and_is_never_409(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        error = database_error()
        spy.fence_error = error

        with capture_events() as logs, pytest.raises(type(error)) as excinfo:
            await admit_cvss_recalculation()

        assert excinfo.value is error
        assert not isinstance(excinfo.value, SettingsServiceError)
        assert spy.sequence == ["fence"]
        assert spy.clients == 0
        assert spy.published == []
        assert await h.lease() is None
        # The helper invalidated the connection (its own contract, #835 T2).
        assert h.connection.invalidated is True
        await wait_until_fence_free(h.engine)
        assert runner_events(logs) == []


# ---------------------------------------------------------------------------
# Fence release failures (step 4)
# ---------------------------------------------------------------------------

_RELEASE_ERRORS = [
    pytest.param(None, id="backend-terminated"),
    pytest.param(database_error, id="database-error"),
    pytest.param(lambda: TimeoutError(LEAK_MARKER), id="timeout"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


def _arm_release_failure(
    h: RecalculationHarness,
    spy: AdmissionSpy,
    make_error: Callable[[], BaseException] | None,
) -> BaseException | None:
    """Make the step-4 unlock raise: a real backend termination for `None`,
    otherwise `make_error()` from the unlock statement of the real
    helper."""
    if make_error is None:

        async def _terminate(connection: AsyncConnection) -> None:
            await terminate_backend(h.observer, connection_pid(connection))

        spy.before_release = _terminate
        return None
    error = make_error()
    spy.release_error = error
    return error


@pytest.mark.integration
class TestReleaseFailure:
    @pytest.mark.parametrize("make_error", _RELEASE_ERRORS)
    async def test_raising_unlock_propagates_unchanged_without_publication(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        make_error: Callable[[], BaseException] | None,
    ) -> None:
        injected = _arm_release_failure(h, spy, make_error)

        with capture_events() as logs:
            raised = await _admission_error()

        # The exception the real unlock raised, unchanged.
        assert spy.release_raised == [raised]
        if injected is not None:
            assert raised is injected
        assert not isinstance(raised, SettingsServiceError)
        assert spy.sequence == ["fence", "setting", "lease", "release", "delete"]
        assert spy.published == []
        assert await h.lease() is None
        assert h.connection.invalidated is True
        await wait_until_fence_free(h.engine)
        events = runner_events(logs)
        assert events == [_admitted(), _cleanup_failed("fence_release_failed")]
        _assert_private(events, spy.task_id)

    async def test_definitive_false_unlock_raises_the_builtin_runtime_error(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        spy.before_release = _unlock_once

        with capture_events() as logs, pytest.raises(RuntimeError) as excinfo:
            await admit_cvss_recalculation()

        assert excinfo.type is RuntimeError
        assert str(excinfo.value) == FENCE_RELEASE_NOT_CONFIRMED_MESSAGE
        assert not isinstance(excinfo.value, SettingsServiceError)
        assert spy.release_raised == []
        assert spy.sequence == ["fence", "setting", "lease", "release", "delete"]
        assert spy.published == []
        assert await h.lease() is None
        # The helper invalidated the connection on `NOT_CONFIRMED` (#835).
        assert h.connection.invalidated is True
        assert await h.fence_holders() == []
        events = runner_events(logs)
        assert events == [_admitted(), _cleanup_failed("fence_release_failed")]
        _assert_private(events, spy.task_id)

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(None, id="not-confirmed"),
            pytest.param(database_error, id="database-error"),
        ],
    )
    async def test_lease_removal_redis_error_is_logged_and_the_lease_expires(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        make_error: Callable[[], BaseException] | None,
    ) -> None:
        if make_error is None:
            spy.before_release = _unlock_once
            expected: type[BaseException] = RuntimeError
            injected = None
        else:
            injected = make_error()
            spy.release_error = injected
            expected = type(injected)
        spy.delete_error = RedisConnectionError(LEAK_MARKER)

        with capture_events() as logs, pytest.raises(expected) as excinfo:
            await admit_cvss_recalculation()

        if injected is not None:
            assert excinfo.value is injected
        else:
            assert str(excinfo.value) == FENCE_RELEASE_NOT_CONFIRMED_MESSAGE
        assert spy.published == []
        assert await h.lease() == f"v1:{spy.task_id}:{TARGET}"
        assert await h.redis.ttl(LEASE_KEY) > 0
        await wait_until_fence_free(h.engine)
        events = runner_events(logs)
        assert events == [
            _admitted(),
            _cleanup_failed("redis_error"),
            _cleanup_failed("fence_release_failed"),
        ]
        _assert_private(events, spy.task_id)

    async def test_control_signal_from_lease_removal_is_never_converted(
        self, h: RecalculationHarness, spy: AdmissionSpy
    ) -> None:
        """After a definitive `false`, a control signal raised by the
        compare-and-delete propagates instead of the `RuntimeError`."""
        spy.before_release = _unlock_once
        signal = asyncio.CancelledError()
        spy.delete_error = signal

        with capture_events() as logs, pytest.raises(asyncio.CancelledError) as excinfo:
            await admit_cvss_recalculation()

        assert excinfo.value is signal
        assert spy.published == []
        await wait_until_fence_free(h.engine)
        assert runner_events(logs) == [
            _admitted(),
            _cleanup_failed("fence_release_failed"),
        ]


# ---------------------------------------------------------------------------
# Publication classification (step 5)
# ---------------------------------------------------------------------------


class _MimickingOperationalError(BrokerOperationalError):  # type: ignore[misc]
    """A broker operational error whose text names another class."""


_PROPAGATED = [
    pytest.param(lambda: EncodeError(LEAK_MARKER), id="encode"),
    pytest.param(lambda: SerializerNotInstalled(LEAK_MARKER), id="serializer"),
    pytest.param(lambda: TypeError(LEAK_MARKER), id="programming"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(lambda: MemoryError(LEAK_MARKER), id="memory"),
    pytest.param(
        lambda: RuntimeError(f"OperationalError: connection refused {LEAK_MARKER}"),
        id="text-mimics-operational",
    ),
]


@pytest.mark.integration
class TestPublication:
    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: BrokerOperationalError(f"connection refused {LEAK_MARKER}"),
                id="operational",
            ),
            pytest.param(
                lambda: _MimickingOperationalError(f"EncodeError: {LEAK_MARKER}"),
                id="subclass-text-mimics-encode",
            ),
        ],
    )
    async def test_operational_error_is_unconfirmed_and_keeps_the_lease(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        make_error: Callable[[], BaseException],
    ) -> None:
        spy.publish_error = make_error()

        with (
            capture_events() as logs,
            pytest.raises(CVSSRecalculationBrokerUnavailableError) as excinfo,
        ):
            await admit_cvss_recalculation()

        assert str(excinfo.value) == BROKER_UNAVAILABLE_MESSAGE
        assert str(excinfo.value) == (
            "Recalculation task publication could not be confirmed"
        )
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert len(spy.published) == 1
        assert await h.lease() == f"v1:{spy.task_id}:{TARGET}"
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        events = runner_events(logs)
        assert events == [
            _admitted(),
            _event(PUBLICATION_UNCONFIRMED_EVENT, "error", target_version=TARGET),
        ]
        _assert_private(events, spy.task_id)

    @pytest.mark.parametrize("make_error", _PROPAGATED)
    async def test_other_publisher_exception_propagates_and_keeps_the_lease(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        make_error: Callable[[], BaseException],
    ) -> None:
        error = make_error()
        spy.publish_error = error

        with capture_events() as logs, pytest.raises(type(error)) as excinfo:
            await admit_cvss_recalculation()

        assert excinfo.value is error
        assert len(spy.published) == 1
        assert await h.lease() == f"v1:{spy.task_id}:{TARGET}"
        assert await h.fence_holders() == []
        _assert_borrowed_intact(h)
        events = runner_events(logs)
        assert events == [_admitted()]
        _assert_private(events, spy.task_id)


# ---------------------------------------------------------------------------
# Connection ownership
# ---------------------------------------------------------------------------


def _queue_pool(engine: AsyncEngine) -> QueuePool:
    pool = engine.pool
    assert isinstance(pool, QueuePool)
    return pool


@pytest.mark.integration
class TestOwnedConnection:
    async def test_confirmed_release_returns_the_connection_to_the_pool(
        self, h: RecalculationHarness, spy: AdmissionSpy, pooled: AsyncEngine
    ) -> None:
        result = await admit_cvss_recalculation()

        assert result.outcome == "submitted"
        pool = _queue_pool(pooled)
        assert pool.checkedout() == 0
        assert pool.checkedin() == 1
        assert await h.fence_holders() == []
        async with pooled.connect() as reused:
            # The same backend session went back to the pool, holding nothing.
            assert connection_pid(reused) == spy.fence_pids[0]
            assert reused.in_transaction() is False
        probe = (await h.borrow()).connection
        assert await try_acquire_execution_fence(probe) is FenceAcquireOutcome.ACQUIRED
        assert await release_execution_fence(probe) is FenceReleaseOutcome.RELEASED

    @pytest.mark.parametrize(
        "failure", ["not-confirmed", "backend-terminated", "database-error"]
    )
    async def test_failed_release_invalidates_and_never_pools_the_fence(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        pooled: AsyncEngine,
        failure: str,
    ) -> None:
        if failure == "not-confirmed":
            spy.before_release = _unlock_once
        else:
            _arm_release_failure(
                h, spy, None if failure == "backend-terminated" else database_error
            )

        raised = await _admission_error()

        assert isinstance(raised, RuntimeError) or spy.release_raised == [raised]
        assert spy.published == []
        await wait_until_fence_free(h.engine)
        assert await h.fence_holders() == []
        assert _queue_pool(pooled).checkedout() == 0
        async with pooled.connect() as fresh:
            # The admission's session was discarded: a new backend session.
            assert connection_pid(fresh) != spy.fence_pids[0]
            assert await try_acquire_execution_fence(fresh) is (
                FenceAcquireOutcome.ACQUIRED
            )
            assert await release_execution_fence(fresh) is FenceReleaseOutcome.RELEASED

    @pytest.mark.parametrize(
        "scenario", ["submitted", "fence-busy", "lease-held", "redis-error"]
    )
    async def test_borrowed_connection_is_never_closed_or_invalidated(
        self, h: RecalculationHarness, spy: AdmissionSpy, scenario: str
    ) -> None:
        if scenario == "fence-busy":
            holder = (await h.borrow()).connection
            assert await try_acquire_execution_fence(holder) is (
                FenceAcquireOutcome.ACQUIRED
            )
        elif scenario == "lease-held":
            await h.admit()
        elif scenario == "redis-error":
            spy.lease_error = RedisConnectionError(LEAK_MARKER)

        try:
            await admit_cvss_recalculation()
        except (
            CVSSRecalculationAlreadyInProgressError,
            CVSSRecalculationRedisUnavailableError,
        ):
            assert scenario != "submitted"
        else:
            assert scenario == "submitted"

        _assert_borrowed_intact(h)
        assert spy.fence_pids == [h.pid]


@pytest.mark.unit
class TestBind:
    async def test_unsupported_bind_raises_type_error_before_any_io(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []

        async def _fence(connection: AsyncConnection) -> FenceAcquireOutcome:
            calls.append("fence")
            raise AssertionError("no fence request is expected")

        monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: object())
        monkeypatch.setattr(admission, "try_acquire_execution_fence", _fence)

        with pytest.raises(TypeError):
            await admit_cvss_recalculation()

        assert calls == []


# ---------------------------------------------------------------------------
# Correlation and privacy
# ---------------------------------------------------------------------------


async def _arrange(h: RecalculationHarness, spy: AdmissionSpy, scenario: str) -> None:
    if scenario == "fence-busy":
        holder = (await h.borrow()).connection
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED
    elif scenario == "lease-held":
        await h.admit()
    elif scenario == "redis-error":
        spy.lease_error = RedisTimeoutError(LEAK_MARKER)
        spy.lease_error_after_write = True
    elif scenario == "release-failed":
        spy.release_error = database_error()
        spy.delete_error = RedisConnectionError(LEAK_MARKER)
    elif scenario == "publication-unconfirmed":
        spy.publish_error = BrokerOperationalError(LEAK_MARKER)


@pytest.mark.integration
class TestEventCorrelation:
    @pytest.mark.parametrize(
        "scenario",
        [
            "submitted",
            "fence-busy",
            "lease-held",
            "redis-error",
            "release-failed",
            "publication-unconfirmed",
        ],
    )
    async def test_events_correlate_by_request_id_only_and_leak_nothing(
        self, h: RecalculationHarness, spy: AdmissionSpy, scenario: str
    ) -> None:
        await _arrange(h, spy, scenario)

        with capture_events() as logs, bound_contextvars(request_id=REQUEST_ID):
            try:
                await admit_cvss_recalculation()
            except Exception:
                assert scenario != "submitted"

        events = [
            entry
            for entry in runner_events(logs)
            if entry["event"] in _ADMISSION_EVENTS
        ]
        assert events
        assert all(entry["request_id"] == REQUEST_ID for entry in events)
        assert not any(
            key in entry
            for entry in events
            for key in ("celery_task_id", "task_id", "lease", "token", "error")
        )
        secrets = [*spy.task_ids]
        if (lease := await h.lease()) is not None:
            secrets.append(lease)
        _assert_private(events, *secrets)
