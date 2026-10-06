"""Tests for the all-CVE CVSS recalculation Celery task boundary
`recalculate_cvss_derived_state` (backend/app/tasks/cvss_tasks.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Task Identity
  and Workflow: wrapper steps 1-5; Input Validation and Stale Delivery;
  Task Adoption: `target_version` first, then the task ID; Timeout and
  Cancellation; Retry, Rerun, and Recovery; Coordination Logging: the
  `task_id_invalid` rejection omits `celery_task_id` and the raw value);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner: Coordination task and process tests, Process lifecycle; Sync
  Entry-Point Tests);
- docs/features/platform/logging.md (Correlation IDs: `task_prerun`
  binding);
- issue #836 decisions U4 (disposal belongs to the workflow) and U7
  (correlation), umbrella #833 P3 (unadmitted delivery), P7
  (validation order), and P18 (no `acks_late` or `reject_on_worker_lost`).

The registered task is executed through Celery's eager tracer
(`Task.apply(task_id=..., throw=True)`), which builds the worker request
from `task_id` and sends the real `task_prerun`/`task_postrun` signals, so
`celery_task_id` is bound exactly as in a worker. `apply()` replaces a
falsy task ID with a fresh one, so an absent or empty ID is pushed as the
request of the registered task after the same `task_prerun` signal.

Every test is a synchronous `def` (Sync Entry-Point Tests). The workflow
itself is covered by `tests/test_services/test_cvss_recalculation.py`, the
two-invocation pooled-engine regression by
`tests/test_tasks/test_cross_loop_engine_lifecycle.py`, and the module
boundaries by
`tests/test_architecture/test_cvss_recalculation_boundaries.py`.
"""

from __future__ import annotations

import ast
import asyncio
import uuid
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import redis.asyncio as redis_asyncio
from celery.app.task import Task
from celery.exceptions import SoftTimeLimitExceeded, WorkerShutdown, WorkerTerminate
from celery.signals import task_postrun, task_prerun
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from structlog.contextvars import get_contextvars, unbind_contextvars

import app.celery_app as celery_app_module
import app.database as database_module
from app.celery_app import celery_app
from app.services import cvss_recalculation, ticket_mutations
from app.services import settings as settings_service
from app.services.cvss_recalculation import (
    ADOPTION_REJECTED_EVENT,
    RECALCULATE_CVSS_DERIVED_STATE_TASK,
    validate_task_id,
)
from app.services.cvss_recalculation_coordination import LEASE_KEY
from app.tasks import cvss_tasks
from tests.support.cvss_recalculation import capture_events, wait_until_fence_free
from tests.support.module_imports import APP_ROOT

TASK_NAME = "recalculate_cvss_derived_state"
TASK = celery_app.tasks[TASK_NAME]
"""The registered task instance (the module attribute is a lazy proxy)."""

TARGET_REQUIRED = (
    "recalculate_cvss_derived_state requires target_version '3.1' or '4.0'"
)
TASK_ID_REQUIRED = "recalculate_cvss_derived_state requires a canonical UUIDv4 task ID"

_CANONICAL = "0e9b3b4c-1f2a-4b3c-8d4e-5f6a7b8c9d0e"
"""A fictional canonical lowercase hyphenated UUIDv4."""

_INVALID_TARGETS = [
    pytest.param("3.0", id="3.0"),
    pytest.param("2.0", id="2.0"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
    pytest.param(3.1, id="float"),
    pytest.param("4.0 ", id="trailing-space"),
]

_INVALID_TASK_IDS = [
    pytest.param(None, id="absent"),
    pytest.param("", id="empty"),
    pytest.param(_CANONICAL.upper(), id="uppercase"),
    pytest.param(_CANONICAL.replace("-", ""), id="unhyphenated"),
    pytest.param(f"{{{_CANONICAL}}}", id="braced"),
    pytest.param(f"urn:uuid:{_CANONICAL}", id="urn"),
    pytest.param("01890a5d-ac96-774b-bcce-b302099a8057", id="uuid-v7"),
    pytest.param("c232ab00-9414-11ec-b3c8-9f6bdeced846", id="uuid-v1"),
    pytest.param("0e9b3b4c-1f2a-4b3c-cd4e-5f6a7b8c9d0e", id="wrong-variant"),
]

_WORKFLOW_FAILURES = [
    pytest.param(lambda: ValueError("fictional contract failure"), id="value-error"),
    pytest.param(lambda: RuntimeError("fictional ownership loss"), id="runtime"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(WorkerShutdown, id="worker-shutdown"),
    pytest.param(WorkerTerminate, id="worker-terminate"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


# ---------------------------------------------------------------------------
# Fixtures and delivery
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_task_correlation() -> Iterator[None]:
    """A delivery whose exception skips `task_postrun` must not leak its
    `celery_task_id` into a later test."""
    yield
    unbind_contextvars("celery_task_id")


@pytest.fixture(autouse=True)
def forbidden_retry(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """`self.retry()` fails the test: the task never retries."""
    retry = MagicMock(side_effect=AssertionError("the task must never retry"))
    monkeypatch.setattr(type(TASK), "retry", retry)
    return retry


@pytest.fixture
def asyncio_run_spy(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the module's `asyncio` reference with a namespace whose `run`
    delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(cvss_tasks, "asyncio", SimpleNamespace(run=spy))
    return spy


def _bound_task_id() -> tuple[bool, object]:
    """Whether `celery_task_id` is bound, and its value."""
    bound = get_contextvars()
    return "celery_task_id" in bound, bound.get("celery_task_id")


class _Workflow:
    """Stand-in for the service workflow (`mock`); records the correlation
    bound while it runs."""

    def __init__(self) -> None:
        self.correlation: list[tuple[bool, object]] = []
        self.mock = AsyncMock(side_effect=self._record)

    async def _record(self, *args: object, **kwargs: object) -> None:
        self.correlation.append(_bound_task_id())


class _ValidateTaskIdSpy:
    """Wraps the real task-ID validation and records the correlation bound
    when each call starts."""

    def __init__(self) -> None:
        self.correlation: list[tuple[bool, object]] = []
        self._validate = validate_task_id

    def __call__(self, task_id: object, **kwargs: Any) -> str:
        self.correlation.append(_bound_task_id())
        return self._validate(task_id, **kwargs)


@pytest.fixture
def workflow(monkeypatch: pytest.MonkeyPatch) -> _Workflow:
    stub = _Workflow()
    monkeypatch.setattr(cvss_tasks, "run_cvss_derived_state_recalculation", stub.mock)
    return stub


@pytest.fixture
def validate_task_id_spy(monkeypatch: pytest.MonkeyPatch) -> _ValidateTaskIdSpy:
    spy = _ValidateTaskIdSpy()
    monkeypatch.setattr(cvss_tasks, "validate_task_id", spy)
    return spy


@pytest.fixture
def no_side_effects(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make the session factory, the fence, and the lease client fail when
    used; returns the names of the resources that were reached."""
    reached: list[str] = []

    def _forbidden(name: str) -> Callable[..., Any]:
        def _fail(*args: object, **kwargs: object) -> Any:
            reached.append(name)
            raise AssertionError(f"{name} must not be used")

        return _fail

    monkeypatch.setattr(
        cvss_tasks, "async_session_factory", MagicMock(side_effect=_forbidden("db"))
    )
    monkeypatch.setattr(
        cvss_recalculation,
        "new_cvss_recalculation_redis_client",
        _forbidden("redis"),
    )
    monkeypatch.setattr(
        cvss_recalculation, "try_acquire_execution_fence", _forbidden("fence")
    )
    return reached


def _deliver(target_version: object, task_id: str | None) -> object:
    """Execute the registered task as one delivery whose `task.request.id`
    is `task_id`; returns the task's return value or raises its exception.

    A non-empty ID runs through Celery's eager tracer, which sends the real
    `task_prerun` (binding `celery_task_id`) and `task_postrun` signals.
    `apply()` would replace a falsy ID, so that request is pushed onto the
    registered task directly, after the same `task_prerun` signal."""
    if task_id:
        result = TASK.apply(args=[target_version], task_id=task_id, throw=True)
        assert result.state == "SUCCESS"
        return result.result
    arguments = (target_version,)
    task_prerun.send(sender=TASK, task_id=task_id, task=TASK, args=arguments, kwargs={})
    TASK.push_request(id=task_id, args=list(arguments), kwargs={})
    try:
        return TASK.run(*arguments)
    finally:
        TASK.pop_request()
        task_postrun.send(
            sender=TASK, task_id=task_id, task=TASK, args=arguments, kwargs={}
        )


def _rejected(reason: str, target: str, **correlation: str) -> dict[str, Any]:
    return {
        "event": ADOPTION_REJECTED_EVENT,
        "log_level": "warning",
        **correlation,
        "reason": reason,
        "target_version": target,
    }


# ---------------------------------------------------------------------------
# Input validation (wrapper steps 1 and 2; Task Adoption, P7 order)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTargetVersionValidation:
    @pytest.mark.parametrize("target_version", _INVALID_TARGETS)
    def test_invalid_target_is_a_non_retryable_failure_without_any_event(
        self,
        target_version: object,
        asyncio_run_spy: MagicMock,
        workflow: _Workflow,
        validate_task_id_spy: _ValidateTaskIdSpy,
        no_side_effects: list[str],
        forbidden_retry: MagicMock,
    ) -> None:
        with (
            capture_events() as logs,
            pytest.raises(ValueError, match="target_version") as raised,
        ):
            _deliver(target_version, str(uuid.uuid4()))

        assert str(raised.value) == TARGET_REQUIRED
        assert logs == []
        assert validate_task_id_spy.correlation == []
        assert asyncio_run_spy.call_count == 0
        workflow.mock.assert_not_called()
        assert no_side_effects == []
        forbidden_retry.assert_not_called()

    @pytest.mark.parametrize(
        "task_id",
        [pytest.param(None, id="absent"), pytest.param(_CANONICAL.upper(), id="upper")],
    )
    def test_both_inputs_invalid_is_the_target_failure_without_any_event(
        self,
        task_id: str | None,
        asyncio_run_spy: MagicMock,
        workflow: _Workflow,
        validate_task_id_spy: _ValidateTaskIdSpy,
        no_side_effects: list[str],
    ) -> None:
        """P7: `target_version` is validated first, so no
        `task_id_invalid` rejection is emitted."""
        with (
            capture_events() as logs,
            pytest.raises(ValueError, match="target_version") as raised,
        ):
            _deliver("3.0", task_id)

        assert str(raised.value) == TARGET_REQUIRED
        assert logs == []
        assert validate_task_id_spy.correlation == []
        assert asyncio_run_spy.call_count == 0
        workflow.mock.assert_not_called()
        assert no_side_effects == []


@pytest.mark.unit
class TestTaskIdValidation:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    @pytest.mark.parametrize("task_id", _INVALID_TASK_IDS)
    def test_invalid_task_id_only_rejects_adoption_without_correlation(
        self,
        task_id: str | None,
        target: str,
        asyncio_run_spy: MagicMock,
        workflow: _Workflow,
        validate_task_id_spy: _ValidateTaskIdSpy,
        no_side_effects: list[str],
        forbidden_retry: MagicMock,
    ) -> None:
        """`task_prerun` bound the raw request ID before validation; the
        rejection carries neither `celery_task_id` nor the raw value, and
        the failure is a `ValueError` before `asyncio.run()`, the fence,
        Redis, or a session."""
        with (
            capture_events() as logs,
            pytest.raises(ValueError, match="UUIDv4 task ID") as raised,
        ):
            _deliver(target, task_id)

        assert str(raised.value) == TASK_ID_REQUIRED
        assert validate_task_id_spy.correlation == [(True, task_id)]
        assert logs == [_rejected("task_id_invalid", target)]
        assert "celery_task_id" not in logs[0]
        if task_id:
            assert task_id not in repr(logs)
        assert asyncio_run_spy.call_count == 0
        workflow.mock.assert_not_called()
        assert no_side_effects == []
        forbidden_retry.assert_not_called()


# ---------------------------------------------------------------------------
# Delegation (wrapper steps 3-5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDelegation:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    def test_valid_inputs_run_the_workflow_once_with_the_explicit_task_id(
        self,
        target: str,
        asyncio_run_spy: MagicMock,
        workflow: _Workflow,
        forbidden_retry: MagicMock,
    ) -> None:
        task_id = str(uuid.uuid4())

        with capture_events() as logs:
            returned = _deliver(target, task_id)

        assert returned is None
        assert asyncio_run_spy.call_count == 1
        workflow.mock.assert_called_once()
        assert workflow.mock.call_args is not None
        assert workflow.mock.call_args.kwargs == {}
        passed_target, passed_id, factory = workflow.mock.call_args.args
        assert passed_target == target
        assert passed_id == task_id
        assert type(passed_id) is str
        # The production factory, bound to the shared pooled engine.
        assert factory is database_module.async_session_factory
        # The workflow inherits the `task_prerun` correlation (U7).
        assert workflow.correlation == [(True, task_id)]
        assert logs == []
        forbidden_retry.assert_not_called()

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    def test_every_workflow_exception_propagates_unchanged_without_retry(
        self,
        make_error: Callable[[], BaseException],
        asyncio_run_spy: MagicMock,
        workflow: _Workflow,
        forbidden_retry: MagicMock,
    ) -> None:
        error = make_error()
        workflow.mock.side_effect = error

        with capture_events() as logs, pytest.raises(type(error)) as raised:
            _deliver("3.1", str(uuid.uuid4()))

        assert raised.value is error
        assert asyncio_run_spy.call_count == 1
        workflow.mock.assert_called_once()
        assert logs == []
        forbidden_retry.assert_not_called()


# ---------------------------------------------------------------------------
# Unadmitted delivery: a delivery with no admitted lease (umbrella P3; the
# manual admission of #837 is the only publisher, and it acquires the lease
# before publishing)
# ---------------------------------------------------------------------------


async def _lease_and_fence(redis_url: str, engine: AsyncEngine) -> str | None:
    client = redis_asyncio.Redis.from_url(redis_url, decode_responses=True)
    try:
        lease: str | None = await client.get(LEASE_KEY)
    finally:
        await client.aclose()
    await wait_until_fence_free(engine)
    await engine.dispose()
    return lease


@pytest.mark.integration
@pytest.mark.usefixtures("redis_client")
def test_delivery_without_a_lease_ends_with_only_lease_absent(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    _redis_test_url: str,  # noqa: PT019 — value used below (lease read)
    asyncio_run_spy: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real wrapper and workflow against the worker database and Redis:
    a valid delivery with no admitted lease acquires and releases the fence
    and emits only `adoption_rejected` (`lease_absent`) with its
    correlation. No setting is read, no unit begins, nothing is stored, and
    the fence is free afterwards. The factory is bound to a `NullPool`
    engine, so no connection crosses event loops."""
    engine = create_async_engine(_engine.url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    reached: list[str] = []

    async def _setting_read(session: AsyncSession) -> str:
        reached.append("setting")
        raise AssertionError("a rejected delivery reads no setting")

    async def _chain(session: AsyncSession, **kwargs: object) -> object:
        reached.append("unit")
        raise AssertionError("a rejected delivery begins no unit")

    monkeypatch.setattr(cvss_tasks, "async_session_factory", factory)
    monkeypatch.setattr(settings_service, "get_default_cvss_version", _setting_read)
    monkeypatch.setattr(ticket_mutations, "recalculate_cvss_chain", _chain)
    task_id = str(uuid.uuid4())

    try:
        with capture_events() as logs:
            returned = _deliver("3.1", task_id)
    finally:
        lease = asyncio.run(_lease_and_fence(_redis_test_url, engine))

    assert returned is None
    assert logs == [_rejected("lease_absent", "3.1", celery_task_id=task_id)]
    assert reached == []
    assert lease is None
    assert asyncio_run_spy.call_count == 1


# ---------------------------------------------------------------------------
# Registration (Task Identity and Workflow; Timeout and Cancellation; P18)
# ---------------------------------------------------------------------------


def _task_decorator_call() -> ast.Call:
    tree = ast.parse((APP_ROOT / "tasks" / "cvss_tasks.py").read_text("utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "task"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "celery_app"
    ]
    assert len(calls) == 1
    return calls[0]


_ACKNOWLEDGEMENT_OPTIONS = {
    "acks_late",
    "reject_on_worker_lost",
    "task_acks_late",
    "task_reject_on_worker_lost",
}


@pytest.mark.unit
class TestRegistration:
    def test_registered_bound_under_the_explicit_name(self) -> None:
        task = celery_app.tasks[TASK_NAME]

        assert RECALCULATE_CVSS_DERIVED_STATE_TASK == TASK_NAME
        assert task.name == TASK_NAME
        assert cvss_tasks.recalculate_cvss_derived_state_task.name == TASK_NAME
        # A bound task's `run` is the wrapper bound to the task instance.
        assert task.run.__func__ is cvss_tasks._recalculate_cvss_derived_state_sync
        assert task.run.__self__ is task
        call = _task_decorator_call()
        assert {keyword.arg for keyword in call.keywords} == {"bind", "name"}
        bind = next(k.value for k in call.keywords if k.arg == "bind")
        name = next(k.value for k in call.keywords if k.arg == "name")
        assert isinstance(bind, ast.Constant)
        assert bind.value is True
        assert isinstance(name, ast.Name)
        assert name.id == "RECALCULATE_CVSS_DERIVED_STATE_TASK"

    def test_no_retry_or_time_limit_is_configured(self) -> None:
        task = celery_app.tasks[TASK_NAME]

        assert not getattr(task, "autoretry_for", None)
        assert not getattr(task, "retry_kwargs", None)
        assert not getattr(task, "retry_backoff", None)
        assert task.max_retries == Task.max_retries
        assert task.soft_time_limit is None
        assert task.time_limit is None
        assert celery_app.conf.task_soft_time_limit is None
        assert celery_app.conf.task_time_limit is None
        assert celery_app.conf.task_annotations is None
        tree = ast.parse((APP_ROOT / "tasks" / "cvss_tasks.py").read_text("utf-8"))
        assert "retry" not in {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }

    def test_neither_task_nor_application_sets_late_acknowledgement(self) -> None:
        """P18: the Celery acknowledgement and visibility defaults stay
        unchanged, on the task and on the application."""
        task = celery_app.tasks[TASK_NAME]

        assert task.acks_late is False
        assert not task.reject_on_worker_lost
        assert celery_app.conf.task_acks_late is False
        assert not celery_app.conf.task_reject_on_worker_lost
        assert (
            not {keyword.arg for keyword in _task_decorator_call().keywords}
            & _ACKNOWLEDGEMENT_OPTIONS
        )
        tree = ast.parse((APP_ROOT / "celery_app.py").read_text("utf-8"))
        named = {
            keyword.arg
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for keyword in node.keywords
        } | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not named & _ACKNOWLEDGEMENT_OPTIONS
        assert not literals & _ACKNOWLEDGEMENT_OPTIONS

    def test_registered_through_the_celery_app_task_module_import(self) -> None:
        tree = ast.parse((APP_ROOT / "celery_app.py").read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "app.tasks"
            for alias in node.names
        }
        assert "cvss_tasks" in imported
        assert vars(celery_app_module)["cvss_tasks"] is cvss_tasks
