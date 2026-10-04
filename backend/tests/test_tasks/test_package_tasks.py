"""Tests for the package-domain Celery task boundaries
(backend/app/tasks/package_tasks.py): `re_evaluate_product_eligibility` and
the root Ticket convergence task `run_ticket_convergence`.

See `docs/features/packages/product-lifecycle-transitions.md` (Sub-task:
`re_evaluate_product_eligibility`: validation before any session, one
`asyncio.run()` per invocation, `engine.dispose()` exactly once on every
path, no automatic Celery retry), `docs/conventions.md` (Sync-to-Async
Bridging, Cross-Loop Pooled Connection Lifecycle), and
`docs/features/platform/fetcher-infrastructure.md` (Celery Integration:
sub-operations are not `FETCHER_REGISTRY` entries and create no
`FetcherRun`) for the contract under test of the re-evaluation task, and
`docs/features/packages/package-service.md` (`run_ticket_convergence()`
workflow: the bound wrapper validates `ticket_id`, runs exactly one
`asyncio.run()`, disposes the engine before the loop closes, retries the
complete workflow at 5, 10, and 20 seconds, logs terminal failure, and
returns `None`) with `docs/features/platform/testing-strategy.md` (Sync
Entry-Point Tests; Cross-Loop Engine Lifecycle) for the convergence task.

The workflows themselves are tested in
`tests/test_services/test_packages/test_product_eligibility_recalculation.py`
and `tests/test_services/test_run_ticket_convergence.py`, and the real
two-invocation cross-loop regressions in
`tests/test_tasks/test_cross_loop_engine_lifecycle.py`. Every test here
rebinds the module-level `engine` to a fake whose `dispose` is an
`AsyncMock` and defaults the session factory to one that fails when
called. Tests of the synchronous wrapper are `def` (testing-strategy.md,
Sync Entry-Point Tests); those that run a real workflow use the `NullPool`
`cli_session_factory` so no connection crosses event loops. The bound
convergence wrapper is called with a fake bound task (`request.retries`,
`retry()`), as in `tests/test_tasks/test_run_catch_up.py`.
"""

from __future__ import annotations

import ast
import asyncio
import uuid
from collections.abc import Callable, MutableMapping
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from celery.app.task import Task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.celery_app as celery_app_module
from app.celery_app import celery_app
from app.services import task_publication
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.packages.product_eligibility_recalculation import (
    RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK,
)
from app.services.ticket_convergence_publication import RUN_TICKET_CONVERGENCE_TASK
from app.tasks import package_tasks
from tests.support.module_imports import APP_ROOT

LogEntry = MutableMapping[str, Any]

TASK_NAME = "re_evaluate_product_eligibility"
DISPOSE_FAILED = "re_evaluate_product_eligibility_engine_dispose_failed"

_WORKFLOW_FAILURES = [
    pytest.param(lambda: RuntimeError("fictional workflow failure"), id="runtime"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]

_INVALID_ARGUMENTS = [
    pytest.param(
        str(uuid.uuid4()),
        "reactivation",
        "unsupported Product eligibility recalculation reason",
        id="unsupported-reason",
    ),
    pytest.param(
        "not-a-uuid",
        "threshold",
        "catalog_product_id must be a UUID",
        id="malformed-product-id",
    ),
]


class _FakeEngine:
    """Substitute for the module-level `engine` singleton (mirrors
    `tests/test_tasks/test_run_catch_up.py`)."""

    def __init__(self) -> None:
        self.dispose = AsyncMock()


def _events(logs: list[LogEntry], name: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["event"] == name]


@pytest.fixture(autouse=True)
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> _FakeEngine:
    engine = _FakeEngine()
    monkeypatch.setattr(package_tasks, "engine", engine)
    return engine


@pytest.fixture(autouse=True)
def forbidden_session_factory(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Default session factory that fails the test when called."""
    factory = MagicMock(side_effect=AssertionError("must not open a session"))
    monkeypatch.setattr(package_tasks, "async_session_factory", factory)
    return factory


@pytest.fixture
def workflow(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stand-in for the package-domain workflow called by the task."""
    mock = AsyncMock(return_value=None)
    monkeypatch.setattr(package_tasks, "re_evaluate_product_eligibility", mock)
    return mock


@pytest.fixture
def asyncio_run_spy(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the module's `asyncio` reference with a namespace whose
    `run` delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(package_tasks, "asyncio", SimpleNamespace(run=spy))
    return spy


# ---------------------------------------------------------------------------
# Async workflow boundary: validation, delegation, and engine disposal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestReEvaluateProductEligibilityAsync:
    @pytest.mark.parametrize("reason", ["threshold", "reactive_ltss"])
    async def test_success_delegates_then_disposes_once(
        self,
        reason: str,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        product_id = uuid.uuid4()
        order: list[str] = []
        workflow.side_effect = lambda *args, **kwargs: order.append("workflow")
        fake_engine.dispose.side_effect = lambda: order.append("dispose")

        await package_tasks.re_evaluate_product_eligibility_async(
            str(product_id), reason
        )

        workflow.assert_awaited_once_with(
            product_id, reason, session_factory=forbidden_session_factory
        )
        assert workflow.await_args is not None
        assert type(workflow.await_args.args[0]) is uuid.UUID
        fake_engine.dispose.assert_awaited_once_with()
        assert order == ["workflow", "dispose"]

    @pytest.mark.parametrize(("product_id", "reason", "message"), _INVALID_ARGUMENTS)
    async def test_invalid_arguments_raise_before_any_session_and_dispose(
        self,
        product_id: str,
        reason: str,
        message: str,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        with capture_logs() as logs, pytest.raises(ValueError, match=message):
            await package_tasks.re_evaluate_product_eligibility_async(
                product_id, reason
            )

        assert len([e for e in logs if e["log_level"] == "error"]) == 1
        workflow.assert_not_awaited()
        forbidden_session_factory.assert_not_called()
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_workflow_failure_propagates_after_one_disposal(
        self,
        make_error: Callable[[], BaseException],
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = make_error()
        workflow.side_effect = error

        with capture_logs() as logs, pytest.raises(type(error)) as exc_info:
            await package_tasks.re_evaluate_product_eligibility_async(
                str(uuid.uuid4()), "threshold"
            )

        assert exc_info.value is error
        workflow.assert_awaited_once()
        fake_engine.dispose.assert_awaited_once_with()
        assert _events(logs, DISPOSE_FAILED) == []

    async def test_dispose_failure_after_success_propagates(
        self, workflow: AsyncMock, fake_engine: _FakeEngine
    ) -> None:
        error = RuntimeError("fictional dispose failure")
        fake_engine.dispose.side_effect = error

        with capture_logs() as logs, pytest.raises(RuntimeError) as exc_info:
            await package_tasks.re_evaluate_product_eligibility_async(
                str(uuid.uuid4()), "threshold"
            )

        assert exc_info.value is error
        workflow.assert_awaited_once()
        fake_engine.dispose.assert_awaited_once_with()
        assert _events(logs, DISPOSE_FAILED) == []

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_dispose_failure_does_not_mask_workflow_failure(
        self,
        make_error: Callable[[], BaseException],
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = make_error()
        workflow.side_effect = error
        fake_engine.dispose.side_effect = RuntimeError("fictional dispose failure")

        with capture_logs() as logs, pytest.raises(type(error)) as exc_info:
            await package_tasks.re_evaluate_product_eligibility_async(
                str(uuid.uuid4()), "threshold"
            )

        assert exc_info.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == [{"event": DISPOSE_FAILED, "log_level": "warning"}]

    async def test_dispose_failure_does_not_mask_validation_failure(
        self,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        fake_engine.dispose.side_effect = RuntimeError("fictional dispose failure")

        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match="catalog_product_id must be a UUID"),
        ):
            await package_tasks.re_evaluate_product_eligibility_async(
                "not-a-uuid", "threshold"
            )

        fake_engine.dispose.assert_awaited_once_with()
        warnings = [e for e in logs if e["log_level"] == "warning"]
        assert warnings == [{"event": DISPOSE_FAILED, "log_level": "warning"}]
        workflow.assert_not_awaited()
        forbidden_session_factory.assert_not_called()


# ---------------------------------------------------------------------------
# Synchronous Celery wrapper
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestReEvaluateProductEligibilitySyncWrapper:
    def test_one_asyncio_run_with_argument_passthrough(
        self, asyncio_run_spy: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str]] = []

        async def fake_async(catalog_product_id: str, reason: str) -> None:
            calls.append((catalog_product_id, reason))

        monkeypatch.setattr(
            package_tasks, "re_evaluate_product_eligibility_async", fake_async
        )
        product_id = str(uuid.uuid4())

        package_tasks._re_evaluate_product_eligibility_sync(product_id, "reactive_ltss")

        assert calls == [(product_id, "reactive_ltss")]
        assert asyncio_run_spy.call_count == 1

    def test_success_runs_workflow_and_disposes_in_one_event_loop(
        self,
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        product_id = uuid.uuid4()

        package_tasks._re_evaluate_product_eligibility_sync(
            str(product_id), "threshold"
        )

        assert asyncio_run_spy.call_count == 1
        workflow.assert_awaited_once_with(
            product_id, "threshold", session_factory=forbidden_session_factory
        )
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize(("product_id", "reason", "message"), _INVALID_ARGUMENTS)
    def test_invalid_arguments_fail_the_task(
        self,
        product_id: str,
        reason: str,
        message: str,
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        with pytest.raises(ValueError, match=message):
            package_tasks._re_evaluate_product_eligibility_sync(product_id, reason)

        assert asyncio_run_spy.call_count == 1
        workflow.assert_not_awaited()
        forbidden_session_factory.assert_not_called()
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    def test_workflow_failure_propagates(
        self,
        make_error: Callable[[], BaseException],
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = make_error()
        workflow.side_effect = error

        # `asyncio.run()` re-creates a `CancelledError` when the task ends
        # cancelled, so only the exception type is asserted.
        with pytest.raises(type(error)):
            package_tasks._re_evaluate_product_eligibility_sync(
                str(uuid.uuid4()), "threshold"
            )

        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()


@pytest.mark.integration
def test_sync_wrapper_runs_the_real_workflow_without_candidates(
    cli_session_factory: async_sessionmaker[AsyncSession],
    asyncio_run_spy: MagicMock,
    fake_engine: _FakeEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real workflow inside the wrapper's own event loop, through the
    `NullPool` factory: an unknown Product has no candidate Ticket, which
    is a successful no-op. Nothing is written, so no cleanup is needed."""
    monkeypatch.setattr(package_tasks, "async_session_factory", cli_session_factory)
    product_id = uuid.uuid4()

    with capture_logs() as logs:
        package_tasks._re_evaluate_product_eligibility_sync(
            str(product_id), "threshold"
        )

    assert logs == [
        {
            "event": "product_eligibility_recalculation_completed",
            "log_level": "info",
            "catalog_product_id": str(product_id),
            "reason": "threshold",
            "candidates": 0,
            "successful": 0,
            "skipped": 0,
            "no_op": 0,
            "changed_records": 0,
            "failed": 0,
        }
    ]
    assert asyncio_run_spy.call_count == 1
    fake_engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Task registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestReEvaluateProductEligibilityTaskRegistration:
    def test_registered_under_exact_name(self) -> None:
        task = celery_app.tasks[TASK_NAME]

        assert task.name == TASK_NAME
        assert RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK == TASK_NAME
        assert package_tasks.re_evaluate_product_eligibility_task.name == TASK_NAME
        assert task.run is package_tasks._re_evaluate_product_eligibility_sync

    def test_no_automatic_retry_is_configured(self) -> None:
        """No `autoretry_for`, retry options, or non-default `max_retries`;
        the task is unbound, so its wrapper cannot call `self.retry()`. The
        module also hosts the bound, retrying convergence task, so only the
        re-evaluation wrapper, its async workflow, and its registration
        are inspected."""
        task = celery_app.tasks[TASK_NAME]

        assert not getattr(task, "autoretry_for", None)
        assert not getattr(task, "retry_kwargs", None)
        assert not getattr(task, "retry_backoff", None)
        assert task.max_retries == Task.max_retries
        assert task.run is package_tasks._re_evaluate_product_eligibility_sync
        tree = ast.parse(
            (APP_ROOT / "tasks" / "package_tasks.py").read_text(encoding="utf-8")
        )
        owned = [
            node
            for node in tree.body
            if (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name
                in {
                    "_re_evaluate_product_eligibility_sync",
                    "re_evaluate_product_eligibility_async",
                }
            )
            or (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Name)
                    and t.id == "re_evaluate_product_eligibility_task"
                    for t in node.targets
                )
            )
        ]
        assert len(owned) == 3
        calls = [
            node
            for owner in owned
            for node in ast.walk(owner)
            if isinstance(node, ast.Call)
        ]
        assert not [
            c
            for c in calls
            if isinstance(c.func, ast.Attribute) and c.func.attr == "retry"
        ]
        assert not [k for c in calls for k in c.keywords if k.arg == "bind"]

    def test_registered_through_the_celery_app_task_module_import(self) -> None:
        tree = ast.parse((APP_ROOT / "celery_app.py").read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "app.tasks"
            for alias in node.names
        }
        assert "package_tasks" in imported
        assert vars(celery_app_module)["package_tasks"] is package_tasks

    def test_is_a_sub_operation_not_a_fetcher(self) -> None:
        assert TASK_NAME not in FETCHER_REGISTRY


# ===========================================================================
# Root Ticket convergence task (package-service.md, `run_ticket_convergence()`
# workflow: the bound Celery wrapper)
# ===========================================================================

CONVERGENCE_TASK = "run_ticket_convergence"
CONVERGENCE_DISPOSE_FAILED = "ticket_convergence_engine_dispose_failed"
INVALID_TICKET_ID = "ticket_convergence_invalid_ticket_id"
RETRYING = "ticket_convergence_retrying"
TERMINAL = "ticket_convergence_failed"
UUID_REQUIRED = "run_ticket_convergence requires a UUID ticket_id"

_MALFORMED_TICKET_IDS = [
    pytest.param("not-a-uuid", id="not-a-uuid"),
    pytest.param("", id="empty"),
    pytest.param("SNTL-42", id="public-locator"),
    pytest.param(12345, id="integer"),
    pytest.param(None, id="none"),
    pytest.param(uuid.UUID("01890a5d-ac96-774b-bcce-b302099a8057"), id="uuid-object"),
]
"""Task arguments that are not the string form of a UUID."""

_CONTROL_SIGNALS = [
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


class _RetryRequested(Exception):  # noqa: N818 — mirrors celery's `Retry`
    """Stand-in for the `celery.exceptions.Retry` that `Task.retry()`
    produces; the wrapper raises whatever `self.retry()` returns."""


class _FakeTask:
    """Minimal stand-in for the bound Celery Task instance (`self`),
    carrying only what `_run_ticket_convergence_sync` reads:
    `request.retries` and `retry()`."""

    def __init__(self, retries: int = 0) -> None:
        self.request = SimpleNamespace(retries=retries)
        self.retry = MagicMock(return_value=_RetryRequested())


@pytest.fixture
def convergence(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stand-in for the package-domain convergence workflow."""
    mock = AsyncMock(return_value=None)
    monkeypatch.setattr(package_tasks, "run_ticket_convergence", mock)
    return mock


def _enumeration_failure(monkeypatch: pytest.MonkeyPatch) -> OperationalError:
    """Make the real workflow fail in its enumeration phase: the session
    factory raises a driver-level error when called."""
    error = OperationalError(
        "fictional statement", None, Exception("fictional-secret-detail")
    )
    monkeypatch.setattr(
        package_tasks, "async_session_factory", MagicMock(side_effect=error)
    )
    return error


@pytest.mark.unit
class TestRunTicketConvergenceAsync:
    async def test_success_delegates_then_disposes_once(
        self,
        convergence: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        ticket_id = uuid.uuid7()
        order: list[str] = []
        convergence.side_effect = lambda **kwargs: order.append("workflow")
        fake_engine.dispose.side_effect = lambda: order.append("dispose")

        await package_tasks.run_ticket_convergence_async(ticket_id)
        convergence.assert_awaited_once_with(
            ticket_id=ticket_id, session_factory=forbidden_session_factory
        )
        fake_engine.dispose.assert_awaited_once_with()
        assert order == ["workflow", "dispose"]

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_workflow_failure_propagates_after_one_disposal(
        self,
        make_error: Callable[[], BaseException],
        convergence: AsyncMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = make_error()
        convergence.side_effect = error

        with capture_logs() as logs, pytest.raises(type(error)) as exc_info:
            await package_tasks.run_ticket_convergence_async(uuid.uuid7())

        assert exc_info.value is error
        convergence.assert_awaited_once()
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == []

    async def test_dispose_failure_after_success_propagates(
        self, convergence: AsyncMock, fake_engine: _FakeEngine
    ) -> None:
        error = RuntimeError("fictional dispose failure")
        fake_engine.dispose.side_effect = error

        with capture_logs() as logs, pytest.raises(RuntimeError) as exc_info:
            await package_tasks.run_ticket_convergence_async(uuid.uuid7())

        assert exc_info.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == []

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_dispose_failure_does_not_mask_workflow_failure(
        self,
        make_error: Callable[[], BaseException],
        convergence: AsyncMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = make_error()
        convergence.side_effect = error
        fake_engine.dispose.side_effect = RuntimeError("fictional dispose failure")

        with capture_logs() as logs, pytest.raises(type(error)) as exc_info:
            await package_tasks.run_ticket_convergence_async(uuid.uuid7())

        assert exc_info.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == [{"event": CONVERGENCE_DISPOSE_FAILED, "log_level": "warning"}]


@pytest.mark.unit
class TestRunTicketConvergenceSyncWrapper:
    def test_success_returns_none_without_retry_or_log(
        self,
        convergence: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        ticket_id = uuid.uuid7()
        task = _FakeTask()

        with capture_logs() as logs:
            package_tasks._run_ticket_convergence_sync(task, str(ticket_id))
        convergence.assert_awaited_once_with(
            ticket_id=ticket_id, session_factory=forbidden_session_factory
        )
        assert convergence.await_args is not None
        assert type(convergence.await_args.kwargs["ticket_id"]) is uuid.UUID
        task.retry.assert_not_called()
        assert logs == []
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("ticket_id", _MALFORMED_TICKET_IDS)
    def test_malformed_ticket_id_is_a_non_retryable_caller_failure(
        self,
        ticket_id: object,
        convergence: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        """One ERROR without the rejected value, then `ValueError`, before
        any event loop, session, workflow call, or retry."""
        task = _FakeTask()

        with capture_logs() as logs, pytest.raises(ValueError, match=UUID_REQUIRED):
            package_tasks._run_ticket_convergence_sync(task, cast(str, ticket_id))

        assert logs == [
            {
                "event": INVALID_TICKET_ID,
                "log_level": "error",
                "cause": "ticket_id is not a valid UUID",
            }
        ]
        task.retry.assert_not_called()
        convergence.assert_not_awaited()
        forbidden_session_factory.assert_not_called()
        assert asyncio_run_spy.call_count == 0
        fake_engine.dispose.assert_not_awaited()

    @pytest.mark.parametrize(
        ("retries", "countdown"),
        [
            pytest.param(0, 5, id="first-retry"),
            pytest.param(1, 10, id="second-retry"),
            pytest.param(2, 20, id="third-retry"),
        ],
    )
    def test_workflow_failure_retries_the_complete_workflow_with_backoff(
        self,
        retries: int,
        countdown: int,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The real workflow fails in enumeration; the wrapper logs one
        WARNING with the Ticket, the failed phase, the exception class as
        the sanitized cause, the retry number, and the countdown, then
        requests the retry of the same `ticket_id`."""
        error = _enumeration_failure(monkeypatch)
        ticket_id = str(uuid.uuid7())
        task = _FakeTask(retries=retries)

        with capture_logs() as logs, pytest.raises(_RetryRequested):
            package_tasks._run_ticket_convergence_sync(task, ticket_id)

        task.retry.assert_called_once_with(exc=error, countdown=countdown)
        assert logs == [
            {
                "event": RETRYING,
                "log_level": "warning",
                "ticket_id": ticket_id,
                "phase": "package_enumeration",
                "cause": "OperationalError",
                "retries": retries,
                "countdown": countdown,
            }
        ]
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_unclassified_failure_is_retried_with_an_unknown_phase(
        self,
        convergence: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = RuntimeError("fictional-secret-detail")
        convergence.side_effect = error
        ticket_id = str(uuid.uuid7())
        task = _FakeTask()

        with capture_logs() as logs, pytest.raises(_RetryRequested):
            package_tasks._run_ticket_convergence_sync(task, ticket_id)

        task.retry.assert_called_once_with(exc=error, countdown=5)
        assert [(e["event"], e["phase"], e["cause"]) for e in logs] == [
            (RETRYING, "unknown", "RuntimeError")
        ]
        assert "fictional-secret-detail" not in repr(logs)

    def test_exhaustion_logs_one_terminal_error_and_returns_none(
        self,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After the third retry the wrapper emits exactly one terminal ERROR
        with the Ticket, the failed phase, and the exception class (no
        exception text), requests no further retry, and returns `None`."""
        _enumeration_failure(monkeypatch)
        ticket_id = str(uuid.uuid7())
        task = _FakeTask(retries=3)

        with capture_logs() as logs:
            package_tasks._run_ticket_convergence_sync(task, ticket_id)
        task.retry.assert_not_called()
        assert logs == [
            {
                "event": TERMINAL,
                "log_level": "error",
                "ticket_id": ticket_id,
                "phase": "package_enumeration",
                "cause": "OperationalError",
                "retries": 3,
            }
        ]
        assert "fictional-secret-detail" not in repr(logs)
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_terminal_and_malformed_errors_carry_bound_celery_task_id(
        self, convergence: AsyncMock
    ) -> None:
        """The task-bound `celery_task_id` (bound by `task_prerun`) reaches
        both the terminal ERROR and the malformed-argument ERROR."""
        convergence.side_effect = RuntimeError("fictional failure")
        celery_task_id = str(uuid.uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                package_tasks._run_ticket_convergence_sync(
                    _FakeTask(retries=3), str(uuid.uuid7())
                )
                with pytest.raises(ValueError, match=UUID_REQUIRED):
                    package_tasks._run_ticket_convergence_sync(
                        _FakeTask(), "not-a-uuid"
                    )
        finally:
            unbind_contextvars("celery_task_id")

        assert [e["event"] for e in logs] == [TERMINAL, INVALID_TICKET_ID]
        assert all(e["celery_task_id"] == celery_task_id for e in logs)

    @pytest.mark.parametrize("make_signal", _CONTROL_SIGNALS)
    def test_control_signals_propagate_without_retry_or_log(
        self,
        make_signal: Callable[[], BaseException],
        convergence: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
    ) -> None:
        convergence.side_effect = make_signal()
        task = _FakeTask()

        # `asyncio.run()` re-creates a `CancelledError` when the task ends
        # cancelled, so only the exception type is asserted.
        with capture_logs() as logs, pytest.raises(type(convergence.side_effect)):
            package_tasks._run_ticket_convergence_sync(task, str(uuid.uuid7()))

        task.retry.assert_not_called()
        assert logs == []
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries")
def test_convergence_wrapper_runs_the_real_workflow_for_a_missing_ticket(
    cli_session_factory: async_sessionmaker[AsyncSession],
    asyncio_run_spy: MagicMock,
    fake_engine: _FakeEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real workflow inside the wrapper's own event loop, through the
    `NullPool` factory: a missing Ticket has no package marker and the
    emptied registry an empty roster, which is a completed no-op. Nothing
    is written or published, so no cleanup is needed."""
    FETCHER_REGISTRY.clear()
    published: list[str] = []

    async def _publish(task_name: str, **options: Any) -> None:
        published.append(task_name)

    monkeypatch.setattr(task_publication, "publish_task", _publish)
    monkeypatch.setattr(package_tasks, "async_session_factory", cli_session_factory)
    ticket_id = str(uuid.uuid7())
    task = _FakeTask()

    with capture_logs() as logs:
        package_tasks._run_ticket_convergence_sync(task, ticket_id)
    task.retry.assert_not_called()
    assert logs == [
        {
            "event": "ticket_convergence_completed",
            "log_level": "info",
            "ticket_id": ticket_id,
            "packages": 0,
            "packages_converged": 0,
            "packages_failed": 0,
            "packages_stale": 0,
            "catch_ups_dispatched": 0,
        }
    ]
    assert published == []
    assert asyncio_run_spy.call_count == 1
    fake_engine.dispose.assert_awaited_once_with()


@pytest.mark.unit
class TestRunTicketConvergenceTaskRegistration:
    def test_registered_bound_under_exact_name_with_three_retries(self) -> None:
        task = celery_app.tasks[CONVERGENCE_TASK]

        assert task.name == CONVERGENCE_TASK
        assert RUN_TICKET_CONVERGENCE_TASK == CONVERGENCE_TASK
        assert package_tasks.run_ticket_convergence_task.name == CONVERGENCE_TASK
        # A bound task's `run` is the wrapper bound to the task instance.
        assert task.run.__func__ is package_tasks._run_ticket_convergence_sync
        assert task.run.__self__ is task
        assert task.max_retries == 3
        assert package_tasks.TICKET_CONVERGENCE_RETRY_DELAYS == (5, 10, 20)
        assert not getattr(task, "autoretry_for", None)

    def test_is_a_sub_operation_not_a_fetcher(self) -> None:
        assert CONVERGENCE_TASK not in FETCHER_REGISTRY
