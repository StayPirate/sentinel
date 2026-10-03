"""Tests for the `re_evaluate_product_eligibility` Celery task boundary
(backend/app/tasks/package_tasks.py).

See `docs/features/packages/product-lifecycle-transitions.md` (Sub-task:
`re_evaluate_product_eligibility`: validation before any session, one
`asyncio.run()` per invocation, `engine.dispose()` exactly once on every
path, no automatic Celery retry), `docs/conventions.md` (Sync-to-Async
Bridging, Cross-Loop Pooled Connection Lifecycle), and
`docs/features/platform/fetcher-infrastructure.md` (Celery Integration:
sub-operations are not `FETCHER_REGISTRY` entries and create no
`FetcherRun`) for the contract under test.

The workflow itself is tested in
`tests/test_services/test_packages/test_product_eligibility_recalculation.py`
and the real two-invocation cross-loop regression in
`tests/test_tasks/test_cross_loop_engine_lifecycle.py`. Every test here
rebinds the module-level `engine` to a fake whose `dispose` is an
`AsyncMock` and defaults the session factory to one that fails when
called. Tests of the synchronous wrapper are `def` (testing-strategy.md,
Sync Entry-Point Tests); the one that runs the real workflow uses the
`NullPool` `cli_session_factory` so no connection crosses event loops.
"""

from __future__ import annotations

import ast
import asyncio
import uuid
from collections.abc import Callable, MutableMapping
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from celery.app.task import Task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.celery_app as celery_app_module
from app.celery_app import celery_app
from app.services.base_fetcher import FETCHER_REGISTRY
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
        assert package_tasks.RE_EVALUATE_PRODUCT_ELIGIBILITY_TASK == TASK_NAME
        assert package_tasks.re_evaluate_product_eligibility_task.name == TASK_NAME
        assert task.run is package_tasks._re_evaluate_product_eligibility_sync

    def test_no_automatic_retry_is_configured(self) -> None:
        """No `autoretry_for`, retry options, or non-default `max_retries`;
        the task is unbound, so the wrapper cannot call `self.retry()`."""
        task = celery_app.tasks[TASK_NAME]

        assert not getattr(task, "autoretry_for", None)
        assert not getattr(task, "retry_kwargs", None)
        assert not getattr(task, "retry_backoff", None)
        assert task.max_retries == Task.max_retries
        tree = ast.parse(
            (APP_ROOT / "tasks" / "package_tasks.py").read_text(encoding="utf-8")
        )
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
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
