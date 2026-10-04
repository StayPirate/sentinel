"""Tests for the CVE-ingestion sub-operation task boundary
(backend/app/tasks/cve_tasks.py): `resolve_ticket_packages`.

See `docs/features/packages/package-service.md` (Post-ingest CVE package
resolution: Task boundary and arguments — five explicit JSON-compatible
arguments, never the `PostIngestTasks` dataclass, validated before any
resolver, database, HTTP-client, or SMELT work; no automatic Celery retry;
returns `None`; no `FetcherRun`; Resource lifecycle — exactly one
`asyncio.run()` and `engine.dispose()` exactly once on every outcome),
`docs/conventions.md` (Sync-to-Async Bridging, Cross-Loop Pooled Connection
Lifecycle), and `docs/features/platform/testing-strategy.md` (Post-Ingest
Package Resolution; Sync Entry-Point Tests) for the contract under test,
with issue #786 decision D4 (validation runs inside the single
`asyncio.run()`, so disposal also follows a validation failure).

The workflow itself is tested in
`tests/test_services/test_post_ingest_package_resolution.py`, argument
validation in `tests/test_services/test_post_ingest_package_arguments.py`,
and the real two-invocation cross-loop regression in
`tests/test_tasks/test_cross_loop_engine_lifecycle.py`. Every test here
rebinds the module-level `engine` to a fake whose `dispose` is an
`AsyncMock`, defaults the session factory to one that fails when called,
and makes the resolvers and the HTTP-client factory fail when called.
Tests of the synchronous wrapper are `def` (testing-strategy.md, Sync
Entry-Point Tests).
"""

from __future__ import annotations

import ast
import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import asdict
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from celery.app.task import Task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.exc import OperationalError
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.celery_app as celery_app_module
from app.celery_app import celery_app
from app.services import package_service
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.cve_ingest import PostIngestTasks
from app.services.package_service import (
    RESOLVE_TICKET_PACKAGES_TASK,
    PostIngestArgumentError,
    ValidatedCPEMatch,
)
from app.tasks import cve_tasks
from tests.support.module_imports import APP_ROOT

LogEntry = MutableMapping[str, Any]

TASK_NAME = "resolve_ticket_packages"
DISPOSE_FAILED = "resolve_ticket_packages_engine_dispose_failed"
FAILED = "ticket_package_resolution_failed"
EMPTY = "ticket_package_resolution_empty"

TICKET_ID = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
MCID = "1aaaaaaa-0000-4000-8000-000000000001"
CPE = "cpe:2.3:a:example:alpha:1.0:*:*:*:*:*:*:*"
MARKER = "Example-Confidential-Task-Value"
INVALID_ARGUMENT = "invalid resolve_ticket_packages argument"

_WORKFLOW_FAILURES = [
    pytest.param(lambda: RuntimeError("fictional workflow failure"), id="runtime"),
    pytest.param(
        lambda: OperationalError("fictional statement", None, Exception(MARKER)),
        id="database",
    ),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


def _primitives(**overrides: object) -> dict[str, object]:
    """Valid JSON-compatible task arguments, one value per container."""
    arguments: dict[str, object] = {
        "ticket_id": TICKET_ID,
        "cpe_matches": [
            {"criteria": CPE, "vulnerable": False, "match_criteria_id": MCID}
        ],
        "affected_cpes": [CPE],
        "vendor_products": [["Example Vendor", "Alpha"]],
        "resolved_packages": ["Fictional-Package"],
    }
    arguments.update(overrides)
    return arguments


_MALFORMED = [
    pytest.param(_primitives(ticket_id=MARKER), "ticket_id", id="ticket-id"),
    pytest.param(_primitives(cpe_matches={}), "cpe_matches", id="cpe-matches-object"),
    pytest.param(
        _primitives(cpe_matches=[{"criteria": CPE, "vulnerable": True}]),
        "cpe_matches",
        id="cpe-match-missing-key",
    ),
    pytest.param(
        _primitives(affected_cpes=["x" * 2049]),
        "affected_cpes",
        id="affected-cpe-overlength",
    ),
    pytest.param(
        _primitives(vendor_products=[["vendor-only"]]),
        "vendor_products",
        id="vendor-product-shape",
    ),
    pytest.param(
        _primitives(resolved_packages=[MARKER + "\x00"]),
        "resolved_packages",
        id="package-name-nul",
    ),
]


class _FakeEngine:
    """Substitute for the module-level `engine` singleton."""

    def __init__(self) -> None:
        self.dispose = AsyncMock()


def _sync(*arguments: object, **keywords: object) -> object:
    """The synchronous wrapper, typed to observe its runtime return value."""
    wrapper: Callable[..., object] = cve_tasks._resolve_ticket_packages_sync
    return wrapper(*arguments, **keywords)


async def _async(**arguments: object) -> object:
    """The async boundary, typed to observe its runtime return value."""
    boundary: Callable[..., Awaitable[object]] = cve_tasks.resolve_ticket_packages_async
    return await boundary(**arguments)


def _events(logs: list[LogEntry], name: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["event"] == name]


@pytest.fixture(autouse=True)
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> _FakeEngine:
    engine = _FakeEngine()
    monkeypatch.setattr(cve_tasks, "engine", engine)
    return engine


@pytest.fixture(autouse=True)
def forbidden_session_factory(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Default session factory that fails the test when called."""
    factory = MagicMock(side_effect=AssertionError("must not open a session"))
    monkeypatch.setattr(cve_tasks, "async_session_factory", factory)
    return factory


@pytest.fixture(autouse=True)
def forbidden_work(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Resolvers and HTTP-client factory that fail the test when called."""
    mocks = {
        name: MagicMock(side_effect=AssertionError(f"{name} must not be called"))
        for name in (
            "resolve_cpe_packages",
            "resolve_vendor_product",
            "create_http_client",
        )
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(package_service, name, mock)
    return mocks


@pytest.fixture
def workflow(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stand-in for the package-domain workflow called by the task."""
    mock = AsyncMock(return_value=None)
    monkeypatch.setattr(cve_tasks, "run_post_ingest_package_resolution", mock)
    return mock


@pytest.fixture
def asyncio_run_spy(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the module's `asyncio` reference with a namespace whose
    `run` delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(cve_tasks, "asyncio", SimpleNamespace(run=spy))
    return spy


def _assert_typed_delegation(workflow: AsyncMock, session_factory: object) -> None:
    """The workflow received the validated, typed values unchanged (no
    trimming or case change) and the module-level session factory."""
    workflow.assert_awaited_once_with(
        ticket_id=uuid.UUID(TICKET_ID),
        cpe_matches=(ValidatedCPEMatch(CPE, False, uuid.UUID(MCID)),),
        affected_cpes=(CPE,),
        vendor_products=(("Example Vendor", "Alpha"),),
        resolved_packages=("Fictional-Package",),
        session_factory=session_factory,
    )
    assert workflow.await_args is not None
    assert type(workflow.await_args.kwargs["ticket_id"]) is uuid.UUID


def _assert_no_work(
    workflow: AsyncMock,
    forbidden_session_factory: MagicMock,
    forbidden_work: dict[str, MagicMock],
) -> None:
    workflow.assert_not_awaited()
    forbidden_session_factory.assert_not_called()
    for mock in forbidden_work.values():
        mock.assert_not_called()


# ---------------------------------------------------------------------------
# Async invocation boundary: validation, delegation, and engine disposal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveTicketPackagesAsync:
    async def test_success_delegates_typed_values_then_disposes_once(
        self,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        order: list[str] = []
        workflow.side_effect = lambda **kwargs: order.append("workflow")
        fake_engine.dispose.side_effect = lambda: order.append("dispose")

        result = await _async(**_primitives())

        assert result is None
        _assert_typed_delegation(workflow, forbidden_session_factory)
        fake_engine.dispose.assert_awaited_once_with()
        assert order == ["workflow", "dispose"]

    @pytest.mark.parametrize(("arguments", "argument"), _MALFORMED)
    async def test_malformed_arguments_raise_before_any_work_and_dispose(
        self,
        arguments: dict[str, object],
        argument: str,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
        forbidden_work: dict[str, MagicMock],
    ) -> None:
        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match=INVALID_ARGUMENT) as raised,
        ):
            await cve_tasks.resolve_ticket_packages_async(**arguments)

        assert isinstance(raised.value, PostIngestArgumentError)
        assert raised.value.argument == argument
        assert [(e["event"], e["argument"]) for e in _events(logs, FAILED)] == [
            (FAILED, argument)
        ]
        assert MARKER not in repr(logs)
        _assert_no_work(workflow, forbidden_session_factory, forbidden_work)
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

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await cve_tasks.resolve_ticket_packages_async(**_primitives())

        assert raised.value is error
        workflow.assert_awaited_once()
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == []

    async def test_dispose_failure_after_success_propagates(
        self, workflow: AsyncMock, fake_engine: _FakeEngine
    ) -> None:
        error = RuntimeError("fictional dispose failure")
        fake_engine.dispose.side_effect = error

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await cve_tasks.resolve_ticket_packages_async(**_primitives())

        assert raised.value is error
        workflow.assert_awaited_once()
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == []

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_dispose_failure_does_not_mask_the_workflow_failure(
        self,
        make_error: Callable[[], BaseException],
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
    ) -> None:
        error = make_error()
        workflow.side_effect = error
        fake_engine.dispose.side_effect = RuntimeError("fictional dispose failure")

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await cve_tasks.resolve_ticket_packages_async(**_primitives())

        assert raised.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == [{"event": DISPOSE_FAILED, "log_level": "warning"}]

    async def test_dispose_failure_does_not_mask_the_validation_failure(
        self,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
        forbidden_work: dict[str, MagicMock],
    ) -> None:
        fake_engine.dispose.side_effect = RuntimeError("fictional dispose failure")

        with capture_logs() as logs, pytest.raises(PostIngestArgumentError):
            await cve_tasks.resolve_ticket_packages_async(
                **_primitives(ticket_id="not-a-uuid")
            )

        fake_engine.dispose.assert_awaited_once_with()
        assert [e["event"] for e in logs] == [FAILED, DISPOSE_FAILED]
        _assert_no_work(workflow, forbidden_session_factory, forbidden_work)


# ---------------------------------------------------------------------------
# Synchronous Celery wrapper
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveTicketPackagesSyncWrapper:
    def test_one_asyncio_run_with_argument_passthrough(
        self, asyncio_run_spy: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[object, ...]] = []

        async def fake_async(*arguments: object) -> None:
            calls.append(arguments)

        monkeypatch.setattr(cve_tasks, "resolve_ticket_packages_async", fake_async)
        arguments = _primitives()

        result = _sync(*cast(Any, arguments.values()))

        assert result is None
        assert calls == [tuple(arguments.values())]
        assert asyncio_run_spy.call_count == 1

    def test_success_runs_workflow_and_disposes_in_one_event_loop(
        self,
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        result = _sync(**cast(Any, _primitives()))

        assert result is None
        assert asyncio_run_spy.call_count == 1
        _assert_typed_delegation(workflow, forbidden_session_factory)
        fake_engine.dispose.assert_awaited_once_with()

    def test_projected_post_ingest_tasks_fields_are_accepted_after_json(
        self,
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        forbidden_session_factory: MagicMock,
    ) -> None:
        """`commit_and_dispatch()` passes the five `PostIngestTasks` fields
        as explicit primitives through JSON serialization; that projection
        validates unchanged."""
        tasks = PostIngestTasks(
            ticket_id=TICKET_ID,
            cpe_matches=[
                {"criteria": CPE, "vulnerable": False, "match_criteria_id": MCID}
            ],
            affected_cpes=[CPE],
            vendor_products=[["Example Vendor", "Alpha"]],
            resolved_packages=["Fictional-Package"],
        )
        projected = json.loads(json.dumps(asdict(tasks)))

        cve_tasks._resolve_ticket_packages_sync(**projected)

        _assert_typed_delegation(workflow, forbidden_session_factory)

    @pytest.mark.parametrize(
        ("position", "argument"),
        [
            pytest.param("ticket_id", "ticket_id", id="as-ticket-id"),
            pytest.param("cpe_matches", "cpe_matches", id="as-container"),
        ],
    )
    def test_post_ingest_tasks_dataclass_is_rejected(
        self,
        position: str,
        argument: str,
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
        forbidden_work: dict[str, MagicMock],
    ) -> None:
        """The wrapper receives explicit primitives; a `PostIngestTasks`
        instance passed in place of an argument is a malformed value."""
        tasks = PostIngestTasks(
            ticket_id=TICKET_ID,
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=["Fictional-Package"],
        )

        with pytest.raises(PostIngestArgumentError) as raised:
            cve_tasks._resolve_ticket_packages_sync(
                **cast(Any, _primitives(**{position: tasks}))
            )

        assert raised.value.argument == argument
        assert asyncio_run_spy.call_count == 1
        _assert_no_work(workflow, forbidden_session_factory, forbidden_work)
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize(("arguments", "argument"), _MALFORMED)
    def test_malformed_arguments_fail_the_task_without_work(
        self,
        arguments: dict[str, object],
        argument: str,
        asyncio_run_spy: MagicMock,
        workflow: AsyncMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
        forbidden_work: dict[str, MagicMock],
    ) -> None:
        with pytest.raises(ValueError, match=INVALID_ARGUMENT) as raised:
            cve_tasks._resolve_ticket_packages_sync(**cast(Any, arguments))

        assert isinstance(raised.value, PostIngestArgumentError)
        assert raised.value.argument == argument
        assert asyncio_run_spy.call_count == 1
        _assert_no_work(workflow, forbidden_session_factory, forbidden_work)
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    def test_workflow_failure_propagates_without_retry(
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
        with capture_logs() as logs, pytest.raises(type(error)):
            cve_tasks._resolve_ticket_packages_sync(**cast(Any, _primitives()))

        assert logs == []
        assert asyncio_run_spy.call_count == 1
        workflow.assert_awaited_once()
        fake_engine.dispose.assert_awaited_once_with()

    def test_non_signal_failure_is_the_same_exception_object(
        self, asyncio_run_spy: MagicMock, workflow: AsyncMock, fake_engine: _FakeEngine
    ) -> None:
        error = OperationalError("fictional statement", None, Exception(MARKER))
        workflow.side_effect = error

        with pytest.raises(OperationalError) as raised:
            cve_tasks._resolve_ticket_packages_sync(**cast(Any, _primitives()))

        assert raised.value is error
        fake_engine.dispose.assert_awaited_once_with()

    def test_real_workflow_with_an_empty_payload_returns_none(
        self,
        asyncio_run_spy: MagicMock,
        fake_engine: _FakeEngine,
        forbidden_session_factory: MagicMock,
        forbidden_work: dict[str, MagicMock],
    ) -> None:
        """The real workflow inside the wrapper's own event loop: an empty
        payload logs only `ticket_package_resolution_empty` and opens no
        session, HTTP client, or resolver call."""
        with capture_logs() as logs:
            result = _sync(TICKET_ID, [], [], [], [])

        assert result is None
        assert logs == [{"event": EMPTY, "log_level": "info", "ticket_id": TICKET_ID}]
        forbidden_session_factory.assert_not_called()
        for mock in forbidden_work.values():
            mock.assert_not_called()
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_invalid_ticket_id_error_is_correlated_only_by_celery_task_id(
        self, workflow: AsyncMock
    ) -> None:
        """The validation ERROR omits the invalid `ticket_id` and carries
        the task-bound `celery_task_id` (bound by `task_prerun`)."""
        celery_task_id = str(uuid.uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with (
                capture_logs(processors=[merge_contextvars]) as logs,
                pytest.raises(PostIngestArgumentError),
            ):
                cve_tasks._resolve_ticket_packages_sync(
                    **cast(Any, _primitives(ticket_id=MARKER))
                )
        finally:
            unbind_contextvars("celery_task_id")

        assert logs == [
            {
                "event": FAILED,
                "log_level": "error",
                "phase": "validation",
                "cause": "PostIngestArgumentError",
                "argument": "ticket_id",
                "celery_task_id": celery_task_id,
            }
        ]


# ---------------------------------------------------------------------------
# Task registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveTicketPackagesTaskRegistration:
    def test_registered_under_exact_name_with_five_explicit_arguments(self) -> None:
        task = celery_app.tasks[TASK_NAME]

        assert task.name == TASK_NAME
        assert RESOLVE_TICKET_PACKAGES_TASK == TASK_NAME
        assert cve_tasks.resolve_ticket_packages_task.name == TASK_NAME
        assert task.run is cve_tasks._resolve_ticket_packages_sync
        tree = ast.parse((APP_ROOT / "tasks" / "cve_tasks.py").read_text("utf-8"))
        (wrapper,) = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_resolve_ticket_packages_sync"
        ]
        assert [a.arg for a in wrapper.args.args] == [
            "ticket_id",
            "cpe_matches",
            "affected_cpes",
            "vendor_products",
            "resolved_packages",
        ]
        assert wrapper.args.kwonlyargs == []
        assert wrapper.args.vararg is None
        assert wrapper.args.kwarg is None

    def test_no_automatic_retry_and_no_stored_result(self) -> None:
        """No `autoretry_for`, retry options, or non-default `max_retries`;
        the task is unbound, so its wrapper cannot call `self.retry()`; no
        result is stored."""
        task = celery_app.tasks[TASK_NAME]

        assert not getattr(task, "autoretry_for", None)
        assert not getattr(task, "retry_kwargs", None)
        assert not getattr(task, "retry_backoff", None)
        assert task.max_retries == Task.max_retries
        assert task.ignore_result is True
        assert celery_app.conf.result_backend is None
        tree = ast.parse((APP_ROOT / "tasks" / "cve_tasks.py").read_text("utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        assert not [
            c
            for c in calls
            if isinstance(c.func, ast.Attribute) and c.func.attr == "retry"
        ]
        assert not [k for c in calls for k in c.keywords if k.arg == "bind"]
        assert not [k for c in calls for k in c.keywords if "retr" in (k.arg or "")]

    def test_registered_through_the_celery_app_task_module_import(self) -> None:
        tree = ast.parse((APP_ROOT / "celery_app.py").read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "app.tasks"
            for alias in node.names
        }
        assert "cve_tasks" in imported
        assert vars(celery_app_module)["cve_tasks"] is cve_tasks

    def test_is_a_sub_operation_not_a_fetcher(self) -> None:
        assert TASK_NAME not in FETCHER_REGISTRY
