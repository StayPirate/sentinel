"""Tests for the service-layer task publication
(backend/app/services/task_publication.py).

Contract under test: the implementation decision of issue #765 (D1) as
documented in the module, applied by docs/features/packages/product-catalog.md
(CVSS Threshold Sync step 10) and docs/features/packages/
product-lifecycle-transitions.md (Integration with AIMAAS Synchronization):
one `send_task()` by registered name with detached `kwargs` and
`ignore_result=True` (docs/features/platform/fetcher-infrastructure.md,
Celery Integration, Result handling), executed off the event loop, with
every publication exception propagating unchanged.

The structural tests run fresh interpreters: `app.celery_app` imports every
fetcher module at load time (Fetcher Discovery (Module Import)), so the
publisher resolves the Celery application lazily and neither import order
may produce a circular import. The Service-to-Tasks layer direction itself
is enforced by `tests/test_architecture/test_layer_dependencies.py`.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import threading
from types import MappingProxyType
from typing import Any, Final

import pytest
from celery.exceptions import OperationalError

from app.celery_app import celery_app
from app.services import task_publication
from app.services.task_publication import JSONValue, publish_task
from tests.support.module_imports import APP_ROOT, imported_modules

_MODULE_PATH: Final = APP_ROOT / "services" / "task_publication.py"

_IMPORT_ORDER_MODULES: Final = (
    "app.services.fetcher_discovery",
    "app.services.packages.sync_aimaas_thresholds",
    "app.services.task_publication",
    "app.celery_app",
)


class _SendTaskRecorder:
    """A substitute `Celery.send_task` recording each call and its thread."""

    def __init__(self, error: BaseException | None = None) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.threads: list[int] = []
        self.error = error

    def __call__(self, *args: Any, **kwargs: Any) -> object:
        self.calls.append((args, kwargs))
        self.threads.append(threading.get_ident())
        if self.error is not None:
            raise self.error
        return object()  # an AsyncResult stand-in, never read


def _run_fresh_interpreter(script: str) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "JWT_SECRET_KEY": "test-secret-key-not-for-production-min-32-chars",
    }
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=APP_ROOT.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


@pytest.mark.unit
class TestPublishTask:
    async def test_sends_exactly_one_task_by_name_without_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _SendTaskRecorder()
        monkeypatch.setattr(celery_app, "send_task", recorder)
        kwargs = MappingProxyType({"catalog_product_id": "example-id", "reason": "x"})

        await publish_task("example_registered_task", kwargs=kwargs)

        assert recorder.calls == [
            (
                ("example_registered_task",),
                {
                    "kwargs": {"catalog_product_id": "example-id", "reason": "x"},
                    "ignore_result": True,
                },
            )
        ]

    async def test_task_id_and_queue_are_passed_only_when_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Issue #784 (D3): the optional caller-allocated task ID and
        explicit queue reach `send_task()`; an omitted queue keeps the
        default route."""
        recorder = _SendTaskRecorder()
        monkeypatch.setattr(celery_app, "send_task", recorder)

        await publish_task(
            "example_registered_task",
            kwargs={"ticket_id": "example-id"},
            task_id="example-task-id",
            queue="git",
        )
        await publish_task(
            "example_registered_task",
            kwargs={"ticket_id": "example-id"},
            task_id="other-task-id",
        )

        assert recorder.calls == [
            (
                ("example_registered_task",),
                {
                    "kwargs": {"ticket_id": "example-id"},
                    "ignore_result": True,
                    "task_id": "example-task-id",
                    "queue": "git",
                },
            ),
            (
                ("example_registered_task",),
                {
                    "kwargs": {"ticket_id": "example-id"},
                    "ignore_result": True,
                    "task_id": "other-task-id",
                },
            ),
        ]

    async def test_kwargs_are_a_detached_plain_dict_copy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _SendTaskRecorder()
        monkeypatch.setattr(celery_app, "send_task", recorder)
        kwargs = {"catalog_product_id": "example-id"}

        await publish_task("example_registered_task", kwargs=kwargs)

        sent = recorder.calls[0][1]["kwargs"]
        assert type(sent) is dict
        assert sent == kwargs
        assert sent is not kwargs

    async def test_nested_json_compatible_kwargs_reach_send_task_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Issue #798: detached JSON-compatible values (lists of objects
        with booleans and `None`, nested lists, numbers) are accepted and
        passed through as the task's `kwargs`."""
        recorder = _SendTaskRecorder()
        monkeypatch.setattr(celery_app, "send_task", recorder)
        kwargs: dict[str, JSONValue] = {
            "ticket_id": "example-id",
            "cpe_matches": [
                {
                    "criteria": "cpe:2.3:a:example_vendor:example_product:1.0",
                    "vulnerable": True,
                    "match_criteria_id": None,
                },
                {
                    "criteria": "cpe:2.3:a:example_vendor:other_product:2.0",
                    "vulnerable": False,
                    "match_criteria_id": "example-match-id",
                },
            ],
            "vendor_products": [["example_vendor", "example_product"], []],
            "resolved_packages": [],
            "attempt": 1,
            "ratio": 0.5,
        }
        expected = json.loads(json.dumps(kwargs))

        await publish_task("example_registered_task", kwargs=kwargs)

        assert recorder.calls == [
            (
                ("example_registered_task",),
                {"kwargs": expected, "ignore_result": True},
            )
        ]
        sent = recorder.calls[0][1]["kwargs"]
        assert type(sent) is dict
        assert json.loads(json.dumps(sent)) == expected

    async def test_publication_runs_off_the_event_loop_thread(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _SendTaskRecorder()
        monkeypatch.setattr(celery_app, "send_task", recorder)

        await publish_task("example_registered_task", kwargs={})

        assert recorder.threads != [threading.get_ident()]
        assert len(recorder.threads) == 1

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(OperationalError("example broker failure"), id="broker"),
            pytest.param(TypeError("example serialization failure"), id="programming"),
        ],
    )
    async def test_publication_exception_propagates_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, error: Exception
    ) -> None:
        recorder = _SendTaskRecorder(error)
        monkeypatch.setattr(celery_app, "send_task", recorder)

        with pytest.raises(type(error)) as raised:
            await publish_task("example_registered_task", kwargs={"a": "b"})

        assert raised.value is error
        assert len(recorder.calls) == 1


@pytest.mark.unit
class TestImportStructure:
    @pytest.mark.parametrize("first", _IMPORT_ORDER_MODULES)
    def test_fresh_interpreter_imports_in_either_order(self, first: str) -> None:
        """Each module first, then the others: no circular import."""
        order = [first, *(m for m in _IMPORT_ORDER_MODULES if m != first)]
        script = "".join(f"import {module}\n" for module in order) + (
            "import app.services.task_publication as publication\n"
            "import app.celery_app as celery\n"
            "assert publication.publish_task is not None\n"
            "assert celery.celery_app is not None\n"
            "print('IMPORT-ORDER-OK')\n"
        )

        result = _run_fresh_interpreter(script)

        assert result.returncode == 0, result.stderr
        assert "IMPORT-ORDER-OK" in result.stdout

    def test_celery_app_first_then_fetcher_modules(self) -> None:
        script = (
            "import app.celery_app\n"
            "import app.services.packages.sync_aimaas_thresholds\n"
            "import app.services.fetcher_discovery\n"
            "from app.services.base_fetcher import FETCHER_REGISTRY\n"
            "assert 'sync_aimaas_thresholds' in FETCHER_REGISTRY\n"
            "print('IMPORT-ORDER-OK')\n"
        )

        result = _run_fresh_interpreter(script)

        assert result.returncode == 0, result.stderr
        assert "IMPORT-ORDER-OK" in result.stdout

    @pytest.mark.parametrize(
        "module",
        [
            "app.services.task_publication",
            "app.services.packages.sync_aimaas_thresholds",
        ],
    )
    def test_module_load_does_not_import_the_celery_app(self, module: str) -> None:
        script = (
            f"import {module}\n"
            "import sys\n"
            "assert 'app.celery_app' not in sys.modules, 'app.celery_app loaded'\n"
            "assert not [m for m in sys.modules if m.startswith('app.tasks')]\n"
            "print('LAZY-OK')\n"
        )

        result = _run_fresh_interpreter(script)

        assert result.returncode == 0, result.stderr
        assert "LAZY-OK" in result.stdout

    def test_celery_app_is_imported_only_inside_the_function(self) -> None:
        tree = ast.parse(_MODULE_PATH.read_text(encoding="utf-8"))
        top_level: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                top_level.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_level.add(node.module)

        assert top_level == {"__future__", "asyncio", "collections.abc"}
        assert "app.celery_app" in imported_modules(_MODULE_PATH, "app.services")

    def test_module_imports_no_task_module(self) -> None:
        modules = imported_modules(_MODULE_PATH, "app.services")

        assert not {
            m for m in modules if m == "app.tasks" or m.startswith("app.tasks.")
        }

    def test_substitution_point_is_the_module_attribute(self) -> None:
        assert task_publication.publish_task is publish_task
