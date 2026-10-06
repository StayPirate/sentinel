"""Structural tests for the all-CVE CVSS recalculation runner boundaries.

The workflow (`app/services/cvss_recalculation.py`) receives the validated
task ID explicitly and never discovers it from Celery or logging state; it
defines no exception class, keeps no persistent run state, writes Redis
only through the coordination lease operations, and counts `failed` only
for the isolable deadlock. The task module (`app/tasks/cvss_tasks.py`) is
a thin boundary with no business query, transaction, or disposal, and the
task is not a fetcher
(docs/features/platform/default-cvss-version-operations.md, Task Identity
and Workflow; Error Taxonomy; Absence of Persistent Run State; Retry,
Rerun, and Recovery; docs/architecture.md, Backend Layer Architecture;
issue #836 U2, U4, U7, umbrella #833 P8).

The behavior is proven by `tests/test_services/test_cvss_recalculation.py`
and `tests/test_tasks/test_cvss_tasks.py`; these checks keep a later edit
from crossing the boundaries.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import ModuleType

import pytest

from app.celery_app import celery_app
from app.services import cvss_recalculation
from app.services import cvss_recalculation_coordination as coordination
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.cvss_recalculation import RECALCULATE_CVSS_DERIVED_STATE_TASK
from app.tasks import cvss_tasks
from tests.support.module_imports import APP_ROOT, imported_modules

_WORKFLOW = APP_ROOT / "services" / "cvss_recalculation.py"
_TASK = APP_ROOT / "tasks" / "cvss_tasks.py"

_TASK_STATE_NAMES = {
    "current_task",
    "request",
    "get_contextvars",
    "get_merged_contextvars",
    "merge_contextvars",
    "bind_contextvars",
    "bound_contextvars",
}
"""Names through which code could discover or bind the task ID from Celery
or logging state."""

_COUNTERS = {"changed", "unchanged", "skipped", "failed"}

_REDIS_COMMANDS = {
    "set",
    "setex",
    "setnx",
    "psetex",
    "getset",
    "getdel",
    "delete",
    "unlink",
    "expire",
    "pexpire",
    "expireat",
    "persist",
    "rename",
    "hset",
    "hdel",
    "lpush",
    "rpush",
    "sadd",
    "zadd",
    "incr",
    "incrby",
    "decr",
    "mset",
    "eval",
    "evalsha",
    "pipeline",
    "publish",
    "xadd",
    "execute_command",
    "flushdb",
    "flushall",
}
"""Redis write commands no runner code may issue directly."""


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }


def _ancestors(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> list[ast.AST]:
    found: list[ast.AST] = []
    while node in parents:
        node = parents[node]
        found.append(node)
    return found


def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    for ancestor in _ancestors(node, parents):
        if isinstance(ancestor, ast.FunctionDef | ast.AsyncFunctionDef):
            return ancestor.name
    return None


def _handler_types(handler: ast.ExceptHandler) -> set[str]:
    """The exception class names a handler catches (`None` for bare)."""
    if handler.type is None:
        return {"BaseException"}
    nodes = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return {
        node.id if isinstance(node, ast.Name) else ast.unparse(node) for node in nodes
    }


def _referenced_names(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    names: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append((node.id, node))
        elif isinstance(node, ast.Attribute):
            names.append((node.attr, node))
        elif isinstance(node, ast.alias):
            names.append((node.asname or node.name.split(".")[-1], node))
    return names


def _counter_increments(tree: ast.AST) -> list[ast.AugAssign]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Attribute)
        and node.target.attr in _COUNTERS
    ]


def _exception_classes(module: ModuleType) -> list[str]:
    return [
        name
        for name, value in inspect.getmembers(module, inspect.isclass)
        if value.__module__ == module.__name__ and issubclass(value, BaseException)
    ]


def _class_bases(tree: ast.AST) -> list[tuple[str, str]]:
    return [
        (node.name, ast.unparse(base))
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        for base in node.bases
    ]


def _is_exception_base(base: str) -> bool:
    name = base.rsplit(".", 1)[-1]
    return name in {"Exception", "BaseException"} or name.endswith(
        ("Error", "Exception")
    )


def _matches(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(
        module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes
    )


@pytest.mark.unit
class TestTaskIdentityDiscovery:
    def test_workflow_never_reads_celery_or_logging_state_for_the_task_id(
        self,
    ) -> None:
        """The workflow receives `celery_task_id` explicitly: no
        `current_task`, request attribute, or context read or binding.
        Only `validate_task_id()` unbinds `celery_task_id` (wrapper step
        2)."""
        tree = _tree(_WORKFLOW)
        parents = _parents(tree)

        assert [
            (name, getattr(node, "lineno", None))
            for name, node in _referenced_names(tree)
            if name in _TASK_STATE_NAMES
        ] == []
        unbinds = [
            node
            for name, node in _referenced_names(tree)
            if name in {"contextvars", "unbind_contextvars", "clear_contextvars"}
        ]
        assert unbinds
        assert {_enclosing_function(node, parents) for node in unbinds} == {
            "validate_task_id"
        }

    def test_workflow_imports_celery_only_for_its_exception_classes(self) -> None:
        modules = imported_modules(_WORKFLOW, "app.services")

        assert {m for m in modules if _matches(m, ("celery", "contextvars"))} == {
            "celery.exceptions"
        }


@pytest.mark.unit
class TestNoExceptionClass:
    @pytest.mark.parametrize(
        ("path", "module"),
        [
            pytest.param(_WORKFLOW, cvss_recalculation, id="workflow"),
            pytest.param(_TASK, cvss_tasks, id="task"),
        ],
    )
    def test_module_defines_no_exception_class(
        self, path: Path, module: ModuleType
    ) -> None:
        """P8: an ownership loss raises the built-in `RuntimeError`; no
        runner-defined class exists."""
        assert [
            (name, base)
            for name, base in _class_bases(_tree(path))
            if _is_exception_base(base)
        ] == []
        assert _exception_classes(module) == []


@pytest.mark.unit
class TestLayerBoundaries:
    def test_workflow_imports_no_boundary_or_framework_module(self) -> None:
        modules = imported_modules(_WORKFLOW, "app.services")

        assert {
            m
            for m in modules
            if _matches(
                m, ("app.api", "app.tasks", "app.celery_app", "app.cli", "fastapi")
            )
        } == set()

    def test_task_module_imports_only_the_app_database_and_workflow(self) -> None:
        """No model, SQLAlchemy, Redis, settings, or configuration import:
        the wrapper performs no business query, settings read,
        transaction, or Redis access of its own."""
        modules = imported_modules(_TASK, "app.tasks")

        assert {m for m in modules if _matches(m, ("app",))} == {
            "app.celery_app",
            "app.database",
            "app.services.cvss_recalculation",
        }
        assert {
            m
            for m in modules
            if _matches(m, ("app.models", "app.config", "sqlalchemy", "redis"))
        } == set()

    def test_task_module_runs_no_query_transaction_or_disposal(self) -> None:
        tree = _tree(_TASK)
        called = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute | ast.Name)
        }

        assert (
            called
            & {
                "select",
                "execute",
                "scalar",
                "scalars",
                "commit",
                "rollback",
                "begin",
                "connect",
                "dispose",
                "close",
                "get_default_cvss_version",
            }
            == set()
        )
        assert "run" in called  # the single `asyncio.run()` boundary


@pytest.mark.unit
class TestFailedCounter:
    def test_failed_is_incremented_only_by_the_isolable_deadlock_handler(
        self,
    ) -> None:
        """P8: the only isolable unit failure is the `40P01` deadlock,
        handled by `except DBAPIError`. No broad handler may convert a
        whole-run signal into `failed`."""
        tree = _tree(_WORKFLOW)
        parents = _parents(tree)
        increments = [
            node
            for node in _counter_increments(tree)
            if isinstance(node.target, ast.Attribute) and node.target.attr == "failed"
        ]

        assert len(increments) == 1
        handlers = [
            ancestor
            for ancestor in _ancestors(increments[0], parents)
            if isinstance(ancestor, ast.ExceptHandler)
        ]
        assert [_handler_types(handler) for handler in handlers] == [{"DBAPIError"}]
        assert _enclosing_function(increments[0], parents) == "_unit"
        assigned = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Attribute) and target.attr in _COUNTERS
        ]
        assert assigned == []

    def test_no_broad_handler_touches_a_counter(self) -> None:
        tree = _tree(_WORKFLOW)
        parents = _parents(tree)

        broad = [
            node
            for node in _counter_increments(tree)
            for ancestor in _ancestors(node, parents)
            if isinstance(ancestor, ast.ExceptHandler)
            and _handler_types(ancestor) & {"Exception", "BaseException"}
        ]

        assert broad == []


@pytest.mark.unit
class TestNoPersistentRunState:
    def test_workflow_reads_only_the_cve_model_and_writes_through_the_chain(
        self,
    ) -> None:
        """Absence of Persistent Run State: no run, progress, cursor, or
        audit model, and no direct ORM write; units mutate only through
        `ticket_mutations.recalculate_cvss_chain()`."""
        modules = imported_modules(_WORKFLOW, "app.services")
        tree = _tree(_WORKFLOW)

        assert {m for m in modules if _matches(m, ("app.models",))} == {
            "app.models.cve"
        }
        assert {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "sqlalchemy"
            for alias in node.names
        } == {"select"}
        assert {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"add", "add_all", "merge", "delete", "flush"}
        } == set()

    def test_workflow_writes_redis_only_through_the_lease_operations(self) -> None:
        tree = _tree(_WORKFLOW)
        modules = imported_modules(_WORKFLOW, "app.services")

        assert [
            (node.func.attr, node.lineno)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _REDIS_COMMANDS
        ] == []
        # The client comes from the coordination URL provider, never from a
        # direct `Redis(...)` or `from_url(...)` construction.
        assert {
            m for m in modules if _matches(m, ("redis",)) and m != "redis.exceptions"
        } <= {"redis.asyncio"}
        assert "from_url" not in {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert (
            vars(cvss_recalculation)["new_cvss_recalculation_redis_client"]
            is coordination.new_cvss_recalculation_redis_client
        )


@pytest.mark.unit
class TestNotAFetcher:
    def test_task_is_neither_a_fetcher_nor_scheduled(self) -> None:
        assert RECALCULATE_CVSS_DERIVED_STATE_TASK not in FETCHER_REGISTRY
        assert RECALCULATE_CVSS_DERIVED_STATE_TASK not in {
            entry["task"] for entry in celery_app.conf.beat_schedule.values()
        }
        modules = imported_modules(_WORKFLOW, "app.services") | imported_modules(
            _TASK, "app.tasks"
        )
        assert [m for m in modules if "fetcher" in m] == []
