"""Structural tests for the shared IBS request reconciliation lock and I/O
boundaries.

- `_reconcile_scope()` in `app/services/packages/ibs_request_reconciliation.py`
  is the only function that takes the Ticket row lock and is called only by
  `_Reconciliation._apply()`; the request and action row locks are taken
  only by `_lock_request()` and `_lock_actions()`, which only the locked
  unit reaches (docs/features/packages/ibs-submission-tracking.md, Shared
  Authoritative Reconciliation > Algorithm steps 4-10: no IBS, Redis,
  AMQP, or Celery I/O while the Ticket lock is held;
  docs/features/packages/package-service.md, Module invariant:
  I/O-then-Lock pattern).
- The functions of the locked unit reference no IBS client, evidence
  cache, HTTP, broker, or session factory, and never commit, roll back, or
  close the caller-owned unit.
- The scope selection and the retained-evidence reader take no lock and
  never write or end their transaction.
- The lock-free observation module (`ibs_request_observation.py`) has no
  database dependency at all.

The behavior is proven by
`tests/test_services/test_packages/test_ibs_request_reconciliation*.py`;
these checks keep a later edit from crossing the boundaries.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_PACKAGES = APP_ROOT / "services" / "packages"
_BOUNDARY = _PACKAGES / "ibs_request_reconciliation.py"
_OBSERVATION = _PACKAGES / "ibs_request_observation.py"

_LOCKING: Final = "_reconcile_scope"
_APPLY: Final = "_Reconciliation._apply"
_ROW_LOCKERS: Final = ("_lock_request", "_lock_actions")
_LOCKED_UNIT: Final = (
    _LOCKING,
    "_lock_request",
    "_write_request",
    "_lock_actions",
    "_write_evidence",
    "_action_changes",
    "_apply_delivery",
)
"""The functions that run inside the locked unit."""
_READERS: Final = ("load_ibs_request_scopes", "read_retained_actions")

_IO_NAMES: Final = {
    "httpx",
    "IBSClient",
    "client",
    "cache",
    "EvidenceCache",
    "observe_scope",
    "asyncio",
    "task_publication",
    "publish_task",
    "redis",
    "celery",
    "celery_app",
    "http_client",
    "async_session_factory",
}
"""Names through which a function could perform IBS, HTTP, broker, or
Redis I/O, or open another session."""

_WRITES: Final = {"add", "add_all", "flush", "delete", "merge", "commit", "rollback"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }


def _qualified_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    """`Class.method` or `function` of the innermost enclosing function."""
    names: list[str] = []
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if names:
                names = []
            names.append(node.name)
        elif isinstance(node, ast.ClassDef) and names:
            names.insert(0, node.name)
    return ".".join(names) if names else None


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    found[f"{node.name}.{item.name}"] = item
    return found


def _referenced_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _called_attributes(node: ast.AST) -> set[str]:
    return {
        child.func.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
    }


def _selects_ticket(call: ast.Call) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "select"
        and bool(node.args)
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "Ticket"
        for node in ast.walk(call)
    )


def _callers(name: str) -> list[tuple[str, str | None]]:
    """Every reference to `name` in the application, by module and
    enclosing function."""
    sites: list[tuple[str, str | None]] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        tree = _tree(path)
        parents = _parents(tree)
        for node in ast.walk(tree):
            referenced = (
                node.id
                if isinstance(node, ast.Name)
                else node.attr
                if isinstance(node, ast.Attribute)
                else None
            )
            if referenced == name:
                sites.append(
                    (
                        str(path.relative_to(APP_ROOT)),
                        _qualified_function(node, parents),
                    )
                )
    return sites


@pytest.mark.unit
class TestLockPlacement:
    def test_the_ticket_row_lock_is_taken_only_by_the_locked_unit(self) -> None:
        tree = _tree(_BOUNDARY)
        parents = _parents(tree)
        ticket_locks = [
            _qualified_function(node, parents)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "with_for_update"
            and _selects_ticket(node)
        ]

        assert ticket_locks == [_LOCKING]

    def test_every_row_lock_is_inside_the_locked_unit(self) -> None:
        tree = _tree(_BOUNDARY)
        parents = _parents(tree)
        sites = {
            _qualified_function(node, parents)
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "with_for_update"
        }

        assert sites == {_LOCKING, *_ROW_LOCKERS}

    def test_the_locked_unit_is_entered_only_through_apply(self) -> None:
        assert _callers(_LOCKING) == [
            ("services/packages/ibs_request_reconciliation.py", _APPLY)
        ]
        assert {caller for _, caller in _callers("_write_evidence")} == {_LOCKING}
        assert {caller for _, caller in _callers("_lock_request")} == {"_write_request"}
        assert {caller for _, caller in _callers("_lock_actions")} == {
            "_write_evidence"
        }


@pytest.mark.unit
class TestLockedUnitBody:
    @pytest.mark.parametrize("name", _LOCKED_UNIT)
    def test_performs_no_ibs_http_broker_or_redis_io(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert _referenced_names(body) & _IO_NAMES == set()

    @pytest.mark.parametrize("name", _LOCKED_UNIT)
    def test_never_commits_rolls_back_or_closes_the_unit(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert _called_attributes(body) & {"commit", "rollback", "close"} == set()

    @pytest.mark.parametrize("name", _READERS)
    def test_readers_take_no_lock_and_never_write(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert "with_for_update" not in _referenced_names(body)
        assert _called_attributes(body) & _WRITES == set()


@pytest.mark.unit
class TestObservationModule:
    def test_has_no_database_dependency(self) -> None:
        modules = imported_modules(_OBSERVATION, "app.services.packages")

        assert {
            module
            for module in modules
            if module == "sqlalchemy"
            or module.startswith(("sqlalchemy.", "app.database", "app.models"))
        } == set()
        assert "with_for_update" not in _referenced_names(_tree(_OBSERVATION))
