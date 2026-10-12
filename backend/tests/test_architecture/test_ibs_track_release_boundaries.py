"""Structural tests for the IBS track release detection lock and I/O
boundaries.

- `_reconcile_track()` in `app/services/packages/ibs_track_release.py` is
  the only function of the detector that takes the Ticket row lock; it is
  called only by `_Reconciliation._apply()`, performs no IBS, HTTP, Redis,
  or Celery I/O, and never commits, rolls back, or closes its
  caller-owned unit (docs/features/packages/ibs-track-release-detection.md,
  Per-Track Local Outcome: external IBS I/O and XML parsing complete
  before any Ticket lock; Checkpoint Concurrency: no IBS call, Redis
  operation, or task enqueue while a Ticket lock is held;
  docs/features/packages/package-service.md, Module invariant:
  I/O-then-Lock pattern).
- The candidate selection, the I/O orchestration
  `reconcile_ibs_track_releases()`, and every other `_Reconciliation`
  method take no lock, and the selection never writes or ends its
  transaction (Scheduled Reconciliation Algorithm step 1: candidate
  selection acquires no Ticket mutation lock).

Each detector module is listed in `_LOCK_OWNERS` with the functions
allowed to take a row lock (the fetcher module joins with none). The
behavior is proven by
`tests/test_services/test_packages/test_ibs_track_release*.py`; these
checks keep a later edit from crossing the boundaries.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final

import pytest

from tests.support.module_imports import APP_ROOT

_PACKAGES = APP_ROOT / "services" / "packages"
_BOUNDARY = _PACKAGES / "ibs_track_release.py"

_LOCKING: Final = "_reconcile_track"
_APPLY: Final = "_Reconciliation._apply"
_ORCHESTRATION: Final = "reconcile_ibs_track_releases"
_SELECTION: Final = "load_track_release_candidates"
_RECONCILIATION: Final = "_Reconciliation"

_LOCK_OWNERS: Final[dict[Path, list[str]]] = {_BOUNDARY: [_LOCKING]}
"""Every detector module and the qualified functions allowed to take a
row lock in it."""

_FOR_UPDATE: Final = re.compile(r"\bfor\s+(no\s+key\s+)?update\b", re.IGNORECASE)

_IO_NAMES: Final = {
    "httpx",
    "IBSClient",
    "client",
    "get_source_info",
    "get_diff_issues",
    "task_publication",
    "publish_task",
    "drain_ticket_convergence",
    "redis",
    "celery",
    "celery_app",
    "http_client",
    "async_session_factory",
}
"""Names through which a function could perform IBS, HTTP, broker, or
Redis I/O, or open another session."""

_SESSION_WRITES: Final = {
    "add",
    "add_all",
    "flush",
    "delete",
    "merge",
    "rollback",
    "commit",
    "close",
    "with_for_update",
}


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
                # A nested function is attributed to its outer function.
                names = []
            names.append(node.name)
        elif isinstance(node, ast.ClassDef) and names:
            names.insert(0, node.name)
    return ".".join(names) if names else None


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Module-level functions by name and class methods as `Class.method`."""
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
        elif isinstance(child, ast.alias):
            names.add(child.asname or child.name.split(".")[-1])
    return names


def _called_attributes(node: ast.AST) -> set[str]:
    return {
        child.func.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
    }


def _docstrings(tree: ast.AST) -> set[ast.AST]:
    found: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                found.add(body[0].value)
    return found


def _lock_sites(path: Path) -> list[str | None]:
    """The qualified enclosing function of every `with_for_update`
    reference."""
    tree = _tree(path)
    parents = _parents(tree)
    return [
        _qualified_function(node, parents)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "with_for_update"
    ]


_MODULES = [pytest.param(path, id=path.name) for path in _LOCK_OWNERS]


@pytest.mark.unit
class TestTicketLockPlacement:
    @pytest.mark.parametrize("path", _MODULES)
    def test_only_the_designated_functions_take_a_row_lock(self, path: Path) -> None:
        assert _lock_sites(path) == _LOCK_OWNERS[path]

    @pytest.mark.parametrize("path", _MODULES)
    def test_no_literal_for_update_sql(self, path: Path) -> None:
        tree = _tree(path)
        docstrings = _docstrings(tree)

        assert [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node not in docstrings
            and _FOR_UPDATE.search(node.value)
        ] == []

    def test_selection_orchestration_and_every_other_method_take_no_lock(
        self,
    ) -> None:
        functions = _functions(_tree(_BOUNDARY))
        unlocked = [
            name
            for name in functions
            if name in (_SELECTION, _ORCHESTRATION)
            or name.startswith(f"{_RECONCILIATION}.")
        ]

        assert {_SELECTION, _ORCHESTRATION, _APPLY} <= set(unlocked)
        assert [
            name
            for name in unlocked
            if "with_for_update" in _referenced_names(functions[name])
        ] == []

    def test_locking_function_is_called_only_by_apply(self) -> None:
        sites: list[tuple[str, str | None]] = []
        for path in sorted(APP_ROOT.rglob("*.py")):
            tree = _tree(path)
            parents = _parents(tree)
            for node in ast.walk(tree):
                name = (
                    node.id
                    if isinstance(node, ast.Name)
                    else node.attr
                    if isinstance(node, ast.Attribute)
                    else node.name
                    if isinstance(node, ast.alias)
                    else None
                )
                if name == _LOCKING:
                    sites.append(
                        (
                            str(path.relative_to(APP_ROOT)),
                            _qualified_function(node, parents),
                        )
                    )

        assert sites == [("services/packages/ibs_track_release.py", _APPLY)]


@pytest.mark.unit
class TestLockingFunctionBody:
    def test_performs_no_ibs_http_broker_or_redis_io(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_LOCKING]

        assert _referenced_names(body) & _IO_NAMES == set()

    def test_never_commits_rolls_back_or_closes_the_caller_owned_unit(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_LOCKING]

        assert _called_attributes(body) & {"commit", "rollback", "close"} == set()

    def test_selection_never_writes_or_ends_the_transaction(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_SELECTION]

        assert _called_attributes(body) & _SESSION_WRITES == set()
