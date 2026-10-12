"""Structural tests for the IBS Product release detection lock and I/O
boundaries.

- `_release_occurrence()` in `app/services/packages/ibs_product_release.py`
  is the only function of the detector that takes the Ticket row lock; it
  is called only by `reconcile_ibs_product_releases()`, performs no
  repository, Redis, or Celery I/O, and never commits or rolls back its
  caller-owned unit (docs/features/packages/ibs-product-release-detection.md,
  Local mutation and concurrency: all repository I/O before any Ticket
  lock; one independent caller-owned transaction per matching occurrence).
- The candidate selection, the I/O orchestration, and the fetcher module
  take no lock, and the fetcher only reads through the session it is
  given: its one session operation is the commit that ends the read
  (Fetcher: `detect_ibs_product_releases`, Algorithm step 1 and
  Catch-Up; docs/features/platform/fetcher-infrastructure.md, Interface
  contract: the passed session is for read-only queries only).

The behavior is proven by
`tests/test_services/test_packages/test_ibs_product_release*.py` and
`test_detect_ibs_product_releases.py`; these checks keep a later edit from
crossing the boundaries.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_PACKAGES = APP_ROOT / "services" / "packages"
_BOUNDARY = _PACKAGES / "ibs_product_release.py"
_FETCHER = _PACKAGES / "detect_ibs_product_releases.py"

_LOCKING: Final = "_release_occurrence"
_ORCHESTRATION: Final = "reconcile_ibs_product_releases"
_SELECTION: Final = "load_product_release_candidates"

_FOR_UPDATE: Final = re.compile(r"\bfor\s+(no\s+key\s+)?update\b", re.IGNORECASE)

_IO_NAMES: Final = {
    "httpx",
    "ProductRepositoryDownloads",
    "task_publication",
    "publish_task",
    "drain_ticket_convergence",
    "redis",
    "celery",
    "celery_app",
    "http_client",
}
"""Names through which a function could perform repository, broker, or
Redis I/O."""

_SESSION_WRITES: Final = {
    "add",
    "add_all",
    "flush",
    "delete",
    "merge",
    "execute",
    "rollback",
    "with_for_update",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }


def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return node.name
    return None


def _functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


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
    """The enclosing function of every `with_for_update` reference."""
    tree = _tree(path)
    parents = _parents(tree)
    return [
        _enclosing_function(node, parents)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "with_for_update"
    ]


@pytest.mark.unit
class TestTicketLockPlacement:
    def test_only_the_locking_function_takes_a_row_lock(self) -> None:
        assert _lock_sites(_BOUNDARY) == [_LOCKING]

    def test_the_fetcher_takes_no_row_lock(self) -> None:
        assert _lock_sites(_FETCHER) == []

    @pytest.mark.parametrize("path", [_BOUNDARY, _FETCHER], ids=lambda p: p.name)
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

    @pytest.mark.parametrize(
        ("path", "function"),
        [
            pytest.param(_BOUNDARY, _ORCHESTRATION, id="orchestration"),
            pytest.param(_BOUNDARY, _SELECTION, id="selection"),
            pytest.param(_FETCHER, "execute", id="execute"),
            pytest.param(_FETCHER, "catch_up", id="catch-up"),
        ],
    )
    def test_selection_orchestration_and_fetcher_take_no_lock(
        self, path: Path, function: str
    ) -> None:
        assert "with_for_update" not in _referenced_names(
            _functions(_tree(path))[function]
        )

    def test_locking_function_is_called_only_by_the_orchestration(self) -> None:
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
                            _enclosing_function(node, parents),
                        )
                    )

        assert sites == [("services/packages/ibs_product_release.py", _ORCHESTRATION)]


@pytest.mark.unit
class TestLockingFunctionBody:
    def test_performs_no_repository_broker_or_redis_io(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_LOCKING]

        assert _referenced_names(body) & _IO_NAMES == set()

    def test_never_commits_or_rolls_back_the_caller_owned_unit(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_LOCKING]

        assert _called_attributes(body) & {"commit", "rollback", "close"} == set()

    def test_selection_never_writes_or_ends_the_transaction(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_SELECTION]

        assert _called_attributes(body) & (_SESSION_WRITES - {"execute"}) == set()
        assert "commit" not in _called_attributes(body)


@pytest.mark.unit
class TestFetcherReadsOnly:
    def test_imports_no_sqlalchemy_write_construct(self) -> None:
        tree = _tree(_FETCHER)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and (node.module or "").startswith("sqlalchemy")
            for alias in node.names
        }

        assert imported & {"update", "insert", "delete", "text"} == set()
        assert [
            module
            for module in imported_modules(_FETCHER, "app.services.packages")
            if module == "app.models" or module.startswith("app.models.")
        ] == []

    @pytest.mark.parametrize("function", ["execute", "catch_up"])
    def test_the_passed_session_only_ends_its_read(self, function: str) -> None:
        """Every method called on the passed `session` is `commit()`."""
        body = _functions(_tree(_FETCHER))[function]
        called = {
            node.func.attr
            for node in ast.walk(body)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "session"
        }

        assert called == {"commit"}

    def test_module_calls_no_session_write(self) -> None:
        assert _called_attributes(_tree(_FETCHER)) & _SESSION_WRITES == set()

    def test_module_opens_no_session_of_its_own(self) -> None:
        names = _referenced_names(_tree(_FETCHER))

        assert names & {"async_session_factory", "get_async_session"} == set()
        assert names & _IO_NAMES - {"httpx", "http_client"} == set()
