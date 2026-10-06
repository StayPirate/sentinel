"""Structural tests for the CVSS recalculation coordination resources.

The lease operations perform no database access and the fence helpers no
Redis access; neither writes an audit record, emits a log event, or
reaches a model or task (docs/features/platform/
default-cvss-version-operations.md, Atomic Lease Operations and Execution
Fence; issue #835, Scope). `EXECUTION_FENCE_ID` is the one advisory-lock
key: every fence helper references it, and no advisory-lock call anywhere
in `backend/app` uses another key ("No path uses a different
identifier"). The behavior is proven by
`tests/test_services/test_cvss_recalculation_coordination*.py`; these
checks keep a later edit from crossing the boundaries.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_MODULE = APP_ROOT / "services" / "cvss_recalculation_coordination.py"

_LEASE_OPERATIONS = (
    "acquire_lease",
    "compare_and_renew_lease",
    "compare_and_delete_lease",
    "encode_lease_value",
    "decode_lease_value",
)

_FENCE_HELPERS = ("try_acquire_execution_fence", "release_execution_fence")

_FORBIDDEN_IMPORTS = (
    "app.models",
    "app.tasks",
    "app.celery_app",
    "app.database",
    "app.core.logging",
    "celery",
    "structlog",
    "logging",
)

_ADVISORY_FUNCTION = re.compile(r"pg_(try_)?advisory")


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _referenced_names(node: ast.AST) -> set[str]:
    """Every bare name and attribute name referenced inside `node`."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _closure(tree: ast.Module, roots: tuple[str, ...]) -> set[str]:
    """`roots` plus every module-level function they reach by name."""
    functions = _functions(tree)
    reached: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(_referenced_names(functions[name]) & functions.keys() - reached)
    return reached


def _names_imported_from(tree: ast.Module, package: str) -> set[str]:
    """Local names bound by imports of `package` or its submodules."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == package or alias.name.startswith(f"{package}."):
                    names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and (
            node.module == package or (node.module or "").startswith(f"{package}.")
        ):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


def _referenced_in(tree: ast.Module, roots: tuple[str, ...]) -> set[str]:
    functions = _functions(tree)
    names: set[str] = set()
    for name in _closure(tree, roots):
        names |= _referenced_names(functions[name])
    return names


def _advisory_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _ADVISORY_FUNCTION.match(node.func.attr)
    ]


def _documentation_strings(tree: ast.Module) -> set[int]:
    """Ids of the string constants that are docstrings (module, class,
    function, or attribute docstrings: bare string statements)."""
    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }


@pytest.mark.unit
class TestCoordinationDependencies:
    def test_imports_no_model_task_audit_or_logging_module(self) -> None:
        modules = imported_modules(_MODULE, "app.services")

        assert {
            module
            for module in modules
            if "audit" in module
            or any(
                module == forbidden or module.startswith(f"{forbidden}.")
                for forbidden in _FORBIDDEN_IMPORTS
            )
        } == set()

    def test_lease_operations_reference_no_database_name(self) -> None:
        tree = _tree(_MODULE)
        database_names = _names_imported_from(tree, "sqlalchemy")
        assert database_names  # the fence helpers import them

        referenced = _referenced_in(tree, _LEASE_OPERATIONS)

        assert referenced & database_names == set()
        assert referenced & {"execute", "commit", "session", "connection"} == set()
        assert referenced & set(_FENCE_HELPERS) == set()

    def test_fence_helpers_reference_no_redis_name(self) -> None:
        tree = _tree(_MODULE)
        redis_names = _names_imported_from(tree, "redis")
        assert redis_names  # the lease operations import them

        referenced = _referenced_in(tree, _FENCE_HELPERS)

        assert referenced & redis_names == set()
        assert (
            referenced
            & {
                "LEASE_KEY",
                "client",
                "eval",
                "get_cvss_recalculation_redis_url",
                "new_cvss_recalculation_redis_client",
                *_LEASE_OPERATIONS,
            }
            == set()
        )


@pytest.mark.unit
class TestExecutionFenceIdentifier:
    def test_identifier_is_assigned_once(self) -> None:
        tree = _tree(_MODULE)

        assignments = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AnnAssign | ast.Assign)
            and "EXECUTION_FENCE_ID"
            in {
                target.id
                for target in (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if isinstance(target, ast.Name)
            }
        ]

        assert len(assignments) == 1

    @pytest.mark.parametrize("helper", _FENCE_HELPERS)
    def test_every_fence_helper_references_the_identifier(self, helper: str) -> None:
        tree = _tree(_MODULE)

        assert "EXECUTION_FENCE_ID" in _referenced_names(_functions(tree)[helper])
        assert {
            call.func.attr
            for call in _advisory_calls(_functions(tree)[helper])
            if isinstance(call.func, ast.Attribute)
        }, f"{helper} requests no advisory lock"

    def test_every_advisory_lock_in_app_uses_the_identifier(self) -> None:
        """Scans every module of `backend/app` that names an advisory-lock
        function: each call passes `EXECUTION_FENCE_ID` and no integer
        literal, and no raw SQL string requests an advisory lock."""
        users: set[Path] = set()
        violations: list[str] = []
        for path in sorted(APP_ROOT.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            if not _ADVISORY_FUNCTION.search(source):
                continue
            users.add(path)
            tree = ast.parse(source)
            relative = path.relative_to(APP_ROOT)
            for call in _advisory_calls(tree):
                arguments = ast.Module(
                    body=[ast.Expr(argument) for argument in call.args],
                    type_ignores=[],
                )
                integers = [
                    node.value
                    for node in ast.walk(arguments)
                    if isinstance(node, ast.Constant)
                    and isinstance(node.value, int)
                    and not isinstance(node.value, bool)
                ]
                if integers or "EXECUTION_FENCE_ID" not in _referenced_names(arguments):
                    violations.append(f"{relative}:{call.lineno}")
            documentation = _documentation_strings(tree)
            violations.extend(
                f"{relative}:{node.lineno} (SQL string)"
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in documentation
                and _ADVISORY_FUNCTION.search(node.value)
            )

        assert _MODULE in users
        assert violations == []
