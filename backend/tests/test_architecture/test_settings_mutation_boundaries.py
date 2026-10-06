"""Structural tests for the setting mutation `update_default_cvss_version()`
(backend/app/services/settings.py).

The mutation performs no Redis command, acquires no lease, publishes no
task, registers no post-commit callback, and never commits or rolls back;
an effective change requests the execution fence identifier in
transaction-level, non-blocking form (docs/features/platform/
system-settings.md, Setting Mutation Service). The behavior is proven by
`tests/test_services/test_settings_mutation.py`; these checks keep a later
edit from crossing the boundaries.
"""

from __future__ import annotations

import ast

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_MODULE = APP_ROOT / "services" / "settings.py"

_FORBIDDEN_IMPORTS = (
    "redis",
    "celery",
    "kombu",
    "app.tasks",
    "app.celery_app",
    "app.services.task_publication",
    "app.services.cvss_recalculation_admission",
    "app.services.cvss_recalculation",
)

_FORBIDDEN_NAMES = {
    "register_post_commit_callback",
    "publish_task",
    "acquire_lease",
    "compare_and_delete_lease",
    "compare_and_renew_lease",
    "new_cvss_recalculation_redis_client",
    "try_acquire_execution_fence",
    "release_execution_fence",
    "commit",
    "rollback",
}


def _tree() -> ast.Module:
    return ast.parse(_MODULE.read_text(encoding="utf-8"))


def _mutation() -> ast.AsyncFunctionDef:
    [function] = [
        node
        for node in _tree().body
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "update_default_cvss_version"
    ]
    return function


def _referenced_names(node: ast.AST) -> set[str]:
    """Every bare name and attribute name referenced inside `node`."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _advisory_calls(node: ast.AST) -> list[ast.Call]:
    return [
        child
        for child in ast.walk(node)
        if isinstance(child, ast.Call)
        and isinstance(child.func, ast.Attribute)
        and "advisory" in child.func.attr
    ]


@pytest.mark.unit
class TestSettingMutationBoundaries:
    def test_module_imports_no_redis_celery_or_admission_module(self) -> None:
        modules = imported_modules(_MODULE, "app.services")

        assert {
            module
            for module in modules
            if any(
                module == forbidden or module.startswith(f"{forbidden}.")
                for forbidden in _FORBIDDEN_IMPORTS
            )
        } == set()

    def test_only_the_fence_identifier_is_imported_from_coordination(self) -> None:
        imported = {
            alias.name
            for node in _tree().body
            if isinstance(node, ast.ImportFrom)
            and node.module == "app.services.cvss_recalculation_coordination"
            for alias in node.names
        }

        assert imported == {"EXECUTION_FENCE_ID"}

    def test_mutation_references_no_side_effect_or_transaction_control(
        self,
    ) -> None:
        assert _referenced_names(_mutation()) & _FORBIDDEN_NAMES == set()

    def test_mutation_requests_only_the_transaction_level_try_lock(self) -> None:
        calls = _advisory_calls(_mutation())

        assert [
            call.func.attr for call in calls if isinstance(call.func, ast.Attribute)
        ] == ["pg_try_advisory_xact_lock"]
        [call] = calls
        assert isinstance(call.func, ast.Attribute)
        assert isinstance(call.func.value, ast.Name)
        assert call.func.value.id == "func"
        assert "EXECUTION_FENCE_ID" in _referenced_names(
            ast.Module(body=[ast.Expr(arg) for arg in call.args], type_ignores=[])
        )
