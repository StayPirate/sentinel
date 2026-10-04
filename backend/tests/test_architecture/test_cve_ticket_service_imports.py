"""Structural tests for the `cve_service` / `ticket_service` import cycle
and the CVE fetcher finalizer's cycle with `cve_service`.

docs/features/tickets/cve-service.md (Relationship with other modules):
`cve_service` composes `ticket_service` for Ticket creation and
lifecycle, while `ticket_service` calls `cve_service.ensure_cve_exists()`.
Each side imports only the other's module object and dereferences it at
call time, so neither uses the other while being imported (issue #750,
decision D2). A fresh interpreter importing either module first proves
the cycle stays import-safe; the AST check pins the module-object form
that makes it so.

`base_cve_fetcher` (docs/features/platform/cve-fetcher-infrastructure.md,
Per-CVE Finalization) dereferences `cve_service`, `package_service`,
`task_publication`, and `ticket_convergence_publication` at call time,
while `cve_service` imports `base_cve_fetcher` and fetcher discovery
imports every CVE fetcher. A fresh interpreter importing any module of
that graph first must succeed with the finalizer bound to the very module
objects; the AST check pins the module-object imports.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_SERVICES = APP_ROOT / "services"
_CYCLE = {"cve_service": "ticket_service", "ticket_service": "cve_service"}
_ENV = {
    **os.environ,
    "JWT_SECRET_KEY": "test-secret-key-not-for-production-min-32-chars",
}

_FINALIZER = "base_cve_fetcher"
_FINALIZER_GRAPH = (
    "base_cve_fetcher",
    "cve_service",
    "package_service",
    "ticket_service",
    "fetcher_discovery",
)
"""Modules whose first import loads the finalizer's import cycle."""
_FINALIZER_DEPENDENCIES = (
    "cve_service",
    "package_service",
    "task_publication",
    "ticket_convergence_publication",
)
"""Service modules the finalizer imports only as module objects."""


def _run_fresh_interpreter(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=APP_ROOT.parent,
        env=_ENV,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.unit
class TestImportCycle:
    @pytest.mark.parametrize("first", sorted(_CYCLE))
    def test_fresh_interpreter_imports_either_module_first(self, first: str) -> None:
        other = _CYCLE[first]
        script = (
            f"import app.services.{first}\n"
            f"import app.services.{other}\n"
            f"assert app.services.{first}.{other} is app.services.{other}\n"
            f"assert app.services.{other}.{first} is app.services.{first}\n"
            "print('IMPORT-CYCLE-OK')\n"
        )
        result = _run_fresh_interpreter(script)

        assert result.returncode == 0, result.stderr
        assert "IMPORT-CYCLE-OK" in result.stdout

    @pytest.mark.parametrize("module", sorted(_CYCLE))
    def test_each_side_imports_only_the_other_module_object(self, module: str) -> None:
        """`from app.services import <other>` resolves to the submodule
        itself; a `from app.services.<other> import name` form would bind
        a name during import and break whichever module loads first."""
        other = _CYCLE[module]
        path = _SERVICES / f"{module}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_object_imports = [
            node
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "app.services"
            and any(alias.name == other for alias in node.names)
        ]

        assert module_object_imports
        assert f"app.services.{other}" not in imported_modules(path, "app.services")


@pytest.mark.unit
class TestFinalizerImportCycle:
    @pytest.mark.parametrize("first", _FINALIZER_GRAPH)
    def test_fresh_interpreter_imports_any_module_of_the_graph_first(
        self, first: str
    ) -> None:
        """Whichever module loads first, every module of the graph imports
        and the finalizer's module attributes are the loaded modules."""
        imports = [first, *(m for m in _FINALIZER_GRAPH if m != first)]
        script = "".join(f"import app.services.{module}\n" for module in imports)
        script += "".join(
            f"import app.services.{dependency}\n"
            f"assert app.services.{_FINALIZER}.{dependency} "
            f"is app.services.{dependency}\n"
            for dependency in _FINALIZER_DEPENDENCIES
        )
        script += "print('FINALIZER-IMPORT-OK')\n"

        result = _run_fresh_interpreter(script)

        assert result.returncode == 0, result.stderr
        assert "FINALIZER-IMPORT-OK" in result.stdout

    @pytest.mark.parametrize("dependency", _FINALIZER_DEPENDENCIES)
    def test_finalizer_imports_each_dependency_only_as_a_module_object(
        self, dependency: str
    ) -> None:
        """Only `from app.services import <dependency>` at module level; no
        name bound from the dependency during import, in any scope."""
        path = _SERVICES / f"{_FINALIZER}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_object_imports = [
            node
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "app.services"
            and any(alias.name == dependency for alias in node.names)
        ]
        name_imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == f"app.services.{dependency}"
        ]
        plain_imports = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == f"app.services.{dependency}"
        ]

        assert len(module_object_imports) == 1
        assert all(
            alias.asname is None
            for node in module_object_imports
            for alias in node.names
        )
        assert name_imports == []
        assert plain_imports == []
        assert f"app.services.{dependency}" not in imported_modules(
            path, "app.services"
        )
