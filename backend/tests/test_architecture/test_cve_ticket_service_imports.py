"""Structural tests for the `cve_service` / `ticket_service` import cycle.

docs/features/tickets/cve-service.md (Relationship with other modules):
`cve_service` composes `ticket_service` for Ticket creation and
lifecycle, while `ticket_service` calls `cve_service.ensure_cve_exists()`.
Each side imports only the other's module object and dereferences it at
call time, so neither uses the other while being imported (issue #750,
decision D2). A fresh interpreter importing either module first proves
the cycle stays import-safe; the AST check pins the module-object form
that makes it so.
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
        env = {
            **os.environ,
            "JWT_SECRET_KEY": "test-secret-key-not-for-production-min-32-chars",
        }

        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=APP_ROOT.parent,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

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
