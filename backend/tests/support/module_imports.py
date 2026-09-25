"""AST import collection for focused module-boundary assertions.

Structural tests of individual pure modules (for example "this service
module imports no Model" or "this module imports no other service") use
`imported_modules()` to read a module's imports without executing it.
The project-wide layer rule is enforced separately by
`tests/test_architecture/test_layer_dependencies.py`.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[2] / "app"
"""Absolute path of the `backend/app` package."""


def imported_modules(path: Path, package: str) -> set[str]:
    """Absolute module names imported by the module at `path`.

    `package` is the dotted package containing the module (for example
    `app.services`); relative imports are resolved against it so a
    `from ..models import X` cannot bypass a boundary assertion. For
    `from package import name` without a module part, each imported name
    is reported as a submodule of the resolved base.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package_parts = package.split(".")
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                parent = package_parts[: len(package_parts) - (node.level - 1)]
                base = ".".join([*parent, node.module] if node.module else parent)
            if node.module:
                modules.add(base)
            else:
                modules.update(f"{base}.{alias.name}" for alias in node.names)
    return modules


FORBIDDEN_PURE_MODULE_PREFIXES: tuple[str, ...] = (
    "app.models",
    "app.config",
    "app.database",
    "app.api",
    "app.schemas",
    "app.tasks",
    "app.cli",
    "sqlalchemy",
    "redis",
    "httpx",
    "celery",
    "logging",
    "os",
    "pathlib",
    "socket",
)
"""Imports a pure (database-free, I/O-free, settings-free) module must not use."""


def forbidden_imports(modules: set[str]) -> set[str]:
    """The subset of `modules` matching `FORBIDDEN_PURE_MODULE_PREFIXES`."""
    return {
        m
        for m in modules
        if any(m == p or m.startswith(f"{p}.") for p in FORBIDDEN_PURE_MODULE_PREFIXES)
    }
