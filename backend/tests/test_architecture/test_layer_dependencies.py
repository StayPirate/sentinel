"""Structural tests enforcing the Backend Layer Architecture dependency
rules defined in `docs/architecture.md`.

Every module under `app/` is checked, for runtime and type-checking-only
imports alike:

- a module in a layer imports only the layers listed in the "May depend
  on" column of the layer table;
- a Core module imports no application module outside Core, including
  the infrastructure modules outside the layer table;
- `app.config` imports only Core, and `app.database` only `app.config`;
- no application module imports the entry points `app.main` or
  `app.ibs_consumer`.

The layers other than Core may also import `app.config`, `app.database`,
and `app.celery_app`; the entry points compose the application and may
import any layer.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[2] / "app"

# Each layer of the Backend Layer Architecture table, by dotted module
# prefix, mapped to its "May depend on" column. A layer may always import
# from itself (intra-layer imports).
ALLOWED_DEPENDENCIES: dict[str, set[str]] = {
    "app.api": {"app.services", "app.schemas", "app.models", "app.core"},
    "app.cli": {"app.services", "app.models", "app.core"},
    "app.services": {"app.models", "app.core"},
    "app.models": {"app.core"},
    "app.schemas": {"app.models", "app.core"},
    "app.core": set(),
    "app.tasks": {"app.services", "app.core"},
}

# The infrastructure modules outside the layer table.
INFRASTRUCTURE_MODULES: tuple[str, ...] = (
    "app.config",
    "app.database",
    "app.main",
    "app.celery_app",
    "app.ibs_consumer",
)

# Infrastructure modules whose own imports are restricted, mapped to what
# each may import besides itself.
INFRASTRUCTURE_ALLOWED_DEPENDENCIES: dict[str, set[str]] = {
    "app.config": {"app.core"},
    "app.database": {"app.config"},
}

# Entry points that no application module imports.
NEVER_IMPORTED_ENTRY_POINTS = frozenset({"app.main", "app.ibs_consumer"})


def _application_files() -> list[Path]:
    """Every `.py` file under `app/`, including the top-level modules."""
    return sorted(APP_ROOT.rglob("*.py"))


def _module_name(file_path: Path) -> str:
    """The dotted module name of `file_path`; a package's `__init__.py`
    is named after its package."""
    parts = file_path.relative_to(APP_ROOT.parent).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _containing_package(file_path: Path) -> str:
    """The dotted package path containing `file_path` — its `__package__`
    value if imported as part of the `app` package. Used to resolve
    relative imports (`from . import x`, `from .. import x`) to an
    absolute `app.*` module path. This is the dotted path of the file's
    parent directory, which is correct both for a regular module and
    for a package's `__init__.py`.
    """
    relative_dir = file_path.relative_to(APP_ROOT.parent).parent
    return ".".join(relative_dir.parts)


def _resolve_relative_import(package: str, node: ast.ImportFrom) -> str | None:
    """Resolve a relative `ast.ImportFrom` (`node.level > 0`) to an
    absolute dotted module path, following the same algorithm Python's
    import system uses (see `importlib._bootstrap._resolve_name`).
    Returns `None` if the relative import climbs above the top-level
    package (invalid, would fail at runtime — not this test's concern).
    """
    bits = package.rsplit(".", node.level - 1)
    if len(bits) < node.level:
        return None
    base = bits[0]
    return f"{base}.{node.module}" if node.module else base


def _imported_app_modules(source: str, package: str) -> set[str]:
    """Every `app.*` module path imported anywhere in `source`.

    Uses a full AST walk (`ast.walk`, not just top-level statements) so
    that imports guarded by `if TYPE_CHECKING:` or nested inside
    functions are still caught — a forbidden coupling is a violation
    whether it is a runtime dependency or a type-only one. Relative
    imports (`from . import x`, `from .. import x`) are resolved to
    their absolute form using `package` (the dotted path of the
    importing file's own package) before the `app.` prefix check, so a
    forbidden relative import cannot silently bypass this test.

    Two `ast.ImportFrom` shapes require distinct handling:

    1. `from app.services import ticket_service` — the from-clause
       target (`node.module`, or its relative-resolved equivalent) is
       already the full layer path (`app.services`); it is added as-is.
    2. `from app import services` (and its relative equivalents, e.g.
       `from .. import services` from a file two packages deep) — the
       from-clause target resolves only to the parent package (`app`),
       with the actual layer name hidden in the imported alias
       (`services`), not in the target. Every imported alias is
       therefore also joined onto the resolved target
       (`f"{target}.{alias.name}"`) and checked, so a layer import
       disguised behind a parent-package import is still caught. This
       is harmless to apply unconditionally: when the from-clause
       target already fully names a layer (case 1), the alias-joined
       candidate is simply a redundant, equally-valid deeper path
       (`app.services.ticket_service`) that resolves to the same layer.
    """
    tree = ast.parse(source)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("app."):
                    modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            target = (
                _resolve_relative_import(package, node)
                if node.level > 0
                else node.module
            )
            if not target:
                continue
            if target.startswith("app."):
                modules.add(target)
            for alias in node.names:
                candidate = f"{target}.{alias.name}"
                if candidate.startswith("app."):
                    modules.add(candidate)
    return modules


def _component_of(module: str) -> str | None:
    """The layer prefix (e.g. `app.services`) or infrastructure module
    (e.g. `app.config`) that `module` belongs to, or `None` for a module
    that is neither, such as the `app` package itself.
    """
    for prefix in (*ALLOWED_DEPENDENCIES, *INFRASTRUCTURE_MODULES):
        if module == prefix or module.startswith(prefix + "."):
            return prefix
    return None


def _dependency_violations(importer: str, imported: Iterable[str]) -> list[str]:
    """Every dependency rule (see the module docstring) that the module
    `importer` breaks by importing the `imported` application modules."""
    source = _component_of(importer)
    violations: list[str] = []
    for module in sorted(imported):
        target = _component_of(module)
        if target == source:
            continue  # intra-component import, always allowed
        if target in NEVER_IMPORTED_ENTRY_POINTS:
            reason = f"no application module may import the entry point '{target}'"
        elif source is None:
            continue
        elif source == "app.core":
            reason = "Core must not import an application module outside Core"
        elif source in INFRASTRUCTURE_ALLOWED_DEPENDENCIES:
            allowed = INFRASTRUCTURE_ALLOWED_DEPENDENCIES[source]
            if target in allowed:
                continue
            reason = f"'{source}' may import only {', '.join(sorted(allowed))}"
        elif source in ALLOWED_DEPENDENCIES and target in ALLOWED_DEPENDENCIES:
            if target in ALLOWED_DEPENDENCIES[source]:
                continue
            reason = f"layer '{source}' must not import from layer '{target}'"
        else:
            continue
        violations.append(f"{reason} (imports '{module}')")
    return violations


def _synthetic_violations(importer: str, source: str) -> list[str]:
    """The violations of a synthetic regular module `importer` whose
    content is `source`."""
    package = importer.rpartition(".")[0]
    return _dependency_violations(importer, _imported_app_modules(source, package))


def _iter_dependency_violations() -> list[str]:
    violations: list[str] = []
    for path in _application_files():
        imported = _imported_app_modules(
            path.read_text(encoding="utf-8"), _containing_package(path)
        )
        violations.extend(
            f"{path.relative_to(APP_ROOT.parent)}: {violation}"
            for violation in _dependency_violations(_module_name(path), imported)
        )
    return violations


@pytest.mark.unit
class TestImportedAppModulesDetector:
    """Unit tests for the pure `_imported_app_modules()` parser, using
    synthetic sources and packages — no dependency on real files under
    `app/`. Covers the parent-package import form (`from app import
    <layer>`) and its relative equivalents, which a plain `node.module`
    prefix check would miss (see the function's docstring)."""

    def test_detects_absolute_full_path_import(self) -> None:
        source = "from app.services import ticket_service"
        modules = _imported_app_modules(source, package="app.api")
        assert "app.services" in modules

    def test_detects_parent_package_import_of_a_layer(self) -> None:
        # `from app import services` — the layer name is hidden in the
        # imported alias, not in the from-clause target ("app").
        source = "from app import services"
        modules = _imported_app_modules(source, package="app.api")
        assert "app.services" in modules

    def test_detects_parent_package_import_of_multiple_layers(self) -> None:
        source = "from app import services, models"
        modules = _imported_app_modules(source, package="app.api")
        assert "app.services" in modules
        assert "app.models" in modules

    def test_detects_relative_equivalent_two_dots_from_layer_root(self) -> None:
        # A file directly under app/api/ (package "app.api") using
        # `from .. import services` — two dots resolve to the "app"
        # root package, same shape as `from app import services`.
        source = "from .. import services"
        modules = _imported_app_modules(source, package="app.api")
        assert "app.services" in modules

    def test_detects_relative_equivalent_three_dots_from_nested_package(
        self,
    ) -> None:
        # A file two packages deep (e.g. app/api/v1/foo.py, package
        # "app.api.v1") using `from ... import services` — three dots
        # resolve to the "app" root package.
        source = "from ... import services"
        modules = _imported_app_modules(source, package="app.api.v1")
        assert "app.services" in modules

    def test_does_not_flag_intra_layer_relative_import(self) -> None:
        # `from . import x` from within app/services/ resolves to the
        # services package itself — same layer, not a cross-layer hop.
        source = "from . import ticket_mutations"
        modules = _imported_app_modules(source, package="app.services")
        assert modules == {"app.services", "app.services.ticket_mutations"}

    def test_parent_package_import_of_infrastructure_resolves_to_its_module(
        self,
    ) -> None:
        # `from app import config` resolves to "app.config", the
        # infrastructure module outside the layer table; classifying it
        # is a separate step.
        source = "from app import config"
        modules = _imported_app_modules(source, package="app.api")
        assert "app.config" in modules
        assert _component_of("app.config") == "app.config"

    def test_ignores_unrelated_third_party_import(self) -> None:
        source = "from fastapi import APIRouter"
        modules = _imported_app_modules(source, package="app.api")
        assert modules == set()


@pytest.mark.unit
class TestDependencyRuleDetection:
    """Self-tests of `_dependency_violations()` over synthetic modules:
    each rule detects a violation, and the allowed imports pass."""

    @pytest.mark.parametrize(
        ("importer", "source"),
        [
            ("app.core.logging", "from app.config import Settings"),
            (
                "app.core.logging",
                "from typing import TYPE_CHECKING\n"
                "if TYPE_CHECKING:\n"
                "    from app.config import Settings\n",
            ),
            ("app.core.logging", "from app import database"),
            ("app.core.logging", "from .. import config"),
            ("app.core.jwt", "import app.services.user_service"),
            ("app.services.example", "from app.main import app"),
            ("app.cli.example", "def run() -> None:\n    import app.ibs_consumer\n"),
            ("app.celery_app", "from app.ibs_consumer import main"),
            ("app.config", "from app.database import engine"),
            ("app.config", "from app.services import settings"),
            ("app.database", "from app.core.enums import Role"),
            ("app.services.example", "from app.api import dependencies"),
        ],
        ids=[
            "core-imports-config",
            "core-imports-config-type-only",
            "core-imports-database-from-parent-package",
            "core-imports-config-relatively",
            "core-imports-layer",
            "layer-imports-main",
            "layer-imports-ibs-consumer-in-function",
            "entry-point-imports-ibs-consumer",
            "config-imports-database",
            "config-imports-layer",
            "database-imports-core",
            "layer-imports-disallowed-layer",
        ],
    )
    def test_forbidden_import_is_detected(self, importer: str, source: str) -> None:
        assert _synthetic_violations(importer, source)

    @pytest.mark.parametrize(
        ("importer", "source"),
        [
            ("app.core.logging", "from app.core.enums import Role\nfrom . import jwt"),
            (
                "app.services.example",
                "from app.config import settings\n"
                "from app.database import Base\n"
                "from app.celery_app import celery_app\n",
            ),
            ("app.tasks.example", "from app.services import x\nfrom app.core import y"),
            ("app.config", "from app.core.ibs_ssh_key import load_ibs_ssh_private_key"),
            ("app.database", "from app.config import settings"),
            (
                "app.main",
                "from app.api.v1 import tickets\n"
                "from app.services import fetcher_discovery\n"
                "from app.database import async_session_factory\n",
            ),
        ],
        ids=[
            "core-imports-core",
            "layer-imports-infrastructure",
            "layer-imports-allowed-layer",
            "config-imports-core",
            "database-imports-config",
            "entry-point-imports-layers",
        ],
    )
    def test_allowed_import_is_not_reported(self, importer: str, source: str) -> None:
        assert _synthetic_violations(importer, source) == []


@pytest.mark.unit
class TestDependencyRules:
    """Enforce the dependency rules of the Backend Layer Architecture
    (`docs/architecture.md`) over every module under `app/`.
    """

    def test_every_infrastructure_module_is_checked(self) -> None:
        modules = {_module_name(path) for path in _application_files()}
        assert set(INFRASTRUCTURE_MODULES) <= modules

    def test_no_module_breaks_a_dependency_rule(self) -> None:
        violations = _iter_dependency_violations()
        assert not violations, "Dependency rule violations found:\n" + "\n".join(
            violations
        )
