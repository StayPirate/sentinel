"""Tests for the fetcher discovery drift protection
(backend/app/services/fetcher_discovery.py).

See `docs/features/platform/fetcher-infrastructure.md` (Fetcher
Discovery (Module Import), Drift protection) for the full contract:
`fetcher_discovery.py` MUST import every concrete `BaseFetcher`
subclass module found under the domain packages
(`app.services.tickets`, `app.services.packages`,
`app.services.identity`, `app.services.platform`,
`app.services.integrations`).

The set of modules `fetcher_discovery.py` declares is parsed
statically via `ast` rather than by importing the module and reading
`FETCHER_REGISTRY` — importing a domain module to inspect its classes
would itself populate the registry (via `__init_subclass__`),
producing a false negative where a fetcher missing from
`fetcher_discovery.py` still appears "registered" merely because this
test imported it. Comparing dotted module-path strings avoids that
self-fulfilling side effect entirely.

The scan is not vacuous: `app.services.packages` contains the first
production fetcher (`sync_smelt_products`), and a dedicated test proves
the scan finds it, so a scan that silently returns nothing fails.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import app.services.fetcher_discovery  # noqa: F401
from app.services.base_fetcher import BaseFetcher

_DOMAIN_PACKAGES = [
    "app.services.tickets",
    "app.services.packages",
    "app.services.identity",
    "app.services.platform",
    "app.services.integrations",
]

_DISCOVERY_MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "app" / "services" / "fetcher_discovery.py"
)


def _imported_modules_in_discovery() -> set[str]:
    """Every dotted module path imported by `fetcher_discovery.py`,
    parsed statically (AST) — never imported at runtime by this
    function, so it has no side effect on `FETCHER_REGISTRY`.
    """
    source = _DISCOVERY_MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
    return modules


def _walk_domain_module_names(package_name: str) -> list[str]:
    """Every importable module's dotted name under `package_name`, or
    an empty list if the package does not exist on disk yet (not every
    domain package has a fetcher)."""
    try:
        package = importlib.import_module(package_name)
    except ModuleNotFoundError:
        return []
    package_path = getattr(package, "__path__", None)
    if package_path is None:
        return []
    return [
        module_info.name
        for module_info in pkgutil.walk_packages(
            package_path, prefix=f"{package_name}."
        )
    ]


def _module_defines_concrete_fetcher(module_name: str) -> bool:
    """Whether `module_name` defines at least one concrete (non-
    abstract) `BaseFetcher` subclass in its own namespace."""
    module = importlib.import_module(module_name)
    return any(
        isinstance(attr, type)
        and issubclass(attr, BaseFetcher)
        and attr is not BaseFetcher
        and not attr.__dict__.get("abstract", False)
        and attr.__module__ == module_name
        for attr in vars(module).values()
    )


@pytest.mark.unit
class TestFetcherDiscoveryDriftProtection:
    def test_every_concrete_domain_fetcher_module_is_imported_by_discovery(
        self,
    ) -> None:
        declared_imports = _imported_modules_in_discovery()
        missing: list[str] = []
        for package_name in _DOMAIN_PACKAGES:
            for module_name in _walk_domain_module_names(package_name):
                if (
                    _module_defines_concrete_fetcher(module_name)
                    and module_name not in declared_imports
                ):
                    missing.append(module_name)
        assert not missing, (
            "Fetcher module(s) not imported by fetcher_discovery.py: "
            + ", ".join(sorted(missing))
        )

    def test_scan_finds_the_production_fetcher_modules(self) -> None:
        fetcher_modules = {
            module_name
            for package_name in _DOMAIN_PACKAGES
            for module_name in _walk_domain_module_names(package_name)
            if _module_defines_concrete_fetcher(module_name)
        }

        assert "app.services.packages.sync_smelt_products" in fetcher_modules
