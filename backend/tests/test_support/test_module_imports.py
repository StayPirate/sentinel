"""Tests for the AST import-collection helper (tests/support/module_imports.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.support.module_imports import (
    APP_ROOT,
    forbidden_imports,
    imported_modules,
)


@pytest.mark.unit
class TestImportedModules:
    def test_resolves_relative_imports_against_package(self, tmp_path: Path) -> None:
        source = tmp_path / "probe.py"
        source.write_text(
            "from ..models import cve\nfrom . import cvss\nfrom .x import y\n",
            encoding="utf-8",
        )

        assert imported_modules(source, "app.services") == {
            "app.models",
            "app.services.cvss",
            "app.services.x",
        }

    def test_collects_absolute_and_nested_imports(self, tmp_path: Path) -> None:
        source = tmp_path / "probe.py"
        source.write_text(
            "import os.path\nfrom app.core import enums\n"
            "def f() -> None:\n    import socket\n",
            encoding="utf-8",
        )

        assert imported_modules(source, "app.core") == {
            "os.path",
            "app.core",
            "socket",
        }

    def test_app_root_points_at_the_app_package(self) -> None:
        assert (APP_ROOT / "core" / "enums.py").is_file()


@pytest.mark.unit
class TestForbiddenImports:
    def test_matches_exact_names_and_submodules_only(self) -> None:
        modules = {"os", "os.path", "osmium", "app.models.cve", "app.core.enums"}

        assert forbidden_imports(modules) == {"os", "os.path", "app.models.cve"}
