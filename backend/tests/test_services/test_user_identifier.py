"""Tests for the user-domain leaf module
(backend/app/services/user_identifier.py).

The matching behavior of `user_identifier_condition()` is covered through its
public `user_service` re-export in `test_user_service.py`. This file verifies
the placement contract that lets `BaseAuditLog` reuse the builder without an
import cycle.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.services import user_identifier, user_service


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return modules


@pytest.mark.unit
class TestUserIdentifierLeafModule:
    def test_imports_no_other_service(self) -> None:
        assert user_identifier.__file__ is not None
        imported = _imported_modules(Path(user_identifier.__file__))
        assert sorted(m for m in imported if m.startswith("app.services")) == []

    def test_user_service_re_exports_the_single_builder(self) -> None:
        assert (
            user_service.user_identifier_condition
            is user_identifier.user_identifier_condition
        )
