"""Structural tests for the Ticket accessibility boundaries.

See docs/features/platform/testing-strategy.md (Structural Tests,
"Ticket accessibility boundaries"), docs/architecture.md (Backend Layer
Architecture), and docs/conventions.md (FastAPI Conventions,
Model-aware resource resolution):

- Core imports no Model or Service module.
- API modules build or execute no business ORM query and never
  reference the Ticket visibility predicate; they delegate to services.
- Ticket audit history is read only by the Ticket audit trail module,
  so no authorization, resolution, or mutation code can use it as
  current visibility state.

Behavioral tests (tests/test_services/test_ticket_visibility.py and the
consumer tests) prove the predicate itself; these AST checks only guard
where queries may live.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[2] / "app"

# SQLAlchemy modules an API module may import: session types and
# factories for dependency injection, never query construction.
_API_ALLOWED_SQLALCHEMY_MODULES = frozenset({"sqlalchemy.ext.asyncio"})

# Session/connection methods that execute SQL.
_QUERY_EXECUTION_METHODS = frozenset(
    {"execute", "scalar", "scalars", "stream", "stream_scalars", "exec_driver_sql"}
)

_VISIBILITY_PREDICATE = "ticket_visibility_condition"
_AUDIT_EVENT_MODEL = "TicketAuditEvent"
_AUDIT_READ_OWNER = APP_ROOT / "services" / "ticket_audit_log.py"


def _python_files(*parts: str) -> list[Path]:
    return sorted((APP_ROOT.joinpath(*parts)).rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


def _referenced_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.name for alias in node.names)
    return names


def _relative(path: Path) -> str:
    return str(path.relative_to(APP_ROOT.parent))


@pytest.mark.unit
class TestCoreHasNoApplicationImports:
    def test_core_imports_no_model_or_service_module(self) -> None:
        offenders = [
            f"{_relative(path)}: {module}"
            for path in _python_files("core")
            for module in _imported_modules(_parse(path))
            if module.startswith(("app.models", "app.services"))
        ]
        assert offenders == []


@pytest.mark.unit
class TestApiBuildsNoBusinessQuery:
    def test_api_imports_no_sqlalchemy_query_construct(self) -> None:
        offenders = [
            f"{_relative(path)}: {module}"
            for path in _python_files("api")
            for module in _imported_modules(_parse(path))
            if module.split(".")[0] == "sqlalchemy"
            and module not in _API_ALLOWED_SQLALCHEMY_MODULES
        ]
        assert offenders == []

    def test_api_executes_no_sql(self) -> None:
        offenders = [
            f"{_relative(path)}:{node.lineno}"
            for path in _python_files("api")
            for node in ast.walk(_parse(path))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _QUERY_EXECUTION_METHODS
        ]
        assert offenders == []

    def test_api_never_references_the_visibility_predicate(self) -> None:
        offenders = [
            _relative(path)
            for path in _python_files("api")
            if _VISIBILITY_PREDICATE in _referenced_names(_parse(path))
        ]
        assert offenders == []


@pytest.mark.unit
class TestAuditHistoryIsNotAccessState:
    def test_only_the_audit_trail_service_reads_ticket_audit_events(self) -> None:
        offenders = [
            _relative(path)
            for layer in ("api", "services", "tasks", "cli", "core")
            for path in _python_files(layer)
            if path != _AUDIT_READ_OWNER
            and _AUDIT_EVENT_MODEL in _referenced_names(_parse(path))
        ]
        assert offenders == []

    def test_visibility_and_resolution_do_not_import_the_audit_trail(self) -> None:
        for module in ("ticket_visibility.py", "ticket_service.py"):
            imports = _imported_modules(_parse(APP_ROOT / "services" / module))
            assert "app.services.ticket_audit_log" not in imports, module
            assert "app.models.ticket_audit_event" not in imports, module


@pytest.mark.unit
class TestDetectorsCatchViolations:
    """Guard the detectors themselves against silently passing."""

    def test_detects_sqlalchemy_query_import(self) -> None:
        tree = ast.parse("from sqlalchemy import select\n")
        assert "sqlalchemy" in _imported_modules(tree)

    def test_detects_execute_call(self) -> None:
        tree = ast.parse("async def f(db):\n    await db.execute(q)\n")
        calls = [
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        ]
        assert "execute" in calls

    def test_detects_referenced_names(self) -> None:
        tree = ast.parse(
            "from app.services.ticket_visibility import ticket_visibility_condition\n"
            "x = models.TicketAuditEvent\n"
        )
        names = _referenced_names(tree)
        assert {_VISIBILITY_PREDICATE, _AUDIT_EVENT_MODEL} <= names
