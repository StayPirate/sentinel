"""Structural test enforcing audit event table immutability.

See `docs/features/platform/audit-trail-infrastructure.md`
(Immutability): "No application-level UPDATE or DELETE operations are
permitted on [audit event] tables." This module provides a mechanical
check so the rule does not rely solely on reviewer attention (see
`docs/features/platform/testing-strategy.md`, Immutability Testing and
Structural Tests — Audit immutability).

Scope: this test detects the two idiomatic SQLAlchemy 2.0 Core
bulk-mutation forms used throughout this codebase — `update(Model)...`
and `delete(Model)...` — where `Model` is referenced directly by name
as the statement's target. It does not attempt to trace instance-level
`session.delete(instance)` calls back to a specific model class, since
that would require full type inference and would risk false positives
against legitimate deletions of unrelated, non-audit records (see
`AGENTS.md`, Guardrail 26 — Reviewer Proportionality). A direct bulk
`update()`/`delete()` statement is the pattern a retention/cleanup
implementation would realistically use, which is what this test
guards against.

Audit event models are discovered dynamically via
`AuditEventMixin.__subclasses__()`, so this test covers every concrete
audit trail, including one added later, without a change to this file.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.models.mixins import AuditEventMixin

APP_SERVICES_ROOT = Path(__file__).resolve().parents[2] / "app" / "services"

_FORBIDDEN_FUNCS = {"update", "delete"}


def _call_target_name(node: ast.expr) -> str | None:
    """The bare name a `Call`'s `func` expression resolves to — e.g.
    `"update"` for both `update(...)` and `sa.update(...)`. Returns
    `None` for any other expression shape.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _arg_names(call: ast.Call) -> set[str]:
    """Bare names referenced as positional arguments of a `Call` — e.g.
    `{"WidgetAuditEvent"}` for both `update(WidgetAuditEvent)` and
    `update(models.WidgetAuditEvent)`.
    """
    names: set[str] = set()
    for arg in call.args:
        if isinstance(arg, ast.Name):
            names.add(arg.id)
        elif isinstance(arg, ast.Attribute):
            names.add(arg.attr)
    return names


def find_forbidden_mutations(source: str, model_names: set[str]) -> list[str]:
    """Return a description of each `update(Model)`/`delete(Model)` call
    in `source` whose target is one of `model_names`.

    Pure function: parses `source` as Python and inspects the AST only.
    Performs no I/O and imports no application code, so it is directly
    unit-testable with synthetic source strings and fictional model
    names, independent of whether any real audit trail model exists.
    """
    if not model_names:
        return []
    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _call_target_name(node.func)
        if func_name not in _FORBIDDEN_FUNCS:
            continue
        for model_name in _arg_names(node) & model_names:
            violations.append(
                f"line {node.lineno}: {func_name}({model_name}, ...) targets "
                "an append-only audit event table"
            )
    return violations


def _audit_event_model_names() -> set[str]:
    """Names of every currently-registered `AuditEventMixin` subclass."""
    return {klass.__name__ for klass in AuditEventMixin.__subclasses__()}


@pytest.mark.unit
class TestFindForbiddenMutationsDetector:
    """Unit tests for the pure AST detector, using synthetic sources and
    fictional model names — independent of the real audit event models.
    """

    def test_detects_bulk_update_by_bare_name(self) -> None:
        source = "update(WidgetAuditEvent).values(comment='x')"
        violations = find_forbidden_mutations(source, {"WidgetAuditEvent"})
        assert len(violations) == 1

    def test_detects_bulk_delete_via_module_attribute(self) -> None:
        source = "sa.delete(models.WidgetAuditEvent).where(WidgetAuditEvent.id == x)"
        violations = find_forbidden_mutations(source, {"WidgetAuditEvent"})
        assert len(violations) == 1

    def test_ignores_unrelated_model_updates(self) -> None:
        source = "update(Ticket).values(status='Resolved')"
        violations = find_forbidden_mutations(source, {"WidgetAuditEvent"})
        assert violations == []

    def test_ignores_calls_to_other_functions(self) -> None:
        source = "refresh(WidgetAuditEvent)"
        violations = find_forbidden_mutations(source, {"WidgetAuditEvent"})
        assert violations == []

    def test_empty_model_names_short_circuits(self) -> None:
        source = "update(WidgetAuditEvent)"
        assert find_forbidden_mutations(source, set()) == []


@pytest.mark.unit
class TestNoForbiddenMutationsInServiceLayer:
    """Scans every real module under `app/services/` for the forbidden
    patterns, against the currently-registered audit event models.

    Importing `app.models` registers every production audit event model;
    the test-only `SampleAuditEvent` (`tests/support/audit_models.py`)
    is also registered when its module has been imported. The services
    reference the production models, so the test passes because no
    service performs a bulk `update()`/`delete()` against an audit
    table, not because `model_names` is empty.
    """

    def test_no_service_module_bulk_updates_or_deletes_an_audit_table(self) -> None:
        model_names = _audit_event_model_names()
        violations: list[str] = []
        for path in sorted(APP_SERVICES_ROOT.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for violation in find_forbidden_mutations(source, model_names):
                violations.append(f"{path}: {violation}")
        assert not violations, "\n".join(violations)
