"""Structural tests for the Ticket mutation primitive boundaries.

- `ticket_mutations` never imports `package_service` or `ticket_service`;
  both import it (docs/features/tickets/ticket-mutations.md, Relationship
  with other modules).
- The atomic CVSS chain's inline Product eligibility write reuses the one
  package-model-owned pure evaluator instead of copying the formula
  (ticket-mutations.md, Contract; docs/features/packages/package-model.md,
  Axis 2: Eligibility and Override Model).
- The transaction-local convergence registry is a leaf reachable by every
  later transaction owner and performs no broker, Redis, or network I/O
  (ticket-mutations.md, Transaction-Local Ticket Convergence Registration;
  docs/features/tickets/ticket-service.md, Initial publication boundary).
"""

from __future__ import annotations

import ast

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_SERVICES = APP_ROOT / "services"
_TICKET_MUTATIONS = _SERVICES / "ticket_mutations.py"


def _parsed() -> ast.Module:
    return ast.parse(_TICKET_MUTATIONS.read_text(encoding="utf-8"))


@pytest.mark.unit
class TestTicketMutationsDependencies:
    def test_imports_neither_package_service_nor_ticket_service(self) -> None:
        modules = imported_modules(_TICKET_MUTATIONS, "app.services")

        forbidden = {"app.services.package_service", "app.services.ticket_service"}
        assert modules & forbidden == set()


@pytest.mark.unit
class TestCVSSChainUsesTheSharedEvaluator:
    """The evaluator's own rule inputs (the Reactive Support phase, the
    implicit threshold, the fallback score) belong to
    `product_eligibility` and `cvss`; `ticket_mutations` only passes the
    four evaluator inputs and reads the outcome."""

    def test_imports_the_product_eligibility_evaluator(self) -> None:
        modules = imported_modules(_TICKET_MUTATIONS, "app.services")

        assert "app.services.product_eligibility" in modules

    def test_calls_the_evaluator(self) -> None:
        tree = _parsed()
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "evaluate_product_eligibility"
        ]

        assert len(calls) >= 1
        for call in calls:
            assert {k.arg for k in call.keywords} == {
                "is_eligible_override",
                "lifecycle_phase",
                "cvss_threshold",
                "eligibility_score",
            }

    def test_does_not_reference_the_formula_rule_inputs(self) -> None:
        tree = _parsed()
        rule_names = {
            "REACTIVE_SUPPORT",
            "IMPLICIT_CVSS_THRESHOLD",
            "ELIGIBILITY_FALLBACK_SCORE",
        }
        referenced = {
            node.attr if isinstance(node, ast.Attribute) else node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute | ast.Name)
        }
        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }

        assert referenced & rule_names == set()
        assert "reactive_support" not in literals

    def test_never_compares_a_product_threshold(self) -> None:
        tree = _parsed()

        def mentions_threshold(node: ast.AST) -> bool:
            return any(
                (isinstance(n, ast.Attribute) and n.attr == "cvss_threshold")
                or (isinstance(n, ast.Name) and n.id == "cvss_threshold")
                for n in ast.walk(node)
            )

        comparisons = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Compare) and mentions_threshold(node)
        ]

        assert comparisons == []


@pytest.mark.unit
class TestConvergenceRegistryIsALeaf:
    def test_imports_only_the_standard_library_and_sqlalchemy(self) -> None:
        modules = imported_modules(
            _SERVICES / "ticket_convergence_registry.py", "app.services"
        )

        allowed_roots = {"__future__", "dataclasses", "typing", "uuid", "sqlalchemy"}
        assert {m.split(".")[0] for m in modules} <= allowed_roots
