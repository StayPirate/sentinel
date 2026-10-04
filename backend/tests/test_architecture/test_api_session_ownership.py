"""Structural test enforcing that API route handlers acquire their
database session exclusively through the `DatabaseSession` dependency.

See `docs/conventions.md` (API Transaction Dependency Scope): every API
transaction session must go through `get_db()` declared with
`scope="function"` (the `DatabaseSession` alias in `app/database.py`),
so its commit/rollback exit phase completes before the response is
transmitted. `backend/tests/test_api_conventions.py`
(`TestTransactionDependencyScope`) already guards every *registered
route dependency* that uses `get_db`. This module guards the narrower,
complementary bypass a route handler could otherwise use to sidestep
that dependency entirely: opening an independent session directly via
`async_session_factory`, or completing a transaction itself via
`.commit()`/`.rollback()` — both would escape FastAPI's dependency
injection graph and are therefore invisible to a route-dependant walk.

Scope: this test detects direct references to `async_session_factory` and
direct `.commit()`/`.rollback()` calls in `app/api/` source text via AST
— it does not attempt full type inference to confirm a `.commit()`
receiver is actually a database session, since no legitimate use of
either pattern exists in the API layer today (see `AGENTS.md`,
Guardrail 26 — Reviewer Proportionality).

These functions are exempt, each for a documented, specification-mandated
reason — narrowed to the specific function or method authorized to own
its own session, not the whole file (see `_AUTHORIZED_QUALNAMES` below).
An unauthorized use added anywhere ELSE in these same modules —
including a different function — is still detected:

- `app/api/health.py`, function `get_readiness_session_factory`: the
  readiness probe (`GET /ready`) never uses the `get_db`
  yield-dependency at all — it opens a read-only, no-commit session
  directly via this factory for its `SELECT 1` check, so the
  `scope="function"` rule (which governs transaction completion
  ordering for `get_db`) does not apply to it in the first place.
- `app/api/dependencies.py`, method `LastUsedDebouncer.touch`: the API
  key `last_used_at` debounce touch is an orchestration boundary per
  `docs/conventions.md` (Transaction and Locking, Caller-Owned Service
  Transactions: "a component that explicitly owns its sessions ...
  keeps the transaction contract defined by its owning specification").
  `docs/features/identity/authentication.md` (API key validation, step
  5) requires this best-effort operational write to commit or roll back
  in its own dedicated transaction, independently of the request's main
  `DatabaseSession` transaction (which may still be open and must not be
  affected by this write's outcome). Its companion factory function
  `get_last_used_session_factory` is authorized for the same reason as
  `get_readiness_session_factory` above.
- `app/api/v1/fetchers.py`, function
  `get_fetcher_trigger_session_factory`: `trigger_fetcher()` (the
  `POST .../trigger` service function) is a service-owned orchestration
  boundary per the same "Caller-Owned Service Transactions" clause — it
  manages its own short-lived sessions across two independent
  transactions and publishes to Celery strictly between them with no
  row lock held (`docs/conventions.md`, Transaction Hygiene Rules). See
  `docs/features/platform/fetcher-operations.md` (`trigger_fetcher`).

- `app/api/v1/tickets.py`, function
  `get_ticket_convergence_session_factory`:
  `dispatch_ticket_convergence()` (the `POST .../rerun-reactivation`
  service function) is a service-owned orchestration boundary: it locks
  and validates the Ticket in its own short transaction, commits and
  closes it, and only then publishes to Celery with no lock held. See
  `docs/features/tickets/ticket-service.md` (`dispatch_ticket_convergence()`).

- `app/api/v1/cves.py`, function
  `get_cve_source_status_session_factory`: `get_cve_source_status()` is
  the service-owned read orchestration of
  `docs/features/tickets/cve-service.md` (CVE Source Status, Transaction
  Ownership): it opens and closes its own short-lived read transaction
  before its best-effort Redis overlay.

- `app/api/v1/cves.py`, function `get_cve_refetch_session_factory`:
  `refetch_cve()` (the `POST .../refetch` service function) is a
  service-owned orchestration boundary: it locks and validates the CVE
  and optional Ticket in its own short transaction, commits and closes
  it, and only then publishes with no lock held. See
  `docs/features/tickets/cve-service.md` (Callers and Ordering,
  Transaction Ownership).

The module-level `import` of `async_session_factory` in each of these
files (needed for the authorized function to reference it at all)
is allowed only in the files that contain an authorized function —
tracked separately from function-scoped usage, since an `import`
statement is inherently outside any function body.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

APP_API_ROOT = Path(__file__).resolve().parents[2] / "app" / "api"

# Relative path (from APP_API_ROOT) -> set of qualified function/method
# names authorized to use a forbidden pattern. A qualified name is
# either a bare function name (`"get_readiness_session_factory"`) or
# `"ClassName.method_name"` for a method. Usage anywhere else in these
# files — a different function, a different class, or module level —
# is still a violation.
_AUTHORIZED_QUALNAMES: dict[Path, set[str]] = {
    Path("health.py"): {"get_readiness_session_factory"},
    Path("dependencies.py"): {
        "get_last_used_session_factory",
        "LastUsedDebouncer.touch",
    },
    Path("v1/fetchers.py"): {"get_fetcher_trigger_session_factory"},
    Path("v1/cves.py"): {
        "get_cve_source_status_session_factory",
        "get_cve_refetch_session_factory",
    },
    Path("v1/tickets.py"): {"get_ticket_convergence_session_factory"},
}

_FORBIDDEN_NAMES = {"async_session_factory"}
_FORBIDDEN_METHODS = {"commit", "rollback"}


@dataclass(frozen=True)
class Violation:
    """One forbidden-pattern occurrence found by `find_forbidden_session_usage()`.

    `qualname` is the enclosing function or method's qualified name
    (`"ClassName.method_name"` for a method, a bare name for a
    module-level function), or `None` when the occurrence is at module
    level (outside any function) — which is exactly where an `import`
    statement always lives, since `import` cannot appear inside an
    expression.
    """

    line: int
    message: str
    qualname: str | None
    is_import: bool

    def __str__(self) -> str:
        return f"line {self.line}: {self.message}"


def _assign_parents(tree: ast.AST) -> None:
    """Annotate every node in `tree` with a `.parent` attribute pointing
    to its direct parent node, enabling upward traversal from a
    violation node to its enclosing function. `ast` does not track
    parent links natively; this is the standard single-pass way to add
    them without a third-party dependency.
    """
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]


def _enclosing_qualname(node: ast.AST) -> str | None:
    """The qualified name of the nearest enclosing function or method
    containing `node`, or `None` if `node` sits at module level.

    Requires `_assign_parents()` to have been run on the containing
    tree first. A function directly nested in a `class` body yields
    `"ClassName.method_name"`; any other function (module-level, or
    nested in another function) yields its bare name.
    """
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            enclosing = getattr(current, "parent", None)
            if isinstance(enclosing, ast.ClassDef):
                return f"{enclosing.name}.{current.name}"
            return current.name
        current = getattr(current, "parent", None)
    return None


def find_forbidden_session_usage(source: str) -> list[Violation]:
    """Every direct session-acquisition or transaction-completion call
    in `source` that bypasses the `DatabaseSession` dependency.

    Pure function: parses `source` as Python and inspects the AST only.
    Performs no I/O and imports no application code, so it is directly
    unit-testable with synthetic source strings. Each returned
    `Violation` carries the enclosing function/method qualified name
    (or `None` for module-level occurrences, e.g. `import` statements)
    so callers can apply function-scoped exemptions.
    """
    tree = ast.parse(source)
    _assign_parents(tree)
    violations: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            violations.append(
                Violation(
                    line=node.lineno,
                    message=(
                        f"references '{node.id}' directly (use the "
                        "'DatabaseSession' dependency instead of opening "
                        "an independent session)"
                    ),
                    qualname=_enclosing_qualname(node),
                    is_import=False,
                )
            )
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in _FORBIDDEN_NAMES:
                    violations.append(
                        Violation(
                            line=node.lineno,
                            message=(
                                f"imports '{alias.name}' directly (use "
                                "the 'DatabaseSession' dependency instead "
                                "of opening an independent session)"
                            ),
                            qualname=_enclosing_qualname(node),
                            is_import=True,
                        )
                    )
        elif isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_NAMES:
            violations.append(
                Violation(
                    line=node.lineno,
                    message=(
                        f"references '{node.attr}' directly via attribute "
                        "access (use the 'DatabaseSession' dependency "
                        "instead of opening an independent session)"
                    ),
                    qualname=_enclosing_qualname(node),
                    is_import=False,
                )
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and (node.func.attr in _FORBIDDEN_METHODS)
        ):
            violations.append(
                Violation(
                    line=node.lineno,
                    message=(
                        f"calls '.{node.func.attr}()' directly (transaction "
                        "completion is owned by the 'get_db' API dependency, "
                        "not by route handlers)"
                    ),
                    qualname=_enclosing_qualname(node),
                    is_import=False,
                )
            )
    return violations


def _unauthorized_violations(
    violations: list[Violation], relative_path: Path
) -> list[Violation]:
    """Filter `violations` down to those NOT covered by an authorization
    for `relative_path`.

    A module-level `import` of a forbidden name is allowed in any file
    that has at least one authorized function (the import is a
    necessary precondition for that function to work) — but every
    other occurrence (a `Name`/`Attribute` reference or a `.commit()`/
    `.rollback()` call) is allowed only when it occurs inside one of
    that file's specifically authorized functions/methods.
    """
    authorized_qualnames = _AUTHORIZED_QUALNAMES.get(relative_path, set())
    unauthorized: list[Violation] = []
    for violation in violations:
        if violation.is_import and authorized_qualnames:
            continue
        if violation.qualname in authorized_qualnames:
            continue
        unauthorized.append(violation)
    return unauthorized


@pytest.mark.unit
class TestFindForbiddenSessionUsageDetector:
    """Unit tests for the pure AST detector, using synthetic sources."""

    def test_detects_direct_factory_reference(self) -> None:
        source = "session = async_session_factory()"
        assert len(find_forbidden_session_usage(source)) == 1

    def test_detects_direct_factory_import(self) -> None:
        source = "from app.database import async_session_factory"
        assert len(find_forbidden_session_usage(source)) == 1

    def test_detects_direct_commit_call(self) -> None:
        source = "await db.commit()"
        assert len(find_forbidden_session_usage(source)) == 1

    def test_detects_direct_rollback_call(self) -> None:
        source = "await db.rollback()"
        assert len(find_forbidden_session_usage(source)) == 1

    def test_ignores_unrelated_names_and_methods(self) -> None:
        source = "db.add(widget)\nawait db.flush()\nresult = await db.execute(stmt)"
        assert find_forbidden_session_usage(source) == []

    def test_ignores_database_session_dependency_usage(self) -> None:
        source = "async def endpoint(db: DatabaseSession) -> None: ..."
        assert find_forbidden_session_usage(source) == []

    def test_detects_factory_reference_via_module_attribute_access(self) -> None:
        source = "session = app.database.async_session_factory()"
        assert len(find_forbidden_session_usage(source)) == 1

    def test_import_violation_has_no_enclosing_qualname(self) -> None:
        source = "from app.database import async_session_factory"
        violations = find_forbidden_session_usage(source)
        assert violations[0].qualname is None
        assert violations[0].is_import is True

    def test_name_reference_inside_function_reports_function_qualname(self) -> None:
        source = "def get_session_factory():\n    return async_session_factory"
        violations = find_forbidden_session_usage(source)
        assert violations[0].qualname == "get_session_factory"
        assert violations[0].is_import is False

    def test_call_inside_method_reports_class_dot_method_qualname(self) -> None:
        source = (
            "class Debouncer:\n"
            "    async def touch(self, db):\n"
            "        await db.commit()\n"
        )
        violations = find_forbidden_session_usage(source)
        assert violations[0].qualname == "Debouncer.touch"

    def test_name_reference_at_module_level_has_no_qualname(self) -> None:
        source = "factory = async_session_factory"
        violations = find_forbidden_session_usage(source)
        assert violations[0].qualname is None


@pytest.mark.unit
class TestUnauthorizedViolationsFilter:
    """Unit tests for the per-file, per-function authorization filter —
    proving that an authorized function is exempt while everything
    else in the SAME file is still caught, including a different
    function newly added to it."""

    def test_authorized_function_usage_is_filtered_out(self) -> None:
        source = (
            "def get_readiness_session_factory():\n    return async_session_factory\n"
        )
        violations = find_forbidden_session_usage(source)
        remaining = _unauthorized_violations(violations, Path("health.py"))
        assert remaining == []

    def test_unauthorized_function_in_the_same_exempt_file_is_still_caught(
        self,
    ) -> None:
        # A second, non-authorized function added to health.py bypassing
        # the DatabaseSession dependency must still be flagged — the
        # exemption is scoped to the one authorized function, not the
        # whole file.
        source = (
            "def get_readiness_session_factory():\n"
            "    return async_session_factory\n"
            "\n"
            "def some_new_endpoint_helper():\n"
            "    session = async_session_factory()\n"
            "    return session\n"
        )
        violations = find_forbidden_session_usage(source)
        remaining = _unauthorized_violations(violations, Path("health.py"))
        assert len(remaining) == 1
        assert remaining[0].qualname == "some_new_endpoint_helper"

    def test_authorized_method_usage_is_filtered_out(self) -> None:
        source = (
            "class LastUsedDebouncer:\n"
            "    async def touch(self, db):\n"
            "        await db.commit()\n"
        )
        violations = find_forbidden_session_usage(source)
        remaining = _unauthorized_violations(violations, Path("dependencies.py"))
        assert remaining == []

    def test_unauthorized_method_in_the_same_exempt_file_is_still_caught(
        self,
    ) -> None:
        source = (
            "class LastUsedDebouncer:\n"
            "    async def touch(self, db):\n"
            "        await db.commit()\n"
            "\n"
            "    async def other(self, db):\n"
            "        await db.rollback()\n"
        )
        violations = find_forbidden_session_usage(source)
        remaining = _unauthorized_violations(violations, Path("dependencies.py"))
        assert len(remaining) == 1
        assert remaining[0].qualname == "LastUsedDebouncer.other"

    def test_module_level_import_allowed_only_in_files_with_an_authorization(
        self,
    ) -> None:
        source = "from app.database import async_session_factory"
        violations = find_forbidden_session_usage(source)

        assert _unauthorized_violations(violations, Path("health.py")) == []
        assert (
            len(_unauthorized_violations(violations, Path("some_other_module.py"))) == 1
        )


@pytest.mark.unit
class TestNoDirectSessionUsageInApiLayer:
    """Scans every real module under `app/api/` for the forbidden
    patterns, applying the per-file, per-function authorizations in
    `_AUTHORIZED_QUALNAMES`.
    """

    def test_no_api_module_bypasses_the_database_session_dependency(self) -> None:
        violations: list[str] = []
        for path in sorted(APP_API_ROOT.rglob("*.py")):
            relative_path = path.relative_to(APP_API_ROOT)
            source = path.read_text(encoding="utf-8")
            found = find_forbidden_session_usage(source)
            for violation in _unauthorized_violations(found, relative_path):
                violations.append(f"{path}: {violation}")
        assert not violations, "\n".join(violations)
