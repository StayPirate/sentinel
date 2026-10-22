"""Structural tests for the shared IBS request reconciliation lock and I/O
boundaries.

- `_reconcile_scope()` in `app/services/packages/ibs_request_reconciliation.py`
  is the only function that takes the Ticket row lock and is called only by
  `_Reconciliation._apply()` and the trusted observation application
  `apply_ibs_request_observation()`; the request and action row locks are taken
  only by `_lock_request()` and `_lock_actions()`, which only the locked
  unit reaches (docs/features/packages/ibs-submission-tracking.md, Shared
  Authoritative Reconciliation > Algorithm steps 4-10: no IBS, Redis,
  AMQP, or Celery I/O while the Ticket lock is held;
  docs/features/packages/package-service.md, Module invariant:
  I/O-then-Lock pattern).
- The functions of the locked unit reference no IBS client, evidence
  cache, HTTP, broker, or session factory, and never commit, roll back, or
  close the caller-owned unit.
- The scope selection and the retained-evidence readers take no lock and
  never write or end their transaction.
- `apply_ibs_request_observation()` performs no IBS, HTTP, broker, or
  Redis I/O, opens no session, and never commits, rolls back, or closes
  the caller's session; outside its own module, only the example dataset
  loader `app/services/example_dataset.py` references it
  (ibs-submission-tracking.md, Trusted Observation Application; Testing
  Requirements).
- The lock-free observation module (`ibs_request_observation.py`) has no
  database dependency at all.
- The fetcher module `sync_ibs_requests.py` takes no row lock, opens no
  session of its own, and uses the session it is given only for the scope
  read and the commit that ends it; it never uses `BaseFetcher.http_client`
  (ibs-submission-tracking.md, Fetcher: sync_ibs_requests > Algorithm;
  Accelerators > Ticket Convergence; fetcher-infrastructure.md, Per-Ticket
  Catch-Up > Interface contract: no direct Ticket lock, the passed session
  is for read-only queries only).

The behavior is proven by
`tests/test_services/test_packages/test_ibs_request_reconciliation*.py` and
`test_sync_ibs_requests.py`; these checks keep a later edit from crossing
the boundaries.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_PACKAGES = APP_ROOT / "services" / "packages"
_BOUNDARY = _PACKAGES / "ibs_request_reconciliation.py"
_OBSERVATION = _PACKAGES / "ibs_request_observation.py"
_FETCHER = _PACKAGES / "sync_ibs_requests.py"
_FETCHER_CLASS: Final = "SyncIbsRequests"
_FETCHER_METHODS: Final = ("execute", "catch_up")
_SCOPE_READER: Final = "load_ibs_request_scopes"

_FOR_UPDATE: Final = re.compile(r"\bfor\s+(no\s+key\s+)?update\b", re.IGNORECASE)

_LOCKING: Final = "_reconcile_scope"
_APPLY: Final = "_Reconciliation._apply"
_TRUSTED: Final = "apply_ibs_request_observation"
_TRUSTED_CALLER: Final = "services/example_dataset.py"
_ROW_LOCKERS: Final = ("_lock_request", "_lock_actions")
_LOCKED_UNIT: Final = (
    _LOCKING,
    "_lock_request",
    "_write_request",
    "_lock_actions",
    "_write_evidence",
    "_action_changes",
    "_apply_delivery",
)
"""The functions that run inside the locked unit."""
_READERS: Final = (
    "load_ibs_request_scopes",
    "read_retained_actions",
    "_read_trusted_scope",
)
_TRUSTED_UNIT: Final = (
    _TRUSTED,
    "_read_trusted_scope",
    "_validate_trusted_observation",
    "_satisfies_action_structure",
)
"""The trusted observation application and its own helpers."""

_IO_NAMES: Final = {
    "httpx",
    "IBSClient",
    "client",
    "cache",
    "EvidenceCache",
    "observe_scope",
    "asyncio",
    "task_publication",
    "publish_task",
    "redis",
    "celery",
    "celery_app",
    "http_client",
    "async_session_factory",
}
"""Names through which a function could perform IBS, HTTP, broker, or
Redis I/O, or open another session."""

_WRITES: Final = {"add", "add_all", "flush", "delete", "merge", "commit", "rollback"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }


def _qualified_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    """`Class.method` or `function` of the enclosing function; a nested
    function is attributed to its outermost enclosing function."""
    names: list[str] = []
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if names:
                names = []
            names.append(node.name)
        elif isinstance(node, ast.ClassDef) and names:
            names.insert(0, node.name)
    return ".".join(names) if names else None


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    found[f"{node.name}.{item.name}"] = item
    return found


def _referenced_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _called_attributes(node: ast.AST) -> set[str]:
    return {
        child.func.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
    }


def _selects_ticket(call: ast.Call) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "select"
        and bool(node.args)
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "Ticket"
        for node in ast.walk(call)
    )


def _callers(name: str) -> list[tuple[str, str | None]]:
    """Every reference to `name` in the application, by module and
    enclosing function."""
    sites: list[tuple[str, str | None]] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        tree = _tree(path)
        parents = _parents(tree)
        for node in ast.walk(tree):
            referenced = (
                node.id
                if isinstance(node, ast.Name)
                else node.attr
                if isinstance(node, ast.Attribute)
                else None
            )
            if referenced == name:
                sites.append(
                    (
                        str(path.relative_to(APP_ROOT)),
                        _qualified_function(node, parents),
                    )
                )
    return sites


@pytest.mark.unit
class TestLockPlacement:
    def test_the_ticket_row_lock_is_taken_only_by_the_locked_unit(self) -> None:
        tree = _tree(_BOUNDARY)
        parents = _parents(tree)
        ticket_locks = [
            _qualified_function(node, parents)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "with_for_update"
            and _selects_ticket(node)
        ]

        assert ticket_locks == [_LOCKING]

    def test_every_row_lock_is_inside_the_locked_unit(self) -> None:
        tree = _tree(_BOUNDARY)
        parents = _parents(tree)
        sites = {
            _qualified_function(node, parents)
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "with_for_update"
        }

        assert sites == {_LOCKING, *_ROW_LOCKERS}

    def test_the_locked_unit_is_entered_only_through_apply(self) -> None:
        assert sorted(_callers(_LOCKING), key=str) == [
            ("services/packages/ibs_request_reconciliation.py", _APPLY),
            ("services/packages/ibs_request_reconciliation.py", _TRUSTED),
        ]
        assert {caller for _, caller in _callers("_write_evidence")} == {_LOCKING}
        assert {caller for _, caller in _callers("_lock_request")} == {"_write_request"}
        assert {caller for _, caller in _callers("_lock_actions")} == {
            "_write_evidence"
        }


@pytest.mark.unit
class TestLockedUnitBody:
    @pytest.mark.parametrize("name", _LOCKED_UNIT)
    def test_performs_no_ibs_http_broker_or_redis_io(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert _referenced_names(body) & _IO_NAMES == set()

    @pytest.mark.parametrize("name", _LOCKED_UNIT)
    def test_never_commits_rolls_back_or_closes_the_unit(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert _called_attributes(body) & {"commit", "rollback", "close"} == set()

    @pytest.mark.parametrize("name", _READERS)
    def test_readers_take_no_lock_and_never_write(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert "with_for_update" not in _referenced_names(body)
        assert _called_attributes(body) & _WRITES == set()


def _references(tree: ast.AST, name: str) -> bool:
    """Whether `tree` references `name` through a name, an attribute, or an
    import alias."""
    return any(
        (isinstance(node, ast.Name) and node.id == name)
        or (isinstance(node, ast.Attribute) and node.attr == name)
        or (isinstance(node, ast.alias) and node.name == name)
        for node in ast.walk(tree)
    )


def _referencing_modules(name: str) -> set[str]:
    """Every application module that references `name`."""
    return {
        str(path.relative_to(APP_ROOT))
        for path in sorted(APP_ROOT.rglob("*.py"))
        if _references(_tree(path), name)
    }


@pytest.mark.unit
class TestTrustedObservationApplication:
    def test_only_the_example_dataset_loader_references_it(self) -> None:
        """The defining module only defines it (and names it in `__all__`,
        a string), so it is not among the referencing modules."""
        assert _referencing_modules(_TRUSTED) == {_TRUSTED_CALLER}

    @pytest.mark.parametrize("name", _TRUSTED_UNIT)
    def test_performs_no_ibs_http_broker_or_redis_io(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert _referenced_names(body) & _IO_NAMES == set()

    @pytest.mark.parametrize("name", _TRUSTED_UNIT)
    def test_never_commits_rolls_back_or_closes_the_session(self, name: str) -> None:
        body = _functions(_tree(_BOUNDARY))[name]

        assert _called_attributes(body) & {"commit", "rollback", "close"} == set()

    def test_takes_no_lock_of_its_own(self) -> None:
        body = _functions(_tree(_BOUNDARY))[_TRUSTED]

        assert "with_for_update" not in _referenced_names(body)

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            (f"from x import {_TRUSTED} as renamed\n", True),
            (f"import x\nx.{_TRUSTED}()\n", True),
            (f"{_TRUSTED}()\n", True),
            ("from x import apply_ibs_requests\n", False),
        ],
        ids=["import-alias", "attribute", "name", "other-name"],
    )
    def test_reference_detection_finds_every_form(
        self, source: str, expected: bool
    ) -> None:
        assert _references(ast.parse(source), _TRUSTED) is expected


@pytest.mark.unit
class TestObservationModule:
    def test_has_no_database_dependency(self) -> None:
        modules = imported_modules(_OBSERVATION, "app.services.packages")

        assert {
            module
            for module in modules
            if module == "sqlalchemy"
            or module.startswith(("sqlalchemy.", "app.database", "app.models"))
        } == set()
        assert "with_for_update" not in _referenced_names(_tree(_OBSERVATION))


def _docstrings(tree: ast.AST) -> set[ast.AST]:
    found: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                found.add(body[0].value)
    return found


def _fetcher_method(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    return _functions(_tree(_FETCHER))[f"{_FETCHER_CLASS}.{name}"]


def _passes_session(call: ast.Call) -> bool:
    return any(
        isinstance(node, ast.Name) and node.id == "session"
        for argument in (*call.args, *(keyword.value for keyword in call.keywords))
        for node in ast.walk(argument)
    )


@pytest.mark.unit
class TestFetcherReadsOnly:
    def test_module_takes_no_row_lock(self) -> None:
        tree = _tree(_FETCHER)
        docstrings = _docstrings(tree)

        assert "with_for_update" not in _referenced_names(tree)
        assert [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node not in docstrings
            and _FOR_UPDATE.search(node.value)
        ] == []

    def test_imports_no_sqlalchemy_write_construct_or_model(self) -> None:
        imported = {
            alias.name
            for node in ast.walk(_tree(_FETCHER))
            if isinstance(node, ast.ImportFrom)
            and (node.module or "").startswith("sqlalchemy")
            for alias in node.names
        }

        assert imported & {"select", "update", "insert", "delete", "text"} == set()
        assert [
            module
            for module in imported_modules(_FETCHER, "app.services.packages")
            if module == "app.models" or module.startswith("app.models.")
        ] == []

    @pytest.mark.parametrize("method", _FETCHER_METHODS)
    def test_the_passed_session_only_reads_scopes_and_ends_the_read(
        self, method: str
    ) -> None:
        """The only method called on `session` is `commit()`, and the only
        call it is passed to is the scope reader."""
        body = _fetcher_method(method)
        calls = [node for node in ast.walk(body) if isinstance(node, ast.Call)]
        on_session = {
            call.func.attr
            for call in calls
            if isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "session"
        }
        receivers = {
            call.func.id if isinstance(call.func, ast.Name) else ast.unparse(call.func)
            for call in calls
            if _passes_session(call)
        }

        assert on_session == {"commit"}
        assert receivers == {_SCOPE_READER}

    def test_module_calls_no_other_session_operation(self) -> None:
        assert _called_attributes(_tree(_FETCHER)) & (
            _WRITES | {"close", "with_for_update"}
        ) == {"commit"}

    def test_module_opens_no_session_and_uses_no_fetcher_http_client(self) -> None:
        """Only the boundary opens the snapshot and unit sessions, and IBS is
        requested through the fetcher's own `IBSClient`; neither
        `BaseFetcher.http_client` nor another HTTP client is used."""
        names = _referenced_names(_tree(_FETCHER))

        assert names & {"async_session_factory", "get_async_session"} == set()
        assert names & {"http_client", "_http_client", "create_http_client"} == set()
        assert names & {"httpx", "task_publication", "publish_task", "redis"} == set()
