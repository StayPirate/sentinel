"""Structural test: only the API key service queries the `ApiKey` model, and
API-key authentication resolves credentials through `get_key_by_hash()`.

See `docs/features/identity/api-key-service.md` (Purpose: "API, CLI,
authentication, and user lifecycle callers remain thin and perform no
direct API key queries or writes"), `docs/features/identity/authentication.md`
(API key validation, step 2: "The authentication boundary performs no
direct `ApiKey` query"), and `docs/features/platform/testing-strategy.md`
(API Key Management: authentication resolves credentials through
`get_key_by_hash()` rather than a direct model query).

Every module in `backend/app/` is enumerated via AST, with names resolved
through the module's imports, including aliases, `*` imports, and imports
inside functions:

1. every reference to the `ApiKey` model (`app.models.api_key.ApiKey` or
   `app.models.ApiKey`) outside a type expression — a parameter, return, or
   variable annotation, including its subscript type arguments — and every
   access to an `.api_keys` relationship attribute occurs only in
   `app/models/` or `app/services/api_key_service.py`. A query, a
   `get()`, a column expression, an `isinstance()` check, and a relationship
   loader option are all references; an import, including one guarded by
   `TYPE_CHECKING`, is not;
2. the calls resolving to `app.services.api_key_service.get_key_by_hash`
   occur in exactly one function, the authentication function
   `_authenticate_api_key` of `app/api/dependencies.py`.

Blind spots: a reference by string, such as `getattr(models, "ApiKey")`, a
loader option or relationship named by a string, an attribute name held in
a variable (`getattr(user, name)`, `setattr(...)`), a `**` expansion that
forwards the model or its attributes, a relative import, and SQL text
(`text("... api_keys ...")`) are not detected.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

_API_KEY_MODEL: Final = frozenset({"app.models.api_key.ApiKey", "app.models.ApiKey"})
_RELATIONSHIP: Final = "api_keys"
_LOOKUP: Final = "app.services.api_key_service.get_key_by_hash"

_MODEL_OWNER_DIRECTORY: Final = "app/models/"
_MODEL_OWNER_MODULE: Final = "app/services/api_key_service.py"
_LOOKUP_CALLERS: Final = {("app/api/dependencies.py", "_authenticate_api_key")}


def _import_bindings(tree: ast.AST) -> tuple[dict[str, str], list[str]]:
    """Local name -> dotted target of every import anywhere in `tree`, and
    the modules imported with `*`."""
    bindings: dict[str, str] = {}
    star_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    bindings[top] = top
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.name == "*":
                    star_modules.append(node.module)
                else:
                    bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bindings, star_modules


def _qualified_name(
    node: ast.expr, bindings: dict[str, str], star_modules: list[str]
) -> str | None:
    if isinstance(node, ast.Name):
        if node.id in bindings:
            return bindings[node.id]
        for module in star_modules:
            if f"{module}.{node.id}" in _API_KEY_MODEL | {_LOOKUP}:
                return f"{module}.{node.id}"
        return None
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, bindings, star_modules)
        return f"{base}.{node.attr}" if base else None
    return None


def _type_expression_nodes(tree: ast.AST) -> set[ast.AST]:
    """Every node inside a parameter, return, or variable annotation."""
    roots: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns:
            roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
    return {child for root in roots for child in ast.walk(root)}


def _assign_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]


def _enclosing_qualname(node: ast.AST) -> str | None:
    """The nearest enclosing function, as `"ClassName.method"` for a method
    and a bare name otherwise, or `None` at module level. Requires
    `_assign_parents()`."""
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            enclosing = getattr(current, "parent", None)
            if isinstance(enclosing, ast.ClassDef):
                return f"{enclosing.name}.{current.name}"
            return current.name
        current = getattr(current, "parent", None)
    return None


def _module_name(path: str) -> str:
    return path.removesuffix(".py").removesuffix("/__init__").replace("/", ".")


def _parse(source: str, module: str) -> tuple[ast.Module, dict[str, str], list[str]]:
    """The tree and its name bindings; the module's own top-level functions
    and classes resolve to `module.<name>`."""
    tree = ast.parse(source)
    _assign_parents(tree)
    bindings, star_modules = _import_bindings(tree)
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bindings.setdefault(statement.name, f"{module}.{statement.name}")
    return tree, bindings, star_modules


def _model_references(source: str, module: str = "fictional") -> list[tuple[int, str]]:
    """(line, name) of every `ApiKey` model reference outside a type
    expression and of every `.api_keys` attribute access."""
    tree, bindings, star_modules = _parse(source, module)
    type_expressions = _type_expression_nodes(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == _RELATIONSHIP:
            found.append((node.lineno, f".{_RELATIONSHIP}"))
        if (
            not isinstance(node, ast.Name | ast.Attribute)
            or not isinstance(node.ctx, ast.Load)
            or node in type_expressions
        ):
            continue
        if _qualified_name(node, bindings, star_modules) in _API_KEY_MODEL:
            found.append((node.lineno, "ApiKey"))
    return sorted(found)


def _lookup_calls(source: str, module: str = "fictional") -> list[str | None]:
    """The enclosing function of every call to `get_key_by_hash()`."""
    tree, bindings, star_modules = _parse(source, module)
    return [
        _enclosing_qualname(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _qualified_name(node.func, bindings, star_modules) == _LOOKUP
    ]


def _app_sources() -> dict[str, str]:
    return {
        path.relative_to(BACKEND_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(APP_ROOT.rglob("*.py"))
    }


@pytest.mark.unit
class TestModelReferenceDetector:
    """The detector on synthetic sources, independent of `app/`."""

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            (
                "from app.models.api_key import ApiKey\nselect(ApiKey)",
                [(2, "ApiKey")],
            ),
            (
                "from app.models import ApiKey\nawait db.get(ApiKey, i)",
                [(2, "ApiKey")],
            ),
            (
                "from app.models.api_key import ApiKey\nApiKey.key_hash == d",
                [(2, "ApiKey")],
            ),
            ("from app.models import ApiKey as K\nK.id", [(2, "ApiKey")]),
            (
                "from app.models.api_key import ApiKey\nisinstance(x, ApiKey)",
                [(2, "ApiKey")],
            ),
            ("selectinload(User.api_keys)", [(1, ".api_keys")]),
            ("user.api_keys.append(key)", [(1, ".api_keys")]),
            (
                "import app.models.api_key\napp.models.api_key.ApiKey.id",
                [(2, "ApiKey")],
            ),
            ("import app.models as m\nselect(m.ApiKey)", [(2, "ApiKey")]),
            ("from app.models import *\nselect(ApiKey)", [(2, "ApiKey")]),
            (
                "def f():\n"
                "    from app.models import ApiKey\n"
                "    return select(ApiKey)",
                [(3, "ApiKey")],
            ),
            (
                "from app.models.api_key import ApiKey\nmodel = ApiKey",
                [(2, "ApiKey")],
            ),
        ],
    )
    def test_model_reference_any_form_is_detected(
        self, source: str, expected: list[tuple[int, str]]
    ) -> None:
        assert _model_references(source) == expected

    @pytest.mark.parametrize(
        "source",
        [
            "from app.models.api_key import ApiKey\ndef f(k: ApiKey) -> ApiKey: ...",
            "from app.models.api_key import ApiKey\nx: ApiKey | None = None",
            "from app.models.api_key import ApiKey\n"
            "def f(keys: list[ApiKey]) -> None: ...",
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from app.models.api_key import ApiKey",
            "from app.services import api_key_service\n"
            "await api_key_service.get_key_by_hash(db, d)",
            "from app.schemas.api_key import ApiKeyData\nApiKeyData(name=n)",
            "class ApiKey:\n    pass\nApiKey()",
            "impact.api_keys_count",
            "from app.api.v1 import api_keys\napi_keys.router",
        ],
    )
    def test_non_reference_source_is_not_detected(self, source: str) -> None:
        assert _model_references(source) == []


@pytest.mark.unit
class TestLookupCallDetector:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            (
                "from app.services import api_key_service\n"
                "async def _authenticate_api_key():\n"
                "    await api_key_service.get_key_by_hash(db, d)",
                ["_authenticate_api_key"],
            ),
            (
                "from app.services.api_key_service import get_key_by_hash as g\n"
                "g(db, d)",
                [None],
            ),
            (
                "import app.services.api_key_service as s\n"
                "class C:\n"
                "    async def m(self):\n"
                "        await s.get_key_by_hash(db, d)",
                ["C.m"],
            ),
        ],
    )
    def test_lookup_call_any_form_is_detected(
        self, source: str, expected: list[str | None]
    ) -> None:
        assert _lookup_calls(source) == expected

    def test_module_local_call_is_detected(self) -> None:
        source = (
            "async def get_key_by_hash(session, key_hash): ...\n"
            "async def other(session):\n"
            "    await get_key_by_hash(session, 'x')"
        )

        assert _lookup_calls(source, "app.services.api_key_service") == ["other"]

    @pytest.mark.parametrize(
        "source",
        [
            "from app.services import other_service\n"
            "other_service.get_key_by_hash(db, d)",
            "from app.services import api_key_service\n"
            "api_key_service.get_key_by_id(db, i)",
            "async def get_key_by_hash(session, key_hash): ...",
        ],
    )
    def test_other_calls_are_not_detected(self, source: str) -> None:
        assert _lookup_calls(source, "app.services.api_key_service") == []


@pytest.mark.unit
class TestApiKeyAccessBoundary:
    def test_only_the_api_key_service_and_models_reference_the_model(self) -> None:
        found = {
            module: references
            for module, source in _app_sources().items()
            if not module.startswith(_MODEL_OWNER_DIRECTORY)
            and module != _MODEL_OWNER_MODULE
            and (references := _model_references(source, _module_name(module)))
        }

        assert found == {}, (
            "ApiKey query outside app/services/api_key_service.py "
            "(docs/features/identity/api-key-service.md, Purpose): call an "
            "api_key_service function instead"
        )

    def test_authentication_resolves_credentials_through_get_key_by_hash(
        self,
    ) -> None:
        callers = {
            (module, caller)
            for module, source in _app_sources().items()
            for caller in _lookup_calls(source, _module_name(module))
        }

        assert callers == _LOOKUP_CALLERS, (
            "get_key_by_hash() is the credential lookup of API key "
            "authentication only (docs/features/identity/authentication.md, "
            "API key validation, step 2)"
        )
