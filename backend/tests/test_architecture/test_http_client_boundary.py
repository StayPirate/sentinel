"""Structural test: `app/services/http_client.py` is the only module in
`backend/app/` that creates an HTTP client or network transport.

See `docs/features/platform/testing-strategy.md` (Structural Tests table,
row "HTTP client boundary") and `docs/features/platform/networking.md`
(Shared HTTP Client): every outgoing HTTP request uses a client from
`create_http_client()`, which applies the TLS trust store, the proxy
configuration, the transport-level retry, and the response content-coding
policy. A client built anywhere else would lose all of them at once.

Every reference is enumerated via AST, resolved through the module's
imports, including aliases and `*` imports:

- any reference to an httpx client or network transport class
  (`AsyncClient`, `Client`, `AsyncHTTPTransport`, `HTTPTransport`) outside
  a type expression (an annotation or a subscript type argument): a call,
  a base class, or a class passed on uncalled;
- any reference to an httpx top-level request function (`request`,
  `stream`, `get`, `options`, `head`, `post`, `put`, `patch`, `delete`);
- any import of another HTTP client library.

`app/services/http_client.py` itself is pinned to its exact references.
A new HTTP client is a reviewed change to this boundary, not a workaround.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

ALLOWED_REFERENCES: Final = {
    "app/services/http_client.py": ["httpx.AsyncHTTPTransport", "httpx.AsyncClient"],
}
"""Module -> the exact references it may contain, in line order."""

_CLIENTS = frozenset(
    {
        "httpx.AsyncClient",
        "httpx.Client",
        "httpx.AsyncHTTPTransport",
        "httpx.HTTPTransport",
    }
)
_REQUEST_FUNCTIONS = frozenset(
    {
        "httpx.request",
        "httpx.stream",
        "httpx.get",
        "httpx.options",
        "httpx.head",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
    }
)
HTTP_LIBRARIES = frozenset(
    {
        "aiohttp",
        "http.client",
        "httpcore",
        "httplib2",
        "pycurl",
        "requests",
        "tornado.httpclient",
        "treq",
        "urllib.request",
        "urllib3",
    }
)


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
            if f"{module}.{node.id}" in _CLIENTS | _REQUEST_FUNCTIONS:
                return f"{module}.{node.id}"
        return None
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, bindings, star_modules)
        return f"{base}.{node.attr}" if base else None
    return None


def _type_expression_nodes(tree: ast.AST) -> set[ast.AST]:
    """Every node inside a parameter, return, or variable annotation, and
    every name used as a subscript type argument, as in
    `Annotated[httpx.AsyncClient, Depends(...)]`; a call inside a subscript
    is not one."""
    roots: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns:
            roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
        elif isinstance(node, ast.Subscript):
            arguments = (
                node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            )
            roots += [
                argument
                for argument in arguments
                if isinstance(argument, ast.Name | ast.Attribute)
            ]
    return {child for root in roots for child in ast.walk(root)}


def _is_http_library(module: str) -> bool:
    return any(
        module == library or module.startswith(f"{library}.")
        for library in HTTP_LIBRARIES
    )


def _library_imports(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            # `from urllib import request` imports the module `urllib.request`.
            names = (
                [node.module]
                if _is_http_library(node.module)
                else [f"{node.module}.{alias.name}" for alias in node.names]
            )
        else:
            continue
        found += [
            (node.lineno, f"import {name}") for name in names if _is_http_library(name)
        ]
    return found


def _client_references(source: str) -> list[tuple[int, str]]:
    """(line, canonical name) of every HTTP client reference."""
    tree = ast.parse(source)
    bindings, star_modules = _import_bindings(tree)
    type_expressions = _type_expression_nodes(tree)
    found = _library_imports(tree)
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Name | ast.Attribute)
            or not isinstance(node.ctx, ast.Load)
            or node in type_expressions
        ):
            continue
        qualified = _qualified_name(node, bindings, star_modules)
        if qualified in _CLIENTS | _REQUEST_FUNCTIONS:
            found.append((node.lineno, qualified))
    return sorted(found)


def _app_sources() -> dict[str, str]:
    return {
        path.relative_to(BACKEND_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(APP_ROOT.rglob("*.py"))
    }


@pytest.mark.unit
class TestClientReferenceDetector:
    """The detector on synthetic sources, independent of `app/`."""

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("import httpx\nhttpx.AsyncClient()", "httpx.AsyncClient"),
            ("import httpx\nhttpx.Client(timeout=1)", "httpx.Client"),
            ("import httpx as h\nh.AsyncHTTPTransport()", "httpx.AsyncHTTPTransport"),
            ("from httpx import HTTPTransport\nHTTPTransport()", "httpx.HTTPTransport"),
            ("from httpx import AsyncClient as C\nC()", "httpx.AsyncClient"),
            ("from httpx import *\nAsyncClient()", "httpx.AsyncClient"),
            ("import httpx\nfactory = httpx.AsyncClient", "httpx.AsyncClient"),
            (
                "import httpx\nclass Own(httpx.AsyncClient):\n    pass",
                "httpx.AsyncClient",
            ),
            (
                "def f():\n    import httpx\n    return httpx.AsyncClient()",
                "httpx.AsyncClient",
            ),
            ("import httpx\nawait httpx.get(url)", "httpx.get"),
            ("import httpx\nhttpx.request('POST', url)", "httpx.request"),
            ("from httpx import stream\nstream('GET', url)", "httpx.stream"),
            ("import httpx\nsend = httpx.post", "httpx.post"),
            ("import httpx\nclients[httpx.AsyncClient()]", "httpx.AsyncClient"),
            ("import requests", "import requests"),
            ("import aiohttp as a", "import aiohttp"),
            ("from urllib.request import urlopen", "import urllib.request"),
            ("from urllib import request", "import urllib.request"),
            ("import http.client", "import http.client"),
            ("from http import client", "import http.client"),
            ("import httpcore", "import httpcore"),
            ("from urllib3.util import Retry", "import urllib3.util"),
        ],
    )
    def test_client_reference_any_form_is_detected(
        self, source: str, expected: str
    ) -> None:
        assert [name for _, name in _client_references(source)] == [expected]

    @pytest.mark.parametrize(
        "source",
        [
            "import httpx\ndef f(client: httpx.AsyncClient) -> httpx.AsyncClient: ...",
            "import httpx\nclient: httpx.AsyncClient | None = None",
            "import httpx\nDependency = Annotated[httpx.AsyncClient, Depends(f)]",
            "import httpx\nclients: list[httpx.Client] = []",
            "import httpx\nhttpx.Response(200)",
            "import httpx\nhttpx.Request('GET', url)",
            "import httpx\nexcept_type = httpx.HTTPStatusError",
            "import httpx\nhttpx.Timeout(10.0)",
            "await client.get(url)",
            "from app.services.http_client import create_http_client\n"
            "create_http_client('name')",
            "from urllib.parse import urlsplit",
            "import http",
        ],
    )
    def test_non_client_source_is_not_detected(self, source: str) -> None:
        assert _client_references(source) == []

    def test_lines_are_reported_in_order(self) -> None:
        source = "import httpx\n\nhttpx.get(url)\nhttpx.AsyncClient()\n"

        assert _client_references(source) == [
            (3, "httpx.get"),
            (4, "httpx.AsyncClient"),
        ]


@pytest.mark.unit
class TestHTTPClientBoundary:
    def test_http_clients_are_created_only_by_the_shared_factory(self) -> None:
        found = {
            module: [name for _, name in references]
            for module, source in _app_sources().items()
            if (references := _client_references(source))
        }

        assert found == ALLOWED_REFERENCES, (
            "HTTP client outside app/services/http_client.py "
            "(docs/features/platform/networking.md, Shared HTTP Client): use "
            "create_http_client(), or change the boundary in a reviewed PR"
        )
