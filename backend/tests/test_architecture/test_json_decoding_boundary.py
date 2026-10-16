"""Structural test: `app/services/json_decoding.py` is the only module in
`backend/app/` that decodes JSON, apart from the reviewed exceptions.

See `docs/features/platform/testing-strategy.md` (Structural Tests table,
row "JSON decoding boundary") and `docs/conventions.md` (External JSON
Decoding): external JSON is decoded only through `decode_json()`, which
makes every decoding failure, including nesting beyond the parser's limit,
a `ValueError`.

Every JSON decoding reference is enumerated via AST, so a call is found as
well as a decoder passed on uncalled: `json.loads`, `json.load`,
`json.JSONDecoder`, `pydantic.Json`, and `pydantic_core.from_json`
resolved through the module's imports, including aliases and `*` imports;
any attribute named `json` (`httpx.Response.json()`, Starlette
`Request.json()`), `raw_decode`, `model_validate_json`, or `validate_json`
whatever its receiver; and any import of a third-party JSON library.

The reviewed exceptions, each pinned to its exact references:

- `app/core/request_admissibility.py` reads the consumer-supplied request
  body that FastAPI has already decoded; API request bodies are governed by
  `docs/api-spec.md`, not by the convention;
- `app/services/cpe_mapping.py` loads the bundled, CI-validated CPE
  mapping (`docs/features/packages/cpe-package-mapping.md`);
- `app/services/fetcher_operations.py` re-validates a settings value it
  has just serialized itself.

A new decoding site is a reviewed exception added to this test, not a
workaround.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

ALLOWED_REFERENCES: Final = {
    "app/core/request_admissibility.py": [".json"],
    "app/services/cpe_mapping.py": ["json.loads"],
    "app/services/fetcher_operations.py": [".validate_json"],
    "app/services/json_decoding.py": ["json.loads"],
}
"""Module -> the exact decoding references it may contain, in line order."""

_DECODERS = frozenset(
    {
        "json.loads",
        "json.load",
        "json.JSONDecoder",
        "json.decoder.JSONDecoder",
        "pydantic.Json",
        "pydantic.types.Json",
        "pydantic_core.from_json",
    }
)
_DECODING_ATTRIBUTES = frozenset(
    {"json", "raw_decode", "model_validate_json", "validate_json"}
)
JSON_LIBRARIES = frozenset(
    {"orjson", "ujson", "simplejson", "rapidjson", "msgspec", "simdjson", "ijson"}
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
            if f"{module}.{node.id}" in _DECODERS:
                return f"{module}.{node.id}"
        return None
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, bindings, star_modules)
        return f"{base}.{node.attr}" if base else None
    return None


def _library_imports(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        found += [
            (node.lineno, f"import {name}")
            for name in names
            if name.split(".")[0] in JSON_LIBRARIES
        ]
    return found


def _decoding_references(source: str) -> list[tuple[int, str]]:
    """(line, canonical name) of every JSON decoding reference."""
    tree = ast.parse(source)
    bindings, star_modules = _import_bindings(tree)
    found = _library_imports(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name | ast.Attribute) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        qualified = _qualified_name(node, bindings, star_modules)
        if qualified in _DECODERS:
            found.append((node.lineno, qualified))
        elif isinstance(node, ast.Attribute) and node.attr in _DECODING_ATTRIBUTES:
            found.append((node.lineno, f".{node.attr}"))
    return sorted(found)


def _app_sources() -> dict[str, str]:
    return {
        path.relative_to(BACKEND_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(APP_ROOT.rglob("*.py"))
    }


@pytest.mark.unit
class TestDecodingReferenceDetector:
    """The detector on synthetic sources, independent of `app/`."""

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("import json\njson.loads(b)", "json.loads"),
            ("import json as j\nj.load(f)", "json.load"),
            ("from json import loads\nloads(b)", "json.loads"),
            ("from json import loads as l\nparse = l", "json.loads"),
            ("from json import *\nloads(b)", "json.loads"),
            ("import json\njson.JSONDecoder().decode(b)", "json.JSONDecoder"),
            (
                "import json.decoder\njson.decoder.JSONDecoder()",
                "json.decoder.JSONDecoder",
            ),
            (
                "def f():\n    import json\n    return json.loads(b)",
                "json.loads",
            ),
            ("response.json()", ".json"),
            ("await request.json()", ".json"),
            ("decode = response.json", ".json"),
            ("decoder.raw_decode(text)", ".raw_decode"),
            ("Model.model_validate_json(b)", ".model_validate_json"),
            ("TypeAdapter(int).validate_json(b)", ".validate_json"),
            ("from pydantic import Json\nfield: Json[int]", "pydantic.Json"),
            (
                "import pydantic_core\npydantic_core.from_json(b)",
                "pydantic_core.from_json",
            ),
            (
                "from pydantic_core import from_json as f\nf(b)",
                "pydantic_core.from_json",
            ),
            ("import orjson", "import orjson"),
            ("import ujson as u", "import ujson"),
            ("from simplejson import loads", "import simplejson"),
            ("from msgspec.json import decode", "import msgspec.json"),
        ],
    )
    def test_decoding_reference_any_form_is_detected(
        self, source: str, expected: str
    ) -> None:
        assert [name for _, name in _decoding_references(source)] == [expected]

    @pytest.mark.parametrize(
        "source",
        [
            "import json\njson.dumps(v)",
            "import json\nexcept_type = json.JSONDecodeError",
            "from app.services.json_decoding import decode_json\ndecode_json(b)",
            "from app.services import json_decoding\njson_decoding.decode_json(b)",
            "loads(b)",
            "model.model_dump(mode='json')",
            "Model.model_validate(value)",
            "headers = {'Accept': 'application/json'}",
            "from json import loads\nloads = None",
        ],
    )
    def test_non_decoding_source_is_not_detected(self, source: str) -> None:
        assert _decoding_references(source) == []

    def test_lines_are_reported_in_order(self) -> None:
        source = "import json\n\nresponse.json()\njson.loads(b)\n"

        assert _decoding_references(source) == [(3, ".json"), (4, "json.loads")]


@pytest.mark.unit
class TestJSONDecodingBoundary:
    def test_json_is_decoded_only_through_the_boundary_and_reviewed_exceptions(
        self,
    ) -> None:
        found = {
            module: [name for _, name in references]
            for module, source in _app_sources().items()
            if (references := _decoding_references(source))
        }

        assert found == ALLOWED_REFERENCES, (
            "JSON decoding outside app/services/json_decoding.py "
            "(docs/conventions.md, External JSON Decoding): decode external "
            "JSON with decode_json(), or add a reviewed exception"
        )
