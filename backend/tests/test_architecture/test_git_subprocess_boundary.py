"""Structural test: `app/services/git_operations.py` is the only module in
`backend/app/` that starts a process, and no Python Git library is used.

See `docs/features/platform/testing-strategy.md` (Structural Tests table,
row "Process-spawning boundary") and
`docs/features/platform/git-fetcher-infrastructure.md` (Implementation
Location; Runtime Dependencies, "No Python Git library is used"; Module
Invariants, Rule 2).

Every reference to a process-spawning function or class is enumerated via
AST, so a call is found as well as the function passed on uncalled (for
example to `functools.partial`). Names are resolved through the module's
imports, including aliases (`import subprocess as sp`, `from os import
system`, `from os import *`); any attribute named `subprocess_exec` or
`subprocess_shell` is an event-loop spawn whatever its receiver. A new
process-spawning module is a reviewed exception added to this test, not a
workaround.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"
PYPROJECT = BACKEND_ROOT / "pyproject.toml"

GIT_OPERATIONS = "app/services/git_operations.py"
ALLOWED_SPAWNS = ["asyncio.create_subprocess_exec"]

_SUBPROCESS_SPAWNERS = frozenset(
    {
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "getoutput",
        "getstatusoutput",
    }
)
_ASYNCIO_SPAWNERS = frozenset({"create_subprocess_exec", "create_subprocess_shell"})
_LOOP_SPAWN_METHODS = frozenset({"subprocess_exec", "subprocess_shell"})
_OS_SPAWNERS = frozenset(
    {"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp"}
)
_OS_SPAWNER_PREFIXES = ("exec", "spawn")
_PTY_SPAWNERS = frozenset({"spawn", "fork"})

GIT_LIBRARIES = frozenset({"git", "pygit2", "dulwich"})
GIT_LIBRARY_DISTRIBUTIONS = frozenset({"gitpython", "pygit2", "dulwich"})


def _spawner(qualified: str) -> str | None:
    """The canonical name of the process-spawning callable `qualified`
    names, or `None` when it names none."""
    module, _, name = qualified.rpartition(".")
    if module == "subprocess" and name in _SUBPROCESS_SPAWNERS:
        return qualified
    if module in {"asyncio", "asyncio.subprocess"} and name in _ASYNCIO_SPAWNERS:
        return f"asyncio.{name}"
    if module in {"os", "posix"} and (
        name in _OS_SPAWNERS or name.startswith(_OS_SPAWNER_PREFIXES)
    ):
        return f"os.{name}"
    if module == "pty" and name in _PTY_SPAWNERS:
        return qualified
    return None


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
            if _spawner(f"{module}.{node.id}"):
                return f"{module}.{node.id}"
        return None
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value, bindings, star_modules)
        return f"{base}.{node.attr}" if base else None
    return None


def _spawn_references(source: str) -> list[tuple[int, str]]:
    """(line, canonical spawner) of every process-spawning reference."""
    tree = ast.parse(source)
    bindings, star_modules = _import_bindings(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name | ast.Attribute) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        if isinstance(node, ast.Attribute) and node.attr in _LOOP_SPAWN_METHODS:
            found.append((node.lineno, f"<event loop>.{node.attr}"))
            continue
        qualified = _qualified_name(node, bindings, star_modules)
        spawner = _spawner(qualified) if qualified else None
        if spawner:
            found.append((node.lineno, spawner))
    return sorted(found)


def _shell_keywords(source: str) -> list[int]:
    """Lines of every call passing `shell=` with anything but `False`."""
    return sorted(
        keyword.value.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "shell"
        and not (
            isinstance(keyword.value, ast.Constant) and keyword.value.value is False
        )
    )


def _git_library_imports(source: str) -> list[str]:
    """Every imported module that belongs to a Python Git library."""
    imported: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.append(node.module)
    return [name for name in imported if name.split(".")[0] in GIT_LIBRARIES]


def _declared_requirements(pyproject: dict[str, Any]) -> list[str]:
    """Every requirement string of every dependency list in `pyproject`."""
    project = pyproject.get("project", {})
    uv = pyproject.get("tool", {}).get("uv", {})
    lists: list[list[Any]] = [
        project.get("dependencies", []),
        *project.get("optional-dependencies", {}).values(),
        *pyproject.get("dependency-groups", {}).values(),
        pyproject.get("build-system", {}).get("requires", []),
        uv.get("dev-dependencies", []),
        uv.get("constraint-dependencies", []),
        uv.get("override-dependencies", []),
    ]
    # A dependency-group entry may be an `{include-group = ...}` table.
    return [item for items in lists for item in items if isinstance(item, str)]


_REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _distribution_name(requirement: str) -> str:
    """The normalized (PEP 503) distribution name of `requirement`."""
    match = _REQUIREMENT_NAME.match(requirement)
    assert match, f"unparsable requirement {requirement!r}"
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def _app_sources() -> dict[str, str]:
    return {
        path.relative_to(BACKEND_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(APP_ROOT.rglob("*.py"))
    }


@pytest.mark.unit
class TestSpawnReferenceDetector:
    """The detector on synthetic sources, independent of `app/`."""

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("import subprocess\nsubprocess.run(['x'])", "subprocess.run"),
            ("import subprocess as sp\nsp.Popen(['x'])", "subprocess.Popen"),
            ("from subprocess import run as r\nr(['x'])", "subprocess.run"),
            (
                "from subprocess import check_output\ncheck_output(['x'])",
                "subprocess.check_output",
            ),
            (
                "import subprocess\nsubprocess.getstatusoutput('x')",
                "subprocess.getstatusoutput",
            ),
            ("import subprocess\nrunner = subprocess.call", "subprocess.call"),
            (
                "def f():\n    import subprocess as s\n    s.check_call(['x'])",
                "subprocess.check_call",
            ),
            ("from os import system\nsystem('x')", "os.system"),
            ("from os import *\nsystem('x')", "os.system"),
            ("import os\nos.popen('x')", "os.popen"),
            ("import os\nos.fork()", "os.fork"),
            ("import os as o\no.forkpty()", "os.forkpty"),
            ("import os\nos.execvp('x', ['x'])", "os.execvp"),
            ("from os import execve\nexecve('x', ['x'], {})", "os.execve"),
            ("import os\nos.spawnlp(os.P_WAIT, 'x', 'x')", "os.spawnlp"),
            ("import os\nos.posix_spawn('x', ['x'], {})", "os.posix_spawn"),
            ("import os\nos.posix_spawnp('x', ['x'], {})", "os.posix_spawnp"),
            ("import pty\npty.spawn(['x'])", "pty.spawn"),
            (
                "import asyncio\nasyncio.create_subprocess_shell('x')",
                "asyncio.create_subprocess_shell",
            ),
            (
                "import asyncio\nasyncio.create_subprocess_exec('x')",
                "asyncio.create_subprocess_exec",
            ),
            (
                "from asyncio import create_subprocess_shell as c\nc('x')",
                "asyncio.create_subprocess_shell",
            ),
            (
                "from asyncio import subprocess as asp\n"
                "asp.create_subprocess_exec('x')",
                "asyncio.create_subprocess_exec",
            ),
            (
                "import asyncio.subprocess\n"
                "asyncio.subprocess.create_subprocess_shell('x')",
                "asyncio.create_subprocess_shell",
            ),
            ("loop.subprocess_exec(factory, 'x')", "<event loop>.subprocess_exec"),
            (
                "import asyncio\nasyncio.get_running_loop().subprocess_shell(f, 'x')",
                "<event loop>.subprocess_shell",
            ),
        ],
    )
    def test_spawn_reference_any_import_form_is_detected(
        self, source: str, expected: str
    ) -> None:
        assert [name for _, name in _spawn_references(source)] == [expected]

    @pytest.mark.parametrize(
        "source",
        [
            "import subprocess\nsubprocess.PIPE",
            "import asyncio\nasyncio.subprocess.DEVNULL\nasyncio.run(main())",
            "import asyncio\nprocess: asyncio.subprocess.Process",
            "def run():\n    pass\nrun()",
            "system('x')",
            "import os\nos.path.join('a', 'b')\nos.environ.get('x')\nos.killpg(1, 9)",
            "import shutil\nshutil.rmtree('x')",
            "class P:\n    def spawn(self):\n        pass\nP().spawn()",
            "from os import system\nsystem = None",
        ],
    )
    def test_non_spawning_source_is_not_detected(self, source: str) -> None:
        assert _spawn_references(source) == []

    def test_shell_keyword_other_than_false_is_detected(self) -> None:
        source = (
            "run('x', shell=True)\nrun('x', shell=flag)\nrun('x', shell=False)\nrun()"
        )
        assert _shell_keywords(source) == [1, 2]

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("import git", ["git"]),
            ("import git.repo as r", ["git.repo"]),
            ("from git import Repo", ["git"]),
            ("import pygit2", ["pygit2"]),
            ("from dulwich.repo import Repo", ["dulwich.repo"]),
            ("def f():\n    from dulwich import porcelain", ["dulwich"]),
            ("import gitlab\nimport github", []),
            ("from app.services import git_operations", []),
            ("from . import git", []),
        ],
    )
    def test_git_library_import_detection(
        self, source: str, expected: list[str]
    ) -> None:
        assert _git_library_imports(source) == expected


@pytest.mark.unit
class TestRequirementParsing:
    def test_declared_requirements_cover_every_dependency_list(self) -> None:
        pyproject = tomllib.loads(
            """
            [project]
            dependencies = ["a>=1"]
            [project.optional-dependencies]
            extra = ["b"]
            [dependency-groups]
            dev = ["c", {include-group = "other"}]
            [build-system]
            requires = ["d"]
            [tool.uv]
            dev-dependencies = ["e"]
            constraint-dependencies = ["f"]
            override-dependencies = ["g"]
            """
        )
        assert _declared_requirements(pyproject) == [
            "a>=1",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
        ]

    @pytest.mark.parametrize(
        ("requirement", "expected"),
        [
            ("GitPython>=3.1", "gitpython"),
            ("pygit2", "pygit2"),
            ("Dulwich[https] ; python_version > '3'", "dulwich"),
            ("git_python==1", "git-python"),
            ("  Example.Package_Name~=2", "example-package-name"),
        ],
    )
    def test_distribution_name_is_pep_503_normalized(
        self, requirement: str, expected: str
    ) -> None:
        assert _distribution_name(requirement) == expected


@pytest.mark.unit
class TestProcessSpawningBoundary:
    def test_process_spawning_references_occur_only_in_git_operations(self) -> None:
        found = {
            module: references
            for module, source in _app_sources().items()
            if (references := _spawn_references(source))
        }

        outside = {
            module: refs for module, refs in found.items() if module != GIT_OPERATIONS
        }
        assert not outside, (
            "Process-spawning references outside "
            f"{GIT_OPERATIONS} (Implementation Location): {outside}"
        )
        assert [name for _, name in found.get(GIT_OPERATIONS, [])] == ALLOWED_SPAWNS

    def test_no_module_passes_shell_argument(self) -> None:
        found = {
            module: lines
            for module, source in _app_sources().items()
            if (lines := _shell_keywords(source))
        }
        assert not found, f"shell= passed (Module Invariants, Rule 2): {found}"

    def test_no_module_imports_python_git_library(self) -> None:
        found = {
            module: imports
            for module, source in _app_sources().items()
            if (imports := _git_library_imports(source))
        }
        assert not found, f"Python Git library imported (Runtime Dependencies): {found}"

    def test_pyproject_declares_no_python_git_library(self) -> None:
        pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        names = {_distribution_name(item) for item in _declared_requirements(pyproject)}

        assert names
        assert not names & GIT_LIBRARY_DISTRIBUTIONS
