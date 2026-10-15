"""Structural test: production discovery is complete for every CVE source in
the startup path of every fetcher-registry process role, and every process
role command loads its production entry module.

See `docs/features/platform/cve-fetcher-infrastructure.md` (`__init_subclass__`
Validation, "Uniqueness tracking — `_CVE_SOURCE_TYPE_MAP`"),
`docs/features/platform/testing-strategy.md` (CVE Fetcher Infrastructure,
Discovery completeness; Structural Tests; Parallel Execution), and
`docs/features/platform/fetcher-infrastructure.md` (Fetcher Discovery (Module
Import); Startup Validation).

Missing members and test-only classes are test failures, not runtime startup
checks. The proof has three parts:

- Startup paths: for each of the API, general-worker, Git-worker, and Beat
  roles, a fresh interpreter imports the unmodified production entry module
  (`app.main` for uvicorn, `app.celery_app` for every Celery role; `-Q git`
  changes queue consumption, not imports) with outbound connections refused
  and an explicit minimal environment (testing-strategy.md, Registration
  Boundary: no inherited shell or `.env` configuration). It then checks that
  no `tests` module was loaded and applies `assert_complete_cve_discovery()`
  (`tests/support/cve_discovery.py`) to the live registries.
- Role commands: the Dockerfile CMD, the smoke Compose service commands, and
  every `uvicorn <module>:`, `celery -A <module>`, and `python -m app.<module>`
  occurrence in `docs/deployment.md` name those entry modules, and together
  cover all five roles. The IBS RabbitMQ consumer (`python -m
  app.ibs_consumer`) is a role without the fetcher registry, so it has no
  startup-path discovery proof; its import boundary is enforced by
  `test_ibs_consumer_runtime_independence.py`. A `python -m app.cli` command
  is a CLI invocation, not a role command. The document is read for command
  spelling only, never for its shape.
- Helper self-test: manipulated copies of the registries, and one test-only
  fetcher registered under `isolated_fetcher_registries`, prove each check
  fails; the production registries pass.

The drift test (`tests/test_services/test_fetcher_discovery.py`) separately
proves `fetcher_discovery.py` imports every concrete fetcher module.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.fetcher_discovery  # noqa: F401 — production discovery
from app.core.enums import CVESourceType
from app.services.base_cve_fetcher import _CVE_SOURCE_TYPE_MAP, BaseCVEFetcher
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from tests.support.cve_discovery import assert_complete_cve_discovery
from tests.support.module_imports import APP_ROOT

_BACKEND_DIR: Final = APP_ROOT.parent
_REPOSITORY_ROOT: Final = _BACKEND_DIR.parent

_ROLE_TARGETS: Final = {
    "api": "app.main:app",
    "worker": "app.celery_app",
    "git-worker": "app.celery_app",
    "beat": "app.celery_app",
}
"""The production entry target each fetcher-registry process role loads."""

_CONSUMER_ROLE: Final = "ibs-consumer"
_CONSUMER_TARGET: Final = "app.ibs_consumer"
"""The entry module of the IBS RabbitMQ consumer, a role without the fetcher
registry (not part of the startup-path discovery proof)."""

# ---------------------------------------------------------------------------
# Startup paths
# ---------------------------------------------------------------------------

_INHERITED_OS_ENV_KEYS: Final = ("PATH", "LANG", "LC_ALL", "TZ")
# Fictional JWT secret — never a real credential (AGENTS.md Guardrail 23).
_JWT_SECRET_KEY: Final = "discovery-test-jwt-secret-key-not-for-production"

_ROLE_SCRIPT: Final = """\
import socket
import sys


def _refuse(*args, **kwargs):
    raise AssertionError("importing the entry module opened a connection")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.create_connection = _refuse

import {module}

loaded = sorted(m for m in sys.modules if m == "tests" or m.startswith("tests."))
assert not loaded, f"the production entry module loaded test modules: {{loaded}}"
assert "app.services.fetcher_discovery" in sys.modules, "no discovery import"

from app.services.base_cve_fetcher import _CVE_SOURCE_TYPE_MAP
from app.services.base_fetcher import FETCHER_REGISTRY
from tests.support.cve_discovery import assert_complete_cve_discovery

assert_complete_cve_discovery(_CVE_SOURCE_TYPE_MAP, FETCHER_REGISTRY)
print("CVE-DISCOVERY-COMPLETE")
"""


def _entry_process_env(home: Path) -> dict[str, str]:
    """OS context plus the one required setting; `cwd` is `home`, so the
    relative `backend/.env` is never read."""
    env = {key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ}
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(_BACKEND_DIR)
    env["JWT_SECRET_KEY"] = _JWT_SECRET_KEY
    return env


@pytest.mark.unit
class TestRoleStartupPaths:
    @pytest.mark.parametrize("role", list(_ROLE_TARGETS))
    def test_entry_module_import_discovers_every_cve_source(
        self, role: str, tmp_path: Path
    ) -> None:
        module = _ROLE_TARGETS[role].partition(":")[0]

        result = subprocess.run(
            [sys.executable, "-c", _ROLE_SCRIPT.format(module=module)],
            cwd=tmp_path,
            env=_entry_process_env(tmp_path),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

        assert result.returncode == 0, f"{role} ({module}):\n{result.stderr}"
        assert "CVE-DISCOVERY-COMPLETE" in result.stdout


# ---------------------------------------------------------------------------
# Role commands
# ---------------------------------------------------------------------------

_UVICORN_COMMAND: Final = re.compile(r"(?<![\w-])uvicorn\s+(?P<target>[\w.]+:\w+)")
_CELERY_COMMAND: Final = re.compile(
    r"(?<![\w-])celery\s+-A\s+(?P<app>[\w.]+)\s+(?P<subcommand>[\w-]+)"
    r"(?P<options>(?:\s+-[^\s`]+(?:\s+[^\s`#-][^\s`]*)?)*)"
)
_CELERY_WITHOUT_APP: Final = re.compile(r"(?<![\w-])celery\s+(?:worker|beat)\b")
# `python -m app.cli ...` runs the operator CLI, not a process role.
_PYTHON_MODULE_COMMAND: Final = re.compile(
    r"(?<![\w-])python\s+-m\s+(?P<module>(?!app\.cli\b)app(?:\.\w+)+)"
)
_FENCED_BLOCK: Final = re.compile(
    r"^[ \t]*```[^\n]*\n(.*?)^[ \t]*```", re.MULTILINE | re.DOTALL
)
_CODE_SPAN: Final = re.compile(r"`([^`]+)`")

_SERVICE_INDENT: Final = 2
_PROPERTY_INDENT: Final = 4


def command_role(argv: Sequence[str]) -> tuple[str, str | None]:
    """The entry target and process role of one `uvicorn`, `celery`, or
    `python -m` command; the role is `None` for any other Celery command."""
    if argv[0] == "uvicorn":
        return argv[1], "api"
    if argv[0] == "python" and len(argv) >= 3 and argv[1] == "-m":
        return argv[2], _CONSUMER_ROLE
    if argv[0] == "celery" and "-A" in argv[:-2]:
        index = argv.index("-A")
        target, subcommand = argv[index + 1], argv[index + 2]
        queues = tuple(
            argv[i + 1] for i, token in enumerate(argv[:-1]) if token == "-Q"
        )
        if subcommand == "worker":
            return target, {(): "worker", ("git",): "git-worker"}.get(queues)
        return target, "beat" if subcommand == "beat" and not queues else None
    msg = f"not a uvicorn, celery -A, or python -m command: {list(argv)}"
    raise ValueError(msg)


def _assert_production_targets(commands: Sequence[Sequence[str]]) -> set[str]:
    """Every command names its production entry target; returns the roles."""
    roles: set[str] = set()
    for argv in commands:
        target, role = command_role(argv)
        expected = {
            "uvicorn": _ROLE_TARGETS["api"],
            "celery": _ROLE_TARGETS["worker"],
            "python": _CONSUMER_TARGET,
        }[argv[0]]
        assert target == expected, f"{shlex.join(argv)!r} does not load {expected}"
        if role is not None:
            roles.add(role)
    return roles


def _dockerfile_cmd() -> list[str]:
    lines = (_BACKEND_DIR / "Dockerfile").read_text(encoding="utf-8").splitlines()
    cmd = [line.removeprefix("CMD ") for line in lines if line.startswith("CMD ")]
    assert cmd, "backend/Dockerfile declares no CMD"
    return cast(list[str], json.loads(cmd[-1]))


def _command_argv(value: str) -> list[str]:
    """A Compose `command`: a flow sequence of quoted strings, or a string."""
    if value.startswith("["):
        return [str(item) for item in ast.literal_eval(value)]
    return shlex.split(value)


def _compose_commands(path: Path) -> dict[str, list[str] | None]:
    """The `command` of every service under `services:` (`None` when the
    service keeps the image CMD), read with a minimal indentation scanner,
    as `tests/test_architecture/test_workflow_timeouts.py` does, because
    PyYAML is not a declared dependency."""
    values: dict[str, list[str] | None] = {}
    in_services = False
    service: str | None = None
    parts: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_services = stripped == "services:"
            service = parts = None
            continue
        if not in_services:
            continue
        if indent == _SERVICE_INDENT and stripped.endswith(":"):
            service, parts = stripped.removesuffix(":"), None
            values[service] = None
        elif service is not None and indent == _PROPERTY_INDENT:
            key, _, rest = stripped.partition(":")
            parts = [rest.strip()] if key == "command" else None
            if parts is not None:
                values[service] = parts
        elif parts is not None and indent > _PROPERTY_INDENT:
            parts.append(stripped)
    return {
        name: None if value is None else _command_argv(" ".join(value).strip())
        for name, value in values.items()
    }


def _code_fragments(text: str) -> list[str]:
    """The fenced code blocks and inline code spans of a Markdown text: the
    only places where a command, rather than prose, is written."""
    prose = _FENCED_BLOCK.sub("", text)
    return [*_FENCED_BLOCK.findall(text), *_CODE_SPAN.findall(prose)]


def _celery_commands_without_app(text: str) -> list[str]:
    """Every `celery worker`/`celery beat` command without `-A`, in code."""
    return [
        match
        for fragment in _code_fragments(text)
        for match in _CELERY_WITHOUT_APP.findall(fragment)
    ]


def _deployment_commands(text: str) -> list[list[str]]:
    """Every `uvicorn <module>:<app>`, `celery -A <module> ...`, and
    `python -m app.<module>` occurrence other than the CLI, wherever it
    appears in the document."""
    commands = [["uvicorn", m["target"]] for m in _UVICORN_COMMAND.finditer(text)]
    commands += [
        ["celery", "-A", m["app"], m["subcommand"], *m["options"].split()]
        for m in _CELERY_COMMAND.finditer(text)
    ]
    commands += [
        ["python", "-m", m["module"]] for m in _PYTHON_MODULE_COMMAND.finditer(text)
    ]
    return commands


@pytest.mark.unit
class TestRoleCommands:
    def test_command_role_classifies_each_role(self) -> None:
        assert command_role(["uvicorn", "app.main:app", "--port", "8000"]) == (
            "app.main:app",
            "api",
        )
        assert command_role(shlex.split("celery -A x worker --pool=prefork")) == (
            "x",
            "worker",
        )
        assert command_role(shlex.split("celery -A x worker -Q git -n git@%h")) == (
            "x",
            "git-worker",
        )
        assert command_role(shlex.split("celery -A x beat")) == ("x", "beat")
        assert command_role(shlex.split("celery -A x worker -Q other")) == ("x", None)
        assert command_role(shlex.split("celery -A x inspect ping")) == ("x", None)
        assert command_role(["python", "-m", "app.ibs_consumer"]) == (
            "app.ibs_consumer",
            "ibs-consumer",
        )
        with pytest.raises(ValueError, match="not a uvicorn, celery -A, or python -m"):
            command_role(["alembic", "upgrade", "head"])

    def test_dockerfile_cmd_runs_the_api_entry_module(self) -> None:
        argv = _dockerfile_cmd()

        assert command_role(argv) == (_ROLE_TARGETS["api"], "api")

    def test_smoke_compose_roles_load_the_production_entry_modules(self) -> None:
        commands = _compose_commands(_REPOSITORY_ROOT / "docker-compose.smoke.yml")

        assert "api" in commands
        assert commands["api"] is None, "api must keep the Dockerfile CMD"
        for role in ("worker", "git-worker", "beat"):
            argv = commands[role]
            assert argv is not None, f"{role} declares no command"
            assert command_role(argv) == (_ROLE_TARGETS[role], role)
        assert commands[_CONSUMER_ROLE] == ["python", "-m", _CONSUMER_TARGET]
        process_commands = [
            argv
            for argv in commands.values()
            if argv is not None and argv[0] in {"uvicorn", "celery", "python"}
        ]
        assert _assert_production_targets(process_commands) == {
            "worker",
            "git-worker",
            "beat",
            _CONSUMER_ROLE,
        }

    def test_deployment_doc_role_commands_load_the_production_entry_modules(
        self,
    ) -> None:
        text = (_REPOSITORY_ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")

        roles = _assert_production_targets(_deployment_commands(text))

        assert roles >= {*_ROLE_TARGETS, _CONSUMER_ROLE}
        assert _celery_commands_without_app(text) == []

    def test_command_without_app_is_found_only_in_code(self) -> None:
        """Prose mentioning a Celery worker is not a command."""
        text = (
            "A celery worker restarts after a crash.\n"
            "Start it with `celery worker --pool=prefork`.\n"
            "```bash\nuv run celery beat\n```\n"
        )

        assert sorted(_celery_commands_without_app(text)) == [
            "celery beat",
            "celery worker",
        ]

    def test_deployment_extraction_is_lenient_about_document_shape(self) -> None:
        """Commands are found in code blocks and in prose, including an
        inline code span that wraps across lines."""
        text = (
            "```bash\ncd backend && uv run uvicorn app.main:app --reload\n"
            "uv run celery -A app.celery_app worker --pool=prefork\n"
            "# Start Beat\nuv run celery -A app.celery_app beat\n"
            "cd backend && uv run python -m app.ibs_consumer\n"
            "cd backend && uv run python -m app.cli manage-user create \\\n```\n"
            "The Git worker is started as `celery -A app.celery_app worker\n"
            "-Q git --pool=prefork -n git@%h` and consumes only `git`.\n"
            "The consumer is started as `python\n-m app.ibs_consumer` (entry\n"
            "module), never as `python -m app.cli`.\n"
            "| API server (uvicorn) | HTTP |\n"
        )

        assert [command_role(argv) for argv in _deployment_commands(text)] == [
            ("app.main:app", "api"),
            ("app.celery_app", "worker"),
            ("app.celery_app", "beat"),
            ("app.celery_app", "git-worker"),
            ("app.ibs_consumer", "ibs-consumer"),
            ("app.ibs_consumer", "ibs-consumer"),
        ]

    def test_a_non_production_entry_module_is_rejected(self) -> None:
        commands = _deployment_commands("`celery -A tests.support.example worker`")

        with pytest.raises(AssertionError, match=r"does not load app\.celery_app"):
            _assert_production_targets(commands)

    def test_a_wrong_consumer_entry_module_is_rejected(self) -> None:
        commands = _deployment_commands("`uv run python -m app.consumer`")

        assert commands == [["python", "-m", "app.consumer"]]
        with pytest.raises(AssertionError, match=r"does not load app\.ibs_consumer"):
            _assert_production_targets(commands)


# ---------------------------------------------------------------------------
# Helper self-test
# ---------------------------------------------------------------------------


class _TestOnlyNvdFetcher:
    """A test-only stand-in owner; a plain class, so defining it registers
    nothing."""

    name = "sync_nvd_cves"
    cve_source_type = CVESourceType.NVD


def _production_copies() -> tuple[dict[CVESourceType, type], dict[str, type]]:
    return dict(_CVE_SOURCE_TYPE_MAP), dict(FETCHER_REGISTRY)


@pytest.mark.unit
class TestDiscoveryAssertion:
    def test_production_registries_pass(self) -> None:
        assert_complete_cve_discovery(_CVE_SOURCE_TYPE_MAP, FETCHER_REGISTRY)

    def test_missing_member_fails(self) -> None:
        source_map, registry = _production_copies()
        del source_map[CVESourceType.EPSS]

        with pytest.raises(AssertionError, match=r"CVESourceType\.EPSS has no owner"):
            assert_complete_cve_discovery(source_map, registry)

    def test_unknown_key_fails(self) -> None:
        """`CVESourceType` is a `StrEnum`, so only a string equal to no
        member is a distinct extra key."""
        source_map, registry = _production_copies()
        unknown = cast(dict[object, type], source_map)
        unknown["example"] = source_map[CVESourceType.NVD]

        with pytest.raises(AssertionError, match="unknown source key 'example'"):
            assert_complete_cve_discovery(source_map, registry)

    def test_test_only_owner_fails(self) -> None:
        assert _TestOnlyNvdFetcher.__module__.startswith("tests.")
        source_map, registry = _production_copies()
        source_map[CVESourceType.NVD] = _TestOnlyNvdFetcher
        registry["sync_nvd_cves"] = _TestOnlyNvdFetcher

        with pytest.raises(AssertionError) as raised:
            assert_complete_cve_discovery(source_map, registry)

        message = str(raised.value)
        assert "is not under app.services.tickets." in message
        assert "_TestOnlyNvdFetcher in _CVE_SOURCE_TYPE_MAP" in message
        assert "_TestOnlyNvdFetcher in FETCHER_REGISTRY" in message

    def test_test_only_class_only_in_the_fetcher_registry_fails(self) -> None:
        source_map, registry = _production_copies()
        registry["sync_example_records"] = _TestOnlyNvdFetcher

        with pytest.raises(AssertionError) as raised:
            assert_complete_cve_discovery(source_map, registry)

        assert str(raised.value).endswith("_TestOnlyNvdFetcher in FETCHER_REGISTRY")

    @pytest.mark.parametrize("change", ["absent", "other-class"])
    def test_owner_not_registered_under_its_name_fails(self, change: str) -> None:
        source_map, registry = _production_copies()
        if change == "absent":
            del registry["sync_nvd_cves"]
        else:
            registry["sync_nvd_cves"] = source_map[CVESourceType.GHSA]

        with pytest.raises(AssertionError, match=r"is not FETCHER_REGISTRY\['sync_nvd"):
            assert_complete_cve_discovery(source_map, registry)

    def test_abstract_owner_fails(self) -> None:
        """An intermediate class declaring `abstract = True` in its own body
        is never registered; as an owner it is not a concrete class."""
        abstract_owner = type(
            "SyncAbstractExample",
            (BaseCVEFetcher,),
            {
                "abstract": True,
                "__module__": "app.services.tickets.example",
                "cve_source_type": CVESourceType.NVD,
                "name": "sync_nvd_cves",
            },
        )
        source_map, registry = _production_copies()
        source_map[CVESourceType.NVD] = abstract_owner
        registry["sync_nvd_cves"] = abstract_owner

        with pytest.raises(AssertionError) as raised:
            assert_complete_cve_discovery(source_map, registry)

        assert str(raised.value).endswith(
            "owner app.services.tickets.example.SyncAbstractExample is not concrete"
        )

    def test_owner_of_another_source_fails(self) -> None:
        source_map, registry = _production_copies()
        source_map[CVESourceType.NVD] = source_map[CVESourceType.GHSA]

        with pytest.raises(AssertionError, match="does not declare that source"):
            assert_complete_cve_discovery(source_map, registry)

    @pytest.mark.usefixtures("isolated_fetcher_registries")
    def test_test_only_fetcher_in_the_live_registry_fails(self) -> None:
        async def execute(self: BaseFetcher, session: AsyncSession) -> None:
            return None

        type(
            "SyncExampleRecords",
            (BaseFetcher,),
            {
                "name": "sync_example_records",
                "description": "Test-only fetcher",
                "default_schedule": "0 * * * *",
                "execute": execute,
            },
        )

        with pytest.raises(AssertionError, match="SyncExampleRecords in FETCHER"):
            assert_complete_cve_discovery(_CVE_SOURCE_TYPE_MAP, FETCHER_REGISTRY)
