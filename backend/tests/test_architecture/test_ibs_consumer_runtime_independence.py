"""Structural test: the IBS RabbitMQ consumer process never loads the Celery
application, a task module, fetcher discovery, Redbeat, or a concrete
fetcher, and never populates the fetcher registry.

See docs/features/integrations/ibs-rabbitmq-integration.md (Runtime
Independence), docs/deployment.md (Singleton Processes), and
docs/features/platform/testing-strategy.md (Structural Tests: IBS consumer
runtime independence).

A fresh interpreter imports the unmodified entry module `app.ibs_consumer`
(the module `python -m app.ibs_consumer` runs) with outbound connections
refused and an explicit minimal environment, and reports every loaded
module and the registry contents. The concrete fetcher modules are the
imports of `app/services/fetcher_discovery.py`, read from its source, so a
new fetcher is covered without editing this test. The self-test repeats the
probe with one forbidden import added and proves each kind is detected.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Final

import pytest

from tests.support.module_imports import APP_ROOT

pytestmark = pytest.mark.unit

_BACKEND_DIR: Final = APP_ROOT.parent
_DISCOVERY: Final = APP_ROOT / "services" / "fetcher_discovery.py"
_INHERITED_OS_ENV_KEYS: Final = ("PATH", "LANG", "LC_ALL", "TZ")
# Fictional JWT secret — never a real credential (AGENTS.md Guardrail 23).
_JWT_SECRET_KEY: Final = "consumer-test-jwt-secret-key-not-for-production"

_PROBE: Final = """\
import json
import socket
import sys


def _refuse(*args, **kwargs):
    raise AssertionError("importing the entry module opened a connection")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.create_connection = _refuse

import app.ibs_consumer
{extra}
from app.services.base_fetcher import FETCHER_REGISTRY

report = {{"modules": sorted(sys.modules), "registry": sorted(FETCHER_REGISTRY)}}
print(json.dumps(report))
"""


def _concrete_fetcher_modules() -> set[str]:
    """Every module `fetcher_discovery.py` imports for registration."""
    tree = ast.parse(_DISCOVERY.read_text("utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)
    return {module for module in modules if module.startswith("app.services.")}


def _forbidden(modules: list[str]) -> list[str]:
    concrete = _concrete_fetcher_modules()
    return sorted(
        module
        for module in modules
        if module == "app.celery_app"
        or module == "app.tasks"
        or module.startswith("app.tasks.")
        or module == "app.services.fetcher_discovery"
        or module == "redbeat"
        or module.startswith("redbeat.")
        or module in concrete
    )


def _probe(tmp_path: Path, extra: str = "") -> dict[str, Any]:
    env = {key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ}
    env.update(
        HOME=str(tmp_path),
        PYTHONPATH=str(_BACKEND_DIR),
        JWT_SECRET_KEY=_JWT_SECRET_KEY,
    )
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(extra=extra)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    report: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    return report


def test_discovery_lists_concrete_fetcher_modules() -> None:
    concrete = _concrete_fetcher_modules()

    assert "app.services.packages.detect_ibs_track_releases" in concrete
    assert "app.services.packages.sync_ibs_requests" in concrete


def test_entry_module_loads_no_celery_application_or_fetcher(tmp_path: Path) -> None:
    report = _probe(tmp_path)

    assert _forbidden(report["modules"]) == []
    assert report["registry"] == []
    assert "app.services.ibs_event_consumer" in report["modules"]
    assert "app.services.packages.ibs_event_handlers" in report["modules"]
    assert not [m for m in report["modules"] if m == "tests" or m.startswith("tests.")]


@pytest.mark.parametrize(
    ("extra", "detected"),
    [
        ("import app.celery_app", "app.celery_app"),
        ("import app.tasks.fetchers", "app.tasks.fetchers"),
        ("import app.services.fetcher_discovery", "app.services.fetcher_discovery"),
        ("import redbeat", "redbeat"),
        (
            "import app.services.packages.detect_ibs_track_releases",
            "app.services.packages.detect_ibs_track_releases",
        ),
    ],
)
def test_probe_detects_each_forbidden_import(
    tmp_path: Path, extra: str, detected: str
) -> None:
    report = _probe(tmp_path, extra)

    assert detected in _forbidden(report["modules"])
