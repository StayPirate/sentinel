"""Registry pruning of the local process system suite's Celery launcher.

`tests/support/system_fetcher_app.py` is the `-A` app path of the spawned
worker and Beat processes (docs/features/platform/testing-strategy.md, Local
Process System Testing, Registration Boundary). Its import pulls in production
discovery, which fills both `FETCHER_REGISTRY` and `_CVE_SOURCE_TYPE_MAP`
(docs/features/platform/fetcher-infrastructure.md, Fetcher Discovery (Module
Import)). The launcher must leave exactly the test-only fetcher in the first
and no production CVE fetcher in the second: the two registries form one
registration unit (docs/features/platform/cve-fetcher-infrastructure.md,
`__init_subclass__` Validation), and a production CVE class left in the source
map would remain visible to `get_fetch_single_fetchers()` and
`get_all_cve_source_types()` in those processes.

A fresh interpreter imports the launcher exactly as `celery -A` does, so the
pytest process's own registries are never touched. Like the role startup-path
test (`tests/test_architecture/test_cve_fetcher_discovery_completeness.py`),
the child refuses outbound connections and receives an explicit minimal
environment with a temporary working directory, so neither the developer's
shell configuration nor `backend/.env` is in scope.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Final

import pytest

_BACKEND_DIR: Final = Path(__file__).resolve().parents[2]

_INHERITED_OS_ENV_KEYS: Final = ("PATH", "LANG", "LC_ALL", "TZ")
# Fictional JWT secret — never a real credential (AGENTS.md Guardrail 23).
_JWT_SECRET_KEY: Final = "system-launcher-test-jwt-secret-key-not-for-production"

_RESULT_PREFIX: Final = "LAUNCHER-REGISTRIES="

_PROBE_SCRIPT: Final = f"""\
import json
import socket
import sys


def _refuse(*args, **kwargs):
    raise AssertionError("importing the launcher opened a connection")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.create_connection = _refuse

import tests.support.system_fetcher_app

from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import FETCHER_REGISTRY


def _qualified(cls):
    return f"{{cls.__module__}}.{{cls.__qualname__}}"


result = {{
    "discovery_imported": "app.services.fetcher_discovery" in sys.modules,
    "fetcher_registry": {{
        name: _qualified(cls) for name, cls in FETCHER_REGISTRY.items()
    }},
    "cve_source_type_map": {{
        source.value: _qualified(cls) for source, cls in _CVE_SOURCE_TYPE_MAP.items()
    }},
    "fetch_single_fetchers": sorted(get_fetch_single_fetchers()),
    "all_cve_source_types": sorted(get_all_cve_source_types()),
}}
print("{_RESULT_PREFIX}" + json.dumps(result))
"""


def _probe_env(home: Path) -> dict[str, str]:
    """OS context plus the one required setting; `cwd` is `home`, so the
    relative `backend/.env` is never read."""
    env = {key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ}
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(_BACKEND_DIR)
    env["JWT_SECRET_KEY"] = _JWT_SECRET_KEY
    return env


def _launcher_registries(tmp_path: Path) -> dict[str, Any]:
    """Import the launcher in a fresh interpreter and return its registries."""
    result = subprocess.run(
        [sys.executable, "-c", _PROBE_SCRIPT],
        cwd=tmp_path,
        env=_probe_env(tmp_path),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = [
        line.removeprefix(_RESULT_PREFIX)
        for line in result.stdout.splitlines()
        if line.startswith(_RESULT_PREFIX)
    ]
    assert len(lines) == 1, result.stdout + result.stderr
    registries: dict[str, Any] = json.loads(lines[0])
    return registries


@pytest.mark.unit
def test_launcher_import_prunes_both_registries_to_the_test_fetcher(
    tmp_path: Path,
) -> None:
    registries = _launcher_registries(tmp_path)

    # Production discovery ran, so an empty source map proves pruning
    # rather than an import path that never registered anything.
    assert registries["discovery_imported"] is True
    assert registries["fetcher_registry"] == {
        "evaluate_test_pipeline": "tests.support.system_fetcher.EvaluateTestPipeline"
    }
    assert registries["cve_source_type_map"] == {}
    assert registries["fetch_single_fetchers"] == []
    assert registries["all_cve_source_types"] == []
