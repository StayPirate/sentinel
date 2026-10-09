"""OCI artifact probes for the Git worker role.

Focused tests own Git operation, routing, and fetcher behavior. These checks
verify only the artifact facts of the role: the packaged git binary meets the
documented minimum, the clone volume is writable by the non-root runtime user,
and the documented command starts a node that consumes only the `git` queue.
No probe clones an external repository.

See ``docs/features/platform/testing-strategy.md`` (Artifact-Risk Rule) and
``docs/features/platform/git-fetcher-infrastructure.md`` (Runtime
Dependencies, Worker Affinity).
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

_MINIMUM_GIT_VERSION = (2, 30)
_GIT_VERSION_PATTERN = re.compile(r"git version (\d+)\.(\d+)")

_CLONE_DIRECTORY_PROBE_SCRIPT = """
import os
import shutil
import tempfile
from pathlib import Path

base = Path("/var/lib/sentinel/git")
assert base.is_dir(), f"{base} is not a directory"
assert os.path.ismount(base), f"{base} is not the mounted clone volume"
assert base.stat().st_uid == os.getuid(), (base.stat().st_uid, os.getuid())
probe = Path(tempfile.mkdtemp(prefix="image-smoke-", dir=base))
try:
    (probe / "probe").write_bytes(b"probe")
finally:
    shutil.rmtree(probe)
assert not probe.exists(), f"{probe} was not removed"
print("CLONE-DIRECTORY-OK")
"""


@pytest.mark.image
def test_git_worker_runs_supported_git_as_non_root(
    compose_exec: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    user = compose_exec("git-worker", "id", "-u")
    assert user.returncode == 0, user.stderr
    assert user.stdout.strip() != "0", "git worker executes as root"

    result = compose_exec("git-worker", "git", "--version")
    assert result.returncode == 0, (
        f"git --version failed (stdout={result.stdout!r}, stderr={result.stderr!r})"
    )
    match = _GIT_VERSION_PATTERN.match(result.stdout.strip())
    assert match is not None, f"unparseable git version: {result.stdout!r}"
    version = (int(match.group(1)), int(match.group(2)))
    assert version >= _MINIMUM_GIT_VERSION, (
        f"git {version} is older than the documented minimum {_MINIMUM_GIT_VERSION}"
    )


@pytest.mark.image
def test_git_worker_clone_volume_is_writable_by_runtime_user(
    compose_exec: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    result = compose_exec("git-worker", "python", "-c", _CLONE_DIRECTORY_PROBE_SCRIPT)
    assert result.returncode == 0, (
        f"clone directory probe failed (stdout={result.stdout!r}, "
        f"stderr={result.stderr!r})"
    )
    assert "CLONE-DIRECTORY-OK" in result.stdout


@pytest.mark.image
def test_git_worker_registers_tasks_and_consumes_only_git_queue(
    celery_node_inspect: Callable[[str, str, str], Any],
) -> None:
    registered_tasks = celery_node_inspect("git-worker", "git", "registered")
    for task in ("run_fetcher", "fetch_single_cve", "run_catch_up"):
        assert task in registered_tasks, f"{task} is not registered"

    queues = celery_node_inspect("git-worker", "git", "active_queues")
    assert {queue["name"] for queue in queues} == {"git"}, queues


@pytest.mark.image
def test_general_worker_does_not_consume_git_queue(
    celery_node_inspect: Callable[[str, str, str], Any],
) -> None:
    queues = celery_node_inspect("worker", "celery", "active_queues")
    assert {queue["name"] for queue in queues} == {"celery"}, queues
