"""Tests for the hermetic Git environment of the test harness
(tests/support/git_repos.py).

Git's automatic maintenance, which `git commit`, `git merge`, and
`git fetch` start as a detached `git maintenance run --auto`, can outlive
the test and repack a temporary repository while the test inspects it;
`docs/features/platform/testing-strategy.md` (Tier 1 — Unit Tests) forbids
both. The trace2 event stream (`GIT_TRACE2_EVENT`) shows whether a Git
process started that child, independently of Git's maintenance thresholds.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.support.git_repos import (
    HERMETIC_GIT_CONFIG,
    automatic_maintenance_runs,
    commit_files,
    foreground_maintenance_config,
    git,
    hermetic_git_env,
    init_upstream,
    isolate_process_environment,
    traced_commands,
)

pytestmark = pytest.mark.unit

# What a Git hook exports to the test suite it runs.
_HOOK_VARIABLES = {
    "GIT_DIR": "/example/invoking/.git",
    "GIT_INDEX_FILE": "/example/invoking/.git/index",
    "GIT_CONFIG_PARAMETERS": "'maintenance.auto'='true'",
    "GIT_CONFIG_GLOBAL": "/example/home/.gitconfig",
}


def _commit_ready(tmp_path: Path) -> Path:
    return init_upstream(tmp_path / "repo")


def _merge_ready(tmp_path: Path) -> Path:
    """A repository whose branch `topic` diverged from `main`."""
    repo = init_upstream(tmp_path / "repo")
    commit_files(repo, {"base": b"base\n"})
    git(repo, "switch", "--quiet", "-c", "topic")
    commit_files(repo, {"topic": b"topic\n"})
    git(repo, "switch", "--quiet", "main")
    commit_files(repo, {"main": b"main\n"})
    return repo


def _fetch_ready(tmp_path: Path) -> Path:
    """A bare clone whose upstream has one commit the clone lacks."""
    upstream = init_upstream(tmp_path / "upstream")
    commit_files(upstream, {"README": b"initial\n"})
    clone = tmp_path / "clone.git"
    git(None, "clone", "--quiet", "--bare", "--", upstream.as_uri(), str(clone))
    commit_files(upstream, {"README": b"updated\n"})
    return clone


_WRITE_COMMANDS: dict[str, tuple[Callable[[Path], Path], tuple[str, ...]]] = {
    "commit": (_commit_ready, ("commit", "--quiet", "--allow-empty", "-m", "x")),
    "merge": (_merge_ready, ("merge", "--quiet", "--no-ff", "--no-edit", "topic")),
    "fetch": (_fetch_ready, ("fetch", "--quiet", "origin", "+HEAD:refs/heads/main")),
}


@pytest.mark.parametrize("command", list(_WRITE_COMMANDS))
@pytest.mark.parametrize(
    ("configuration", "expected_runs"),
    [
        pytest.param("hermetic", 0, id="hermetic"),
        # Control: with Git's default, the same command starts maintenance.
        pytest.param("git-default", 1, id="git-default"),
    ],
)
def test_write_command_automatic_maintenance_follows_global_configuration(
    tmp_path: Path, command: str, configuration: str, expected_runs: int
) -> None:
    arrange, args = _WRITE_COMMANDS[command]
    repo = arrange(tmp_path)
    trace = tmp_path / "trace.json"
    env_extra = {"GIT_TRACE2_EVENT": str(trace)}
    if configuration == "git-default":
        env_extra["GIT_CONFIG_GLOBAL"] = str(foreground_maintenance_config(tmp_path))

    git(repo, *args, env_extra=env_extra)

    assert traced_commands(trace)[0][1] == command
    assert len(automatic_maintenance_runs(trace)) == expected_runs


def test_hermetic_git_env_inherited_git_variables_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _HOOK_VARIABLES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SENTINEL_EXAMPLE_UNRELATED", "kept")

    env = hermetic_git_env()

    assert {"GIT_DIR", "GIT_INDEX_FILE", "GIT_CONFIG_PARAMETERS"}.isdisjoint(env)
    assert env["GIT_CONFIG_GLOBAL"] == str(HERMETIC_GIT_CONFIG)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["SENTINEL_EXAMPLE_UNRELATED"] == "kept"


def test_isolate_process_environment_inherited_git_variables_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _HOOK_VARIABLES.items():
        monkeypatch.setenv(name, value)

    isolate_process_environment(monkeypatch)

    git_variables = {
        name: value for name, value in os.environ.items() if name.startswith("GIT_")
    }
    assert git_variables == {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(HERMETIC_GIT_CONFIG),
    }
