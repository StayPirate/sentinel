"""Hermetic temporary Git repositories for the Git operations tests.

Every Git command of a test runs against a temporary repository with no
inherited `GIT_*` variable, no user or system Git configuration, and Git's
automatic maintenance disabled (see
`docs/features/platform/testing-strategy.md`, Tier 1 — Unit Tests). The Git
hooks run the suite inside a real Git command, which exports variables such
as `GIT_DIR` and `GIT_INDEX_FILE`; inherited, they would redirect the
temporary repository's commands to the invoking repository. The global
configuration `hermetic.gitconfig` replaces the user's: `git commit`,
`git merge`, and `git fetch` would otherwise start a detached
`git maintenance run --auto` that outlives the test and can repack the
repository while the test inspects it.

The helpers here prepare test state only (upstream repositories, commits,
deliberate damage) and observe the trace2 event stream of Git processes;
the module under test starts its own processes.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

AUTHOR_NAME = "Example Author"
AUTHOR_EMAIL = "author@example.invalid"

HERMETIC_GIT_CONFIG = Path(__file__).with_name("hermetic.gitconfig")
"""The global Git configuration of every hermetic Git process: it disables
Git's automatic maintenance."""

_HERMETIC_CONFIG = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": str(HERMETIC_GIT_CONFIG),
}

_IDENTITY = {
    "GIT_AUTHOR_NAME": AUTHOR_NAME,
    "GIT_AUTHOR_EMAIL": AUTHOR_EMAIL,
    "GIT_COMMITTER_NAME": AUTHOR_NAME,
    "GIT_COMMITTER_EMAIL": AUTHOR_EMAIL,
}


def hermetic_git_env() -> dict[str, str]:
    """The current environment without any `GIT_*` variable, plus the
    hermetic global configuration instead of the user and system ones, a
    fictional identity, and the C locale."""
    inherited = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    return inherited | _HERMETIC_CONFIG | _IDENTITY | {"LC_ALL": "C"}


def isolate_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make processes started by the code under test hermetic: remove every
    inherited `GIT_*` variable from `os.environ` and replace the user and
    system Git configuration with the hermetic one, which the module's own
    environment filter keeps (restored by `monkeypatch` after the test)."""
    for name in [name for name in os.environ if name.startswith("GIT_")]:
        monkeypatch.delenv(name)
    for name, value in _HERMETIC_CONFIG.items():
        monkeypatch.setenv(name, value)


def git(
    cwd: Path | None,
    *args: str,
    env_extra: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run one hermetic setup Git command; raise on failure when `check`."""
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=hermetic_git_env() | dict(env_extra or {}),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        check=check,
    )


def rev_parse(git_dir: Path, rev: str) -> str:
    """The object name of `rev` in the repository at `git_dir`."""
    return git(
        None, f"--git-dir={git_dir}", "rev-parse", "--verify", rev
    ).stdout.strip()


def init_upstream(path: Path, *, branch: str = "main") -> Path:
    """An empty work-tree repository at `path` whose branch is `branch`."""
    path.mkdir(parents=True)
    git(path, "init", "--quiet", f"--initial-branch={branch}")
    return path


def init_bare(path: Path, *, branch: str = "main") -> Path:
    """An empty bare repository at `path` whose `HEAD` names `branch`."""
    git(None, "init", "--quiet", "--bare", f"--initial-branch={branch}", str(path))
    return path


def commit_files(
    repo: Path,
    files: Mapping[str, bytes | None],
    *,
    message: str = "change",
    date: str | None = None,
) -> str:
    """Write (`bytes`) or delete (`None`) the given paths of the work-tree
    repository `repo`, commit every change, and return the commit SHA.
    `date` sets both the author and the committer date."""
    for relative, content in files.items():
        path = repo / relative
        if content is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    git(repo, "add", "--all")
    dates = (
        {} if date is None else {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    )
    git(repo, "commit", "--quiet", "--allow-empty", "-m", message, env_extra=dates)
    return rev_parse(repo / ".git", "HEAD")


def loose_object_path(git_dir: Path, sha: str) -> Path:
    """The loose object file of `sha` in the repository at `git_dir`."""
    return git_dir / "objects" / sha[:2] / sha[2:]


def foreground_maintenance_config(directory: Path) -> Path:
    """A global Git configuration file under `directory` that keeps Git's
    default automatic maintenance but runs it in the foreground, so a
    control case observes it without leaving a detached process behind."""
    path = directory / "foreground-maintenance.gitconfig"
    path.write_text("[maintenance]\n\tautoDetach = false\n", encoding="utf-8")
    return path


def _trace_events(trace: Path, event: str) -> list[list[str]]:
    lines = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
    records = [json.loads(line) for line in lines]
    return [record["argv"] for record in records if record["event"] == event]


def traced_commands(trace: Path) -> list[list[str]]:
    """The argv of every Git process that wrote to the `GIT_TRACE2_EVENT`
    file `trace`."""
    return _trace_events(trace, "start")


def automatic_maintenance_runs(trace: Path) -> list[list[str]]:
    """The argv of every `git maintenance run --auto` child started by a Git
    process that wrote to the `GIT_TRACE2_EVENT` file `trace`."""
    return [
        argv
        for argv in _trace_events(trace, "child_start")
        if argv[1:4] == ["maintenance", "run", "--auto"]
    ]
