"""Behavioral tests for the CI dependency-audit scope decision.

`scripts/dependency-audit-scope.sh` decides whether `ci.yml` runs
`pip-audit`. Per `docs/features/platform/testing-strategy.md` (CI Pipeline,
gate 6) the scan is required when a run modifies `backend/pyproject.toml`
or `backend/uv.lock`, for every release-please Release PR, for manual
runs, and whenever the changed files cannot be determined; other runs skip
it. See issue #708.

Each test builds a throwaway Git repository in a temporary directory (never
this repository) that mirrors the CI checkout shape: a pull request is a
merge commit whose first parent is the base branch tip, and a push is a
commit compared against the pushed ``before`` SHA.

The Git hooks run this file inside a real commit or push, so every Git and
script subprocess receives the hermetic environment of
`tests/support/git_repos.py`: no inherited ``GIT_*`` variable, which would
redirect the throwaway repository's commands to the repository whose hook
runs this file, and Git's automatic maintenance disabled, so no detached
repack outlives a test (see `docs/features/platform/testing-strategy.md`,
Tier 1 — Unit Tests).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.support.git_repos import (
    automatic_maintenance_runs,
    foreground_maintenance_config,
    hermetic_git_env,
    traced_commands,
)

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "dependency-audit-scope.sh"
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=hermetic_git_env(),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(repo: Path, message: str, files: dict[str, str]) -> str:
    for relative, content in files.items():
        _write(repo, relative, content)
    _git(repo, "add", "--all")
    _git(repo, "commit", "--quiet", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _init_repository(repository: Path) -> Path:
    """Create a repository with a base commit containing both dependency files."""
    repository.mkdir()
    _git(repository, "init", "--quiet", "--initial-branch=master")
    _commit(
        repository,
        "base",
        {
            "backend/pyproject.toml": '[project]\nname = "example"\n',
            "backend/uv.lock": "version = 1\n",
            "backend/app/main.py": "VALUE = 1\n",
            "docs/readme.md": "base\n",
        },
    )
    return repository


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Repository with a base commit containing both dependency files."""
    return _init_repository(tmp_path / "repo")


def _pull_request_merge(repo: Path, files: dict[str, str]) -> None:
    """Check out a merge commit of a topic branch into an advanced master."""
    _git(repo, "switch", "--quiet", "-c", "topic")
    _commit(repo, "topic change", files)
    _git(repo, "switch", "--quiet", "master")
    _commit(repo, "unrelated master change", {"docs/readme.md": "master\n"})
    _git(repo, "merge", "--quiet", "--no-ff", "--no-edit", "topic")


def _run_scope(
    repo: Path, tmp_path: Path, *, cwd: Path | None = None, **env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    return _run_scope_with_env(repo, tmp_path, env, cwd=cwd)


def _run_scope_with_env(
    repo: Path, tmp_path: Path, env: dict[str, str], *, cwd: Path | None = None
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    output = tmp_path / "github-output"
    output.unlink(missing_ok=True)
    run_env = {
        key: value
        for key, value in hermetic_git_env().items()
        if key not in {"EVENT_NAME", "HEAD_REF", "PUSH_BEFORE"}
    }
    run_env |= {"GITHUB_OUTPUT": str(output), **env}
    result = subprocess.run(
        [str(SCRIPT_PATH)],
        cwd=cwd or repo,
        env=run_env,
        capture_output=True,
        text=True,
        check=False,
    )
    values = (
        dict(line.split("=", 1) for line in output.read_text().splitlines())
        if output.exists()
        else {}
    )
    return result, values


@pytest.mark.unit
@pytest.mark.parametrize(
    "changed_file",
    ["backend/pyproject.toml", "backend/uv.lock"],
)
def test_pull_request_changing_a_dependency_file_requires_audit(
    repo: Path, tmp_path: Path, changed_file: str
) -> None:
    _pull_request_merge(repo, {changed_file: "changed\n"})

    result, values = _run_scope(
        repo, tmp_path, EVENT_NAME="pull_request", HEAD_REF="topic"
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    assert f"dependency files changed: {changed_file}" in result.stdout


@pytest.mark.unit
def test_pull_request_without_dependency_change_skips_audit(
    repo: Path, tmp_path: Path
) -> None:
    # The base branch advanced with an unrelated commit after the topic
    # branch was created; only the pull request's own change is compared.
    _pull_request_merge(repo, {"backend/app/main.py": "VALUE = 2\n"})

    result, values = _run_scope(
        repo, tmp_path, EVENT_NAME="pull_request", HEAD_REF="topic"
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "false"}
    assert "no dependency file changed" in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    "unrelated_file",
    ["pyproject.toml", "uv.lock", "backend/tests/fixtures/uv.lock"],
)
def test_same_named_files_outside_backend_root_do_not_require_audit(
    repo: Path, tmp_path: Path, unrelated_file: str
) -> None:
    _pull_request_merge(repo, {unrelated_file: "unrelated\n"})

    result, values = _run_scope(
        repo, tmp_path, EVENT_NAME="pull_request", HEAD_REF="topic"
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "false"}


@pytest.mark.unit
def test_release_please_pull_request_always_requires_audit(
    repo: Path, tmp_path: Path
) -> None:
    _pull_request_merge(repo, {"CHANGELOG.md": "release notes\n"})

    result, values = _run_scope(
        repo,
        tmp_path,
        EVENT_NAME="pull_request",
        HEAD_REF="release-please--branches--master--components--sentinel",
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    assert "release-please Release PR" in result.stdout


@pytest.mark.unit
def test_branch_merely_containing_release_please_is_not_a_release_pr(
    repo: Path, tmp_path: Path
) -> None:
    _pull_request_merge(repo, {"backend/app/main.py": "VALUE = 2\n"})

    result, values = _run_scope(
        repo, tmp_path, EVENT_NAME="pull_request", HEAD_REF="fix/release-please--x"
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "false"}


@pytest.mark.unit
def test_push_changing_dependency_file_since_before_requires_audit(
    repo: Path, tmp_path: Path
) -> None:
    before = _git(repo, "rev-parse", "HEAD")
    # A multi-commit push: the dependency change is not in the last commit.
    _commit(repo, "lock refresh", {"backend/uv.lock": "version = 2\n"})
    _commit(repo, "code change", {"backend/app/main.py": "VALUE = 3\n"})

    result, values = _run_scope(repo, tmp_path, EVENT_NAME="push", PUSH_BEFORE=before)

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    assert "backend/uv.lock" in result.stdout


@pytest.mark.unit
def test_push_without_dependency_change_skips_audit(repo: Path, tmp_path: Path) -> None:
    before = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "code change", {"backend/app/main.py": "VALUE = 3\n"})

    result, values = _run_scope(repo, tmp_path, EVENT_NAME="push", PUSH_BEFORE=before)

    assert result.returncode == 0, result.stderr
    assert values == {"required": "false"}


def _shallow_clone_without_before(repo: Path, tmp_path: Path) -> tuple[Path, str]:
    """Mirror the shallow CI checkout: a clone whose pushed "before" commit
    is absent locally and must be fetched from origin before comparing."""
    before = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "lock refresh", {"backend/uv.lock": "version = 2\n"})
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "--quiet", "--depth=1", f"file://{repo}", str(clone))
    assert (
        subprocess.run(
            ["git", "cat-file", "-e", f"{before}^{{commit}}"],
            cwd=clone,
            env=hermetic_git_env(),
            capture_output=True,
            check=False,
        ).returncode
        != 0
    )
    return clone, before


@pytest.mark.unit
def test_push_fetches_missing_before_commit_from_origin(
    repo: Path, tmp_path: Path
) -> None:
    clone, before = _shallow_clone_without_before(repo, tmp_path)

    result, values = _run_scope(clone, tmp_path, EVENT_NAME="push", PUSH_BEFORE=before)

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    # The fetched base was actually compared; the fail-safe did not fire.
    assert "dependency files changed: backend/uv.lock" in result.stdout
    assert "could not be determined" not in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    ("configuration", "expected_runs"),
    [
        pytest.param("hermetic", 0, id="hermetic"),
        # Control: with Git's default, the same fetch starts maintenance.
        pytest.param("git-default", 1, id="git-default"),
    ],
)
def test_push_fetch_automatic_maintenance_follows_global_configuration(
    repo: Path, tmp_path: Path, configuration: str, expected_runs: int
) -> None:
    clone, before = _shallow_clone_without_before(repo, tmp_path)
    trace = tmp_path / "trace.json"
    env = {"EVENT_NAME": "push", "PUSH_BEFORE": before, "GIT_TRACE2_EVENT": str(trace)}
    if configuration == "git-default":
        env["GIT_CONFIG_GLOBAL"] = str(foreground_maintenance_config(tmp_path))

    result, values = _run_scope_with_env(clone, tmp_path, env)

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    # The fetch succeeded; the fail-safe did not fire.
    assert "dependency files changed: backend/uv.lock" in result.stdout
    assert ["fetch"] in [argv[1:2] for argv in traced_commands(trace)]
    assert len(automatic_maintenance_runs(trace)) == expected_runs


@pytest.mark.unit
@pytest.mark.parametrize(
    "event_env",
    [
        pytest.param(
            {"EVENT_NAME": "push", "PUSH_BEFORE": "f" * 40}, id="unknown-before-sha"
        ),
        pytest.param(
            {"EVENT_NAME": "push", "PUSH_BEFORE": "0" * 40}, id="zero-before-sha"
        ),
        pytest.param({"EVENT_NAME": "push"}, id="missing-before-sha"),
        pytest.param({"EVENT_NAME": "workflow_dispatch"}, id="manual-run"),
    ],
)
def test_undeterminable_or_manual_runs_require_audit(
    repo: Path, tmp_path: Path, event_env: dict[str, str]
) -> None:
    _commit(repo, "code change", {"backend/app/main.py": "VALUE = 3\n"})

    result, values = _run_scope_with_env(repo, tmp_path, event_env)

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}


@pytest.mark.unit
def test_pull_request_without_base_commit_requires_audit(
    repo: Path, tmp_path: Path
) -> None:
    # A single-commit checkout has no first parent to compare against.
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "--quiet", "--depth=1", f"file://{repo}", str(clone))

    result, values = _run_scope(
        clone, tmp_path, EVENT_NAME="pull_request", HEAD_REF="topic"
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    assert "could not be determined" in result.stdout


@pytest.mark.unit
def test_decision_is_independent_of_working_directory(
    repo: Path, tmp_path: Path
) -> None:
    # ci.yml invokes the script from the backend/ working directory.
    _pull_request_merge(repo, {"backend/app/main.py": "VALUE = 2\n"})

    result, values = _run_scope(
        repo,
        tmp_path,
        cwd=repo / "backend",
        EVENT_NAME="pull_request",
        HEAD_REF="topic",
    )

    assert result.returncode == 0, result.stderr
    assert values == {"required": "false"}


@pytest.mark.unit
def test_missing_event_name_fails(repo: Path, tmp_path: Path) -> None:
    result, values = _run_scope(repo, tmp_path)

    assert result.returncode != 0
    assert values == {}
    assert "EVENT_NAME" in result.stderr


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "hook_variables",
    [
        # `git commit -a` and `git commit <path>` export an absolute index.
        pytest.param({"GIT_INDEX_FILE": "{git_dir}/index"}, id="index-file"),
        # A hook running in a linked worktree receives an absolute GIT_DIR.
        pytest.param(
            {
                "GIT_DIR": "{git_dir}",
                "GIT_WORK_TREE": "{work_tree}",
                "GIT_INDEX_FILE": "{git_dir}/index",
                "GIT_OBJECT_DIRECTORY": "{git_dir}/objects",
            },
            id="repository-location",
        ),
    ],
)
def test_inherited_hook_environment_does_not_reach_the_invoking_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook_variables: dict[str, str]
) -> None:
    # The pre-commit and pre-push hooks run this file inside a real Git
    # command, which exports the invoking repository's location.
    invoking = tmp_path / "invoking"
    invoking.mkdir()
    _git(invoking, "init", "--quiet", "--initial-branch=master")
    _commit(invoking, "invoking", {"readme.md": "invoking\n"})
    git_dir = invoking / ".git"
    before = _snapshot(git_dir)

    with monkeypatch.context() as patch:
        for name, value in hook_variables.items():
            patch.setenv(name, value.format(git_dir=git_dir, work_tree=invoking))
        repository = _init_repository(tmp_path / "repo")
        _pull_request_merge(repository, {"backend/uv.lock": "changed\n"})
        result, values = _run_scope(
            repository, tmp_path, EVENT_NAME="pull_request", HEAD_REF="topic"
        )

    assert _snapshot(git_dir) == before
    assert result.returncode == 0, result.stderr
    assert values == {"required": "true"}
    assert "dependency files changed: backend/uv.lock" in result.stdout
