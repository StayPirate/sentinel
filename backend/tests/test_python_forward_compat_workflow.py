"""Regression tests for the Python forward-compatibility workflow
(`.github/workflows/python-forward-compat.yml`).

On the next Python minor, the workflow runs the default in-process and
local process system suites with the worker options of `ci.yml`'s
backend-test invocation, without coverage, and the strict type check of
`ci.yml`'s backend-typecheck job. The type check still runs when the
tests fail, every check is skipped when no build of the next minor
exists, and no image is built. See `docs/deployment.md` (Python
Forward-Compatibility Check) and issue #980.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FORWARD_COMPAT_PATH = WORKFLOWS_DIR / "python-forward-compat.yml"
CI_PATH = WORKFLOWS_DIR / "ci.yml"

SYNC_STEP = "Install next Python version and sync dependencies"
DURABILITY_STEP = "Disable durability on the ephemeral PostgreSQL service"
SUITES_STEP = "Run default in-process and local process system suites"
TYPE_CHECK_STEP = "Run strict type check against next Python version"

NEXT_PYTHON_ENV = "NEXT_PYTHON: ${{ steps.python-version.outputs.next }}"
NEXT_PYTHON_PREFIX = ["uv", "run", "--python", "${NEXT_PYTHON}"]
SYNC_SUCCEEDED = "steps.sync.outcome == 'success'"


def _steps(workflow_path: Path) -> list[str]:
    """Split a workflow into text blocks, one per step list item.

    Comment lines are dropped: a comment above a step would otherwise end
    the block of the step before it.
    """
    lines = workflow_path.read_text(encoding="utf-8").splitlines()
    code = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    return re.split(r"\n(?=\s+- (?:name|uses|run):)", code)


def _step(workflow_path: Path, name_prefix: str) -> str:
    """Return the only step whose name starts with `name_prefix`."""
    matches = [
        step
        for step in _steps(workflow_path)
        if step.lstrip().startswith(f"- name: {name_prefix}")
    ]
    assert len(matches) == 1, f"{workflow_path.name}: {name_prefix!r} not unique"
    return matches[0]


def _step_index(workflow_path: Path, name_prefix: str) -> int:
    return _steps(workflow_path).index(_step(workflow_path, name_prefix))


def _key(step: str, key: str) -> str:
    """Return the complete single-line value of a step key."""
    match = re.search(rf"^\s*(?:- )?{key}: (?![|>])(.+)$", step, re.MULTILINE)
    assert match is not None, f"no single-line {key!r} in step"
    return match.group(1)


def _command(step: str) -> list[str]:
    """Return the tokens of a step's single-line `run:` command."""
    return shlex.split(_key(step, "run"))


def _folded_run(step: str) -> str:
    """Return a step's `run: >-` block as one space-joined line."""
    lines = step.splitlines()
    run_index = next(i for i, line in enumerate(lines) if line.strip() == "run: >-")
    run_indent = len(lines[run_index]) - len(lines[run_index].lstrip())
    content: list[str] = []
    for line in lines[run_index + 1 :]:
        if not line.strip() or len(line) - len(line.lstrip()) <= run_indent:
            break
        content.append(line.strip())
    return " ".join(content)


def _arguments_after(command: list[str], program: str) -> list[str]:
    return command[command.index(program) + 1 :]


def _ci_mypy_command() -> list[str]:
    commands = [
        _command(step)
        for step in _steps(CI_PATH)
        if step.lstrip().startswith("- run: uv run mypy ")
    ]
    assert len(commands) == 1
    return commands[0]


@pytest.mark.unit
def test_suites_step_uses_ci_worker_options_without_coverage() -> None:
    ci_arguments = _arguments_after(_command(_step(CI_PATH, SUITES_STEP)), "pytest")
    step = _step(FORWARD_COMPAT_PATH, SUITES_STEP)
    command = _command(step)

    assert _arguments_after(command, "pytest") == [
        argument for argument in ci_arguments if not argument.startswith("--cov")
    ]
    # The marker override selects the local process system suite, which the
    # pyproject addopts filter otherwise excludes.
    assert _arguments_after(command, "pytest")[:2] == ["-m", "not image"]
    assert command[: command.index("pytest")] == NEXT_PYTHON_PREFIX
    assert NEXT_PYTHON_ENV in step


@pytest.mark.unit
def test_type_check_step_runs_ci_scope_on_next_python_after_test_failure() -> None:
    step = _step(FORWARD_COMPAT_PATH, TYPE_CHECK_STEP)
    command = _command(step)

    assert _arguments_after(command, "mypy") == _arguments_after(
        _ci_mypy_command(), "mypy"
    )
    assert command[: command.index("mypy")] == NEXT_PYTHON_PREFIX
    assert NEXT_PYTHON_ENV in step
    # `!cancelled()` replaces the implicit `success()`, so a failed test
    # step does not skip the type check.
    assert _key(step, "if") == "${{ !cancelled() && " + SYNC_SUCCEEDED + " }}"
    assert _step_index(FORWARD_COMPAT_PATH, SUITES_STEP) < _step_index(
        FORWARD_COMPAT_PATH, TYPE_CHECK_STEP
    )


@pytest.mark.unit
def test_suites_step_timeout_leaves_time_for_the_type_check() -> None:
    # A step timeout fails the step and the type check still runs; reaching
    # the job timeout instead cancels the job and skips it.
    workflow = FORWARD_COMPAT_PATH.read_text(encoding="utf-8")
    job_timeout = re.search(r"^    timeout-minutes: (\d+)$", workflow, re.MULTILINE)
    step_timeout = _key(_step(FORWARD_COMPAT_PATH, SUITES_STEP), "timeout-minutes")

    assert job_timeout is not None
    assert int(step_timeout) < int(job_timeout.group(1))


@pytest.mark.unit
def test_durability_step_matches_ci_and_precedes_the_suites() -> None:
    step = _step(FORWARD_COMPAT_PATH, DURABILITY_STEP)

    assert _folded_run(step) == _folded_run(_step(CI_PATH, DURABILITY_STEP))
    assert "POSTGRES_CONTAINER: ${{ job.services.postgres.id }}" in step
    assert _step_index(FORWARD_COMPAT_PATH, DURABILITY_STEP) < _step_index(
        FORWARD_COMPAT_PATH, SUITES_STEP
    )


@pytest.mark.unit
def test_every_check_is_skipped_when_next_python_is_unavailable() -> None:
    sync_step = _step(FORWARD_COMPAT_PATH, SYNC_STEP)

    assert "id: sync" in sync_step
    assert _key(sync_step, "if") == "steps.availability.outputs.available == 'true'"
    assert _step_index(FORWARD_COMPAT_PATH, SYNC_STEP) < _step_index(
        FORWARD_COMPAT_PATH, DURABILITY_STEP
    )
    for name in (DURABILITY_STEP, SUITES_STEP):
        assert _key(_step(FORWARD_COMPAT_PATH, name), "if") == SYNC_SUCCEEDED
    assert SYNC_SUCCEEDED in _key(_step(FORWARD_COMPAT_PATH, TYPE_CHECK_STEP), "if")


@pytest.mark.unit
def test_sync_step_resolves_without_the_lockfile_pin() -> None:
    # Best-effort resolution: dependency versions may float on the next minor.
    sync_step = _step(FORWARD_COMPAT_PATH, SYNC_STEP)

    assert 'uv sync --python "${NEXT_PYTHON}"' in sync_step
    assert "--locked" not in sync_step


@pytest.mark.unit
def test_workflow_builds_and_publishes_no_image() -> None:
    workflow = FORWARD_COMPAT_PATH.read_text(encoding="utf-8")

    for forbidden in (
        "docker/build-push-action",
        "docker build",
        "docker push",
        "image-smoke.sh",
        ": write",
    ):
        assert forbidden not in workflow
    assert "\npermissions:\n  contents: read\n" in workflow
