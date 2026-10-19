"""Regression tests for the Python forward-compatibility workflow
(`.github/workflows/python-forward-compat.yml`).

On the next Python minor, the workflow runs the default in-process and
local process system suites with the worker options of `ci.yml`'s
backend-test invocation, without coverage, and the strict type check of
`ci.yml`'s backend-typecheck job. The type check still runs when the
tests fail, every check is skipped when no build of the next minor
exists, and no image is built. See `docs/deployment.md` (Python
Forward-Compatibility Check) and issue #980.

Both workflows are parsed as YAML (`tests/support/yaml_files.py`).
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from tests.support.yaml_files import (
    YamlMapping,
    job_steps,
    load_yaml_file,
    named_step,
    step_index,
    workflow_jobs,
)

WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FORWARD_COMPAT_PATH = WORKFLOWS_DIR / "python-forward-compat.yml"
CI_PATH = WORKFLOWS_DIR / "ci.yml"

AVAILABILITY_STEP = "Check next Python version is available for download"
SYNC_STEP = "Install next Python version and sync dependencies"
DURABILITY_STEP = "Disable durability on the ephemeral PostgreSQL service"
SUITES_STEP = (
    "Run default in-process and local process system suites against next Python version"
)
CI_SUITES_STEP = "Run default in-process and local process system suites with coverage"
TYPE_CHECK_STEP = "Run strict type check against next Python version"

NEXT_PYTHON = "${{ steps.python-version.outputs.next }}"
NEXT_PYTHON_PREFIX = ["uv", "run", "--python", "${NEXT_PYTHON}"]
SYNC_SUCCEEDED = "steps.sync.outcome == 'success'"


def _forward_compat_job() -> YamlMapping:
    jobs = workflow_jobs(load_yaml_file(FORWARD_COMPAT_PATH))
    assert list(jobs) == ["forward-compat"]
    return jobs["forward-compat"]


def _ci_jobs() -> dict[str, YamlMapping]:
    return workflow_jobs(load_yaml_file(CI_PATH))


def _command(step: YamlMapping) -> list[str]:
    """Return the tokens of a step's single-line `run:` command."""
    run = step["run"]
    assert isinstance(run, str)
    assert "\n" not in run.strip(), f"{step.get('name')!r}: run is not one line"
    return shlex.split(run)


def _arguments_after(command: list[str], program: str) -> list[str]:
    return command[command.index(program) + 1 :]


def _ci_mypy_command() -> list[str]:
    commands = [
        _command(step)
        for job in _ci_jobs().values()
        for step in job_steps(job)
        if str(step.get("run", "")).startswith("uv run mypy ")
    ]
    assert len(commands) == 1
    return commands[0]


@pytest.mark.unit
def test_suites_step_uses_ci_worker_options_without_coverage() -> None:
    ci_step = named_step(_ci_jobs()["backend-test"], CI_SUITES_STEP)
    ci_arguments = _arguments_after(_command(ci_step), "pytest")
    step = named_step(_forward_compat_job(), SUITES_STEP)
    command = _command(step)

    assert _arguments_after(command, "pytest") == [
        argument for argument in ci_arguments if not argument.startswith("--cov")
    ]
    # The marker override selects the local process system suite, which the
    # pyproject addopts filter otherwise excludes.
    assert _arguments_after(command, "pytest")[:2] == ["-m", "not image"]
    assert command[: command.index("pytest")] == NEXT_PYTHON_PREFIX
    assert step["env"]["NEXT_PYTHON"] == NEXT_PYTHON


@pytest.mark.unit
def test_type_check_step_runs_ci_scope_on_next_python_after_test_failure() -> None:
    job = _forward_compat_job()
    step = named_step(job, TYPE_CHECK_STEP)
    command = _command(step)

    assert _arguments_after(command, "mypy") == _arguments_after(
        _ci_mypy_command(), "mypy"
    )
    assert command[: command.index("mypy")] == NEXT_PYTHON_PREFIX
    assert step["env"]["NEXT_PYTHON"] == NEXT_PYTHON
    # `!cancelled()` replaces the implicit `success()`, so a failed test
    # step does not skip the type check.
    assert step["if"] == "${{ !cancelled() && " + SYNC_SUCCEEDED + " }}"
    assert step_index(job, SUITES_STEP) < step_index(job, TYPE_CHECK_STEP)


@pytest.mark.unit
def test_suites_step_timeout_leaves_time_for_the_type_check() -> None:
    # A step timeout fails the step and the type check still runs; reaching
    # the job timeout instead cancels the job and skips it.
    job = _forward_compat_job()
    job_timeout = job["timeout-minutes"]
    step_timeout = named_step(job, SUITES_STEP)["timeout-minutes"]

    assert isinstance(job_timeout, int)
    assert isinstance(step_timeout, int)
    assert step_timeout < job_timeout


@pytest.mark.unit
def test_durability_step_matches_ci_and_precedes_the_suites() -> None:
    job = _forward_compat_job()
    step = named_step(job, DURABILITY_STEP)
    ci_step = named_step(_ci_jobs()["backend-test"], DURABILITY_STEP)

    assert step["run"] == ci_step["run"]
    assert step["env"]["POSTGRES_CONTAINER"] == "${{ job.services.postgres.id }}"
    assert step_index(job, DURABILITY_STEP) < step_index(job, SUITES_STEP)


@pytest.mark.unit
def test_every_check_is_skipped_when_next_python_is_unavailable() -> None:
    job = _forward_compat_job()
    sync_index = step_index(job, SYNC_STEP)
    sync_step = named_step(job, SYNC_STEP)

    assert named_step(job, AVAILABILITY_STEP)["id"] == "availability"
    assert step_index(job, AVAILABILITY_STEP) < sync_index
    assert sync_step["id"] == "sync"
    assert sync_step["if"] == "steps.availability.outputs.available == 'true'"
    assert sync_index < step_index(job, DURABILITY_STEP)
    for name in (DURABILITY_STEP, SUITES_STEP):
        assert named_step(job, name)["if"] == SYNC_SUCCEEDED
    # Every step after the sync, including any added later, is a check.
    for step in job_steps(job)[sync_index + 1 :]:
        assert SYNC_SUCCEEDED in str(step.get("if", "")), step.get("name")


@pytest.mark.unit
def test_sync_step_resolves_without_the_lockfile_pin() -> None:
    # Best-effort resolution: dependency versions may float on the next minor.
    run = named_step(_forward_compat_job(), SYNC_STEP)["run"]

    assert 'uv sync --python "${NEXT_PYTHON}"' in run
    assert "--locked" not in run


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
    assert load_yaml_file(FORWARD_COMPAT_PATH)["permissions"] == {"contents": "read"}
