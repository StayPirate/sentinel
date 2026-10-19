"""Structural test verifying every GitHub Actions job declares a timeout.

GitHub's default job timeout is 360 minutes. Without an explicit
job-level `timeout-minutes`, a hung step (e.g. a stuck `docker build` or
a `compose up --wait` that never becomes healthy) can occupy a runner —
and its `concurrency` group — for up to six hours before GitHub kills
it. See issue #69.

Workflows are parsed as YAML (`tests/support/yaml_files.py`), so every job
is checked whatever its formatting.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tests.support.yaml_files import (
    YamlMapping,
    load_yaml,
    load_yaml_file,
    workflow_jobs,
)

WORKFLOWS_DIR = Path(__file__).resolve().parents[3] / ".github" / "workflows"


def _is_timeout(value: object) -> bool:
    """Whether `value` declares a timeout: a positive number of minutes, or an
    expression that GitHub Actions evaluates at run time."""
    if isinstance(value, str):
        return value.startswith("${{") and value.endswith("}}")
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _jobs_missing_timeout(workflow: YamlMapping) -> list[str]:
    """Return the ids of jobs that do not declare a job-level
    `timeout-minutes`.

    A step-level `timeout-minutes` bounds a single step, not the job's
    360-minute default, and does not satisfy the job-level requirement.
    """
    return [
        job_id
        for job_id, job in workflow_jobs(workflow).items()
        if not _is_timeout(job.get("timeout-minutes"))
    ]


def _workflow_files() -> list[Path]:
    return sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")})


@pytest.mark.unit
@pytest.mark.parametrize("workflow_path", _workflow_files(), ids=lambda p: p.name)
def test_every_job_declares_timeout_minutes(workflow_path: Path) -> None:
    missing = _jobs_missing_timeout(load_yaml_file(workflow_path))

    assert not missing, (
        f"{workflow_path.name}: job(s) missing 'timeout-minutes': {missing}"
    )


@pytest.mark.unit
def test_workflow_files_are_found() -> None:
    assert len(_workflow_files()) > 1


@pytest.mark.unit
def test_jobs_missing_timeout_detects_job_without_declaration() -> None:
    text = textwrap.dedent(
        """\
        name: Example
        jobs:
          compliant:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: echo hi
          missing:
            runs-on: ubuntu-latest
            steps:
              - run: echo bye
        """
    )

    assert _jobs_missing_timeout(load_yaml(text, source="probe")) == ["missing"]


@pytest.mark.unit
def test_jobs_missing_timeout_ignores_step_level_declaration() -> None:
    # A timeout-minutes key nested under a steps: list item bounds only
    # that one step, not the job's 360-minute default, and must not
    # satisfy the job-level requirement.
    text = textwrap.dedent(
        """\
        name: Example
        jobs:
          example:
            runs-on: ubuntu-latest
            steps:
              - name: A step with its own timeout
                timeout-minutes: 5
                run: echo hi
        """
    )

    assert _jobs_missing_timeout(load_yaml(text, source="probe")) == ["example"]


@pytest.mark.unit
def test_jobs_missing_timeout_sees_every_job_whatever_its_formatting() -> None:
    # A trailing comment on a job id, a quoted job id, and a flow mapping
    # are valid YAML; none of them may hide a job from the check.
    text = textwrap.dedent(
        """\
        jobs:
          commented:  # no timeout
            runs-on: ubuntu-latest
          "quoted":
            runs-on: ubuntu-latest
          flow: {runs-on: ubuntu-latest, timeout-minutes: 5}
          flow-missing: {runs-on: ubuntu-latest}
        """
    )

    assert _jobs_missing_timeout(load_yaml(text, source="probe")) == [
        "commented",
        "quoted",
        "flow-missing",
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "declared"),
    [
        ("10", True),
        ("${{ inputs.timeout }}", True),
        ("", False),
        ("0", False),
        ("-5", False),
        ("true", False),
        ('"10"', False),
    ],
)
def test_jobs_missing_timeout_accepts_only_a_timeout_value(
    value: str, declared: bool
) -> None:
    text = f"jobs:\n  example:\n    timeout-minutes: {value}\n"

    missing = _jobs_missing_timeout(load_yaml(text, source="probe"))

    assert missing == ([] if declared else ["example"])
