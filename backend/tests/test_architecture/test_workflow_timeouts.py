"""Structural test verifying every GitHub Actions job declares a timeout.

GitHub's default job timeout is 360 minutes. Without an explicit
job-level `timeout-minutes`, a hung step (e.g. a stuck `docker build` or
a `compose up --wait` that never becomes healthy) can occupy a runner —
and its `concurrency` group — for up to six hours before GitHub kills
it. See issue #69.

This test parses workflow YAML with a minimal indentation-based scanner
rather than a full YAML parser, because `pyproject.toml` declares no
YAML parser dependency.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).resolve().parents[3] / ".github" / "workflows"

# GitHub Actions workflow indentation, as used consistently across this
# repository's workflow files: job ids are nested 2 spaces under `jobs:`,
# and job-level properties (runs-on, timeout-minutes, steps, ...) are
# nested a further 2 spaces under the job id.
JOB_ID_INDENT = 2
JOB_PROPERTY_INDENT = 4


def _job_bodies(workflow_text: str) -> dict[str, list[str]]:
    """Split a workflow file's `jobs:` block into per-job line groups.

    Returns a mapping of job id -> every line belonging to that job's
    body (excluding the job id line itself), up to the next sibling job
    or the end of the `jobs:` block. Line indentation is preserved so
    callers can distinguish job-level properties from nested step-level
    properties.
    """
    lines = workflow_text.splitlines()
    try:
        jobs_index = next(
            index for index, line in enumerate(lines) if line.rstrip() == "jobs:"
        )
    except StopIteration:
        return {}

    jobs: dict[str, list[str]] = {}
    current_job: str | None = None
    for line in lines[jobs_index + 1 :]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            # Dedent past the jobs: block entirely (a new top-level key).
            break
        if indent == JOB_ID_INDENT and line.rstrip().endswith(":"):
            current_job = line.strip().rstrip(":")
            jobs[current_job] = []
            continue
        if current_job is not None:
            jobs[current_job].append(line)

    return jobs


def _jobs_missing_timeout(workflow_text: str) -> list[str]:
    """Return job ids that do not declare a job-level `timeout-minutes`.

    Only a `timeout-minutes:` key at `JOB_PROPERTY_INDENT` counts — a
    step-level `timeout-minutes` (nested further, under a `steps:` list
    item) bounds a single step, not the job's overall 360-minute
    default, and must not be mistaken for the job-level declaration this
    test requires.
    """
    jobs = _job_bodies(workflow_text)
    missing: list[str] = []
    for job_name, body_lines in jobs.items():
        has_job_level_timeout = any(
            line.strip().startswith("timeout-minutes:")
            and (len(line) - len(line.lstrip(" "))) == JOB_PROPERTY_INDENT
            for line in body_lines
        )
        if not has_job_level_timeout:
            missing.append(job_name)
    return missing


def _workflow_files() -> list[Path]:
    return sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")})


@pytest.mark.unit
@pytest.mark.parametrize("workflow_path", _workflow_files(), ids=lambda p: p.name)
def test_every_job_declares_timeout_minutes(workflow_path: Path) -> None:
    text = workflow_path.read_text(encoding="utf-8")
    jobs = _job_bodies(text)

    assert jobs, f"{workflow_path.name}: no jobs found (parser or file issue)"

    missing = _jobs_missing_timeout(text)

    assert not missing, (
        f"{workflow_path.name}: job(s) missing 'timeout-minutes': {missing}"
    )


@pytest.mark.unit
def test_job_bodies_isolates_sibling_jobs() -> None:
    text = textwrap.dedent(
        """\
        name: Example
        jobs:
          first:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: echo hi
          second:
            runs-on: ubuntu-latest
            steps:
              - run: echo bye
        """
    )

    jobs = _job_bodies(text)

    assert set(jobs) == {"first", "second"}
    assert any("timeout-minutes: 5" in line for line in jobs["first"])
    assert not any("timeout-minutes" in line for line in jobs["second"])


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

    assert _jobs_missing_timeout(text) == ["missing"]


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

    assert _jobs_missing_timeout(text) == ["example"]
