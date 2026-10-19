"""Parsed YAML for tests that read repository configuration files.

Tests read GitHub Actions workflows, Compose files, `codecov.yml`, and the
YAML front matter of OpenCode definitions through this module instead of
scanning their text, so a valid reformatting can neither hide a job, step,
or service from a test nor make the test fail spuriously.

The loader is ruamel.yaml's safe, pure-Python YAML 1.2 loader:

- the workflow `on:` key stays the string `"on"`, as GitHub Actions reads
  it (a YAML 1.1 loader reads `on`, `yes`, and `off` as booleans);
- a duplicate key is an error, as it is for actionlint and Docker Compose,
  instead of silently keeping the last value; and
- merge keys (`<<: *anchor`) are resolved, so a test sees every value a
  mapping inherits.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

type YamlMapping = dict[str, Any]


def _mapping(value: object, what: str) -> YamlMapping:
    if not isinstance(value, dict):
        msg = f"{what} is not a mapping: {value!r}"
        raise AssertionError(msg)
    return value


def load_yaml(text: str, *, source: str) -> YamlMapping:
    """Parse one YAML document whose root is a mapping; `source` names the
    document in failure messages."""
    document = YAML(typ="safe", pure=True).load(text)
    return _mapping(document, f"{source}: the document root")


def load_yaml_file(path: Path) -> YamlMapping:
    """Parse the YAML file at `path`, whose root is a mapping."""
    return load_yaml(path.read_text(encoding="utf-8"), source=path.name)


def workflow_jobs(workflow: YamlMapping) -> dict[str, YamlMapping]:
    """Every job of a GitHub Actions workflow, by job id. A workflow that
    declares no job fails."""
    jobs = _mapping(workflow.get("jobs"), "the workflow's jobs")
    if not jobs:
        msg = "the workflow declares no jobs"
        raise AssertionError(msg)
    return {job_id: _mapping(job, f"job {job_id!r}") for job_id, job in jobs.items()}


def job_steps(job: YamlMapping) -> list[YamlMapping]:
    """The steps of a workflow job, in order."""
    steps = job.get("steps")
    if not isinstance(steps, list):
        msg = f"the job's steps are not a list: {steps!r}"
        raise AssertionError(msg)
    return [_mapping(step, f"step {index}") for index, step in enumerate(steps)]


def step_index(job: YamlMapping, name: str) -> int:
    """The position of the only step of `job` whose `name` is `name`."""
    indices = [
        index for index, step in enumerate(job_steps(job)) if step.get("name") == name
    ]
    if len(indices) != 1:
        msg = f"{len(indices)} steps named {name!r}; expected exactly one"
        raise AssertionError(msg)
    return indices[0]


def named_step(job: YamlMapping, name: str) -> YamlMapping:
    """The only step of `job` whose `name` is `name`."""
    return job_steps(job)[step_index(job, name)]


def string_values(node: object) -> Iterator[str]:
    """Every string value in a parsed YAML node, depth first. Mapping keys
    are not values and are not yielded."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from string_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from string_values(item)
