"""Tests for the YAML loading helpers (tests/support/yaml_files.py)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from ruamel.yaml.constructor import DuplicateKeyError

from tests.support.yaml_files import (
    job_steps,
    load_yaml,
    load_yaml_file,
    named_step,
    step_index,
    string_values,
    workflow_jobs,
)


@pytest.mark.unit
class TestLoadYaml:
    def test_workflow_on_key_and_yaml_1_1_booleans_stay_strings(self) -> None:
        document = load_yaml(
            "on:\n  push:\nflags: [yes, no, off, on]\nmode: 0755\n", source="probe"
        )

        assert list(document) == ["on", "flags", "mode"]
        assert document["flags"] == ["yes", "no", "off", "on"]
        assert document["mode"] == 755

    def test_duplicate_key_is_rejected(self) -> None:
        text = "jobs:\n  a:\n    timeout-minutes: 5\n    timeout-minutes: 600\n"

        with pytest.raises(DuplicateKeyError, match="duplicate key"):
            load_yaml(text, source="probe")

    def test_merge_keys_are_resolved(self) -> None:
        text = textwrap.dedent(
            """\
            x-common: &common
              image: example.test/app
              command: ["run"]
            services:
              api:
                <<: *common
                command: ["serve"]
              worker:
                <<: *common
            """
        )

        services = load_yaml(text, source="probe")["services"]

        assert services["api"] == {"image": "example.test/app", "command": ["serve"]}
        assert services["worker"] == {"image": "example.test/app", "command": ["run"]}

    @pytest.mark.parametrize("text", ["", "- a\n", "plain\n"])
    def test_non_mapping_root_is_rejected(self, text: str) -> None:
        with pytest.raises(AssertionError, match="probe: the document root is not"):
            load_yaml(text, source="probe")

    def test_file_failures_name_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "example.yml"
        path.write_text("- a\n", encoding="utf-8")

        with pytest.raises(AssertionError, match=r"example\.yml: the document root"):
            load_yaml_file(path)


_WORKFLOW = textwrap.dedent(
    """\
    jobs:
      build:  # a trailing comment
        steps:
          - id: first
            run: echo first
          - name: Second
            run: echo second
          - name: Duplicate
            run: echo a
          - name: Duplicate
            run: echo b
      "quoted": {steps: []}
    """
)


@pytest.mark.unit
class TestWorkflowAccessors:
    def test_jobs_are_found_whatever_their_formatting(self) -> None:
        jobs = workflow_jobs(load_yaml(_WORKFLOW, source="probe"))

        assert list(jobs) == ["build", "quoted"]
        assert job_steps(jobs["quoted"]) == []

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("name: x\n", "the workflow's jobs is not a mapping"),
            ("jobs: {}\n", "the workflow declares no jobs"),
            ("jobs:\n  a: [1]\n", "job 'a' is not a mapping"),
        ],
    )
    def test_invalid_jobs_fail(self, text: str, message: str) -> None:
        with pytest.raises(AssertionError, match=message):
            workflow_jobs(load_yaml(text, source="probe"))

    def test_steps_must_be_a_list_of_mappings(self) -> None:
        with pytest.raises(AssertionError, match="steps are not a list"):
            job_steps({"runs-on": "ubuntu-latest"})
        with pytest.raises(AssertionError, match="step 1 is not a mapping"):
            job_steps({"steps": [{"run": "echo"}, "echo"]})

    def test_named_step_is_unique_by_exact_name(self) -> None:
        job = workflow_jobs(load_yaml(_WORKFLOW, source="probe"))["build"]

        assert step_index(job, "Second") == 1
        assert named_step(job, "Second")["run"] == "echo second"
        with pytest.raises(AssertionError, match="2 steps named 'Duplicate'"):
            named_step(job, "Duplicate")
        with pytest.raises(AssertionError, match="0 steps named 'Sec'"):
            named_step(job, "Sec")


@pytest.mark.unit
def test_string_values_yields_nested_values_but_not_keys() -> None:
    node = {"run": "a", "with": {"key": ["b", 1, {"nested": "c"}]}, "flag": True}

    assert list(string_values(node)) == ["a", "b", "c"]
