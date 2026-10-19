"""Regression tests for the pull request metadata workflow.

The validation step is read from the parsed workflow
(`tests/support/yaml_files.py`) and its script is executed with
representative event metadata.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.support.yaml_files import (
    YamlMapping,
    load_yaml_file,
    named_step,
    workflow_jobs,
)

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "pr-metadata.yml"
)


def _validation_step() -> YamlMapping:
    jobs = workflow_jobs(load_yaml_file(WORKFLOW_PATH))
    return named_step(jobs["validate"], "Validate title and issue linkage")


def _workflow_script() -> str:
    """Extract the shell script executed by the metadata workflow."""
    script = _validation_step()["run"]
    assert isinstance(script, str)
    return script


@pytest.mark.unit
def test_pr_metadata_event_values_enter_shell_only_through_environment() -> None:
    # The title, body, and branch are attacker-controlled; interpolated into
    # the script they would be executed as shell.
    step = _validation_step()

    assert step["env"] == {
        "PR_TITLE": "${{ github.event.pull_request.title }}",
        "PR_BODY": "${{ github.event.pull_request.body }}",
        "PR_AUTHOR": "${{ github.event.pull_request.user.login }}",
        "PR_HEAD_REF": "${{ github.event.pull_request.head.ref }}",
    }
    assert "${{" not in step["run"]


def _validate_metadata(
    *,
    title: str = "ci: adopt issue-first GitHub workflow",
    body: str = "- Issue linkage: Closes #29",
    author: str = "jdoe",
    head_ref: str = "ci/issue-first-workflow",
) -> subprocess.CompletedProcess[str]:
    """Execute the workflow validator with representative event metadata."""
    env = os.environ | {
        "PR_TITLE": title,
        "PR_BODY": body,
        "PR_AUTHOR": author,
        "PR_HEAD_REF": head_ref,
    }
    return subprocess.run(
        ["bash", "-c", _workflow_script()],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.unit
def test_pr_metadata_valid_title_and_issue_linkage_pass() -> None:
    result = _validate_metadata()

    assert result.returncode == 0
    assert result.stderr == ""


@pytest.mark.unit
def test_pr_metadata_invalid_title_fails() -> None:
    result = _validate_metadata(title="Adopt issue-first GitHub workflow")

    assert result.returncode == 1
    assert "does not follow Conventional Commits format" in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    "commit_type", ["feat", "fix", "docs", "refactor", "test", "chore", "ci"]
)
def test_pr_metadata_ordinary_approved_types_pass(commit_type: str) -> None:
    result = _validate_metadata(title=f"{commit_type}: update policy fixture")

    assert result.returncode == 0


@pytest.mark.unit
@pytest.mark.parametrize(
    "title",
    [
        "feat!: replace public contract",
        "feat(api)!: replace public contract",
        "fix!: correct incompatible behavior",
        "fix(api)!: correct incompatible behavior",
    ],
)
def test_pr_metadata_feat_and_fix_breaking_titles_pass(title: str) -> None:
    result = _validate_metadata(title=title)

    assert result.returncode == 0


@pytest.mark.unit
@pytest.mark.parametrize("commit_type", ["docs", "refactor", "test", "chore", "ci"])
def test_pr_metadata_non_release_breaking_titles_fail(commit_type: str) -> None:
    result = _validate_metadata(title=f"{commit_type}!: replace public contract")

    assert result.returncode == 1
    assert "does not follow Conventional Commits format" in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    ("title", "expected_returncode"),
    [
        (f"ci: {'x' * 67}", 0),
        (f"ci: {'x' * 68}", 1),
    ],
)
def test_pr_metadata_title_length_boundary(
    title: str, expected_returncode: int
) -> None:
    result = _validate_metadata(title=title)

    assert result.returncode == expected_returncode


@pytest.mark.unit
def test_pr_metadata_missing_issue_linkage_fails() -> None:
    result = _validate_metadata(body="No issue linkage")

    assert result.returncode == 1
    assert "must contain exactly one issue linkage" in result.stdout


@pytest.mark.unit
def test_pr_metadata_duplicate_issue_linkage_fails() -> None:
    result = _validate_metadata(
        body="- Issue linkage: Closes #29\n- Issue linkage: Closes #30"
    )

    assert result.returncode == 1
    assert "at most one '- Issue linkage:' field" in result.stdout


@pytest.mark.unit
def test_pr_metadata_standalone_closes_line_passes() -> None:
    result = _validate_metadata(body="## Summary\nSome free-form body.\n\nCloses #42")

    assert result.returncode == 0
    assert result.stderr == ""


@pytest.mark.unit
def test_pr_metadata_standalone_na_is_rejected() -> None:
    result = _validate_metadata(body="## Summary\nN/A - cosmetic fix\n")

    assert result.returncode == 1
    assert "must contain exactly one issue linkage" in result.stdout


@pytest.mark.unit
def test_pr_metadata_duplicate_standalone_closes_fails() -> None:
    result = _validate_metadata(body="Closes #29\nCloses #30")

    assert result.returncode == 1
    assert "must contain exactly one issue linkage" in result.stdout


@pytest.mark.unit
def test_pr_metadata_inline_closes_mention_is_not_matched() -> None:
    result = _validate_metadata(
        body="This eventually closes #29 once merged. See also Closes #30 text."
    )

    assert result.returncode == 1
    assert "must contain exactly one issue linkage" in result.stdout


@pytest.mark.unit
def test_pr_metadata_template_format_takes_precedence_over_standalone() -> None:
    # A template field with an invalid value must fail even if a valid
    # standalone `Closes #N` line is also present elsewhere in the body.
    result = _validate_metadata(body="- Issue linkage: not-a-valid-value\n\nCloses #42")

    assert result.returncode == 1
    assert "Issue linkage must be 'Closes #N' or 'N/A - <specific reason>'" in (
        result.stdout
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("linkage", "expected_returncode"),
    [
        ("N/A - spelling correction", 0),
        ("N/A", 1),
        ("N/A -    ", 1),
    ],
)
def test_pr_metadata_human_exemption_requires_specific_reason(
    linkage: str, expected_returncode: int
) -> None:
    result = _validate_metadata(body=f"- Issue linkage: {linkage}")

    assert result.returncode == expected_returncode


@pytest.mark.unit
@pytest.mark.parametrize(
    ("author", "head_ref"),
    [
        ("renovate[bot]", "renovate/pip-httpx-1.x"),
        ("github-actions[bot]", "release-please--branches--master"),
    ],
)
def test_pr_metadata_approved_automation_does_not_require_issue_linkage(
    author: str, head_ref: str
) -> None:
    result = _validate_metadata(body="", author=author, head_ref=head_ref)

    assert result.returncode == 0


@pytest.mark.unit
def test_pr_metadata_automation_with_invalid_title_still_fails() -> None:
    result = _validate_metadata(
        title="Invalid automated title",
        body="",
        author="renovate[bot]",
        head_ref="renovate/pip-httpx-1.x",
    )

    assert result.returncode == 1
    assert "does not follow Conventional Commits format" in result.stdout
