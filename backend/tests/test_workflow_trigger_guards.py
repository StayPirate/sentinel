"""Regression tests for the complete workflow_run privileged-trigger guard.

`workflow_run.branches` matches the *head* branch of the triggering CI
run, not the base branch it targeted (see the GitHub Actions
`workflow_run` event documentation, "Limiting your workflow to run based
on branches"). A CI run produced by a `pull_request` event whose head
branch happens to be named "master" (e.g. a fork's default branch) would
otherwise pass the `branches: [master]` filter declared in
`build-images.yml` and `release-please.yml`, letting an unreviewed commit
be built and published with `packages: write` (`build-images.yml`) or
processed with `contents: write` (`release-please.yml`). See issue #96.

Both workflows require the COMPLETE guard in their job-level `if:`
condition:

1. `github.event.workflow_run.event == 'push'` — the triggering CI run
   was itself caused by a `push` (never a `pull_request`).
2. `github.event.workflow_run.conclusion == 'success'` — the triggering
   CI run actually passed; a failed or cancelled CI run on master must
   not trigger an image build or a release.

Either condition alone is insufficient: a `push`-triggered CI run that
failed must not publish an image or cut a release, and a successful
`pull_request`-triggered run must not either. A plain substring check
for both guard fragments would still pass if they were combined with
`||` instead of `&&` (a real regression that weakens the guard while
keeping both fragments present in the text). This module instead
extracts the `if:` condition and evaluates it as a boolean expression
against synthetic GitHub context values, proving the actual AND
relationship — a push-triggered, successful run is allowed, but every
other combination (wrong event, failed conclusion, or both) is
rejected. See issue #185.

The condition is read from the parsed workflow (`tests/support/yaml_files.py`),
so it is always the job-level `if:`, whatever the order of the job's keys.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.support.yaml_files import load_yaml_file, workflow_jobs

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def _job_if_condition(workflow_path: Path, job_id: str) -> str:
    """Return the job-level `if:` condition of `job_id`."""
    condition = workflow_jobs(load_yaml_file(workflow_path))[job_id].get("if")
    assert isinstance(condition, str), f"{job_id}: no job-level if: condition"
    return condition


def _evaluate_condition(
    condition: str,
    *,
    event_name: str,
    workflow_run_event: str,
    workflow_run_conclusion: str,
) -> bool:
    """Evaluate a GitHub Actions job `if:` expression as a Python boolean
    expression, substituting the three context values this module cares
    about with literal strings.

    Only handles the operators actually used by these two workflows'
    guard conditions (`==`, `!=`, `&&`, `||`, parentheses) — not a
    general GitHub Actions expression evaluator. The substituted values
    come exclusively from this test module's own parametrization (never
    from the workflow file's dynamic content), so building a Python
    expression string and evaluating it is safe. The expression's
    *structure* (operators, parentheses) does come from the workflow
    file's text, so `__builtins__` is stripped from the eval globals as
    a defense-in-depth measure — this expression never needs to call
    any builtin. An optional `${{ }}` wrapper is removed and line breaks
    of a block scalar are folded into spaces, as GitHub Actions reads them.
    """
    expr = " ".join(condition.split())
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[len("${{") : -len("}}")].strip()
    expr = expr.replace("github.event_name", repr(event_name))
    expr = expr.replace("github.event.workflow_run.event", repr(workflow_run_event))
    expr = expr.replace(
        "github.event.workflow_run.conclusion", repr(workflow_run_conclusion)
    )
    expr = expr.replace("&&", " and ").replace("||", " or ")
    return bool(eval(expr, {"__builtins__": {}}))


@pytest.mark.unit
class TestBuildImagesGuard:
    """`build-images.yml` accepts a `push` trigger unconditionally (tag
    push path) and a `workflow_run` trigger only when it was itself
    caused by a `push` event that concluded successfully."""

    def _condition(self) -> str:
        return _job_if_condition(WORKFLOWS_DIR / "build-images.yml", "build-backend")

    def test_tag_push_always_allowed(self) -> None:
        # event_name='push' takes the `github.event_name != 'workflow_run'`
        # branch — workflow_run fields are irrelevant for this path.
        assert _evaluate_condition(
            self._condition(),
            event_name="push",
            workflow_run_event="push",
            workflow_run_conclusion="success",
        )

    def test_push_triggered_successful_ci_run_allowed(self) -> None:
        assert _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="push",
            workflow_run_conclusion="success",
        )

    def test_pull_request_triggered_ci_run_rejected(self) -> None:
        assert not _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="pull_request",
            workflow_run_conclusion="success",
        )

    def test_failed_ci_run_rejected(self) -> None:
        assert not _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="push",
            workflow_run_conclusion="failure",
        )

    def test_pull_request_and_failed_ci_run_rejected(self) -> None:
        assert not _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="pull_request",
            workflow_run_conclusion="failure",
        )


@pytest.mark.unit
class TestReleasePleaseGuard:
    """`release-please.yml` has no tag-push path — a `workflow_run`
    trigger is accepted only when it was itself caused by a `push` event
    that concluded successfully."""

    def _condition(self) -> str:
        return _job_if_condition(WORKFLOWS_DIR / "release-please.yml", "release-please")

    def test_push_triggered_successful_ci_run_allowed(self) -> None:
        assert _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="push",
            workflow_run_conclusion="success",
        )

    def test_pull_request_triggered_ci_run_rejected(self) -> None:
        assert not _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="pull_request",
            workflow_run_conclusion="success",
        )

    def test_failed_ci_run_rejected(self) -> None:
        assert not _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="push",
            workflow_run_conclusion="failure",
        )

    def test_pull_request_and_failed_ci_run_rejected(self) -> None:
        assert not _evaluate_condition(
            self._condition(),
            event_name="workflow_run",
            workflow_run_event="pull_request",
            workflow_run_conclusion="failure",
        )


@pytest.mark.unit
class TestConditionExtraction:
    def test_job_level_condition_is_read_whatever_the_key_order(
        self, tmp_path: Path
    ) -> None:
        # A step-level `if:` that precedes the job-level one in the file is
        # not the job's guard.
        workflow_path = tmp_path / "workflow.yml"
        workflow_path.write_text(
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - name: Step\n"
            "        if: github.event_name == 'workflow_run'\n"
            "        run: echo\n"
            "    name: Build\n"
            "    if: >\n"
            "      github.event.workflow_run.event == 'push' &&\n"
            "       github.event.workflow_run.conclusion == 'success'\n",
            encoding="utf-8",
        )

        condition = _job_if_condition(workflow_path, "build")

        assert _evaluate_condition(
            condition,
            event_name="workflow_run",
            workflow_run_event="push",
            workflow_run_conclusion="success",
        )
        assert not _evaluate_condition(
            condition,
            event_name="workflow_run",
            workflow_run_event="pull_request",
            workflow_run_conclusion="success",
        )

    def test_job_without_condition_fails(self, tmp_path: Path) -> None:
        workflow_path = tmp_path / "workflow.yml"
        workflow_path.write_text(
            "jobs:\n  build:\n    steps:\n      - if: always()\n        run: echo\n",
            encoding="utf-8",
        )

        with pytest.raises(AssertionError, match="build: no job-level if"):
            _job_if_condition(workflow_path, "build")

    def test_expression_wrapper_is_removed(self) -> None:
        assert not _evaluate_condition(
            "${{ github.event_name == 'push' }}",
            event_name="workflow_run",
            workflow_run_event="push",
            workflow_run_conclusion="success",
        )
