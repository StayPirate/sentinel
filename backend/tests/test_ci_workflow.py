"""Regression tests for the Python-version drift check in ci.yml.

The `backend-lint` job's "Verify Dockerfile and pyproject.toml Python
version match .python-version" step fails the build when
`backend/Dockerfile`'s `ARG PYTHON_VERSION` or `backend/pyproject.toml`'s
`requires-python` disagree with `backend/.python-version`
(`docs/conventions.md`, Runtime Version -> Source of Truth). See issue
#69, Acceptance Criteria: "The Python-version drift check fails when
`requires-python` and `.python-version` disagree."

This test extracts the exact shell script from the step and executes it
against fixture files in an isolated temporary directory (never against
this repository's real `backend/` files), verifying both the match and
each mismatch case.
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

WORKFLOW_PATH = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"

STEP_NAME_MARKER = (
    "name: Verify Dockerfile and pyproject.toml Python version match .python-version"
)


def _drift_check_script() -> str:
    """Extract the shell script executed by the version drift check step."""
    lines = WORKFLOW_PATH.read_text(encoding="utf-8").splitlines()
    marker_index = next(
        index for index, line in enumerate(lines) if STEP_NAME_MARKER in line
    )
    run_index = next(
        index
        for index in range(marker_index, len(lines))
        if lines[index].strip() == "run: |"
    )
    run_indent = len(lines[run_index]) - len(lines[run_index].lstrip())
    script_lines: list[str] = []

    for line in lines[run_index + 1 :]:
        indentation = len(line) - len(line.lstrip())
        if line.strip() and indentation <= run_indent:
            break
        script_lines.append(line)

    return textwrap.dedent("\n".join(script_lines))


def _run_drift_check(
    tmp_path: Path,
    *,
    python_version: str = "3.13",
    dockerfile_version: str = "3.13",
    requires_python: str = "3.13",
) -> subprocess.CompletedProcess[str]:
    (tmp_path / ".python-version").write_text(f"{python_version}\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        f"ARG PYTHON_VERSION={dockerfile_version}\n"
        "FROM python:${PYTHON_VERSION}-slim\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nrequires-python = ">={requires_python}"\n',
        encoding="utf-8",
    )

    return subprocess.run(
        ["bash", "-c", _drift_check_script()],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.unit
def test_drift_check_passes_when_all_versions_match(tmp_path: Path) -> None:
    result = _run_drift_check(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""


@pytest.mark.unit
def test_drift_check_fails_on_dockerfile_mismatch(tmp_path: Path) -> None:
    result = _run_drift_check(tmp_path, dockerfile_version="3.12")

    assert result.returncode == 1
    assert "Dockerfile ARG PYTHON_VERSION=3.12 does not match" in result.stdout


@pytest.mark.unit
def test_drift_check_fails_on_requires_python_mismatch(tmp_path: Path) -> None:
    result = _run_drift_check(tmp_path, requires_python="3.14")

    assert result.returncode == 1
    assert "pyproject.toml requires-python=>=3.14 does not match" in result.stdout


@pytest.mark.unit
def test_drift_check_reports_dockerfile_mismatch_before_requires_python(
    tmp_path: Path,
) -> None:
    # When both files disagree, the Dockerfile check runs first and
    # exits immediately — the requires-python check is never reached.
    result = _run_drift_check(
        tmp_path, dockerfile_version="3.12", requires_python="3.14"
    )

    assert result.returncode == 1
    assert "Dockerfile ARG PYTHON_VERSION=3.12 does not match" in result.stdout
    assert "requires-python" not in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    "python_version",
    [
        "3.13.7",  # patch-level — violates minor-only granularity
        "3",  # major only, no minor
        "python3.13",  # non-numeric prefix
        "3.13-slim",  # trailing non-numeric suffix
        "",  # empty
        " 3.13",  # leading whitespace
    ],
)
def test_drift_check_fails_on_malformed_python_version(
    tmp_path: Path, python_version: str
) -> None:
    # The format check runs before the Dockerfile/pyproject.toml
    # comparisons, so a malformed .python-version is rejected even when
    # the other two files happen to carry the exact same (invalid)
    # string — matching values are not sufficient, the shared value
    # itself must be minor-only (docs/conventions.md, Runtime Version ->
    # Source of Truth: ".python-version file uses minor-version
    # granularity").
    result = _run_drift_check(
        tmp_path,
        python_version=python_version,
        dockerfile_version=python_version,
        requires_python=python_version,
    )

    assert result.returncode == 1
    assert "is not a valid minor-only version" in result.stdout


@pytest.mark.unit
def test_drift_check_accepts_well_formed_minor_only_version(tmp_path: Path) -> None:
    result = _run_drift_check(
        tmp_path,
        python_version="3.14",
        dockerfile_version="3.14",
        requires_python="3.14",
    )

    assert result.returncode == 0
    assert result.stdout == ""


@pytest.mark.unit
def test_pull_request_image_job_generates_validated_sbom_candidate() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    image_job = workflow.split("  image-smoke:", 1)[1]
    smoke_step = image_job.split("- name: Image smoke test", 1)[1].split(
        "- name: Generate and validate", 1
    )[0]
    sbom_step = image_job.split("- name: Generate and validate", 1)[1].split(
        "- name: Upload release SBOM", 1
    )[0]

    assert "if: github.event_name == 'pull_request'" in workflow
    assert "name: Generate and validate release SBOM candidate" in workflow
    assert "./scripts/sbom-gate.sh" in workflow
    assert "name: sentinel-sbom-candidate" in workflow
    assert '"ghcr.io/${IMAGE_NAME,,}"' in workflow
    assert "retention-days: 7" in workflow
    assert "actions/attest@" not in workflow
    assert "gh release upload" not in workflow
    assert "id: image-smoke" in smoke_step
    assert "TESTED_IMAGE: ${{ steps.image-smoke.outputs.image_id }}" in sbom_step
    assert '"${TESTED_IMAGE}"' in sbom_step
    assert '"${SMOKE_IMAGE}"' not in sbom_step
    assert (
        workflow.index("name: Build backend image (load only, no push)")
        < workflow.index("name: Image smoke test (blocking gate)")
        < workflow.index("name: Generate and validate release SBOM candidate")
    )


@pytest.mark.unit
def test_pull_request_image_job_smokes_loaded_image_without_override() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    image_job = workflow.split("  image-smoke:", 1)[1]
    build_step = image_job.split("- name: Build backend image", 1)[1].split(
        "- name: Image smoke test", 1
    )[0]
    smoke_step = image_job.split("- name: Image smoke test", 1)[1].split(
        "- name: Generate and validate", 1
    )[0]

    assert image_job.count("uses: docker/build-push-action") == 1
    assert "push: false" in build_step
    assert "load: true" in build_step
    assert "SENTINEL_IMAGE: ${{ env.SMOKE_IMAGE }}" in smoke_step
    assert "./scripts/image-smoke.sh --no-build" in smoke_step
    assert "COMPOSE_CMD" not in image_job


@pytest.mark.unit
def test_ci_and_release_workflows_share_sbom_gate() -> None:
    release_workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "build-images.yml"
    ).read_text(encoding="utf-8")
    ci_workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    gate_command = "./scripts/sbom-gate.sh"
    assert ci_workflow.count(gate_command) == 1
    assert release_workflow.count(gate_command) == 1


def _backend_security_job() -> str:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    return workflow.split("  backend-security:", 1)[1].split("\n  shell-lint:", 1)[0]


@pytest.mark.unit
def test_pip_audit_runs_only_when_audit_scope_requires_it() -> None:
    # testing-strategy.md (CI Pipeline, gate 6); issue #708.
    job = _backend_security_job()
    scope_step = job.split("- name: Determine dependency audit scope", 1)[1].split(
        "- name: Run pip-audit", 1
    )[0]
    audit_step = job.split("- name: Run pip-audit", 1)[1]

    assert "name: Backend Security Scan" in job
    assert "fetch-depth: 2" in job
    assert "id: audit-scope" in scope_step
    assert "run: ../scripts/dependency-audit-scope.sh" in scope_step
    assert "EVENT_NAME: ${{ github.event_name }}" in scope_step
    assert "HEAD_REF: ${{ github.head_ref }}" in scope_step
    assert "PUSH_BEFORE: ${{ github.event.before }}" in scope_step
    assert "if: steps.audit-scope.outputs.required == 'true'" in audit_step
    assert "uvx pip-audit@" in audit_step
    assert "continue-on-error" not in audit_step
    # Untrusted context values reach the script only through env, never by
    # interpolation into the shell command.
    assert "${{" not in scope_step.split("run:", 1)[1]


@pytest.mark.unit
def test_bandit_and_security_job_run_unconditionally() -> None:
    job = _backend_security_job()
    header = job.split("steps:", 1)[0]
    bandit_step = job.split("- name: Run bandit", 1)[1].split("- name:", 1)[0]

    assert "if:" not in header
    assert "if:" not in bandit_step
    assert "uvx bandit@" in bandit_step
