"""Behavioral tests for the Renovate lookup-log validator."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_renovate_log.py"
FIXTURE_DIR = REPO_ROOT / "backend" / "tests" / "fixtures" / "renovate"
IP_ALLOW_LIST_LOG = FIXTURE_DIR / "ip-allow-list.ndjson"

TRIVY_ACTION = "aquasecurity/trivy-action"
TRIVY_ACTION_WARNING = "(github-tags package aquasecurity/trivy-action)"
TRIVY_WARNING = "(github-releases package aquasecurity/trivy)"

Records = list[dict[str, Any]]


def _run_validator(
    log_path: Path, *, merge_output: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(log_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge_output else subprocess.PIPE,
        text=True,
        check=False,
    )


def _write_mixed_log(tmp_path: Path) -> Path:
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(
        IP_ALLOW_LIST_LOG.read_text(encoding="utf-8")
        + (FIXTURE_DIR / "lookup-warning.ndjson").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return log_path


def _read_records(log_path: Path) -> Records:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _write_records(tmp_path: Path, records: Records) -> Path:
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    return log_path


def _trivy_action_refusals(records: Records) -> Records:
    return [
        record
        for record in records
        if "err" in record and record["packageName"] == TRIVY_ACTION
    ]


def _trivy_action_dependencies(records: Records) -> Records:
    return [
        dependency
        for record in records
        if record.get("msg") == "packageFiles with updates"
        for package_file in record["config"]["github-actions"]
        for dependency in package_file["deps"]
        if dependency["packageName"] == TRIVY_ACTION
    ]


def _set_trivy_action_warning(records: Records, message: str) -> Records:
    for dependency in _trivy_action_dependencies(records):
        dependency["warnings"] = [{"topic": TRIVY_ACTION, "message": message}]
    return records


def _drop_refusals(records: Records) -> Records:
    return [record for record in records if "err" not in record]


def _refuse_another_package(records: Records) -> Records:
    for refusal in _trivy_action_refusals(records):
        refusal["packageName"] = "aquasecurity/example-tool"
    return records


def _refuse_another_datasource(records: Records) -> Records:
    for refusal in _trivy_action_refusals(records):
        refusal["datasource"] = "github-releases"
    return records


def _name_another_organization_in_refusals(records: Records) -> Records:
    for record in records:
        if "err" in record:
            error = record["err"]
            error["message"] = error["message"].replace("aquasecurity", "example-org")
    return records


def _move_trivy_action_lookup_to_releases(records: Records) -> Records:
    for refusal in _trivy_action_refusals(records):
        refusal["datasource"] = "github-releases"
    for dependency in _trivy_action_dependencies(records):
        dependency["datasource"] = "github-releases"
    return _set_trivy_action_warning(
        records, f"Failed to look up github-releases package {TRIVY_ACTION}: no-result"
    )


def _report_other_lookup_failure(records: Records) -> Records:
    return _set_trivy_action_warning(
        records, f"Failed to look up github-tags package {TRIVY_ACTION}: other-reason"
    )


def _report_other_warning(records: Records) -> Records:
    return _set_trivy_action_warning(
        records, "Could not determine new digest for update"
    )


@pytest.mark.unit
def test_validator_accepts_clean_log_and_missing_warnings_field() -> None:
    result = _run_validator(FIXTURE_DIR / "clean.ndjson")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "without package warnings" in result.stdout


@pytest.mark.unit
def test_validator_rejects_digest_lookup_warning_with_context() -> None:
    result = _run_validator(FIXTURE_DIR / "lookup-warning.ndjson")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Could not determine new digest" in result.stderr
    assert ".github/sbom-tools.env" in result.stderr
    assert "docker package anchore/syft" in result.stderr


@pytest.mark.unit
def test_validator_tolerates_ip_allow_list_refusal_of_exempt_packages() -> None:
    result = _run_validator(IP_ALLOW_LIST_LOG)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Tolerated Renovate package lookup warnings" in result.stdout
    assert TRIVY_ACTION_WARNING in result.stdout
    assert TRIVY_WARNING in result.stdout
    assert "without other package warnings" in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutate", "blocking", "tolerated"),
    [
        pytest.param(
            _drop_refusals,
            [TRIVY_ACTION_WARNING, TRIVY_WARNING],
            [],
            id="without-refusal-record",
        ),
        pytest.param(
            _refuse_another_package,
            [TRIVY_ACTION_WARNING],
            [TRIVY_WARNING],
            id="refusal-for-another-package",
        ),
        pytest.param(
            _refuse_another_datasource,
            [TRIVY_ACTION_WARNING],
            [TRIVY_WARNING],
            id="refusal-for-another-datasource",
        ),
        pytest.param(
            _name_another_organization_in_refusals,
            [TRIVY_ACTION_WARNING, TRIVY_WARNING],
            [],
            id="refusal-naming-another-organization",
        ),
        pytest.param(
            _move_trivy_action_lookup_to_releases,
            ["(github-releases package aquasecurity/trivy-action)"],
            [TRIVY_WARNING],
            id="exempt-package-with-another-datasource",
        ),
        pytest.param(
            _report_other_lookup_failure,
            [TRIVY_ACTION_WARNING],
            [TRIVY_WARNING],
            id="other-lookup-failure-reason",
        ),
        pytest.param(
            _report_other_warning,
            [TRIVY_ACTION_WARNING],
            [TRIVY_WARNING],
            id="other-warning-for-exempt-package",
        ),
    ],
)
def test_validator_rejects_exempt_package_warning_without_exact_refused_lookup(
    tmp_path: Path,
    mutate: Callable[[Records], Records],
    blocking: list[str],
    tolerated: list[str],
) -> None:
    log_path = _write_records(tmp_path, mutate(_read_records(IP_ALLOW_LIST_LOG)))

    result = _run_validator(log_path)

    assert result.returncode == 1
    for warning in blocking:
        assert warning in result.stderr
    for warning in tolerated:
        assert warning not in result.stderr
        assert warning in result.stdout


@pytest.mark.unit
def test_validator_rejects_ip_allow_list_refusal_of_non_exempt_organization(
    tmp_path: Path,
) -> None:
    content = IP_ALLOW_LIST_LOG.read_text(encoding="utf-8")
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(
        content.replace("aquasecurity", "example-org"), encoding="utf-8"
    )

    result = _run_validator(log_path)

    assert result.returncode == 1
    assert "(github-tags package example-org/trivy-action)" in result.stderr
    assert "(github-releases package example-org/trivy)" in result.stderr
    assert "Tolerated" not in result.stdout


@pytest.mark.unit
def test_validator_rejects_other_warning_alongside_tolerated_ones(
    tmp_path: Path,
) -> None:
    result = _run_validator(_write_mixed_log(tmp_path))

    assert result.returncode == 1
    assert "docker package anchore/syft" in result.stderr
    assert TRIVY_ACTION_WARNING not in result.stderr
    assert TRIVY_WARNING not in result.stderr
    assert TRIVY_ACTION_WARNING in result.stdout
    assert TRIVY_WARNING in result.stdout


@pytest.mark.unit
def test_validator_combined_output_lists_tolerated_before_blocking_warnings(
    tmp_path: Path,
) -> None:
    result = _run_validator(_write_mixed_log(tmp_path), merge_output=True)

    output = result.stdout
    assert result.returncode == 1
    assert (
        output.index(TRIVY_WARNING)
        < output.index("Renovate package lookup warnings found:")
        < output.index("docker package anchore/syft")
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "content",
    [
        pytest.param("not-json\n", id="invalid-json"),
        pytest.param(
            '{"name":"renovate","msg":"Repository finished"}\n',
            id="missing-summary",
        ),
        pytest.param(
            '{"msg":"packageFiles with updates","config":[]}\n',
            id="invalid-summary-shape",
        ),
    ],
)
def test_validator_rejects_unverifiable_log(tmp_path: Path, content: str) -> None:
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(content, encoding="utf-8")

    result = _run_validator(log_path)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Cannot validate Renovate lookup log" in result.stderr
