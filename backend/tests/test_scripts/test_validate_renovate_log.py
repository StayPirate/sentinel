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


def _run_validator(log_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def _read_records(log_path: Path) -> Records:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _write_records(tmp_path: Path, records: Records) -> Path:
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    return log_path


def _drop_refusals(records: Records) -> Records:
    return [record for record in records if "err" not in record]


def _drop_trivy_action_refusal(records: Records) -> Records:
    return [
        record
        for record in records
        if "err" not in record or record["packageName"] != TRIVY_ACTION
    ]


def _move_trivy_action_refusal_to_releases(records: Records) -> Records:
    for record in records:
        if "err" in record and record["packageName"] == TRIVY_ACTION:
            record["datasource"] = "github-releases"
    return records


def _name_another_organization_in_refusals(records: Records) -> Records:
    for record in records:
        if "err" in record:
            error = record["err"]
            error["message"] = error["message"].replace("aquasecurity", "example-org")
    return records


def _replace_trivy_action_warnings(records: Records) -> Records:
    for record in records:
        if record.get("msg") != "packageFiles with updates":
            continue
        for package_file in record["config"]["github-actions"]:
            for dependency in package_file["deps"]:
                if dependency["packageName"] == TRIVY_ACTION:
                    dependency["warnings"] = [
                        {
                            "topic": TRIVY_ACTION,
                            "message": "Could not determine new digest for update",
                        }
                    ]
    return records


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
            _drop_trivy_action_refusal,
            [TRIVY_ACTION_WARNING],
            [TRIVY_WARNING],
            id="refusal-for-another-package",
        ),
        pytest.param(
            _move_trivy_action_refusal_to_releases,
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
            _replace_trivy_action_warnings,
            [TRIVY_ACTION_WARNING],
            [TRIVY_WARNING],
            id="other-warning-for-exempt-package",
        ),
    ],
)
def test_validator_rejects_exempt_package_warning_without_matching_refusal(
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
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(
        IP_ALLOW_LIST_LOG.read_text(encoding="utf-8")
        + (FIXTURE_DIR / "lookup-warning.ndjson").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = _run_validator(log_path)

    assert result.returncode == 1
    assert "docker package anchore/syft" in result.stderr
    assert TRIVY_ACTION_WARNING not in result.stderr
    assert TRIVY_WARNING not in result.stderr
    assert TRIVY_ACTION_WARNING in result.stdout
    assert TRIVY_WARNING in result.stdout


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
