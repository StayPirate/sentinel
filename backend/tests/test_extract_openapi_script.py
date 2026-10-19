"""Tests for the OpenAPI extraction from a built image
(`scripts/extract-openapi.sh`).

The release asset `sentinel-<version>.openapi.json` is the document that the
tested candidate image generates (`docs/deployment.md`, API Documentation
Publication; issue #1036). A stubbed `docker` records how the generator is run
in the image; one stub runs the generator with the local interpreter to prove
that the script fed on standard input produces the application's document.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from app.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "extract-openapi.sh"
GENERATOR_PATH = REPO_ROOT / "backend" / "scripts" / "generate_openapi.py"

IMAGE_ID = "sha256:" + "a" * 64

# Logs the arguments and standard input, then prints DOCKER_STUB_OUTPUT and
# exits with DOCKER_STUB_EXIT.
DOCKER_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "${DOCKER_STUB_LOG}"
cat > "${DOCKER_STUB_STDIN}"
printf '%s' "${DOCKER_STUB_OUTPUT}"
exit "${DOCKER_STUB_EXIT:-0}"
"""

# Runs the program on standard input with the backend's interpreter, from the
# backend directory, as the image runs it from its application directory.
GENERATOR_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
cd "${GENERATOR_CWD}"
exec "${GENERATOR_PYTHON}" -
"""

OPENAPI_DOCUMENT = json.dumps(
    {"openapi": "3.1.0", "info": {"title": "Sentinel", "version": "1.2.3"}, "paths": {}}
)


def _run_extract(
    tmp_path: Path,
    *,
    stub: str = DOCKER_STUB,
    stub_output: str = OPENAPI_DOCUMENT,
    stub_exit: str = "0",
    arguments: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub_path = bin_dir / "docker"
    stub_path.write_text(stub, encoding="utf-8")
    stub_path.chmod(stub_path.stat().st_mode | stat.S_IEXEC)
    log_path = tmp_path / "docker.log"
    log_path.write_text("", encoding="utf-8")
    output = tmp_path / "openapi" / "openapi.json"

    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_STUB_LOG": str(log_path),
        "DOCKER_STUB_STDIN": str(tmp_path / "docker.stdin"),
        "DOCKER_STUB_OUTPUT": stub_output,
        "DOCKER_STUB_EXIT": stub_exit,
        "GENERATOR_CWD": str(REPO_ROOT / "backend"),
        "GENERATOR_PYTHON": sys.executable,
    }
    result = subprocess.run(
        [
            str(SCRIPT_PATH),
            *(arguments if arguments is not None else [IMAGE_ID, str(output)]),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, log_path.read_text(encoding="utf-8").splitlines(), output


@pytest.mark.unit
def test_extract_runs_the_generator_inside_the_image_without_network(
    tmp_path: Path,
) -> None:
    result, docker_calls, output = _run_extract(tmp_path)

    assert result.returncode == 0, result.stderr
    assert docker_calls == [
        f"run --rm --interactive --network none --pull never {IMAGE_ID} python -"
    ]
    assert (tmp_path / "docker.stdin").read_bytes() == GENERATOR_PATH.read_bytes()
    assert output.read_text(encoding="utf-8") == OPENAPI_DOCUMENT


@pytest.mark.unit
def test_extract_writes_the_application_document(tmp_path: Path) -> None:
    result, _, output = _run_extract(tmp_path, stub=GENERATOR_STUB)

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document == json.loads(json.dumps(app.openapi()))


@pytest.mark.unit
def test_extract_propagates_a_docker_failure(tmp_path: Path) -> None:
    result, docker_calls, _ = _run_extract(tmp_path, stub_output="", stub_exit="125")

    assert result.returncode == 125
    assert len(docker_calls) == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    "stub_output",
    [
        "",
        "not json",
        "[]",
        '{"info": {"version": "1.2.3"}, "paths": {}}',
        '{"openapi": "3.1.0", "paths": {}}',
        '{"openapi": "3.1.0", "info": {"version": "1.2.3"}}',
    ],
)
def test_extract_rejects_output_that_is_not_an_openapi_document(
    tmp_path: Path, stub_output: str
) -> None:
    result, _, output = _run_extract(tmp_path, stub_output=stub_output)

    assert result.returncode == 1
    assert f"Not an OpenAPI document: {output}" in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize("arguments", [[], [IMAGE_ID], [IMAGE_ID, "a", "b"]])
def test_extract_rejects_wrong_argument_count(
    tmp_path: Path, arguments: list[str]
) -> None:
    result, docker_calls, _ = _run_extract(tmp_path, arguments=arguments)

    assert result.returncode == 2
    assert "Usage:" in result.stderr
    assert docker_calls == []
