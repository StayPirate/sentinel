"""Regression tests for the Docker-only image-smoke runner."""

from __future__ import annotations

import os
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT_DIR / "scripts" / "image-smoke.sh"
IMAGE_ID = f"sha256:{'a' * 64}"
DRIFTED_IMAGE_ID = f"sha256:{'f' * 64}"
# Application roles in verification order, with their fake container IDs.
ROLE_CONTAINERS = {
    "api": "aaaaaaaaaaaa",
    "migrate": "bbbbbbbbbbbb",
    "worker": "cccccccccccc",
    "git-worker": "eeeeeeeeeeee",
    "beat": "dddddddddddd",
}

PYTHON_STUB = r"""#!/usr/bin/env bash
set -euo pipefail
supervisor_path="$1"
shift
if [[ ! -f "${supervisor_path}" ]]; then
    printf "python3: can't open file '%s'\n" "${supervisor_path}" >&2
    exit 2
fi
label=""
timeout=""
grace=""
while (($#)); do
    case "$1" in
        --label) label="$2"; shift 2 ;;
        --timeout) timeout="$2"; shift 2 ;;
        --grace-period) grace="$2"; shift 2 ;;
        --) shift; break ;;
        *) exit 96 ;;
    esac
done
printf 'supervisor %s timeout=%s grace=%s -- %s\n' \
    "${label}" "${timeout}" "${grace}" "$*" >> "${IMAGE_SMOKE_STUB_LOG}"
times_out=0
[[ "${TIMEOUT_LABEL:-}" != "${label}" ]] || times_out=1
if [[ -n "${TIMEOUT_LABEL_PREFIX:-}" &&
      "${label}" == "${TIMEOUT_LABEL_PREFIX}"* ]]; then
    times_out=1
fi
if ((times_out)); then
    if [[ "${label}" == "pytest" && -n "${REGISTER_DISPOSABLE:-}" ]]; then
        printf '%s\n' "${COMPOSE_PROJECT}-isolated-deadbeef" \
            >> "${IMAGE_SMOKE_PROJECT_REGISTRY}"
    fi
    printf "Timeout: label='%s' timeout=%ss\n" "${label}" "${timeout}" >&2
    exit 124
fi
if [[ "${ABORT_LABEL:-}" == "${label}" ]]; then
    kill -TERM "${PPID}"
    exit 143
fi
exec "$@"
"""

DOCKER_STUB = r"""#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >> "${IMAGE_SMOKE_STUB_LOG}"
image_id="${LOCAL_IMAGE_ID:-sha256:$(printf 'a%.0s' {1..64})}"
mismatch_id="sha256:$(printf 'b%.0s' {1..64})"

if [[ "${1:-}" == "context" && "${2:-}" == "show" ]]; then
    printf '%s\n' "${DOCKER_CONTEXT-default}"
    exit "${CONTEXT_SHOW_EXIT:-0}"
fi
if [[ "${1:-}" == "context" && "${2:-}" == "inspect" ]]; then
    printf '%s\n' "${CONTEXT_ENDPOINT:-unix:///var/run/docker.sock}"
    exit "${CONTEXT_INSPECT_EXIT:-0}"
fi
if [[ "${1:-}" == "version" ]]; then
    [[ "${DOCKER_VERSION_EXIT:-0}" == "0" ]] || exit "${DOCKER_VERSION_EXIT}"
    printf '%s\n' "${DOCKER_SERVER_IDENTITY:-Docker Engine - Community|Engine}"
    exit 0
fi
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
    [[ "${COMPOSE_VERSION_EXIT:-0}" == "0" ]] || exit "${COMPOSE_VERSION_EXIT}"
    printf '%s\n' "${DETECTED_COMPOSE_VERSION:-2.32.2}"
    exit 0
fi
if [[ "${1:-}" == "build" ]]; then
    exit "${DOCKER_BUILD_EXIT:-0}"
fi
if [[ "${1:-}" == "pull" ]]; then
    exit "${DOCKER_PULL_EXIT:-0}"
fi
if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
    count_file="${IMAGE_SMOKE_STATE_DIR}/inspect-count"
    count=0
    [[ ! -f "${count_file}" ]] || read -r count < "${count_file}"
    count=$((count + 1))
    printf '%s\n' "${count}" > "${count_file}"
    if ((count > 1)) && [[ "${POST_IMAGE_INSPECT_EXIT:-0}" != "0" ]]; then
        exit "${POST_IMAGE_INSPECT_EXIT}"
    fi
    if ((count > 1)) && [[ -n "${DRIFT_IMAGE_ID:-}" ]]; then
        printf '%s\n' "${DRIFT_IMAGE_ID}"
    else
        printf '%s\n' "${image_id}"
    fi
    exit "${IMAGE_INSPECT_EXIT:-0}"
fi
if [[ "${1:-}" == "inspect" ]]; then
    container="${*: -1}"
    case "${container}" in
        aaaaaaaaaaaa) role=api ;;
        bbbbbbbbbbbb) role=migrate ;;
        cccccccccccc) role=worker ;;
        dddddddddddd) role=beat ;;
        eeeeeeeeeeee) role=git-worker ;;
        *) role=unknown ;;
    esac
    if [[ "$*" == *"{{.State.Running}}"* ]]; then
        printf '%s\n' "${BEAT_RUNNING:-true}"
    elif [[ "${ROLE_MISMATCH:-}" == "${role}" ]]; then
        printf '%s\n' "${mismatch_id}"
    elif [[ "$*" == *"{{.Name}} {{.Image}}"* ]]; then
        printf '/%s %s\n' "${role}" "${image_id}"
    else
        printf '%s\n' "${image_id}"
    fi
    exit 0
fi
if [[ "${1:-}" == "logs" ]]; then
    [[ "${BEAT_LOG_READY:-1}" == "1" ]] && printf 'beat_startup_completed\n'
    exit 0
fi
if [[ "${1:-}" == "exec" ]]; then
    [[ "${BEAT_ENTRY_READY:-1}" == "1" ]] || exit 6
    printf 'BEAT-READY\n'
    exit 0
fi

if [[ "${1:-}" == "compose" ]]; then
    project=""
    shift
    while (($#)); do
        case "$1" in
            -p) project="$2"; shift 2 ;;
            -f) shift 2 ;;
            *) break ;;
        esac
    done
    case "${1:-}" in
        up) exit "${COMPOSE_UP_EXIT:-0}" ;;
        port)
            printf '%s\n' "${COMPOSE_PORT-127.0.0.1:49152}"
            exit "${COMPOSE_PORT_EXIT:-0}"
            ;;
        ps)
            if [[ "$*" == *"-q api"* ]]; then printf 'aaaaaaaaaaaa\n'
            elif [[ "$*" == *"-q migrate"* ]]; then printf 'bbbbbbbbbbbb\n'
            elif [[ "$*" == *"-q git-worker"* ]]; then printf 'eeeeeeeeeeee\n'
            elif [[ "$*" == *"-q worker"* ]]; then printf 'cccccccccccc\n'
            elif [[ "$*" == *"-q beat"* ]]; then printf 'dddddddddddd\n'
            elif [[ "$*" == *"-q"* ]]; then
                printf '%s\n' aaaaaaaaaaaa bbbbbbbbbbbb cccccccccccc \
                    dddddddddddd eeeeeeeeeeee
            else
                printf '{"Project":"%s","State":"running"}\n' "${project}"
            fi
            exit "${DIAGNOSTIC_PS_EXIT:-0}"
            ;;
        logs)
            printf '%s api-1 | ready\n' '2026-09-07T12:00:00Z'
            exit "${DIAGNOSTIC_LOGS_EXIT:-0}"
            ;;
        down)
            if [[ "${project}" == *"-isolated-"* ]]; then
                exit "${DISPOSABLE_DOWN_EXIT:-0}"
            fi
            exit "${COMPOSE_DOWN_EXIT:-0}"
            ;;
    esac
fi
exit 0
"""

UV_STUB = r"""#!/usr/bin/env bash
set -euo pipefail
printf 'uv %s project=%s files=%s image=%s base=%s registry=%s\n' \
    "$*" "${COMPOSE_PROJECT:-}" "${COMPOSE_FILES:-}" \
    "${IMAGE_SMOKE_IMAGE_ID:-}" "${IMAGE_SMOKE_BASE_URL:-}" \
    "${IMAGE_SMOKE_PROJECT_REGISTRY:-}" >> "${IMAGE_SMOKE_STUB_LOG}"
if [[ -n "${REGISTER_DISPOSABLE:-}" ]]; then
    printf '%s\n' "${REGISTER_PROJECT:-${COMPOSE_PROJECT}-isolated-deadbeef}" \
        >> "${IMAGE_SMOKE_PROJECT_REGISTRY}"
fi
exit "${UV_EXIT:-0}"
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _prepare_bin(tmp_path: Path, *, docker: bool = True, python: bool = True) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    for command in ("bash", "dirname", "mktemp", "rm", "tr"):
        target = Path("/usr/bin") / command
        bin_dir.joinpath(command).symlink_to(target)
    if python:
        _write_executable(bin_dir / "python3", PYTHON_STUB)
    if docker:
        _write_executable(bin_dir / "docker", DOCKER_STUB)
    _write_executable(bin_dir / "uv", UV_STUB)
    return bin_dir


def _run_script(
    tmp_path: Path,
    *args: str,
    docker: bool = True,
    python: bool = True,
    runner_without_supervisor: bool = False,
    env_overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = _prepare_bin(tmp_path, docker=docker, python=python)
    log_path = tmp_path / "stub.log"
    log_path.write_text("", encoding="utf-8")
    env = os.environ | {
        "PATH": str(bin_dir),
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "IMAGE_SMOKE_STUB_LOG": str(log_path),
        "IMAGE_SMOKE_STATE_DIR": str(tmp_path),
        "IMAGE_SMOKE_TERM_GRACE": "0.01",
    }
    env.update(env_overrides or {})
    script_path = SCRIPT_PATH
    if runner_without_supervisor:
        harness_dir = tmp_path / "harness"
        harness_dir.mkdir()
        script_path = harness_dir / "image-smoke.sh"
        script_path.write_text(
            SCRIPT_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
    result = subprocess.run(
        ["/usr/bin/bash", str(script_path), *args],
        cwd=ROOT_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    return result, log_path.read_text(encoding="utf-8").splitlines()


def _docker_calls(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("docker ")]


def _supervisor_calls(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("supervisor ")]


def _project_from_up(calls: list[str]) -> str:
    up_call = next(
        call
        for call in calls
        if call.startswith("docker compose -p ") and " up " in call
    )
    return up_call.split()[3]


@pytest.mark.unit
def test_runner_rejects_unknown_argument_before_preflight(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "--unknown")

    assert result.returncode == 1
    assert "Error: unknown argument '--unknown'" in result.stderr
    assert calls == []


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", "0", "-1", "nan", "inf", "1s"])
def test_runner_rejects_invalid_timeout_override(tmp_path: Path, value: str) -> None:
    result, calls = _run_script(
        tmp_path, env_overrides={"IMAGE_SMOKE_STARTUP_TIMEOUT": value}
    )

    assert result.returncode != 0
    assert "IMAGE_SMOKE_STARTUP_TIMEOUT must be a finite number" in result.stderr
    assert calls == []


@pytest.mark.unit
@pytest.mark.parametrize(("grace", "accepted"), [("0", True), ("-1", False)])
def test_runner_validates_nonnegative_term_grace(
    tmp_path: Path, grace: str, accepted: bool
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"IMAGE_SMOKE_TERM_GRACE": grace},
    )

    if accepted:
        assert result.returncode == 0, result.stderr
        assert any("grace=0 --" in call for call in _supervisor_calls(calls))
    else:
        assert result.returncode == 1
        assert "IMAGE_SMOKE_TERM_GRACE must be a finite non-negative" in result.stderr
        assert calls == []


@pytest.mark.unit
def test_runner_rejects_missing_docker_cli(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, docker=False)

    assert result.returncode != 0
    assert "Error: Docker CLI not found." in result.stderr
    assert _docker_calls(calls) == []
    assert any(call.startswith("supervisor teardown-registry") for call in calls)


@pytest.mark.unit
def test_runner_rejects_missing_python_before_docker_preflight(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, python=False)

    assert result.returncode == 1
    assert "Python 3 and scripts/run-with-timeout.py are required" in result.stderr
    assert _docker_calls(calls) == []


@pytest.mark.unit
def test_runner_rejects_missing_timeout_supervisor_file(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, runner_without_supervisor=True)

    assert result.returncode == 1
    assert "Python 3 and scripts/run-with-timeout.py are required" in result.stderr
    assert "temporary project registry cleanup failed with exit 2" in result.stderr
    assert _docker_calls(calls) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("overrides", "message", "expected_status"),
    [
        (
            {"CONTEXT_SHOW_EXIT": "12"},
            "cannot resolve the active Docker context",
            12,
        ),
        (
            {"DOCKER_CONTEXT": ""},
            "Docker returned an empty active context name",
            1,
        ),
        (
            {"DOCKER_CONTEXT": "broken", "CONTEXT_INSPECT_EXIT": "13"},
            "cannot inspect Docker endpoint for context 'broken'",
            13,
        ),
    ],
)
def test_runner_fails_closed_when_active_context_resolution_fails(
    tmp_path: Path,
    overrides: dict[str, str],
    message: str,
    expected_status: int,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"DOCKER_HOST": ""} | overrides,
    )

    assert result.returncode == expected_status
    assert message in result.stderr
    assert not any("docker build" in call or "docker pull" in call for call in calls)


@pytest.mark.unit
def test_runner_rejects_unreachable_docker_engine(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, env_overrides={"DOCKER_VERSION_EXIT": "1"})

    assert result.returncode == 1
    assert "Docker Engine is unreachable" in result.stderr
    assert any("preflight-docker" in call for call in _supervisor_calls(calls))
    assert not any("docker pull" in call for call in calls)


@pytest.mark.unit
def test_runner_rejects_podman_api_behind_docker_cli(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        env_overrides={"DOCKER_SERVER_IDENTITY": "Podman Engine|Engine"},
    )

    assert result.returncode == 1
    assert "Podman compatibility endpoints are not supported" in result.stderr
    assert not any("docker pull" in call for call in calls)


@pytest.mark.unit
@pytest.mark.parametrize("version", ["2.32.1", "2.31.9", "1.29.2", "not-a-version"])
def test_runner_rejects_unsupported_or_invalid_compose(
    tmp_path: Path, version: str
) -> None:
    result, calls = _run_script(
        tmp_path, env_overrides={"DETECTED_COMPOSE_VERSION": version}
    )

    assert result.returncode == 1
    assert "Docker Compose" in result.stderr or "Compose version" in result.stderr
    assert not any("docker pull" in call for call in calls)


@pytest.mark.unit
def test_runner_rejects_missing_compose_plugin(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, env_overrides={"COMPOSE_VERSION_EXIT": "1"})

    assert result.returncode == 1
    assert "Docker Compose CLI plugin not found" in result.stderr
    assert not any("docker pull" in call for call in calls)


@pytest.mark.unit
@pytest.mark.parametrize(
    "endpoint",
    [
        "ssh://builder.example.test",
        "tcp://192.0.2.10:2376",
        "http://docker.example.test:2375",
        "https://198.51.100.8:2376",
        "https://[2001:db8::1]:2376",
        "tcp://user@127.0.0.1:2375",
        "tcp://127.0.0.999:2375",
        "tcp://127.0.0.1:2375/path",
        "invalid://endpoint",
    ],
)
def test_runner_rejects_remote_endpoint_before_candidate_work(
    tmp_path: Path, endpoint: str
) -> None:
    result, calls = _run_script(tmp_path, env_overrides={"DOCKER_HOST": endpoint})

    assert result.returncode == 1
    assert endpoint in result.stderr
    assert "DOCKER_HOST" in result.stderr
    assert not any("docker build" in call or "docker pull" in call for call in calls)


@pytest.mark.unit
def test_runner_rejects_remote_active_context_with_context_name(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "DOCKER_HOST": "",
            "DOCKER_CONTEXT": "remote-builder",
            "CONTEXT_ENDPOINT": "ssh://builder.example.test",
        },
    )

    assert result.returncode == 1
    assert "context 'remote-builder'" in result.stderr
    assert "ssh://builder.example.test" in result.stderr
    assert any("docker context inspect remote-builder" in call for call in calls)


@pytest.mark.unit
def test_runner_checks_active_context_even_with_local_docker_host(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "DOCKER_CONTEXT": "remote-builder",
            "CONTEXT_ENDPOINT": "ssh://builder.example.test",
        },
    )

    assert result.returncode == 1
    assert "context 'remote-builder'" in result.stderr
    assert "ssh://builder.example.test" in result.stderr
    assert any("docker context inspect remote-builder" in call for call in calls)
    assert not any("docker build" in call or "docker pull" in call for call in calls)


@pytest.mark.unit
def test_runner_accepts_local_active_context_and_tears_down_once(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"DOCKER_HOST": "", "DOCKER_CONTEXT": "desktop-linux"},
    )

    assert result.returncode == 0, result.stderr
    assert any("docker context show" in call for call in calls)
    assert any("docker context inspect desktop-linux" in call for call in calls)
    project = _project_from_up(calls)
    primary_down = [
        call
        for call in _docker_calls(calls)
        if f"docker compose -p {project} " in call and " down " in call
    ]
    assert len(primary_down) == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    "endpoint",
    [
        "unix:///var/run/docker.sock",
        "npipe:////./pipe/docker_engine",
        "tcp://127.0.0.1:2375",
        "tcp://127.12.34.56:2375",
        "http://localhost:2375",
        "https://[::1]:2376",
    ],
)
def test_runner_accepts_local_endpoint_variants(tmp_path: Path, endpoint: str) -> None:
    result, _ = _run_script(
        tmp_path, "--no-build", env_overrides={"DOCKER_HOST": endpoint}
    )

    assert result.returncode == 0, result.stderr
    assert endpoint in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    ("identity", "version"),
    [
        ("Docker Engine - Community", "2.32.2"),
        ("|Engine", "v2.32.2"),
        ("Docker Desktop 4.50.0", "2.40.3-desktop.1"),
        ("Docker Engine - Community", "3.0.0"),
    ],
)
def test_runner_preserves_supported_preflight_variants(
    tmp_path: Path, identity: str, version: str
) -> None:
    result, _ = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "DOCKER_SERVER_IDENTITY": identity,
            "DETECTED_COMPOSE_VERSION": version,
        },
    )

    assert result.returncode == 0, result.stderr
    assert f"Docker Compose {version}" in result.stdout


@pytest.mark.unit
def test_runner_propagates_unique_project_dynamic_url_and_candidate_context(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"COMPOSE_PORT": "127.0.0.1:54321"},
    )

    assert result.returncode == 0, result.stderr
    project = _project_from_up(calls)
    uv_call = next(call for call in calls if call.startswith("uv "))
    assert project.startswith("sentinel-smoke-")
    assert f"project={project}" in uv_call
    assert f"files={ROOT_DIR / 'docker-compose.smoke.yml'}" in uv_call
    assert f"image={IMAGE_ID}" in uv_call
    assert "base=http://127.0.0.1:54321" in uv_call
    assert "registry=/" in uv_call
    assert f"project={project}" in result.stdout
    assert "base_url=http://127.0.0.1:54321" in result.stdout


@pytest.mark.unit
def test_parallel_invocations_use_distinct_projects(tmp_path: Path) -> None:
    paths = [tmp_path / "one", tmp_path / "two"]
    for path in paths:
        path.mkdir()

    with ThreadPoolExecutor(max_workers=2) as executor:
        runs = list(executor.map(lambda path: _run_script(path, "--no-build"), paths))

    assert all(result.returncode == 0 for result, _ in runs)
    projects = [_project_from_up(calls) for _, calls in runs]
    assert len(set(projects)) == 2


@pytest.mark.unit
def test_runner_builds_exactly_once_then_pins_compose_to_image_id(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(tmp_path)

    assert result.returncode == 0, result.stderr
    docker_calls = _docker_calls(calls)
    builds = [call for call in docker_calls if call.startswith("docker build ")]
    assert builds == [
        f"docker build --tag sentinel-backend:smoke {ROOT_DIR / 'backend'}"
    ]
    up_call = next(call for call in docker_calls if " up " in call)
    assert up_call.endswith(" up -d --wait --no-build --pull never")
    assert not any("compose" in call and " build" in call for call in docker_calls)
    assert not any(
        " pull " in call and "postgres:18" not in call and "redis:8" not in call
        for call in docker_calls
    )


@pytest.mark.unit
def test_runner_propagates_initial_candidate_resolution_failure(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"IMAGE_INSPECT_EXIT": "14"},
    )

    assert result.returncode == 14
    assert "candidate image 'sentinel-backend:smoke' is not available locally" in (
        result.stderr
    )
    assert "phase=candidate exit=14" in result.stderr
    assert not any("docker pull" in call for call in calls)


@pytest.mark.unit
@pytest.mark.parametrize(
    "image_id",
    ["sentinel:latest", f"sha256:{'A' * 64}", f"sha256:{'a' * 63}"],
)
def test_runner_rejects_malformed_candidate_image_id(
    tmp_path: Path, image_id: str
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"LOCAL_IMAGE_ID": image_id},
    )

    assert result.returncode == 1
    assert f"Docker returned invalid image ID '{image_id}'" in result.stderr
    assert not any("docker pull" in call for call in calls)


@pytest.mark.unit
def test_runner_retains_original_candidate_reference_for_capture_and_drift(
    tmp_path: Path,
) -> None:
    candidate = "registry.example.test/sentinel:candidate"
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"SENTINEL_IMAGE": candidate},
    )

    assert result.returncode == 0, result.stderr
    inspect_calls = [
        call
        for call in _docker_calls(calls)
        if call.startswith(f"docker image inspect {candidate} ")
    ]
    assert len(inspect_calls) == 2
    assert f"candidate_image_id={IMAGE_ID}" in result.stdout


@pytest.mark.unit
def test_compose_pins_app_roles_and_uses_dynamic_loopback_port() -> None:
    compose = (ROOT_DIR / "docker-compose.smoke.yml").read_text(encoding="utf-8")

    assert "image: ${IMAGE_SMOKE_IMAGE_ID:?IMAGE_SMOKE_IMAGE_ID is required}" in compose
    assert "build:" not in compose
    assert "SENTINEL_IMAGE" not in compose
    assert "IMAGE_SMOKE_PORT" not in compose
    assert '- "127.0.0.1::8000"' in compose
    assert "image: postgres:18" in compose
    assert "image: redis:8" in compose
    api_section = compose.split("  api:\n", 1)[1].split("\n  migrate:\n", 1)[0]
    assert "command:" not in api_section
    assert "http://localhost:8000/ready" in api_section


@pytest.mark.unit
def test_runner_no_build_reuses_local_image_and_pulls_only_infrastructure(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(tmp_path, "--no-build")

    assert result.returncode == 0, result.stderr
    docker_calls = _docker_calls(calls)
    assert not any(call.startswith("docker build ") for call in docker_calls)
    assert [call for call in docker_calls if call.startswith("docker pull ")] == [
        "docker pull postgres:18",
        "docker pull redis:8",
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "mapping", ["0.0.0.0:49152", "localhost:49152", "127.0.0.1:0", "49152", ""]
)
def test_runner_strictly_rejects_invalid_discovered_port(
    tmp_path: Path, mapping: str
) -> None:
    result, calls = _run_script(
        tmp_path, "--no-build", env_overrides={"COMPOSE_PORT": mapping}
    )

    assert result.returncode != 0
    assert "invalid API" in result.stderr
    assert not any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
def test_runner_verifies_every_role_container_uses_candidate_image(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(tmp_path, "--no-build")

    assert result.returncode == 0, result.stderr
    project = _project_from_up(calls)
    verification_labels = [
        call.split()[1]
        for call in _supervisor_calls(calls)
        if call.startswith("supervisor image-verification-")
    ]
    assert verification_labels == [
        f"image-verification-{role}-{step}"
        for role in ROLE_CONTAINERS
        for step in ("container", "image")
    ]
    for role, container in ROLE_CONTAINERS.items():
        assert f"docker compose -p {project} " in next(
            call for call in calls if call.endswith(f" ps --all -q {role}")
        )
        assert f"docker inspect --format {{{{.Image}}}} {container}" in calls


@pytest.mark.unit
@pytest.mark.parametrize("role", list(ROLE_CONTAINERS))
def test_runner_rejects_role_image_substitution(tmp_path: Path, role: str) -> None:
    result, calls = _run_script(
        tmp_path, "--no-build", env_overrides={"ROLE_MISMATCH": role}
    )

    assert result.returncode == 1
    assert f"{role} container uses" in result.stderr
    assert not any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
def test_runner_detects_reference_drift_after_pytest(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"DRIFT_IMAGE_ID": DRIFTED_IMAGE_ID},
    )

    assert result.returncode == 1
    assert "drifted" in result.stderr
    assert any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
def test_runner_propagates_post_pytest_reference_resolution_failure(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"POST_IMAGE_INSPECT_EXIT": "15"},
    )

    assert result.returncode == 15
    assert "candidate reference 'sentinel-backend:smoke' no longer resolves" in (
        result.stderr
    )
    assert "phase=image-drift exit=15" in result.stderr
    assert any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
def test_pytest_failure_precedes_later_reference_drift(tmp_path: Path) -> None:
    result, _ = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"UV_EXIT": "7", "DRIFT_IMAGE_ID": DRIFTED_IMAGE_ID},
    )

    assert result.returncode == 7
    assert "phase=pytest exit=7" in result.stderr
    assert "drifted" in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    ("label", "override", "expected_phase"),
    [
        ("preflight-docker", "IMAGE_SMOKE_PREFLIGHT_TIMEOUT", "preflight"),
        ("infra-pull-postgres", "IMAGE_SMOKE_INFRA_PULL_TIMEOUT", "infra-pull"),
        ("local-build", "IMAGE_SMOKE_LOCAL_BUILD_TIMEOUT", "candidate"),
        ("startup", "IMAGE_SMOKE_STARTUP_TIMEOUT", "startup"),
        (
            "beat-readiness",
            "IMAGE_SMOKE_BEAT_READINESS_TIMEOUT",
            "beat-readiness",
        ),
        ("port-discovery", "IMAGE_SMOKE_PORT_DISCOVERY_TIMEOUT", "port-discovery"),
        (
            "image-verification-api-container",
            "IMAGE_SMOKE_IMAGE_VERIFICATION_TIMEOUT",
            "image-verification",
        ),
        (
            "image-id-capture",
            "IMAGE_SMOKE_IMAGE_VERIFICATION_TIMEOUT",
            "candidate",
        ),
        ("image-drift", "IMAGE_SMOKE_IMAGE_VERIFICATION_TIMEOUT", "image-drift"),
        ("pytest", "IMAGE_SMOKE_PYTEST_TIMEOUT", "pytest"),
    ],
)
def test_configured_stage_routes_through_supervisor_and_times_out(
    tmp_path: Path, label: str, override: str, expected_phase: str
) -> None:
    args = () if label == "local-build" else ("--no-build",)
    result, calls = _run_script(
        tmp_path,
        *args,
        env_overrides={"TIMEOUT_LABEL": label, override: "0.25"},
    )

    assert result.returncode == 124
    assert f"phase={expected_phase} exit=124" in result.stderr
    assert any(
        call.startswith(f"supervisor {label} timeout=0.25 ")
        for call in _supervisor_calls(calls)
    )


@pytest.mark.unit
def test_beat_readiness_requires_current_container_log_and_static_entry(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(tmp_path, "--no-build")

    assert result.returncode == 0, result.stderr
    beat_container = next(call for call in calls if " ps --all -q beat" in call)
    assert "sentinel-smoke-" in beat_container
    assert any(
        "docker inspect --format {{.State.Running}} dddddddddddd" in call
        for call in calls
    )
    assert any(
        "docker logs --timestamps --tail 200 dddddddddddd" in call for call in calls
    )
    assert any("docker exec dddddddddddd python -c" in call for call in calls)
    runner = SCRIPT_PATH.read_text(encoding="utf-8")
    assert "from redbeat.schedulers import ensure_conf" in runner
    assert "ensure_conf(celery_app)" in runner
    assert 'entry.task == "cleanup_sessions"' in runner
    assert "entry.enabled is True" in runner


@pytest.mark.unit
def test_beat_container_exit_fails_before_pytest(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"BEAT_RUNNING": "false"},
    )

    assert result.returncode == 1
    assert "phase=beat-readiness exit=1" in result.stderr
    assert "exited before readiness" in result.stderr
    assert not any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
def test_missing_beat_completion_marker_times_out_before_pytest(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "BEAT_LOG_READY": "0",
            "TIMEOUT_LABEL": "beat-readiness",
            "IMAGE_SMOKE_BEAT_READINESS_TIMEOUT": "0.25",
        },
    )

    assert result.returncode == 124
    assert "phase=beat-readiness exit=124" in result.stderr
    assert not any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
def test_missing_static_beat_entry_fails_before_pytest(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"BEAT_ENTRY_READY": "0"},
    )

    assert result.returncode == 6
    assert "phase=beat-readiness exit=6" in result.stderr
    assert not any(call.startswith("uv ") for call in calls)


@pytest.mark.unit
@pytest.mark.parametrize(
    "label",
    ["diagnostic-ps", "diagnostic-logs", "diagnostic-migrate", "diagnostic-images"],
)
def test_each_diagnostic_is_independently_supervised(
    tmp_path: Path, label: str
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "COMPOSE_UP_EXIT": "8",
            "TIMEOUT_LABEL": label,
            "IMAGE_SMOKE_DIAGNOSTIC_TIMEOUT": "0.25",
        },
    )

    assert result.returncode == 8
    assert any(
        call.startswith(f"supervisor {label} timeout=0.25 ")
        for call in _supervisor_calls(calls)
    )
    assert "Warning: diagnostic" in result.stderr


@pytest.mark.unit
def test_teardown_is_supervised_and_timeout_fails_green_run(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "TIMEOUT_LABEL_PREFIX": "teardown-",
            "IMAGE_SMOKE_TEARDOWN_TIMEOUT": "0.25",
        },
    )

    assert result.returncode == 124
    teardown_call = next(
        call
        for call in _supervisor_calls(calls)
        if call.startswith("supervisor teardown-")
    )
    assert "timeout=0.25" in teardown_call
    assert "phase=teardown exit=124" in result.stderr


@pytest.mark.unit
def test_startup_diagnostics_are_complete_and_ordered_before_teardown(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path, "--no-build", env_overrides={"COMPOSE_UP_EXIT": "8"}
    )

    assert result.returncode == 8
    output = result.stdout + result.stderr
    assert "phase=startup" in output
    assert "candidate_ref=sentinel-backend:smoke" in output
    assert f"candidate_image_id={IMAGE_ID}" in output
    assert "docker_endpoint=unix:///var/run/docker.sock" in output
    for evidence in (
        "compose ps --all JSON",
        "timestamped logs (tail=100)",
        "migrate exit evidence",
        "actual container image IDs",
    ):
        assert evidence in output
    diagnostic_index = next(
        index for index, call in enumerate(calls) if "diagnostic-ps" in call
    )
    teardown_index = next(
        index
        for index, call in enumerate(calls)
        if call.startswith("supervisor teardown-")
    )
    assert diagnostic_index < teardown_index


@pytest.mark.unit
def test_unexpected_termination_runs_diagnostics_and_owned_cleanup(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"ABORT_LABEL": "startup"},
    )

    assert result.returncode == 143
    assert "phase=interrupted" in result.stdout
    diagnostic_index = next(
        index for index, call in enumerate(calls) if "diagnostic-ps" in call
    )
    teardown_index = next(
        index
        for index, call in enumerate(calls)
        if call.startswith("supervisor teardown-sentinel-smoke-")
    )
    assert diagnostic_index < teardown_index


@pytest.mark.unit
def test_termination_before_startup_skips_diagnostics_and_cleans_registry(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        env_overrides={"ABORT_LABEL": "local-build"},
    )

    assert result.returncode == 143
    assert "Failure diagnostics" not in result.stdout
    assert not any("supervisor diagnostic-" in call for call in calls)
    assert any(call.startswith("supervisor teardown-registry") for call in calls)
    assert not any("docker compose" in call and " down " in call for call in calls)


@pytest.mark.unit
def test_pytest_failure_diagnostics_run_before_teardown(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "--no-build", env_overrides={"UV_EXIT": "7"})

    assert result.returncode == 7
    pytest_index = next(
        index for index, call in enumerate(calls) if call.startswith("uv ")
    )
    diagnostic_index = next(
        index for index, call in enumerate(calls) if "diagnostic-ps" in call
    )
    teardown_index = next(
        index
        for index, call in enumerate(calls)
        if call.startswith("supervisor teardown-")
    )
    assert pytest_index < diagnostic_index < teardown_index


@pytest.mark.unit
def test_diagnostic_failure_does_not_replace_primary_failure(tmp_path: Path) -> None:
    result, _ = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"COMPOSE_UP_EXIT": "8", "DIAGNOSTIC_PS_EXIT": "9"},
    )

    assert result.returncode == 8
    assert "diagnostic 'compose ps --all JSON' failed with exit 9" in result.stderr
    assert "phase=startup exit=8" in result.stderr


@pytest.mark.unit
def test_cleanup_failure_fails_green_but_not_earlier_red(tmp_path: Path) -> None:
    green_result, _ = _run_script(
        tmp_path / "green",
        "--no-build",
        env_overrides={"COMPOSE_DOWN_EXIT": "9"},
    )
    red_path = tmp_path / "red"
    red_path.mkdir()
    red_result, _ = _run_script(
        red_path,
        "--no-build",
        env_overrides={"UV_EXIT": "7", "COMPOSE_DOWN_EXIT": "9"},
    )

    assert green_result.returncode == 9
    assert "phase=teardown exit=9" in green_result.stderr
    assert red_result.returncode == 7
    assert "phase=pytest exit=7" in red_result.stderr
    assert "teardown failed" in red_result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(("pytest_exit", "expected_exit"), [("0", 9), ("7", 7)])
def test_disposable_cleanup_failure_obeys_first_error_precedence(
    tmp_path: Path, pytest_exit: str, expected_exit: int
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "REGISTER_DISPOSABLE": "1",
            "UV_EXIT": pytest_exit,
            "DISPOSABLE_DOWN_EXIT": "9",
        },
    )

    assert result.returncode == expected_exit
    assert "teardown failed for disposable project" in result.stderr
    down_calls = [
        call for call in calls if call.startswith("docker compose") and " down " in call
    ]
    assert len(down_calls) == 2
    assert "-isolated-deadbeef" in down_calls[0]
    assert "-isolated-deadbeef" not in down_calls[1]
    expected_phase = "teardown" if expected_exit == 9 else "pytest"
    assert f"phase={expected_phase} exit={expected_exit}" in result.stderr


@pytest.mark.unit
def test_pytest_timeout_cleans_registered_disposable_before_primary(
    tmp_path: Path,
) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={"TIMEOUT_LABEL": "pytest", "REGISTER_DISPOSABLE": "1"},
    )

    assert result.returncode == 124
    down_calls = [
        call for call in calls if call.startswith("docker compose") and " down " in call
    ]
    assert len(down_calls) == 2
    project = _project_from_up(calls)
    assert f"-p {project}-isolated-deadbeef " in down_calls[0]
    assert f"-p {project} " in down_calls[1]
    disposable_diagnostic_index = next(
        index
        for index, call in enumerate(calls)
        if call.startswith("docker compose")
        and f"-p {project}-isolated-deadbeef " in call
        and " ps --all --format json" in call
    )
    disposable_down_index = calls.index(down_calls[0])
    assert disposable_diagnostic_index < disposable_down_index


@pytest.mark.unit
def test_invalid_registry_record_is_never_targeted(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "--no-build",
        env_overrides={
            "REGISTER_DISPOSABLE": "1",
            "REGISTER_PROJECT": "unowned-project",
            "UV_EXIT": "7",
        },
    )

    assert result.returncode == 7
    assert "refusing unowned project registry entry 'unowned-project'" in result.stderr
    assert not any("-p unowned-project " in call for call in calls)


@pytest.mark.unit
def test_github_output_is_written_only_after_complete_success(tmp_path: Path) -> None:
    success_output = tmp_path / "success-output"
    failure_output = tmp_path / "failure-output"
    failure_output.touch()
    success_path = tmp_path / "success"
    success_path.mkdir()
    success_result, _ = _run_script(
        success_path,
        "--no-build",
        env_overrides={"GITHUB_OUTPUT": str(success_output)},
    )
    failure_path = tmp_path / "failure"
    failure_path.mkdir()
    failure_result, _ = _run_script(
        failure_path,
        "--no-build",
        env_overrides={
            "GITHUB_OUTPUT": str(failure_output),
            "COMPOSE_DOWN_EXIT": "9",
        },
    )

    assert success_result.returncode == 0
    assert success_output.read_text(encoding="utf-8") == f"image_id={IMAGE_ID}\n"
    assert failure_result.returncode == 9
    assert failure_output.read_text(encoding="utf-8") == ""


@pytest.mark.unit
def test_green_path_emits_no_failure_diagnostics(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "--no-build")

    assert result.returncode == 0
    assert "Failure diagnostics" not in result.stdout
    assert not any("supervisor diagnostic-" in call for call in calls)
