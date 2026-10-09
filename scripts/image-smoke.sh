#!/usr/bin/env bash
# Build or select one Sentinel image, run the Docker Compose image suite against
# that exact artifact, collect bounded failure evidence, and remove owned stacks.
#
# Usage: scripts/image-smoke.sh [--no-build]
#
# SENTINEL_IMAGE selects the candidate reference (default:
# sentinel-backend:smoke). IMAGE_SMOKE_*_TIMEOUT variables and
# IMAGE_SMOKE_TERM_GRACE tune finite lifecycle bounds in seconds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SMOKE_COMPOSE="${ROOT_DIR}/docker-compose.smoke.yml"
TIMEOUT_RUNNER="${SCRIPT_DIR}/run-with-timeout.py"
MINIMUM_COMPOSE_VERSION="2.32.2"

PREFLIGHT_TIMEOUT="${IMAGE_SMOKE_PREFLIGHT_TIMEOUT-20}"
INFRA_PULL_TIMEOUT="${IMAGE_SMOKE_INFRA_PULL_TIMEOUT-300}"
LOCAL_BUILD_TIMEOUT="${IMAGE_SMOKE_LOCAL_BUILD_TIMEOUT-900}"
STARTUP_TIMEOUT="${IMAGE_SMOKE_STARTUP_TIMEOUT-300}"
BEAT_READINESS_TIMEOUT="${IMAGE_SMOKE_BEAT_READINESS_TIMEOUT-45}"
PORT_DISCOVERY_TIMEOUT="${IMAGE_SMOKE_PORT_DISCOVERY_TIMEOUT-30}"
IMAGE_VERIFICATION_TIMEOUT="${IMAGE_SMOKE_IMAGE_VERIFICATION_TIMEOUT-30}"
PYTEST_TIMEOUT="${IMAGE_SMOKE_PYTEST_TIMEOUT-600}"
DIAGNOSTIC_TIMEOUT="${IMAGE_SMOKE_DIAGNOSTIC_TIMEOUT-20}"
TEARDOWN_TIMEOUT="${IMAGE_SMOKE_TEARDOWN_TIMEOUT-180}"
TERM_GRACE="${IMAGE_SMOKE_TERM_GRACE-10}"

NO_BUILD=0
CANDIDATE_REF="${SENTINEL_IMAGE:-sentinel-backend:smoke}"
CANDIDATE_ID=""
COMPOSE_VERSION=""
DOCKER_ENDPOINT=""
DOCKER_ENDPOINT_SOURCE=""
IMAGE_SMOKE_BASE_URL=""
PROJECT_ACTIVE=0
PRIMARY_STATUS=0
FAILURE_PHASE=""
REGISTRY_DIR=""
IMAGE_SMOKE_PROJECT_REGISTRY=""
FINALIZED=0

validate_positive_bound() {
    local name="$1"
    local value="$2"
    if [[ ! "${value}" =~ ^[0-9]+([.][0-9]+)?$ || ! "${value}" =~ [1-9] ]]; then
        echo "Error: ${name} must be a finite number greater than zero; got '${value}'." >&2
        return 1
    fi
}

validate_nonnegative_bound() {
    local name="$1"
    local value="$2"
    if [[ ! "${value}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "Error: ${name} must be a finite non-negative number; got '${value}'." >&2
        return 1
    fi
}

validate_bounds() {
    validate_positive_bound IMAGE_SMOKE_PREFLIGHT_TIMEOUT "${PREFLIGHT_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_INFRA_PULL_TIMEOUT "${INFRA_PULL_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_LOCAL_BUILD_TIMEOUT "${LOCAL_BUILD_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_STARTUP_TIMEOUT "${STARTUP_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_BEAT_READINESS_TIMEOUT "${BEAT_READINESS_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_PORT_DISCOVERY_TIMEOUT "${PORT_DISCOVERY_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_IMAGE_VERIFICATION_TIMEOUT "${IMAGE_VERIFICATION_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_PYTEST_TIMEOUT "${PYTEST_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_DIAGNOSTIC_TIMEOUT "${DIAGNOSTIC_TIMEOUT}" &&
        validate_positive_bound IMAGE_SMOKE_TEARDOWN_TIMEOUT "${TEARDOWN_TIMEOUT}" &&
        validate_nonnegative_bound IMAGE_SMOKE_TERM_GRACE "${TERM_GRACE}"
}

run_bounded() {
    local label="$1"
    local timeout="$2"
    shift 2
    python3 "${TIMEOUT_RUNNER}" \
        --label "${label}" \
        --timeout "${timeout}" \
        --grace-period "${TERM_GRACE}" \
        -- "$@"
}

capture_bounded() {
    local destination_name="$1"
    local label="$2"
    local timeout="$3"
    local output
    shift 3
    local status=0
    output="$(run_bounded "${label}" "${timeout}" "$@")" || status=$?
    printf -v "${destination_name}" '%s' "${output}"
    return "${status}"
}

record_failure() {
    local status="$1"
    local phase="$2"
    if ((PRIMARY_STATUS == 0)); then
        PRIMARY_STATUS="${status}"
        FAILURE_PHASE="${phase}"
    fi
}

endpoint_is_local() {
    local endpoint="$1"
    local remainder authority host port octet
    local -a octets
    case "${endpoint}" in
        unix://?* | npipe://?*) return 0 ;;
        ssh://*) return 1 ;;
        tcp://* | http://* | https://*)
            remainder="${endpoint#*://}"
            [[ "${remainder}" != */* ]] || return 1
            authority="${remainder%%/*}"
            [[ "${authority}" != *"@"* ]] || return 1
            if [[ "${authority}" == \[* ]]; then
                [[ "${authority}" =~ ^\[::1\]:([0-9]+)$ ]] || return 1
                port="${BASH_REMATCH[1]}"
            else
                [[ "${authority}" == *:* ]] || return 1
                host="${authority%:*}"
                port="${authority##*:}"
                if [[ "${host}" != "localhost" && ! "${host}" =~ ^127(\.[0-9]{1,3}){3}$ ]]; then
                    return 1
                fi
                if [[ "${host}" != "localhost" ]]; then
                    IFS=. read -r -a octets <<<"${host}"
                    for octet in "${octets[@]}"; do
                        ((10#${octet} <= 255)) || return 1
                    done
                fi
            fi
            [[ "${port}" =~ ^[0-9]+$ ]] || return 1
            ((10#${port} >= 1 && 10#${port} <= 65535))
            ;;
        *) return 1 ;;
    esac
}

resolve_docker_endpoint() {
    local context context_endpoint status
    if capture_bounded context preflight-context "${PREFLIGHT_TIMEOUT}" \
        docker context show; then
        :
    else
        status=$?
        echo "Error: cannot resolve the active Docker context." >&2
        return "${status}"
    fi
    if [[ -z "${context}" ]]; then
        echo "Error: Docker returned an empty active context name." >&2
        return 1
    fi
    if capture_bounded context_endpoint preflight-endpoint "${PREFLIGHT_TIMEOUT}" \
        docker context inspect "${context}" \
        --format '{{(index .Endpoints "docker").Host}}'; then
        :
    else
        status=$?
        echo "Error: cannot inspect Docker endpoint for context '${context}'." >&2
        return "${status}"
    fi
    if [[ -z "${context_endpoint}" ]] || ! endpoint_is_local "${context_endpoint}"; then
        echo "Error: image smoke requires a local Docker endpoint because host pytest connects to a loopback-published API port." >&2
        echo "Endpoint '${context_endpoint:-unknown}' from context '${context}' is not local; use a unix/npipe endpoint or loopback TCP context, not ssh or a remote host." >&2
        return 1
    fi

    DOCKER_ENDPOINT="${context_endpoint}"
    DOCKER_ENDPOINT_SOURCE="context '${context}'"
    if [[ -n "${DOCKER_HOST-}" ]]; then
        if ! endpoint_is_local "${DOCKER_HOST}"; then
            echo "Error: image smoke requires a local Docker endpoint because host pytest connects to a loopback-published API port." >&2
            echo "Endpoint '${DOCKER_HOST}' from DOCKER_HOST is not local; unset DOCKER_HOST or use a unix/npipe or loopback TCP endpoint." >&2
            return 1
        fi
        DOCKER_ENDPOINT="${DOCKER_HOST}"
        DOCKER_ENDPOINT_SOURCE="DOCKER_HOST (active context '${context}' also verified)"
    fi
}

check_docker_environment() {
    local server_identity compose_version status
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker CLI not found." >&2
        echo "Install Docker Engine or Docker Desktop with Docker Compose ${MINIMUM_COMPOSE_VERSION} or later." >&2
        return 1
    fi
    if ! command -v python3 &>/dev/null || [[ ! -f "${TIMEOUT_RUNNER}" ]]; then
        echo "Error: Python 3 and scripts/run-with-timeout.py are required." >&2
        return 1
    fi

    resolve_docker_endpoint || return $?

    if capture_bounded server_identity preflight-docker "${PREFLIGHT_TIMEOUT}" \
        docker version --format '{{.Server.Platform.Name}}|{{(index .Server.Components 0).Name}}'; then
        :
    else
        status=$?
        echo "Error: Docker Engine is unreachable at '${DOCKER_ENDPOINT}' (${DOCKER_ENDPOINT_SOURCE})." >&2
        return "${status}"
    fi
    case "${server_identity}" in
        Docker\ Engine* | Docker\ Desktop* | \|Engine) ;;
        *)
            echo "Error: unsupported container server '${server_identity:-unknown}'." >&2
            echo "The image-smoke harness requires Docker Engine or Docker Desktop; Podman compatibility endpoints are not supported." >&2
            return 1
            ;;
    esac

    if capture_bounded compose_version preflight-compose "${PREFLIGHT_TIMEOUT}" \
        docker compose version --short; then
        :
    else
        status=$?
        echo "Error: Docker Compose CLI plugin not found." >&2
        echo "Install Docker Compose ${MINIMUM_COMPOSE_VERSION} or later." >&2
        return "${status}"
    fi
    if [[ ! "${compose_version}" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)([-+._][0-9A-Za-z.+_-]+)?$ ]]; then
        echo "Error: unable to parse Docker Compose version '${compose_version}'." >&2
        return 1
    fi
    local major="${BASH_REMATCH[1]}"
    local minor="${BASH_REMATCH[2]}"
    local patch="${BASH_REMATCH[3]}"
    local unsupported=0
    if ((major < 2)); then
        unsupported=1
    elif ((major == 2 && minor < 32)); then
        unsupported=1
    elif ((major == 2 && minor == 32 && patch < 2)); then
        unsupported=1
    fi
    if ((unsupported)); then
        echo "Error: Docker Compose ${compose_version} is unsupported; ${MINIMUM_COMPOSE_VERSION} or later is required." >&2
        return 1
    fi
    COMPOSE_VERSION="${compose_version}"
}

resolve_candidate() {
    local status=0
    if ((NO_BUILD == 0)); then
        echo "[image-smoke] Building candidate once: ${CANDIDATE_REF}"
        run_bounded local-build "${LOCAL_BUILD_TIMEOUT}" \
            docker build --tag "${CANDIDATE_REF}" "${ROOT_DIR}/backend" || status=$?
        ((status == 0)) || return "${status}"
    fi

    if capture_bounded CANDIDATE_ID image-id-capture \
        "${IMAGE_VERIFICATION_TIMEOUT}" docker image inspect "${CANDIDATE_REF}" \
        --format '{{.Id}}'; then
        :
    else
        status=$?
        echo "Error: candidate image '${CANDIDATE_REF}' is not available locally." >&2
        return "${status}"
    fi
    if [[ ! "${CANDIDATE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "Error: Docker returned invalid image ID '${CANDIDATE_ID}' for '${CANDIDATE_REF}'." >&2
        return 1
    fi
    export IMAGE_SMOKE_IMAGE_ID="${CANDIDATE_ID}"
}

pull_infrastructure() {
    local image status=0
    # Keep this list aligned with the infrastructure image declarations in
    # docker-compose.smoke.yml; startup itself also rejects pulls explicitly.
    for image in postgres:18 redis:8; do
        run_bounded "infra-pull-${image%%:*}" "${INFRA_PULL_TIMEOUT}" \
            docker pull "${image}" || status=$?
        ((status == 0)) || return "${status}"
    done
}

start_stack() {
    PROJECT_ACTIVE=1
    run_bounded startup "${STARTUP_TIMEOUT}" docker compose \
        -p "${COMPOSE_PROJECT}" -f "${SMOKE_COMPOSE}" \
        up -d --wait --no-build --pull never
}

wait_for_beat_readiness() {
    local container status
    if capture_bounded container beat-container "${IMAGE_VERIFICATION_TIMEOUT}" \
        docker compose -p "${COMPOSE_PROJECT}" -f "${SMOKE_COMPOSE}" \
        ps --all -q beat; then
        :
    else
        status=$?
        echo "Error: cannot resolve the Beat container in project '${COMPOSE_PROJECT}'." >&2
        return "${status}"
    fi
    if [[ ! "${container}" =~ ^[0-9a-f]{12,64}$ ]]; then
        echo "Error: invalid or missing Beat container ID '${container}'." >&2
        return 1
    fi

    # shellcheck disable=SC2016  # inner Bash receives the container as $1
    run_bounded beat-readiness "${BEAT_READINESS_TIMEOUT}" bash -c '
        set -euo pipefail
        container="$1"
        while true; do
            running="$(docker inspect --format "{{.State.Running}}" "${container}")"
            if [[ "${running}" != "true" ]]; then
                echo "Error: Beat container ${container} exited before readiness." >&2
                exit 1
            fi
            logs="$(docker logs --timestamps --tail 200 "${container}" 2>&1)"
            if [[ "${logs}" == *beat_startup_completed* ]]; then
                break
            fi
            sleep 1
        done

        docker exec "${container}" python -c '\''
from app.celery_app import celery_app
from redbeat import RedBeatSchedulerEntry
from redbeat.schedulers import ensure_conf

ensure_conf(celery_app)
key = RedBeatSchedulerEntry.generate_key(celery_app, "cleanup_sessions")
entry = RedBeatSchedulerEntry.from_key(key, app=celery_app)
assert entry.task == "cleanup_sessions", entry.task
assert entry.enabled is True, entry.enabled
print("BEAT-READY")
'\''
    ' bash "${container}"
}

discover_api_port() {
    local mapping port status
    if capture_bounded mapping port-discovery "${PORT_DISCOVERY_TIMEOUT}" \
        docker compose -p "${COMPOSE_PROJECT}" -f "${SMOKE_COMPOSE}" \
        port api 8000; then
        :
    else
        status=$?
        echo "Error: could not discover the API port for project '${COMPOSE_PROJECT}'." >&2
        return "${status}"
    fi
    if [[ ! "${mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
        echo "Error: invalid API port mapping '${mapping}'; expected 127.0.0.1:<port>." >&2
        return 1
    fi
    port="${BASH_REMATCH[1]}"
    if ((10#${port} < 1 || 10#${port} > 65535)); then
        echo "Error: invalid API host port '${port}'." >&2
        return 1
    fi
    IMAGE_SMOKE_BASE_URL="http://127.0.0.1:${port}"
    export IMAGE_SMOKE_BASE_URL
}

verify_role_images() {
    local role container actual status
    # Every application role in docker-compose.smoke.yml; worker and
    # git-worker readiness is their per-node Compose healthcheck (up --wait).
    for role in api migrate worker git-worker beat; do
        if capture_bounded container "image-verification-${role}-container" \
            "${IMAGE_VERIFICATION_TIMEOUT}" docker compose \
            -p "${COMPOSE_PROJECT}" -f "${SMOKE_COMPOSE}" \
            ps --all -q "${role}"; then
            :
        else
            status=$?
            echo "Error: cannot resolve ${role} container in project '${COMPOSE_PROJECT}'." >&2
            return "${status}"
        fi
        if [[ ! "${container}" =~ ^[0-9a-f]{12,64}$ ]]; then
            echo "Error: invalid or missing ${role} container ID '${container}'." >&2
            return 1
        fi
        if capture_bounded actual "image-verification-${role}-image" \
            "${IMAGE_VERIFICATION_TIMEOUT}" docker inspect --format '{{.Image}}' \
            "${container}"; then
            :
        else
            status=$?
            echo "Error: cannot inspect image for ${role} container '${container}'." >&2
            return "${status}"
        fi
        if [[ "${actual}" != "${CANDIDATE_ID}" ]]; then
            echo "Error: ${role} container uses '${actual}', expected candidate '${CANDIDATE_ID}'." >&2
            return 1
        fi
    done
}

run_pytest() {
    local status=0
    export COMPOSE_PROJECT COMPOSE_FILES IMAGE_SMOKE_PROJECT_REGISTRY
    (
        cd "${ROOT_DIR}/backend"
        run_bounded pytest "${PYTEST_TIMEOUT}" uv run pytest -m image tests/image/
    ) || status=$?
    return "${status}"
}

verify_candidate_drift() {
    local current status
    if capture_bounded current image-drift "${IMAGE_VERIFICATION_TIMEOUT}" \
        docker image inspect "${CANDIDATE_REF}" --format '{{.Id}}'; then
        :
    else
        status=$?
        echo "Error: candidate reference '${CANDIDATE_REF}' no longer resolves after pytest." >&2
        return "${status}"
    fi
    if [[ "${current}" != "${CANDIDATE_ID}" ]]; then
        echo "Error: candidate reference '${CANDIDATE_REF}' drifted from '${CANDIDATE_ID}' to '${current}'." >&2
        return 1
    fi
}

run_diagnostic() {
    local title="$1"
    local label="$2"
    shift 2
    local status=0
    echo "[image-smoke] Diagnostic: ${title}"
    run_bounded "diagnostic-${label}" "${DIAGNOSTIC_TIMEOUT}" "$@" || status=$?
    if ((status != 0)); then
        echo "Warning: diagnostic '${title}' failed with exit ${status}." >&2
    fi
}

capture_diagnostics() {
    local project="${1:-${COMPOSE_PROJECT}}"
    local container_output status container
    local -a containers=()
    echo "[image-smoke] Failure diagnostics"
    echo "phase=${FAILURE_PHASE}"
    echo "project=${project}"
    echo "candidate_ref=${CANDIDATE_REF}"
    echo "candidate_image_id=${CANDIDATE_ID:-unknown}"
    echo "docker_endpoint=${DOCKER_ENDPOINT:-unknown}"
    echo "base_url=${IMAGE_SMOKE_BASE_URL:-unknown}"

    run_diagnostic "compose ps --all JSON" ps \
        docker compose -p "${project}" -f "${SMOKE_COMPOSE}" \
        ps --all --format json
    run_diagnostic "timestamped logs (tail=100)" logs \
        docker compose -p "${project}" -f "${SMOKE_COMPOSE}" \
        logs --timestamps --tail 100 --no-color
    run_diagnostic "migrate exit evidence" migrate \
        docker compose -p "${project}" -f "${SMOKE_COMPOSE}" \
        ps --all --format json migrate

    status=0
    container_output="$(run_bounded diagnostic-container-list \
        "${DIAGNOSTIC_TIMEOUT}" docker compose \
        -p "${project}" -f "${SMOKE_COMPOSE}" ps --all -q)" || status=$?
    if ((status != 0)); then
        echo "Warning: diagnostic 'container list' failed with exit ${status}." >&2
        return
    fi
    mapfile -t containers <<<"${container_output}"
    for container in "${containers[@]}"; do
        if [[ -n "${container}" && ! "${container}" =~ ^[0-9a-f]{12,64}$ ]]; then
            echo "Warning: diagnostic returned invalid container ID '${container}'." >&2
            return
        fi
    done
    if ((${#containers[@]} > 0)) && [[ -n "${containers[0]}" ]]; then
        run_diagnostic "actual container image IDs" images \
            docker inspect --format '{{.Name}} {{.Image}}' "${containers[@]}"
    else
        echo "[image-smoke] Diagnostic: actual container image IDs"
        echo "[no containers]"
    fi
}

valid_disposable_project() {
    local project="$1"
    [[ "${project}" =~ ^[a-z0-9][a-z0-9_-]*$ &&
        "${project}" =~ ^${COMPOSE_PROJECT}-isolated-[a-z0-9][a-z0-9_-]*$ ]]
}

teardown_project() {
    local project="$1"
    run_bounded "teardown-${project}" "${TEARDOWN_TIMEOUT}" \
        docker compose -p "${project}" -f "${SMOKE_COMPOSE}" \
        down -v --remove-orphans
}

cleanup() {
    local project status
    local cleanup_status=0

    if [[ -n "${IMAGE_SMOKE_PROJECT_REGISTRY}" && -f "${IMAGE_SMOKE_PROJECT_REGISTRY}" ]]; then
        while IFS= read -r project || [[ -n "${project}" ]]; do
            if ! valid_disposable_project "${project}"; then
                echo "Error: refusing unowned project registry entry '${project}'." >&2
                ((cleanup_status == 0)) && cleanup_status=1
                continue
            fi
            if [[ "${FAILURE_PHASE}" == "pytest" && "${PRIMARY_STATUS}" -eq 124 ]]; then
                capture_diagnostics "${project}"
            fi
            status=0
            teardown_project "${project}" || status=$?
            if ((status != 0)); then
                echo "Error: teardown failed for disposable project '${project}' with exit ${status}." >&2
                ((cleanup_status == 0)) && cleanup_status="${status}"
            fi
        done <"${IMAGE_SMOKE_PROJECT_REGISTRY}"
    fi

    if ((PROJECT_ACTIVE)); then
        status=0
        teardown_project "${COMPOSE_PROJECT}" || status=$?
        if ((status != 0)); then
            echo "Error: teardown failed for primary project '${COMPOSE_PROJECT}' with exit ${status}." >&2
            ((cleanup_status == 0)) && cleanup_status="${status}"
        fi
    fi
    if [[ -n "${REGISTRY_DIR}" ]]; then
        status=0
        run_bounded teardown-registry "${TEARDOWN_TIMEOUT}" \
            rm -rf "${REGISTRY_DIR}" || status=$?
        if ((status != 0)); then
            echo "Error: temporary project registry cleanup failed with exit ${status}." >&2
            ((cleanup_status == 0)) && cleanup_status="${status}"
        fi
    fi
    return "${cleanup_status}"
}

# shellcheck disable=SC2317,SC2329  # invoked indirectly by the EXIT trap
emergency_cleanup() {
    local exit_status=$?
    local cleanup_status=0
    if ((FINALIZED)); then
        return 0
    fi
    trap - EXIT
    if ((PROJECT_ACTIVE && exit_status != 0)); then
        [[ -n "${FAILURE_PHASE}" ]] || FAILURE_PHASE="interrupted"
        capture_diagnostics
    fi
    cleanup || cleanup_status=$?
    if ((exit_status == 0 && cleanup_status != 0)); then
        exit_status="${cleanup_status}"
    fi
    exit "${exit_status}"
}

# shellcheck disable=SC2317,SC2329  # invoked indirectly by signal traps
handle_signal() {
    local signal_number="$1"
    exit "$((128 + signal_number))"
}

main() {
    local arg token status cleanup_status output_status
    for arg in "$@"; do
        case "${arg}" in
            --no-build) NO_BUILD=1 ;;
            *)
                echo "Error: unknown argument '${arg}'" >&2
                echo "Usage: scripts/image-smoke.sh [--no-build]" >&2
                return 1
                ;;
        esac
    done
    validate_bounds || return $?

    REGISTRY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-image-smoke.XXXXXXXXXX")"
    trap emergency_cleanup EXIT
    trap 'handle_signal 2' INT
    trap 'handle_signal 15' TERM
    token="$(printf '%s' "${REGISTRY_DIR##*.}" | tr '[:upper:]' '[:lower:]')"
    COMPOSE_PROJECT="sentinel-smoke-$$-${token}"
    IMAGE_SMOKE_PROJECT_REGISTRY="${REGISTRY_DIR}/projects"
    : >"${IMAGE_SMOKE_PROJECT_REGISTRY}"
    COMPOSE_FILES="${SMOKE_COMPOSE}"
    export COMPOSE_PROJECT COMPOSE_FILES IMAGE_SMOKE_PROJECT_REGISTRY

    status=0
    check_docker_environment || status=$?
    if ((status != 0)); then
        record_failure "${status}" preflight
    else
        echo "[image-smoke] Using Docker Compose ${COMPOSE_VERSION} at ${DOCKER_ENDPOINT}"

        status=0
        resolve_candidate || status=$?
        ((status == 0)) || record_failure "${status}" candidate

        if ((PRIMARY_STATUS == 0)); then
            status=0
            pull_infrastructure || status=$?
            ((status == 0)) || record_failure "${status}" infra-pull
        fi

        if ((PRIMARY_STATUS == 0)); then
            status=0
            start_stack || status=$?
            ((status == 0)) || record_failure "${status}" startup
        fi

        if ((PRIMARY_STATUS == 0)); then
            status=0
            wait_for_beat_readiness || status=$?
            ((status == 0)) || record_failure "${status}" beat-readiness
        fi

        if ((PRIMARY_STATUS == 0)); then
            status=0
            discover_api_port || status=$?
            ((status == 0)) || record_failure "${status}" port-discovery
        fi

        if ((PRIMARY_STATUS == 0)); then
            status=0
            verify_role_images || status=$?
            ((status == 0)) || record_failure "${status}" image-verification
        fi

        if ((PRIMARY_STATUS == 0)); then
            status=0
            run_pytest || status=$?
            ((status == 0)) || record_failure "${status}" pytest

            status=0
            verify_candidate_drift || status=$?
            ((status == 0)) || record_failure "${status}" image-drift
        fi
    fi

    if ((PROJECT_ACTIVE && PRIMARY_STATUS != 0)); then
        capture_diagnostics
    fi

    cleanup_status=0
    cleanup || cleanup_status=$?
    if ((cleanup_status != 0)); then
        record_failure "${cleanup_status}" teardown
    fi
    FINALIZED=1

    if ((PRIMARY_STATUS == 0)) && [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        output_status=0
        printf 'image_id=%s\n' "${CANDIDATE_ID}" >>"${GITHUB_OUTPUT}" || output_status=$?
        if ((output_status != 0)); then
            echo "Error: could not append image_id to GITHUB_OUTPUT '${GITHUB_OUTPUT}'." >&2
            record_failure "${output_status}" github-output
        fi
    fi

    if ((PRIMARY_STATUS == 0)); then
        echo "[image-smoke] Green: project=${COMPOSE_PROJECT} candidate_image_id=${CANDIDATE_ID} base_url=${IMAGE_SMOKE_BASE_URL}"
    else
        echo "[image-smoke] Failed: phase=${FAILURE_PHASE} exit=${PRIMARY_STATUS}" >&2
    fi
    return "${PRIMARY_STATUS}"
}

main "$@"
