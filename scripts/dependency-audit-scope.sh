#!/usr/bin/env bash
# Decide whether the CI dependency vulnerability scan (pip-audit) must run.
#
# The scan is required when a run can change or ship the locked dependency
# set (docs/features/platform/testing-strategy.md, CI Pipeline, gate 6):
#   - a pull request or push that modifies a dependency file below;
#   - a release-please Release PR (head branch "release-please--*");
#   - a manual (workflow_dispatch) or any other event;
#   - any run whose changed files cannot be determined (fail-safe).
#
# Usage (from a GitHub Actions step, inside a checkout that includes the
# base commit — a pull request merge commit needs fetch-depth >= 2):
#   EVENT_NAME=pull_request HEAD_REF=<branch> scripts/dependency-audit-scope.sh
#   EVENT_NAME=push PUSH_BEFORE=<sha> scripts/dependency-audit-scope.sh
#
# Writes "required=true|false" to $GITHUB_OUTPUT and a one-line reason to
# stdout.

set -euo pipefail

DEPENDENCY_FILES=(backend/pyproject.toml backend/uv.lock)
RELEASE_BRANCH_PREFIX="release-please--"

# Print the files among DEPENDENCY_FILES that differ between $1 and HEAD.
# Fails when the base commit is unavailable.
changed_dependency_files() {
    local base="$1"
    git rev-parse --quiet --verify "${base}^{commit}" >/dev/null ||
        git fetch --no-tags --quiet --depth=1 origin "${base}" >/dev/null 2>&1 ||
        return 1
    git diff --name-only "${base}" HEAD -- "${DEPENDENCY_FILES[@]}"
}

main() {
    : "${EVENT_NAME:?EVENT_NAME must name the triggering event}"
    : "${GITHUB_OUTPUT:?GITHUB_OUTPUT must identify the step output file}"

    local required=true reason base="" changed

    cd "$(git rev-parse --show-toplevel)"

    case "${EVENT_NAME}" in
        pull_request)
            if [[ "${HEAD_REF:-}" == "${RELEASE_BRANCH_PREFIX}"* ]]; then
                reason="release-please Release PR"
            else
                # First parent of the pull request merge commit is the base
                # branch tip the merge was computed against.
                base="HEAD^1"
            fi
            ;;
        push)
            base="${PUSH_BEFORE:-}"
            if [[ -z "${base}" || "${base}" =~ ^0+$ ]]; then
                base=""
                reason="push without a previous commit"
            fi
            ;;
        *)
            reason="${EVENT_NAME} run"
            ;;
    esac

    if [[ -n "${base}" ]]; then
        if changed="$(changed_dependency_files "${base}")"; then
            if [[ -n "${changed}" ]]; then
                reason="dependency files changed: ${changed//$'\n'/, }"
            else
                required=false
                reason="no dependency file changed"
            fi
        else
            reason="changed files could not be determined"
        fi
    fi

    echo "required=${required}" >>"${GITHUB_OUTPUT}"
    echo "Dependency audit required=${required} (${reason})"
}

main "$@"
