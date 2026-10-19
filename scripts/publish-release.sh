#!/usr/bin/env bash
# Attach the release SBOM, the Sigstore bundles of both image attestations, and
# the OpenAPI document to the draft GitHub Release of RELEASE_TAG, then publish
# the release. Publication is the last action: every asset must be in place
# before an immutable release locks them.

set -euo pipefail

require_sigstore_bundle() {
    local path="$1"

    if ! jq -e '.mediaType | startswith("application/vnd.dev.sigstore.bundle")' \
        "${path}" >/dev/null 2>&1; then
        echo "Not a Sigstore bundle: ${path}" >&2
        return 1
    fi
}

require_openapi_document() {
    local path="$1"
    local version="$2"

    # --slurp: the file must hold exactly one JSON value.
    if ! jq -e --slurp --arg version "${version}" \
        'length == 1 and (.[0].openapi | type == "string")
            and .[0].info.version == $version' \
        "${path}" >/dev/null 2>&1; then
        echo "Not the OpenAPI document of version ${version}: ${path}" >&2
        return 1
    fi
}

main() {
    : "${RELEASE_TAG:?RELEASE_TAG must identify the release tag}"
    : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must identify the repository}"
    : "${SBOM_PATH:?SBOM_PATH must name the validated release SBOM}"
    : "${SBOM_BUNDLE_PATH:?SBOM_BUNDLE_PATH must name the SBOM attestation bundle}"
    : "${PROVENANCE_BUNDLE_PATH:?PROVENANCE_BUNDLE_PATH must name the provenance attestation bundle}"
    : "${OPENAPI_PATH:?OPENAPI_PATH must name the OpenAPI document of the release image}"
    : "${RUNNER_TEMP:?RUNNER_TEMP must identify temporary storage}"

    local version asset_dir sbom_asset sbom_bundle_asset provenance_bundle_asset
    local openapi_asset immutable

    if [[ ! "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Release tag must have the form v<major>.<minor>.<patch>" >&2
        return 1
    fi
    version="${RELEASE_TAG#v}"

    if [[ "$(basename "${SBOM_PATH}")" != "sentinel-${version}.sbom.cdx.json" ]]; then
        echo "SBOM file name does not match release ${RELEASE_TAG}: ${SBOM_PATH}" >&2
        return 1
    fi
    if [[ ! -s "${SBOM_PATH}" ]]; then
        echo "SBOM file is missing or empty: ${SBOM_PATH}" >&2
        return 1
    fi
    require_sigstore_bundle "${SBOM_BUNDLE_PATH}"
    require_sigstore_bundle "${PROVENANCE_BUNDLE_PATH}"
    require_openapi_document "${OPENAPI_PATH}" "${version}"

    asset_dir="$(mktemp -d "${RUNNER_TEMP}/release-assets.XXXXXX")"
    sbom_asset="${asset_dir}/sentinel-${version}.sbom.cdx.json"
    sbom_bundle_asset="${asset_dir}/sentinel-${version}.sbom.sigstore.json"
    provenance_bundle_asset="${asset_dir}/sentinel-${version}.provenance.sigstore.json"
    openapi_asset="${asset_dir}/sentinel-${version}.openapi.json"
    cp -- "${SBOM_PATH}" "${sbom_asset}"
    cp -- "${SBOM_BUNDLE_PATH}" "${sbom_bundle_asset}"
    cp -- "${PROVENANCE_BUNDLE_PATH}" "${provenance_bundle_asset}"
    cp -- "${OPENAPI_PATH}" "${openapi_asset}"

    # --clobber keeps a rerun of a still-draft release idempotent.
    gh release upload "${RELEASE_TAG}" \
        "${sbom_asset}" "${sbom_bundle_asset}" "${provenance_bundle_asset}" \
        "${openapi_asset}" \
        --repo "${GITHUB_REPOSITORY}" --clobber
    gh release edit "${RELEASE_TAG}" --repo "${GITHUB_REPOSITORY}" --draft=false

    # Diagnostic only: the release is already published, so a missing
    # repository setting must not turn the publication into a failure.
    immutable="$(
        gh release view "${RELEASE_TAG}" --repo "${GITHUB_REPOSITORY}" \
            --json isImmutable --jq '.isImmutable'
    )" || immutable="unknown"
    if [[ "${immutable}" != "true" ]]; then
        echo "::warning::Release ${RELEASE_TAG} is not immutable (isImmutable=${immutable}); enable release immutability in the repository settings."
    fi
}

main "$@"
