#!/usr/bin/env bash
# Fail when the GitHub Release of RELEASE_TAG is already published. A
# published release is final: its image tags and release assets must never
# be replaced. A draft or a not yet created release passes. Any lookup error
# fails closed.

set -euo pipefail

main() {
    : "${RELEASE_TAG:?RELEASE_TAG must identify the release tag}"
    : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must identify the repository}"

    local releases published_url

    if [[ ! "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Release tag must have the form v<major>.<minor>.<patch>" >&2
        return 1
    fi

    # Only published releases are visible to every reader, so this listing
    # never depends on the token's ability to see drafts.
    releases="$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100")"
    published_url="$(
        jq -rs --arg tag "${RELEASE_TAG}" \
            '[.[][] | select(.tag_name == $tag and .draft == false)][0].html_url // empty' \
            <<<"${releases}"
    )"

    if [[ -n "${published_url}" ]]; then
        echo "Release ${RELEASE_TAG} is already published (${published_url})." >&2
        echo "Its image tags and release assets are final; ship changes as a new release." >&2
        return 1
    fi

    echo "Release ${RELEASE_TAG} is not published; publication may proceed."
}

main "$@"
