"""Contract tests for Sentinel's release-please policy.

`release-please-config.json` configures a `GenericToml` `extra-files`
updater that patches the `sentinel` package version entry inside
`backend/uv.lock` in the same commit as `backend/pyproject.toml`. This
avoids the race condition where a release PR bumps `pyproject.toml`
without `uv.lock`, causing `uv sync --locked` to fail in CI on the
first push (see PR #46, issue #81).

The updater relies on an undocumented detail of release-please's
internal TOML parser: JSONPath filters must address `@.name.value`
(not the more natural `@.name`) because release-please tags every
parsed TOML scalar as `{start, end, value}` to allow formatting-
preserving edits (see googleapis/release-please#2455). If a future
release-please version changes this internal representation, the
configured jsonpath would silently stop matching, `uv.lock` would no
longer be updated by the release PR, and `uv sync --locked` would fail
in CI on the next release — but only *after* a release PR is opened,
not at commit time on `master`.

This test catches that regression earlier and independently of
release-please's own behavior, by asserting the two invariants the
`extra-files` config depends on:

1. The config still points at `uv.lock` with the exact jsonpath
   selector currently known to work.
2. The `sentinel` package version recorded in `uv.lock` is not
   currently drifted from `pyproject.toml` — i.e., the workaround (or
   a manual `uv lock`) has been kept effective.

This does not simulate release-please's parser; it only guards the
static configuration and the current on-disk consistency. Actual
atomicity is verified manually on the next real release PR (see issue
#81, Verification).
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

_PACKAGE_NAME = "sentinel"
_EXPECTED_JSONPATH = f"$.package[?(@.name.value=='{_PACKAGE_NAME}')].version"
_EXPECTED_CHANGELOG_SECTIONS = [
    {"type": "feat", "section": "Features"},
    {"type": "fix", "section": "Bug Fixes"},
    {"type": "docs", "section": "Documentation", "hidden": True},
    {"type": "chore", "section": "Miscellaneous", "hidden": True},
    {"type": "ci", "section": "Continuous Integration", "hidden": True},
    {"type": "test", "section": "Tests", "hidden": True},
    {"type": "refactor", "section": "Code Refactoring", "hidden": True},
]


def _release_package_config() -> dict[str, Any]:
    """Return the single package policy from the release-please config."""
    config = json.loads(
        (REPO_ROOT / "release-please-config.json").read_text(encoding="utf-8")
    )
    assert set(config["packages"]) == {"backend"}
    return cast(dict[str, Any], config["packages"]["backend"])


@pytest.mark.unit
def test_release_please_config_preserves_single_platform_release_shape() -> None:
    package_config = _release_package_config()

    assert package_config["release-type"] == "python"
    assert package_config["package-name"] == _PACKAGE_NAME
    assert package_config["include-component-in-tag"] is False
    assert package_config["changelog-path"] == "/CHANGELOG.md"


@pytest.mark.unit
def test_release_please_config_uses_pre_major_minor_bumps() -> None:
    package_config = _release_package_config()

    assert package_config["bump-minor-pre-major"] is True
    assert "bump-patch-for-minor-pre-major" not in package_config


@pytest.mark.unit
def test_release_please_config_exposes_only_features_and_fixes() -> None:
    package_config = _release_package_config()

    assert package_config["changelog-sections"] == _EXPECTED_CHANGELOG_SECTIONS


@pytest.mark.unit
def test_release_please_config_creates_a_tagged_draft_release() -> None:
    # docs/deployment.md (Release Publication and Immutability): the release
    # stays a draft until build-images.yml attaches its assets and publishes
    # it. The tag must still be created immediately, because its push starts
    # build-images.yml and release-please finds the previous release by it.
    package_config = _release_package_config()

    assert package_config["draft"] is True
    assert package_config["force-tag-creation"] is True


@pytest.mark.unit
def test_release_please_config_pins_the_uv_lock_updater() -> None:
    package_config = _release_package_config()

    assert {
        "type": "toml",
        "path": "uv.lock",
        "jsonpath": _EXPECTED_JSONPATH,
    } in package_config.get("extra-files", []), (
        "release-please-config.json no longer configures the uv.lock "
        "extra-files updater for the 'backend' package; without it, "
        "release PRs bump pyproject.toml without updating uv.lock, "
        "reintroducing the `uv sync --locked` race condition fixed in "
        "issue #81"
    )


@pytest.mark.unit
def test_uv_lock_sentinel_entry_matches_the_selector_shape() -> None:
    lockfile = tomllib.loads((REPO_ROOT / "backend" / "uv.lock").read_text())
    matches = [
        package
        for package in lockfile.get("package", [])
        if package.get("name") == _PACKAGE_NAME
    ]

    assert len(matches) == 1, (
        f"Expected exactly one {_PACKAGE_NAME!r} entry in backend/uv.lock "
        f"(found {len(matches)}); the configured jsonpath "
        f"{_EXPECTED_JSONPATH!r} assumes a single match"
    )
    assert "version" in matches[0], (
        f"The {_PACKAGE_NAME!r} entry in backend/uv.lock has no 'version' "
        "field (e.g., it became a virtual/workspace member); the "
        "extra-files updater has nothing to patch"
    )


@pytest.mark.unit
def test_uv_lock_version_matches_pyproject_toml() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "backend" / "pyproject.toml").read_text())
    lockfile = tomllib.loads((REPO_ROOT / "backend" / "uv.lock").read_text())

    pyproject_version = pyproject["project"]["version"]
    locked_version = next(
        package["version"]
        for package in lockfile["package"]
        if package.get("name") == _PACKAGE_NAME
    )

    assert locked_version == pyproject_version, (
        f"backend/uv.lock pins {_PACKAGE_NAME}=={locked_version} but "
        f"backend/pyproject.toml declares version={pyproject_version!r}; "
        "run `uv lock` (from backend/) and commit the result, or verify "
        "the release-please extra-files updater actually ran on the "
        "latest release PR"
    )


@pytest.mark.unit
def test_release_manifest_version_matches_pyproject_toml() -> None:
    """`.release-please-manifest.json["backend"]` is release-please's
    record of the last version it released for the `backend` package
    (`docs/deployment.md`, Release Process -> Platform Version and Source of
    Truth). It must match `backend/pyproject.toml`'s `version` field — a drift
    here means either the manifest was hand-edited without a matching
    release, or a release PR merged without updating the manifest,
    either of which would cause release-please to compute the next
    version bump from a stale baseline.
    """
    pyproject = tomllib.loads((REPO_ROOT / "backend" / "pyproject.toml").read_text())
    manifest = json.loads((REPO_ROOT / ".release-please-manifest.json").read_text())

    pyproject_version = pyproject["project"]["version"]
    manifest_version = manifest["backend"]

    assert manifest_version == pyproject_version, (
        f".release-please-manifest.json declares backend={manifest_version!r} "
        f"but backend/pyproject.toml declares version={pyproject_version!r}; "
        "these must match so release-please computes the next version "
        "bump from the correct baseline"
    )
