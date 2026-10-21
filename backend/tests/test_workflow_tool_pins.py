"""Regression tests for the tool pins that Renovate tracks in the workflows.

`docs/deployment.md` (Workflow Conventions) requires every tool version a
workflow pins to be tracked by Renovate, and lists the forms that the
`renovate.jsonc` custom managers match. These tests keep the pins of the
`Shell Lint` job, the `uvx` tools, and the Swagger UI assets in those forms
with exact versions: a pin that leaves its form is silently dropped from
dependency extraction rather than rejected. See issue #1060.

The workflows are parsed as YAML (`tests/support/yaml_files.py`); only the
Renovate hint comments, which are not YAML data, and the `Makefile` are
read as text.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.support.yaml_files import (
    load_yaml_file,
    named_step,
    string_values,
    workflow_jobs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CI_PATH = WORKFLOWS_DIR / "ci.yml"
DEPLOY_API_DOCS_PATH = WORKFLOWS_DIR / "deploy-api-docs.yml"
MAKEFILE_PATH = REPO_ROOT / "Makefile"

EXACT_VERSION = r"\d+\.\d+\.\d+"

# The release repository of each tool the Shell Lint job downloads, by the
# env: entry that pins its version.
SHELL_TOOL_RELEASES = {
    "SHELLCHECK_VERSION": "koalaman/shellcheck",
    "SHFMT_VERSION": "mvdan/sh",
    "ACTIONLINT_VERSION": "rhysd/actionlint",
}

UVX_INVOCATION = re.compile(r"\buvx\s+\S+")
UVX_PIN = re.compile(
    rf"uvx\s+(?P<package>[A-Za-z0-9][A-Za-z0-9._-]*)@(?P<version>{EXACT_VERSION})"
)
UNPKG_URL = re.compile(r"https://unpkg\.com/[^\s\"']+")
SWAGGER_UI_ASSET = re.compile(
    rf"https://unpkg\.com/swagger-ui-dist@(?P<version>{EXACT_VERSION})/(?P<asset>[\w.-]+)"
)


def _uvx_pins(text: str) -> list[tuple[str, str]]:
    """The (package, version) pin of every `uvx` invocation in `text`; an
    invocation that is not `uvx <package>@<exact version>` fails."""
    pins: list[tuple[str, str]] = []
    for invocation in UVX_INVOCATION.findall(text):
        match = UVX_PIN.fullmatch(invocation)
        assert match, f"{invocation!r} is not uvx <package>@<exact version>"
        pins.append((match["package"], match["version"]))
    return pins


@pytest.mark.unit
def test_shell_lint_tool_versions_are_exact_and_carry_renovate_hints() -> None:
    # A value omits the v prefix of the release tag, which the download URL
    # adds, and the hint names the repository the job downloads from.
    job = workflow_jobs(load_yaml_file(CI_PATH))["shell-lint"]
    install_script = named_step(job, "Install pinned shell tooling")["run"]
    workflow = CI_PATH.read_text(encoding="utf-8")

    assert job["env"].keys() == SHELL_TOOL_RELEASES.keys()
    for name, repository in SHELL_TOOL_RELEASES.items():
        version = job["env"][name]
        assert re.fullmatch(EXACT_VERSION, version), name
        assert (
            f"https://github.com/{repository}/releases/download/v${{{name}}}/"
            in install_script
        ), name
        assert re.search(
            rf"# renovate: datasource=github-releases depName={re.escape(repository)}\n"
            rf"\s+{name}: \"{re.escape(version)}\"\n",
            workflow,
        ), name


@pytest.mark.unit
def test_uvx_tools_are_pinned_exactly_and_makefile_copy_matches_ci() -> None:
    # A bare `uvx <package>` resolves to the latest release and escapes
    # tracking. The Makefile security target matches the CI bandit pin.
    workflow_pins = [
        pin
        for path in sorted(WORKFLOWS_DIR.glob("*.yml"))
        for value in string_values(load_yaml_file(path))
        for pin in _uvx_pins(value)
    ]
    makefile_pins = _uvx_pins(MAKEFILE_PATH.read_text(encoding="utf-8"))

    assert {package for package, _ in workflow_pins} >= {"bandit", "pip-audit"}
    assert makefile_pins
    assert set(makefile_pins) <= set(workflow_pins)


@pytest.mark.unit
def test_swagger_ui_assets_share_one_exact_unpkg_version() -> None:
    jobs = workflow_jobs(load_yaml_file(DEPLOY_API_DOCS_PATH))
    site_script = named_step(jobs["build"], "Build Swagger UI static site")["run"]
    urls = UNPKG_URL.findall(site_script)
    assets = [SWAGGER_UI_ASSET.fullmatch(url) for url in urls]

    assert all(assets), urls
    assert sorted(asset["asset"] for asset in assets if asset) == [
        "swagger-ui-bundle.js",
        "swagger-ui.css",
    ]
    assert len({asset["version"] for asset in assets if asset}) == 1
