"""Regression tests for the tool pins that Renovate tracks in the workflows.

`docs/deployment.md` (Workflow Conventions) requires every tool version a
workflow pins to be tracked by Renovate, and lists the forms that the
`renovate.jsonc` custom managers match. These tests keep the pins of the
`Shell Lint` job, the `uvx` tools, and the Swagger UI assets in those forms
with exact versions: a pin that leaves its form is silently dropped from
dependency extraction rather than rejected. See issue #1060. The Swagger UI
of the API's `/docs` page shares the GitHub Pages site's pin, and the site
enables the operation filter (issue #1070).

The workflows are parsed as YAML (`tests/support/yaml_files.py`); only the
Renovate hint comments, which are not YAML data, the `Makefile`, and the
`/docs` page module are read as text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.api.interactive_docs import SWAGGER_UI_DIST
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
INTERACTIVE_DOCS_PATH = REPO_ROOT / "backend" / "app" / "api" / "interactive_docs.py"
RENOVATE_CONFIG_PATH = REPO_ROOT / "renovate.jsonc"

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


def _renovate_config() -> dict[str, Any]:
    """`renovate.jsonc` without its comments, which are whole lines."""
    lines = RENOVATE_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    document = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
    config: dict[str, Any] = json.loads(document)
    return config


def _workflow_files() -> list[Path]:
    return sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")})


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
        for path in _workflow_files()
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


@pytest.mark.unit
def test_pages_site_enables_the_operation_filter() -> None:
    jobs = workflow_jobs(load_yaml_file(DEPLOY_API_DOCS_PATH))
    site_script = named_step(jobs["build"], "Build Swagger UI static site")["run"]

    assert "filter: true," in site_script


@pytest.mark.unit
def test_unpkg_manager_extracts_both_swagger_ui_copies_on_one_version() -> None:
    # Renovate updates the GitHub Pages site and the API's /docs page in
    # one PR only while its unpkg manager extracts both as the same
    # dependency, and the page loads only the literal it extracts.
    manager = next(
        manager
        for manager in _renovate_config()["customManagers"]
        if manager.get("datasourceTemplate") == "npm"
    )
    file_patterns = [re.compile(p.strip("/")) for p in manager["managerFilePatterns"]]
    # Renovate's named groups use the JavaScript (?<name>) syntax.
    match_strings = [
        re.compile(string.replace("(?<", "(?P<")) for string in manager["matchStrings"]
    ]
    api_version = re.fullmatch(
        rf"https://unpkg\.com/swagger-ui-dist@(?P<version>{EXACT_VERSION})/",
        SWAGGER_UI_DIST,
    )
    assert api_version, SWAGGER_UI_DIST

    for path in (DEPLOY_API_DOCS_PATH, INTERACTIVE_DOCS_PATH):
        relative = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        extracted = {
            (match["depName"], match["currentValue"])
            for pattern in match_strings
            for match in pattern.finditer(text)
        }

        assert any(pattern.search(relative) for pattern in file_patterns), relative
        assert extracted == {("swagger-ui-dist", api_version["version"])}, relative
    assert UNPKG_URL.findall(INTERACTIVE_DOCS_PATH.read_text(encoding="utf-8")) == [
        SWAGGER_UI_DIST
    ]
