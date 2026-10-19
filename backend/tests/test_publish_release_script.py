"""Tests for draft-release publication (`scripts/publish-release.sh`).

Every release asset — the SBOM, the Sigstore bundles of both image
attestations, and the OpenAPI document — must be attached to the draft GitHub
Release before it is published, because release immutability locks the assets
on publication (`docs/deployment.md`, Release Supply-Chain Artifacts, Release
Publication and Immutability, and API Documentation Publication; issues #457
and #1036).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "publish-release.sh"

SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

# Logs every invocation; GH_STUB_FAIL_ON selects the failing release
# subcommand and GH_STUB_IMMUTABLE the `isImmutable` value reported by view.
GH_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "${GH_STUB_LOG}"
if [[ "${1:-}" == "release" && "${2:-}" == "${GH_STUB_FAIL_ON:-}" ]]; then
    exit 1
fi
if [[ "${1:-}" == "release" && "${2:-}" == "view" ]]; then
    echo "${GH_STUB_IMMUTABLE:-true}"
fi
"""


@dataclass(frozen=True)
class _Inputs:
    sbom: Path
    sbom_bundle: Path
    provenance_bundle: Path
    openapi: Path
    runner_temp: Path


def _bundle(path: Path, marker: str) -> Path:
    path.write_text(
        json.dumps({"mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE, "marker": marker}) + "\n",
        encoding="utf-8",
    )
    return path


def _openapi_document(version: str) -> str:
    return (
        json.dumps(
            {
                "openapi": "3.1.0",
                "info": {"title": "Sentinel", "version": version},
                "paths": {},
            }
        )
        + "\n"
    )


def _inputs(tmp_path: Path) -> _Inputs:
    source = tmp_path / "source"
    source.mkdir()
    sbom = source / "sentinel-1.2.3.sbom.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX"}\n', encoding="utf-8")
    # The workflow artifact keeps the extraction's unversioned file name.
    openapi = source / "openapi.json"
    openapi.write_text(_openapi_document("1.2.3"), encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    return _Inputs(
        sbom=sbom,
        sbom_bundle=_bundle(source / "sbom-attestation.json", "sbom"),
        provenance_bundle=_bundle(source / "provenance-attestation.json", "slsa"),
        openapi=openapi,
        runner_temp=runner_temp,
    )


def _run_publish(
    tmp_path: Path,
    inputs: _Inputs,
    *,
    tag: str = "v1.2.3",
    fail_on: str = "",
    immutable: str = "true",
    env_overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub_path = bin_dir / "gh"
    stub_path.write_text(GH_STUB, encoding="utf-8")
    stub_path.chmod(stub_path.stat().st_mode | stat.S_IEXEC)
    log_path = tmp_path / "gh.log"
    log_path.write_text("", encoding="utf-8")

    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_STUB_LOG": str(log_path),
        "GH_STUB_FAIL_ON": fail_on,
        "GH_STUB_IMMUTABLE": immutable,
        "RELEASE_TAG": tag,
        "GITHUB_REPOSITORY": "example/sentinel",
        "SBOM_PATH": str(inputs.sbom),
        "SBOM_BUNDLE_PATH": str(inputs.sbom_bundle),
        "PROVENANCE_BUNDLE_PATH": str(inputs.provenance_bundle),
        "OPENAPI_PATH": str(inputs.openapi),
        "RUNNER_TEMP": str(inputs.runner_temp),
    }
    env |= env_overrides or {}
    result = subprocess.run(
        [str(SCRIPT_PATH)], env=env, capture_output=True, text=True, check=False
    )
    return result, log_path.read_text(encoding="utf-8").splitlines()


def _uploaded_assets(gh_calls: list[str]) -> list[Path]:
    upload = next(call for call in gh_calls if call.startswith("release upload "))
    arguments = upload.split()
    return [Path(argument) for argument in arguments[3:7]]


@pytest.mark.unit
def test_publish_uploads_all_assets_before_publishing_the_draft(
    tmp_path: Path,
) -> None:
    inputs = _inputs(tmp_path)

    result, gh_calls = _run_publish(tmp_path, inputs)

    assert result.returncode == 0
    assert [call.split()[1] for call in gh_calls] == ["upload", "edit", "view"]
    upload, edit, view = gh_calls
    assert upload.startswith("release upload v1.2.3 ")
    assert upload.endswith(" --repo example/sentinel --clobber")
    assert edit == "release edit v1.2.3 --repo example/sentinel --draft=false"
    assert view == (
        "release view v1.2.3 --repo example/sentinel "
        "--json isImmutable --jq .isImmutable"
    )
    assert "::warning::" not in result.stdout


@pytest.mark.unit
def test_publish_names_release_assets_after_the_version(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    result, gh_calls = _run_publish(tmp_path, inputs)

    assert result.returncode == 0
    sbom, sbom_bundle, provenance_bundle, openapi = _uploaded_assets(gh_calls)
    assert [sbom.name, sbom_bundle.name, provenance_bundle.name, openapi.name] == [
        "sentinel-1.2.3.sbom.cdx.json",
        "sentinel-1.2.3.sbom.sigstore.json",
        "sentinel-1.2.3.provenance.sigstore.json",
        "sentinel-1.2.3.openapi.json",
    ]
    assert sbom.read_bytes() == inputs.sbom.read_bytes()
    assert sbom_bundle.read_bytes() == inputs.sbom_bundle.read_bytes()
    assert provenance_bundle.read_bytes() == inputs.provenance_bundle.read_bytes()
    assert openapi.read_bytes() == inputs.openapi.read_bytes()
    assert sbom.parent.parent == inputs.runner_temp
    assert {asset.parent for asset in (sbom_bundle, provenance_bundle, openapi)} == {
        sbom.parent
    }


@pytest.mark.unit
@pytest.mark.parametrize("fail_on", ["upload", "edit"])
def test_publish_stops_when_a_release_command_fails(
    tmp_path: Path, fail_on: str
) -> None:
    result, gh_calls = _run_publish(tmp_path, _inputs(tmp_path), fail_on=fail_on)

    assert result.returncode != 0
    assert gh_calls[-1].startswith(f"release {fail_on} ")
    if fail_on == "upload":
        assert not any(call.startswith("release edit") for call in gh_calls)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("fail_on", "immutable", "reported"),
    [("", "false", "isImmutable=false"), ("view", "true", "isImmutable=unknown")],
)
def test_publish_warns_without_failing_when_release_is_not_immutable(
    tmp_path: Path, fail_on: str, immutable: str, reported: str
) -> None:
    result, gh_calls = _run_publish(
        tmp_path, _inputs(tmp_path), fail_on=fail_on, immutable=immutable
    )

    assert result.returncode == 0
    assert any(call.startswith("release edit") for call in gh_calls)
    assert "::warning::Release v1.2.3 is not immutable" in result.stdout
    assert reported in result.stdout


@pytest.mark.unit
def test_publish_rejects_an_sbom_of_another_version(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    other = inputs.sbom.rename(inputs.sbom.with_name("sentinel-1.2.4.sbom.cdx.json"))

    result, gh_calls = _run_publish(tmp_path, replace(inputs, sbom=other))

    assert result.returncode != 0
    assert "SBOM file name does not match release v1.2.3" in result.stderr
    assert gh_calls == []


@pytest.mark.unit
def test_publish_rejects_an_empty_sbom(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    inputs.sbom.write_text("", encoding="utf-8")

    result, gh_calls = _run_publish(tmp_path, inputs)

    assert result.returncode != 0
    assert "SBOM file is missing or empty" in result.stderr
    assert gh_calls == []


@pytest.mark.unit
@pytest.mark.parametrize("bundle", ["sbom_bundle", "provenance_bundle"])
@pytest.mark.parametrize(
    "content",
    [None, "", "not json", '{"mediaType": "application/json"}', "{}"],
)
def test_publish_rejects_a_missing_or_foreign_attestation_bundle(
    tmp_path: Path, bundle: str, content: str | None
) -> None:
    inputs = _inputs(tmp_path)
    path: Path = getattr(inputs, bundle)
    if content is None:
        path.unlink()
    else:
        path.write_text(content, encoding="utf-8")

    result, gh_calls = _run_publish(tmp_path, inputs)

    assert result.returncode != 0
    assert f"Not a Sigstore bundle: {path}" in result.stderr
    assert gh_calls == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "content",
    [
        None,
        "",
        "not json",
        "[]",
        _openapi_document("1.2.4"),
        '{"info": {"version": "1.2.3"}, "paths": {}}',
        '{"openapi": "3.1.0", "paths": {}}',
    ],
)
def test_publish_refuses_without_the_openapi_document_of_the_release(
    tmp_path: Path, content: str | None
) -> None:
    inputs = _inputs(tmp_path)
    if content is None:
        inputs.openapi.unlink()
    else:
        inputs.openapi.write_text(content, encoding="utf-8")

    result, gh_calls = _run_publish(tmp_path, inputs)

    assert result.returncode != 0
    assert (
        f"Not the OpenAPI document of version 1.2.3: {inputs.openapi}" in result.stderr
    )
    assert gh_calls == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "variable",
    [
        "RELEASE_TAG",
        "GITHUB_REPOSITORY",
        "SBOM_PATH",
        "SBOM_BUNDLE_PATH",
        "PROVENANCE_BUNDLE_PATH",
        "OPENAPI_PATH",
        "RUNNER_TEMP",
    ],
)
def test_publish_requires_its_inputs(tmp_path: Path, variable: str) -> None:
    result, gh_calls = _run_publish(
        tmp_path, _inputs(tmp_path), env_overrides={variable: ""}
    )

    assert result.returncode != 0
    assert variable in result.stderr
    assert gh_calls == []


@pytest.mark.unit
@pytest.mark.parametrize("tag", ["1.2.3", "v1.2", 'v1.2.3";id'])
def test_publish_rejects_a_non_release_tag(tmp_path: Path, tag: str) -> None:
    result, gh_calls = _run_publish(tmp_path, _inputs(tmp_path), tag=tag)

    assert result.returncode != 0
    assert "Release tag must have the form" in result.stderr
    assert gh_calls == []
