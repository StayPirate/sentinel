"""Regression tests for the build-images workflow's build/smoke/publish
pipeline (`.github/workflows/build-images.yml`).

Covers two related invariants:

1. **Fail-fast push loop**: prior to a fix, a failed intermediate
   `docker push` inside the tag loop was masked — the step's exit code
   was that of the *last* loop iteration, so a transient failure on an
   earlier tag went undetected as long as the final iteration
   succeeded. See issue #69.
2. **Single build, tested artifact published unchanged**: the image is
   built exactly once (`push: false`, `load: true`), the blocking smoke
   gate runs against that exact local artifact, and its immutable image
   ID feeds both SBOM generation and publication. See issues #185 and
   #473.

The workflow is parsed as YAML (`tests/support/yaml_files.py`); only the
version comments after pinned action references and whole-file absence
checks read its text.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from tests.support.yaml_files import (
    YamlMapping,
    job_steps,
    load_yaml_file,
    named_step,
    step_index,
    string_values,
    workflow_jobs,
)

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "build-images.yml"
)

BUILD_JOB = "build-backend"
RELEASE_METADATA_JOB = "publish-release-metadata"

BUILD_STEP = "Build backend image (load only, no push)"
SMOKE_STEP = "Image smoke test (blocking gate)"
SBOM_STEP = "Generate and validate release SBOM candidate"
PUSH_STEP = "Push tested image (same digest)"
GUARD_STEP = "Verify release is unpublished"
GUARD_RUN = "./scripts/check-release-unpublished.sh"
PUBLISH_RELEASE_RUN = "./scripts/publish-release.sh"
RELEASE_IF = "startsWith(github.ref, 'refs/tags/v')"
SMOKE_OUTPUT = "${{ steps.image-smoke.outputs.image_id }}"
RELEASE_GUARD_ENV = {
    "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
    "RELEASE_TAG": "${{ github.ref_name }}",
}


def _jobs() -> dict[str, YamlMapping]:
    return workflow_jobs(load_yaml_file(WORKFLOW_PATH))


def _uses(step: YamlMapping, action: str) -> bool:
    """Whether `step` uses `action` (`owner/name`) at any reference."""
    return str(step.get("uses", "")).startswith(f"{action}@")


# Logs both `docker tag <source> <target>` and `docker push <target>`
# invocations (space-separated, one call per line) so tests can assert
# on the tag *source* image, not just which tags were pushed.
DOCKER_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "tag" ]]; then
    echo "tag ${2:-} ${3:-}" >> "${DOCKER_STUB_LOG}"
    exit 0
fi
if [[ "${1:-}" == "push" ]]; then
    tag="${2:-}"
    echo "push ${tag}" >> "${DOCKER_STUB_LOG}"
    if [[ "${tag}" == *fail* ]]; then
        exit 1
    fi
    exit 0
fi
if [[ "${1:-}" == "buildx" && "${2:-}" == "imagetools" && "${3:-}" == "inspect" ]]; then
    if [[ "${4:-}" == *malformed* ]]; then
        echo '{"digest":"not-a-digest"}'
        exit 0
    fi
    if [[ "${4:-}" == *different* ]]; then
        digest="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    else
        digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    fi
    printf '{"digest":"sha256:%s"}\n' "${digest}"
    exit 0
fi
exit 0
"""


def _push_loop_script() -> str:
    """Return the standalone script invoked by the image push step."""
    push_step = named_step(_jobs()[BUILD_JOB], PUSH_STEP)
    assert push_step["run"] == "./scripts/publish-image.sh"
    return (
        Path(__file__).resolve().parents[2] / "scripts" / "publish-image.sh"
    ).read_text(encoding="utf-8")


def _install_docker_stub(bin_dir: Path) -> None:
    stub_path = bin_dir / "docker"
    stub_path.write_text(DOCKER_STUB, encoding="utf-8")
    mode = stub_path.stat().st_mode
    stub_path.chmod(mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run_push_loop(
    tmp_path: Path, *, image_tags: str
) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _install_docker_stub(bin_dir)
    log_file = tmp_path / "docker-stub.log"
    log_file.write_text("", encoding="utf-8")

    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SMOKE_IMAGE": "sentinel-backend:smoke",
        "IMAGE_TAGS": image_tags,
        "DOCKER_STUB_LOG": str(log_file),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
    }
    result = subprocess.run(
        ["bash", "-c", _push_loop_script()],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, log_file


def _pushed_tags(log_file: Path) -> list[str]:
    entries = log_file.read_text(encoding="utf-8").splitlines()
    return [
        entry.removeprefix("push ") for entry in entries if entry.startswith("push ")
    ]


def _tag_invocations(log_file: Path) -> list[str]:
    entries = log_file.read_text(encoding="utf-8").splitlines()
    return [entry.removeprefix("tag ") for entry in entries if entry.startswith("tag ")]


@pytest.mark.unit
def test_push_loop_aborts_on_first_failing_push(tmp_path: Path) -> None:
    tags = "ghcr.io/example/sentinel:fail\nghcr.io/example/sentinel:should-not-push"

    result, log_file = _run_push_loop(tmp_path, image_tags=tags)

    assert result.returncode != 0
    assert _pushed_tags(log_file) == ["ghcr.io/example/sentinel:fail"]


@pytest.mark.unit
def test_push_loop_pushes_all_tags_when_all_succeed(tmp_path: Path) -> None:
    tags = (
        "ghcr.io/example/sentinel:master\n"
        "ghcr.io/example/sentinel:1.2.3\n"
        "ghcr.io/example/sentinel:1.2"
    )

    result, log_file = _run_push_loop(tmp_path, image_tags=tags)

    assert result.returncode == 0
    assert _pushed_tags(log_file) == [
        "ghcr.io/example/sentinel:master",
        "ghcr.io/example/sentinel:1.2.3",
        "ghcr.io/example/sentinel:1.2",
    ]


@pytest.mark.unit
def test_push_loop_rejects_tags_with_different_registry_digests(
    tmp_path: Path,
) -> None:
    tags = "ghcr.io/example/sentinel:1.2.3\nghcr.io/example/sentinel:different"

    result, _ = _run_push_loop(tmp_path, image_tags=tags)

    assert result.returncode != 0
    assert "do not resolve to one digest" in result.stderr


@pytest.mark.unit
def test_push_loop_rejects_malformed_registry_digest(tmp_path: Path) -> None:
    result, _ = _run_push_loop(
        tmp_path, image_tags="ghcr.io/example/sentinel:malformed"
    )

    assert result.returncode != 0
    assert "invalid digest" in result.stderr


@pytest.mark.unit
def test_push_loop_rejects_tag_list_without_publishable_entry(tmp_path: Path) -> None:
    result, _ = _run_push_loop(tmp_path, image_tags="\n")

    assert result.returncode != 0
    assert "did not contain a publishable tag" in result.stderr


@pytest.mark.unit
def test_push_loop_skips_blank_tag_lines(tmp_path: Path) -> None:
    tags = "ghcr.io/example/sentinel:master\n\nghcr.io/example/sentinel:1.2.3"

    result, log_file = _run_push_loop(tmp_path, image_tags=tags)

    assert result.returncode == 0
    assert _pushed_tags(log_file) == [
        "ghcr.io/example/sentinel:master",
        "ghcr.io/example/sentinel:1.2.3",
    ]


@pytest.mark.unit
def test_every_pushed_tag_is_sourced_from_the_smoke_image(tmp_path: Path) -> None:
    # Each `docker tag` call must re-tag the exact local artifact that
    # was smoke-tested (env.SMOKE_IMAGE) — never a different or rebuilt
    # image. This is what makes the published digest mechanically
    # identical to the tested one.
    tags = "ghcr.io/example/sentinel:master\nghcr.io/example/sentinel:1.2.3"

    result, log_file = _run_push_loop(tmp_path, image_tags=tags)

    assert result.returncode == 0
    assert _tag_invocations(log_file) == [
        "sentinel-backend:smoke ghcr.io/example/sentinel:master",
        "sentinel-backend:smoke ghcr.io/example/sentinel:1.2.3",
    ]


@pytest.mark.unit
def test_image_is_built_exactly_once_without_pushing() -> None:
    build_steps = [
        step
        for job in _jobs().values()
        for step in job_steps(job)
        if _uses(step, "docker/build-push-action")
    ]

    assert len(build_steps) == 1, (
        "Expected exactly one docker/build-push-action step; a second "
        "build invocation would produce a different digest than the one "
        "smoke-tested, breaking the 'published == tested' guarantee"
    )
    assert build_steps[0]["name"] == BUILD_STEP
    assert build_steps[0]["with"]["push"] is False
    assert build_steps[0]["with"]["load"] is True


@pytest.mark.unit
def test_smoke_test_step_precedes_push_step() -> None:
    job = _jobs()[BUILD_JOB]

    assert step_index(job, SMOKE_STEP) < step_index(job, PUSH_STEP), (
        "The blocking smoke gate must run before the publish step so a "
        "failing smoke test prevents any push"
    )


@pytest.mark.unit
def test_smoke_step_uses_loaded_image_without_compose_override() -> None:
    smoke_step = named_step(_jobs()[BUILD_JOB], SMOKE_STEP)

    assert smoke_step["env"]["SENTINEL_IMAGE"] == "${{ env.SMOKE_IMAGE }}"
    assert smoke_step["run"] == "./scripts/image-smoke.sh --no-build"
    assert "COMPOSE_CMD" not in WORKFLOW_PATH.read_text(encoding="utf-8")


@pytest.mark.unit
def test_smoke_output_is_the_sbom_and_publish_source() -> None:
    job = _jobs()[BUILD_JOB]
    sbom_step = named_step(job, SBOM_STEP)

    assert named_step(job, SMOKE_STEP)["id"] == "image-smoke"
    assert sbom_step["env"]["TESTED_IMAGE"] == SMOKE_OUTPUT
    assert '"${TESTED_IMAGE}"' in sbom_step["run"]
    assert not any("SMOKE_IMAGE" in value for value in string_values(sbom_step))
    assert named_step(job, PUSH_STEP)["env"]["SMOKE_IMAGE"] == SMOKE_OUTPUT


@pytest.mark.unit
def test_sbom_gate_precedes_push_and_release_metadata_depends_on_build() -> None:
    jobs = _jobs()
    build_job = jobs[BUILD_JOB]
    release_job = jobs[RELEASE_METADATA_JOB]
    attest_steps = [
        step for step in job_steps(release_job) if _uses(step, "actions/attest")
    ]

    assert (
        step_index(build_job, BUILD_STEP)
        < step_index(build_job, SMOKE_STEP)
        < step_index(build_job, SBOM_STEP)
        < step_index(build_job, PUSH_STEP)
    )
    assert release_job["if"] == RELEASE_IF
    assert release_job["needs"] == BUILD_JOB
    assert len(attest_steps) == 2
    for step in attest_steps:
        assert step["with"]["create-storage-record"] is False
        assert step["with"]["push-to-registry"] is True
    # Release assets are uploaded only by scripts/publish-release.sh, which
    # publishes the draft after the upload (test_publish_release_script.py).
    assert "gh release" not in WORKFLOW_PATH.read_text(encoding="utf-8")


@pytest.mark.unit
def test_release_attestations_use_build_outputs_and_expected_predicates() -> None:
    steps = job_steps(_jobs()[RELEASE_METADATA_JOB])
    attest_steps = [step for step in steps if _uses(step, "actions/attest")]
    download_steps = [
        step for step in steps if _uses(step, "actions/download-artifact")
    ]
    sbom_path = (
        "${{ runner.temp }}/release-sbom/"
        "${{ needs.build-backend.outputs.sbom-file-name }}"
    )

    assert len(attest_steps) == 2
    assert len({step["uses"] for step in attest_steps}) == 1
    for step in attest_steps:
        assert step["with"]["subject-digest"] == (
            "${{ needs.build-backend.outputs.image-digest }}"
        )
    assert [step["with"].get("sbom-path") for step in attest_steps] == [
        sbom_path,
        None,
    ]
    assert len(download_steps) == 1
    assert download_steps[0]["with"]["name"] == (
        "${{ needs.build-backend.outputs.sbom-artifact-name }}"
    )
    # The version comment after a pinned reference is not YAML data.
    commented_references = re.findall(
        r"uses: (actions/attest@[0-9a-f]{40}) # v[0-9]+\.[0-9]+\.[0-9]+",
        WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    assert commented_references == [step["uses"] for step in attest_steps]


@pytest.mark.unit
def test_build_job_exports_exact_release_metadata_outputs() -> None:
    assert _jobs()[BUILD_JOB]["outputs"] == {
        "image-name": "${{ steps.push.outputs.image_name }}",
        "image-digest": "${{ steps.push.outputs.digest }}",
        "sbom-artifact-name": "${{ steps.sbom-metadata.outputs.artifact_name }}",
        "sbom-file-name": "${{ steps.sbom-metadata.outputs.file_name }}",
    }


@pytest.mark.unit
def test_release_metadata_job_has_only_required_write_permissions() -> None:
    permissions = _jobs()[RELEASE_METADATA_JOB]["permissions"]

    assert isinstance(permissions, dict)
    assert {scope for scope, access in permissions.items() if access == "write"} == {
        "attestations",
        "contents",
        "id-token",
        "packages",
    }


@pytest.mark.unit
def test_sbom_metadata_outputs_enter_shell_via_environment() -> None:
    step = named_step(_jobs()[BUILD_JOB], SBOM_STEP)

    assert step["env"]["SBOM_FILE_PATH"] == (
        "${{ steps.sbom-metadata.outputs.file_path }}"
    )
    assert step["env"]["SBOM_VERSION"] == "${{ steps.sbom-metadata.outputs.version }}"
    assert "${{" not in step["run"]


@pytest.mark.unit
def test_sbom_subject_name_is_normalized_for_ghcr() -> None:
    step = named_step(_jobs()[BUILD_JOB], SBOM_STEP)

    assert '"${REGISTRY}/${IMAGE_NAME,,}"' in step["run"]


@pytest.mark.unit
def test_build_job_guards_published_release_immediately_before_push() -> None:
    # docs/deployment.md (Release Publication and Immutability): a rerun must
    # fail before the first registry push once the GitHub Release is
    # published, so the X.Y.Z tag of a published release never moves.
    job = _jobs()[BUILD_JOB]
    guard = named_step(job, GUARD_STEP)

    assert step_index(job, PUSH_STEP) == step_index(job, GUARD_STEP) + 1
    assert guard["if"] == RELEASE_IF
    assert RELEASE_GUARD_ENV.items() <= guard["env"].items()
    assert guard["run"] == GUARD_RUN


@pytest.mark.unit
def test_release_metadata_job_guards_published_release_before_attesting() -> None:
    job = _jobs()[RELEASE_METADATA_JOB]
    steps = job_steps(job)
    guard_index = step_index(job, GUARD_STEP)
    attest_indices = [
        index for index, step in enumerate(steps) if _uses(step, "actions/attest")
    ]

    # The job-level condition, not the guard, keeps master builds out of it.
    assert job["if"] == RELEASE_IF
    assert _uses(steps[0], "actions/checkout")
    assert guard_index == 1
    assert len(attest_indices) == 2
    assert guard_index < min(attest_indices)
    guard = steps[guard_index]
    assert RELEASE_GUARD_ENV.items() <= guard["env"].items()
    assert guard["run"] == GUARD_RUN


@pytest.mark.unit
def test_release_publication_is_the_last_step_and_uses_attestation_bundles() -> None:
    job = _jobs()[RELEASE_METADATA_JOB]
    sbom_attestation = named_step(job, "Attest release SBOM")
    provenance_attestation = named_step(job, "Attest release build provenance")
    publication = job_steps(job)[-1]

    assert sbom_attestation["id"] == "attest-sbom"
    assert "sbom-path" in sbom_attestation["with"]
    assert provenance_attestation["id"] == "attest-provenance"
    assert "sbom-path" not in provenance_attestation["with"]
    assert publication["name"] == "Publish GitHub Release"
    assert publication["run"] == PUBLISH_RELEASE_RUN
    expected_env = RELEASE_GUARD_ENV | {
        "SBOM_PATH": (
            "${{ runner.temp }}/release-sbom/"
            "${{ needs.build-backend.outputs.sbom-file-name }}"
        ),
        "SBOM_BUNDLE_PATH": "${{ steps.attest-sbom.outputs.bundle-path }}",
        "PROVENANCE_BUNDLE_PATH": "${{ steps.attest-provenance.outputs.bundle-path }}",
    }
    assert expected_env.items() <= publication["env"].items()


@pytest.mark.unit
def test_release_scripts_receive_workflow_values_only_through_environment() -> None:
    workflow = load_yaml_file(WORKFLOW_PATH)
    runs = [
        step.get("run")
        for job in workflow_jobs(workflow).values()
        for step in job_steps(job)
    ]
    mentions = [
        value
        for value in string_values(workflow)
        if "check-release-unpublished.sh" in value or "publish-release.sh" in value
    ]

    # Each script is a whole `run:` command without arguments, and no other
    # value (an argument, an input, or an interpolated command) names one.
    assert runs.count(GUARD_RUN) == 2
    assert runs.count(PUBLISH_RELEASE_RUN) == 1
    assert len(mentions) == 3
