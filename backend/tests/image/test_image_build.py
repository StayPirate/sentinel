"""Consolidated manifest and API probes for the packaged Sentinel image."""

from __future__ import annotations

import subprocess
from collections.abc import Callable

import httpx
import pytest

_RUNTIME_MANIFEST_SCRIPT = """
import shutil
import ssl
from importlib.metadata import files as distribution_files
from importlib.metadata import version
from importlib.resources import files as package_files
from pathlib import Path

import app
from app.services.http_client import build_tls_context

cpe_resource = "app/data/cpe-package-mapping.json"
assert package_files("app").joinpath("data", "cpe-package-mapping.json").is_file()
installed = [
    record
    for record in distribution_files("sentinel") or ()
    if record.as_posix() == cpe_resource
]
assert installed, f"{cpe_resource} is not in the installed distribution"
assert Path(installed[0].locate()).is_file(), installed[0].locate()

assert Path("/app/alembic.ini").is_file()
assert Path("/app/alembic/versions").is_dir()
assert Path("/app/certs/SUSE_Trust_Root.crt").is_file()
assert not Path("/app/tests").exists(), "/app/tests is present"
assert shutil.which("sentinel") is not None
assert version("sentinel")

subjects = [
    dict(rdn[0] for rdn in cert.get("subject", ()))
    for cert in ssl.create_default_context().get_ca_certs()
]
names = {subject.get("commonName") for subject in subjects}
assert "SUSE Trust Root" in names, sorted(name for name in names if name)
assert build_tls_context().verify_mode.name == "CERT_REQUIRED"
print("RUNTIME-MANIFEST-OK")
"""


@pytest.mark.image
def test_default_api_command_serves_health_readiness_and_openapi(
    http_client: httpx.Client,
) -> None:
    """The image's default command exposes all external artifact probes."""
    health = http_client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    ready = http_client.get("/ready")
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ok",
        "checks": {"postgresql": "ok", "redis": "ok"},
    }

    openapi = http_client.get("/openapi.json")
    assert openapi.status_code == 200
    assert openapi.json()["info"]["title"] == "Sentinel"


@pytest.mark.image
def test_runtime_manifest_is_complete_non_root_and_excludes_test_code(
    compose_exec: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Inspect the physical contents and metadata unique to the OCI artifact."""
    user = compose_exec("api", "id", "-u")
    assert user.returncode == 0, user.stderr
    assert user.stdout.strip() != "0", "runtime image executes as root"

    result = compose_exec("api", "python", "-c", _RUNTIME_MANIFEST_SCRIPT)
    assert result.returncode == 0, (
        f"runtime manifest check failed (rc={result.returncode}): "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "RUNTIME-MANIFEST-OK" in result.stdout

    metadata = compose_exec(
        "api",
        "python",
        "-c",
        "from importlib.metadata import version; print(version('sentinel'))",
    )
    assert metadata.returncode == 0, (
        f"installed package metadata lookup failed (rc={metadata.returncode}): "
        f"stdout={metadata.stdout!r} stderr={metadata.stderr!r}"
    )
    installed_version = metadata.stdout.strip()
    assert installed_version, "installed package metadata returned an empty version"

    commands = (
        ("sentinel", "--version"),
        ("python", "-m", "app.cli", "--version"),
    )
    for command in commands:
        cli = compose_exec("api", *command)
        invocation = " ".join(command)
        assert cli.returncode == 0, (
            f"{invocation} failed (rc={cli.returncode}): "
            f"stdout={cli.stdout!r} stderr={cli.stderr!r}"
        )
        assert cli.stdout.strip() == installed_version, (
            f"{invocation} returned {cli.stdout.strip()!r}, expected installed "
            f"package version {installed_version!r}"
        )
