"""Fixtures for OCI artifact verification of the built Sentinel image."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

_DEFAULT_EXEC_TIMEOUT = 30.0
_DIAGNOSTIC_TIMEOUT = 15.0
_COMPOSE_CMD = ("docker", "compose")
_COMPOSE_PROJECT_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ImageSmokeContext:
    """Validated identity and addresses for one image-smoke invocation."""

    compose_files: tuple[Path, ...]
    project: str
    image_id: str
    base_url: str
    project_registry: Path

    @property
    def file_args(self) -> list[str]:
        args: list[str] = []
        for compose_file in self.compose_files:
            args.extend(["-f", str(compose_file)])
        return args

    @property
    def common_args(self) -> list[str]:
        return [*_COMPOSE_CMD, "-p", self.project, *self.file_args]

    def for_project(self, project: str) -> ImageSmokeContext:
        return replace(self, project=project)


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise pytest.UsageError(f"{name} is required for image smoke tests")
    return value


def _validate_compose_project(project: str, source: str) -> None:
    if _COMPOSE_PROJECT_PATTERN.fullmatch(project) is None:
        raise pytest.UsageError(
            f"{source} must start with a lowercase letter or digit and contain "
            "only lowercase letters, digits, hyphens, and underscores"
        )


def _resolve_image_smoke_context() -> ImageSmokeContext:
    """Resolve and validate the canonical runner's required configuration."""
    project = _required_environment("COMPOSE_PROJECT")
    _validate_compose_project(project, "COMPOSE_PROJECT")

    compose_file_values = _required_environment("COMPOSE_FILES").split(":")
    if any(not value for value in compose_file_values):
        raise pytest.UsageError(
            "COMPOSE_FILES must be a colon-separated list of non-empty paths"
        )
    compose_files = tuple(Path(value) for value in compose_file_values)
    missing_files = [str(path) for path in compose_files if not path.is_file()]
    if missing_files:
        raise pytest.UsageError(
            f"COMPOSE_FILES paths must exist and be files: {missing_files!r}"
        )

    image_id = _required_environment("IMAGE_SMOKE_IMAGE_ID")
    if _IMAGE_ID_PATTERN.fullmatch(image_id) is None:
        raise pytest.UsageError(
            "IMAGE_SMOKE_IMAGE_ID must be sha256: followed by 64 lowercase "
            "hexadecimal characters"
        )

    base_url = _required_environment("IMAGE_SMOKE_BASE_URL")
    try:
        parsed_url = urlsplit(base_url)
        port = parsed_url.port
    except ValueError as exc:
        raise pytest.UsageError(
            "IMAGE_SMOKE_BASE_URL must contain a valid explicit port"
        ) from exc
    if (
        parsed_url.scheme != "http"
        or parsed_url.hostname != "127.0.0.1"
        or port is None
        or port == 0
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.path
        or parsed_url.query
        or parsed_url.fragment
        or "?" in base_url
        or "#" in base_url
    ):
        raise pytest.UsageError(
            "IMAGE_SMOKE_BASE_URL must be http://127.0.0.1:<port> with a "
            "valid explicit port and no path, query, fragment, or credentials"
        )

    registry_value = _required_environment("IMAGE_SMOKE_PROJECT_REGISTRY")
    if "\x00" in registry_value:
        raise pytest.UsageError("IMAGE_SMOKE_PROJECT_REGISTRY contains a NUL byte")
    project_registry = Path(registry_value)
    if not project_registry.is_absolute():
        raise pytest.UsageError("IMAGE_SMOKE_PROJECT_REGISTRY must be an absolute path")
    if not project_registry.is_file():
        raise pytest.UsageError(
            "IMAGE_SMOKE_PROJECT_REGISTRY must identify an existing regular file"
        )

    return ImageSmokeContext(
        compose_files=compose_files,
        project=project,
        image_id=image_id,
        base_url=base_url,
        project_registry=project_registry,
    )


def _run_compose_bounded(
    cmd: list[str], timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run a Compose command with a finite bound and captured output."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            f"compose command timed out after {timeout}s: cmd={cmd!r} "
            f"stdout={exc.stdout!r} stderr={exc.stderr!r}"
        )


def _capture_compose_diagnostics(
    phase: str, context: ImageSmokeContext
) -> list[tuple[str, str]]:
    """Capture bounded diagnostics for the context's exact Compose project."""
    commands = [
        (
            "compose ps --all",
            [*context.common_args, "ps", "--all", "--format", "json"],
        ),
        (
            "compose logs (tail=100)",
            [
                *context.common_args,
                "logs",
                "--timestamps",
                "--tail",
                "100",
                "--no-color",
            ],
        ),
        (
            "migration exit evidence",
            [
                *context.common_args,
                "ps",
                "--all",
                "--format",
                "json",
                "migrate",
            ],
        ),
        (
            "container image IDs",
            [*context.common_args, "images", "--format", "json"],
        ),
    ]
    sections = [
        (
            f"image smoke metadata ({phase})",
            f"project={context.project}\n"
            f"candidate_image_id={context.image_id}\n"
            f"base_url={context.base_url}\n"
            f"compose_files={':'.join(map(str, context.compose_files))}",
        )
    ]

    for title, command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=_DIAGNOSTIC_TIMEOUT,
            )
            output = (
                (result.stdout or "") + (result.stderr or "")
            ).strip() or "[no output]"
            if result.returncode != 0:
                output = f"[diagnostic command exited {result.returncode}]\n{output}"
        except (subprocess.TimeoutExpired, OSError) as exc:
            output = f"[diagnostic command failed: {exc!r}]"
        sections.append((f"{title} ({phase}, project={context.project})", output))

    return sections


_DISPOSABLE_STACKS: pytest.StashKey[list[IsolatedComposeStack]] = pytest.StashKey()


@pytest.hookimpl(tryfirst=True, wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Attach project-specific diagnostics without masking a pytest failure."""
    report = yield

    if not report.failed or item.get_closest_marker("image") is None:
        return report

    try:
        context = _resolve_image_smoke_context()
        report.sections.extend(_capture_compose_diagnostics(report.when, context))
        for stack in item.stash.get(_DISPOSABLE_STACKS, []):
            if not stack.brought_up:
                continue
            sections = stack.teardown_failure_diagnostics
            if sections is None:
                sections = _capture_compose_diagnostics(report.when, stack.context)
            report.sections.extend(sections)
    except BaseException as exc:
        report.sections.append(
            (
                f"image smoke diagnostics unavailable ({report.when})",
                repr(exc),
            )
        )
    return report


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Validate the complete harness context before every image test."""
    if item.get_closest_marker("image") is not None:
        _resolve_image_smoke_context()


@pytest.fixture(scope="session")
def image_smoke_context() -> ImageSmokeContext:
    """Fail closed unless invoked with the canonical runner's full context."""
    return _resolve_image_smoke_context()


@pytest.fixture(scope="session")
def base_url(image_smoke_context: ImageSmokeContext) -> str:
    """Return the runner-discovered loopback URL of the API container."""
    return image_smoke_context.base_url


@pytest.fixture(scope="session")
def http_client(base_url: str) -> Iterator[httpx.Client]:
    """Provide a synchronous client for the real containerized API."""
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        yield client


@pytest.fixture(scope="session")
def compose_exec(
    image_smoke_context: ImageSmokeContext,
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run a bounded command in a service from the invocation's project."""

    def _exec(
        service: str,
        *args: str,
        env: dict[str, str] | None = None,
        timeout: float = _DEFAULT_EXEC_TIMEOUT,
    ) -> subprocess.CompletedProcess[str]:
        env_args: list[str] = []
        for key, value in (env or {}).items():
            env_args.extend(["-e", f"{key}={value}"])
        cmd = [
            *image_smoke_context.common_args,
            "exec",
            "-T",
            *env_args,
            service,
            *args,
        ]
        return _run_compose_bounded(cmd, timeout)

    return _exec


@pytest.fixture(scope="session")
def celery_node_inspect(
    compose_exec: Callable[..., subprocess.CompletedProcess[str]],
) -> Callable[[str, str, str], Any]:
    """Run one Celery inspect command addressed only to a service's own node.

    The node is ``<node_prefix>@<container hostname>``; an untargeted inspect
    is a broadcast that every worker node of the stack answers.
    """

    def _inspect(service: str, node_prefix: str, command: str) -> Any:
        hostname = compose_exec(
            service, "python", "-c", "import socket; print(socket.gethostname())"
        )
        assert hostname.returncode == 0, (
            f"{service} hostname lookup failed (stdout={hostname.stdout!r}, "
            f"stderr={hostname.stderr!r})"
        )
        node = f"{node_prefix}@{hostname.stdout.strip()}"
        result = compose_exec(
            service,
            "celery",
            "-A",
            "app.celery_app",
            "inspect",
            command,
            "--json",
            "--timeout",
            "10",
            "-d",
            node,
        )
        assert result.returncode == 0, (
            f"inspect {command} for {node} failed (stdout={result.stdout!r}, "
            f"stderr={result.stderr!r})"
        )
        replies = json.loads(result.stdout)
        assert set(replies) == {node}, f"unexpected repliers: {result.stdout!r}"
        return replies[node]

    return _inspect


def _register_disposable_project(context: ImageSmokeContext, project: str) -> None:
    """Append one complete project record before any disposable operation."""
    _validate_compose_project(project, "disposable project")
    record = f"{project}\n".encode()
    try:
        descriptor = os.open(
            context.project_registry,
            os.O_WRONLY | os.O_APPEND,
        )
        try:
            written = os.write(descriptor, record)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise pytest.UsageError(
            f"cannot append disposable project to IMAGE_SMOKE_PROJECT_REGISTRY: {exc}"
        ) from exc
    if written != len(record):
        raise pytest.UsageError(
            "could not atomically append the complete disposable project record"
        )


class IsolatedComposeStack:
    """A disposable Compose project derived from the primary invocation."""

    def __init__(
        self,
        context: ImageSmokeContext,
        override_path: Path,
    ) -> None:
        self.context = context
        self._override_path = override_path
        self._brought_up = False
        self._teardown_failure_diagnostics: list[tuple[str, str]] | None = None

    @property
    def brought_up(self) -> bool:
        return self._brought_up

    @property
    def teardown_failure_diagnostics(self) -> list[tuple[str, str]] | None:
        return self._teardown_failure_diagnostics

    @property
    def project(self) -> str:
        return self.context.project

    def up(
        self, override_yaml: str, *services: str
    ) -> subprocess.CompletedProcess[str]:
        """Bring up the disposable stack without a build or pull."""
        self._override_path.write_text(override_yaml, encoding="utf-8")
        cmd = [
            *self.context.common_args,
            "-f",
            str(self._override_path),
            "up",
            "-d",
            "--wait",
            "--no-build",
            "--pull",
            "never",
            *services,
        ]
        self._brought_up = True
        return _run_compose_bounded(cmd, timeout=90.0)

    def exec_check(self, service: str, *args: str) -> subprocess.CompletedProcess[str]:
        """Check whether a disposable service still accepts exec commands."""
        return _run_compose_bounded(
            [
                *self.context.common_args,
                "exec",
                "-T",
                service,
                *args,
            ],
            timeout=10.0,
        )

    def exec(
        self, service: str, *args: str, timeout: float = _DEFAULT_EXEC_TIMEOUT
    ) -> subprocess.CompletedProcess[str]:
        """Run a bounded command in a running disposable service."""
        return _run_compose_bounded(
            [
                *self.context.common_args,
                "exec",
                "-T",
                service,
                *args,
            ],
            timeout=timeout,
        )

    def service_state(self, service: str) -> subprocess.CompletedProcess[str]:
        """Return the disposable service's container state and exit code."""
        return _run_compose_bounded(
            [
                *self.context.common_args,
                "ps",
                "--all",
                "--format",
                "{{.State}}|{{.ExitCode}}",
                service,
            ],
            timeout=10.0,
        )

    def wait_until_exited(
        self, service: str, *, timeout: float = 45.0, poll_interval: float = 1.0
    ) -> None:
        """Wait until a deliberately broken service exits."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.exec_check(service, "true").returncode != 0:
                return
            time.sleep(poll_interval)
        pytest.fail(
            f"service {service!r} in project {self.project!r} did not "
            f"exit within {timeout}s"
        )

    def logs(self, service: str) -> str:
        """Return color-free logs retained for one disposable service."""
        result = _run_compose_bounded(
            [
                *self.context.common_args,
                "logs",
                "--no-color",
                service,
            ],
            timeout=15.0,
        )
        return result.stdout + result.stderr

    def teardown(self) -> None:
        """Remove the project and make any cleanup failure pytest-visible."""
        if not self._brought_up:
            return
        result = _run_compose_bounded(
            [
                *self.context.common_args,
                "down",
                "-v",
                "--remove-orphans",
            ],
            timeout=60.0,
        )
        if result.returncode != 0:
            self._teardown_failure_diagnostics = _capture_compose_diagnostics(
                "teardown", self.context
            )
            pytest.fail(
                f"disposable project {self.project!r} teardown failed with "
                f"exit {result.returncode}: stdout={result.stdout!r} "
                f"stderr={result.stderr!r}"
            )


@pytest.fixture
def isolated_compose_stack(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    image_smoke_context: ImageSmokeContext,
) -> Iterator[IsolatedComposeStack]:
    """Register, provide, diagnose, and tear down one disposable project."""
    project = f"{image_smoke_context.project}-isolated-{uuid.uuid4().hex[:8]}"
    context = image_smoke_context.for_project(project)
    _register_disposable_project(context, project)
    stack = IsolatedComposeStack(context, tmp_path / "override.yml")
    request.node.stash[_DISPOSABLE_STACKS] = [stack]
    try:
        yield stack
    finally:
        stack.teardown()
