"""Process lifecycle, timeout, and invocation tests of `git_operations`.

Contract: `docs/features/platform/git-fetcher-infrastructure.md` (Runtime
Dependencies, Error Classification, Function Catalog: Module Invariants
Rule 3, Fetch Operations, Read Operations). A fake `git` (a `/bin/sh`
script first on `PATH`) records each invocation's PID, argv, and
environment, and can print fixed output, exit with a given code, hang with
a background grandchild that holds git's output pipes, or ignore SIGTERM.
Timeouts are shortened by patching the module's constants, which are read
at call time, and the retry backoff is recorded instead of awaited.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import time
from collections.abc import Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from celery.exceptions import SoftTimeLimitExceeded

from app.services import git_operations
from app.services.git_operations import (
    GitCorruptionError,
    GitError,
    GitFetchError,
    GitFileError,
    check_sha_reachable,
    clone,
    diff_names,
    fetch_origin,
    get_commit_date,
    get_head_sha,
    is_clone_valid,
    rev_list_before,
    show_file,
)
from tests.support.git_repos import isolate_process_environment

pytestmark = pytest.mark.unit

RETRY_DELAYS = [2, 4, 8]
HEAD_SHA = "0123456789abcdef" * 2 + "01234567"
SOURCE_URL = "https://git.example.invalid/source.git"
_SHORT_TIMEOUT = 0.5
_BOUNDED_WAIT_SECONDS = 10


@dataclass(frozen=True)
class Behavior:
    """What the fake git does for one subcommand."""

    stdout: str = ""
    exit_code: int = 0
    hang: bool = False
    ignore_term: bool = False
    # Invocations of the subcommand that fail (exit 128) before it behaves.
    fail_first: int = 0


_HANG = Behavior(hang=True)
_FAIL = Behavior(exit_code=128)


def _script_body(behavior: Behavior) -> str:
    lines = []
    if behavior.fail_first:
        lines += [
            'n=$(grep -c " $sub$" "$state/calls")',
            f'if [ "$n" -le {behavior.fail_first} ]; then',
            "  echo 'fatal: transient failure' >&2; exit 128",
            "fi",
        ]
    if behavior.ignore_term:
        lines.append("trap '' TERM")
    if behavior.hang:
        # The grandchild inherits git's stdout and stderr pipes, as a
        # transport helper would.
        lines += [
            "sleep 300 &",
            'echo "$!" >> "$state/grandchildren"',
            "exec sleep 300",
        ]
    lines += [
        f"printf '%s' {shlex.quote(behavior.stdout)}",
        f"exit {behavior.exit_code}",
    ]
    return "\n    ".join(lines)


@dataclass
class FakeGit:
    state: Path

    def calls(self) -> list[tuple[int, str]]:
        path = self.state / "calls"
        if not path.exists():
            return []
        entries = (line.split(" ", 1) for line in path.read_text().splitlines())
        return [(int(pid), subcommand) for pid, subcommand in entries]

    def subcommands(self) -> list[str]:
        return [subcommand for _, subcommand in self.calls()]

    def git_pids(self) -> list[int]:
        return [pid for pid, _ in self.calls()]

    def grandchild_pids(self) -> list[int]:
        path = self.state / "grandchildren"
        return [int(pid) for pid in path.read_text().split()] if path.exists() else []

    def environments(self) -> list[dict[str, str]]:
        environments = []
        for pid in self.git_pids():
            raw = (self.state / f"env.{pid}").read_bytes()
            entries = (
                entry.decode(errors="surrogateescape").split("=", 1)
                for entry in raw.split(b"\0")
                if entry
            )
            environments.append(dict(entries))
        return environments


@dataclass
class FakeGitFactory:
    tmp_path: Path
    monkeypatch: pytest.MonkeyPatch
    installed: list[FakeGit] = field(default_factory=list)

    def install(
        self,
        behaviors: Mapping[str, Behavior],
        *,
        default: Behavior = _FAIL,
    ) -> FakeGit:
        state = self.tmp_path / "fake-git-state"
        bin_dir = self.tmp_path / "fake-git-bin"
        state.mkdir()
        bin_dir.mkdir()
        cases = "".join(
            f"  {shlex.quote(name)})\n    {_script_body(behavior)}\n    ;;\n"
            for name, behavior in behaviors.items()
        )
        script = bin_dir / "git"
        script.write_text(
            "#!/bin/sh\n"
            f"state={shlex.quote(str(state))}\n"
            'sub="$1"\n'
            'case "$sub" in --git-dir=*) sub="$2" ;; esac\n'
            'env -0 > "$state/env.$$"\n'
            'echo "$$ $sub" >> "$state/calls"\n'
            'case "$sub" in\n'
            f"{cases}"
            f"  *)\n    {_script_body(default)}\n    ;;\n"
            "esac\n"
        )
        script.chmod(0o755)
        self.monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        fake = FakeGit(state)
        self.installed.append(fake)
        return fake


def _process_state(pid: int) -> str | None:
    """`None` when no process has `pid` (it was reaped), else its state."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except FileNotFoundError:
        return None
    states = [
        line.split()[1] for line in status.splitlines() if line.startswith("State:")
    ]
    return states[0] if states else "?"


def _kill_survivors(fake: FakeGit) -> None:
    for pid in fake.git_pids() + fake.grandchild_pids():
        if _process_state(pid) not in (None, "Z"):
            os.kill(pid, 9)


async def _wait_until(condition: Callable[[], bool]) -> None:
    async with asyncio.timeout(_BOUNDED_WAIT_SECONDS):
        while True:
            if condition():
                return
            await asyncio.sleep(0.01)


async def _assert_no_process_left(fake: FakeGit) -> None:
    """The module reaped every git process it started; their grandchildren
    are gone too (an orphan reparented to init may briefly be a zombie)."""
    assert fake.git_pids()
    assert [_process_state(pid) for pid in fake.git_pids()] == [None] * len(
        fake.git_pids()
    )
    await _wait_until(
        lambda: all(
            _process_state(pid) in (None, "Z") for pid in fake.grandchild_pids()
        )
    )


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_process_environment(monkeypatch)


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """The retry backoff delays, recorded instead of awaited."""
    delays: list[float] = []

    async def record(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(git_operations, "_sleep", record)
    return delays


@pytest.fixture
def fake_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[FakeGitFactory]:
    factory = FakeGitFactory(tmp_path, monkeypatch)
    yield factory
    # A failed assertion must not leave a hanging fake behind.
    for fake in factory.installed:
        _kill_survivors(fake)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


@dataclass(frozen=True)
class _Operation:
    behaviors: Mapping[str, Behavior]
    call: Callable[[Path], Awaitable[object]]
    timeout_constant: str
    error: type[GitError]
    subcommands: list[str]


_BRANCH = Behavior(stdout="refs/heads/main\n")

_OPERATIONS = {
    "read": _Operation(
        {"rev-parse": _HANG},
        get_head_sha,
        "READ_TIMEOUT_SECONDS",
        GitCorruptionError,
        ["rev-parse"] * 4,
    ),
    "fetch": _Operation(
        {"symbolic-ref": _BRANCH, "fetch": _HANG},
        fetch_origin,
        "FETCH_TIMEOUT_SECONDS",
        GitFetchError,
        ["symbolic-ref", "fetch"],
    ),
    "clone": _Operation(
        {"clone": _HANG},
        lambda repo: clone(SOURCE_URL, repo / "clone"),
        "CLONE_TIMEOUT_SECONDS",
        GitFetchError,
        ["clone"],
    ),
    "show": _Operation(
        {"show": _HANG},
        lambda repo: show_file(repo, "HEAD", "README"),
        "SHOW_TIMEOUT_SECONDS",
        GitFileError,
        ["show"],
    ),
}


# --- Timeouts ---------------------------------------------------------------


@pytest.mark.parametrize("operation", _OPERATIONS.values(), ids=_OPERATIONS.keys())
async def test_hanging_git_timeout_kills_process_group_and_raises_phase_error(
    fake_git: FakeGitFactory,
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    sleeps: list[float],
    operation: _Operation,
) -> None:
    fake = fake_git.install(operation.behaviors)
    monkeypatch.setattr(git_operations, operation.timeout_constant, _SHORT_TIMEOUT)

    with pytest.raises(operation.error, match=r"timed out after 0\.5 seconds"):
        await operation.call(repo)

    assert fake.subcommands() == operation.subcommands
    hanging = [name for name in operation.subcommands if operation.behaviors[name].hang]
    assert len(fake.grandchild_pids()) == len(hanging)
    assert sleeps == (RETRY_DELAYS if operation.error is GitCorruptionError else [])
    await _assert_no_process_left(fake)


async def test_git_ignoring_sigterm_is_killed_after_grace_period(
    fake_git: FakeGitFactory, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_git.install({"show": Behavior(hang=True, ignore_term=True)})
    grace = 0.5
    monkeypatch.setattr(git_operations, "SHOW_TIMEOUT_SECONDS", _SHORT_TIMEOUT)
    monkeypatch.setattr(git_operations, "_TERMINATION_GRACE_SECONDS", grace)
    started = time.monotonic()

    with pytest.raises(GitFileError, match="timed out"):
        await show_file(repo, "HEAD", "README")

    assert time.monotonic() - started >= _SHORT_TIMEOUT + grace
    await _assert_no_process_left(fake)


# --- Cancellation and whole-run signals -------------------------------------


@pytest.mark.parametrize("operation", _OPERATIONS.values(), ids=_OPERATIONS.keys())
async def test_cancelled_call_propagates_cancelled_error_and_leaves_no_process(
    fake_git: FakeGitFactory, repo: Path, sleeps: list[float], operation: _Operation
) -> None:
    fake = fake_git.install(operation.behaviors)
    task = asyncio.ensure_future(operation.call(repo))
    await _wait_until(lambda: len(fake.grandchild_pids()) == 1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert sleeps == []
    await _assert_no_process_left(fake)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(SoftTimeLimitExceeded(), id="soft-time-limit"),
        pytest.param(MemoryError(), id="memory-error"),
    ],
)
async def test_exception_while_git_runs_propagates_unchanged_and_leaves_no_process(
    fake_git: FakeGitFactory,
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    sleeps: list[float],
    error: BaseException,
) -> None:
    fake = fake_git.install({"rev-parse": _HANG})
    real_communicate = asyncio.subprocess.Process.communicate
    readers: list[asyncio.Future[tuple[bytes, bytes]]] = []

    async def communicate(
        self: asyncio.subprocess.Process, input: bytes | None = None
    ) -> tuple[bytes, bytes]:
        readers.append(asyncio.ensure_future(real_communicate(self, input)))
        await _wait_until(lambda: len(fake.grandchild_pids()) == 1)
        raise error

    monkeypatch.setattr(asyncio.subprocess.Process, "communicate", communicate)

    with pytest.raises(type(error)) as excinfo:
        await get_head_sha(repo)

    assert excinfo.value is error
    assert fake.subcommands() == ["rev-parse"]
    assert sleeps == []
    await _assert_no_process_left(fake)
    # The real reader completes: no process holds git's pipes any more.
    async with asyncio.timeout(_BOUNDED_WAIT_SECONDS):
        await asyncio.gather(*readers)


async def test_exception_after_git_exited_propagates_without_signalling(
    fake_git: FakeGitFactory, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_git.install({}, default=Behavior())
    signalled: list[tuple[int, int]] = []

    async def communicate(
        self: asyncio.subprocess.Process, input: bytes | None = None
    ) -> tuple[bytes, bytes]:
        await self.wait()
        raise MemoryError

    def killpg(pgid: int, signum: int) -> None:
        signalled.append((pgid, signum))

    monkeypatch.setattr(asyncio.subprocess.Process, "communicate", communicate)
    monkeypatch.setattr(os, "killpg", killpg)

    with pytest.raises(MemoryError):
        await show_file(repo, "HEAD", "README")

    assert signalled == []
    await _assert_no_process_left(fake)


# --- Invocation counts and failed attempts ----------------------------------


_SINGLE_ATTEMPT = {
    "clone": (
        {"clone": Behavior(exit_code=128)},
        lambda repo: clone(SOURCE_URL, repo / "clone"),
        GitFetchError,
        ["clone"],
    ),
    "fetch": (
        {"symbolic-ref": _BRANCH, "fetch": Behavior(exit_code=1)},
        fetch_origin,
        GitFetchError,
        ["symbolic-ref", "fetch"],
    ),
    "show": (
        {"show": Behavior(exit_code=1)},
        lambda repo: show_file(repo, "HEAD", "README"),
        GitFileError,
        ["show"],
    ),
}


@pytest.mark.parametrize(
    ("behaviors", "call", "error", "subcommands"),
    _SINGLE_ATTEMPT.values(),
    ids=_SINGLE_ATTEMPT.keys(),
)
async def test_clone_fetch_show_failure_makes_one_attempt(
    fake_git: FakeGitFactory,
    repo: Path,
    sleeps: list[float],
    behaviors: Mapping[str, Behavior],
    call: Callable[[Path], Awaitable[object]],
    error: type[GitError],
    subcommands: list[str],
) -> None:
    fake = fake_git.install(behaviors)

    with pytest.raises(error):
        await call(repo)

    assert fake.subcommands() == subcommands
    assert sleeps == []


async def test_read_transient_failure_retried_then_succeeds(
    fake_git: FakeGitFactory, repo: Path, sleeps: list[float]
) -> None:
    fake = fake_git.install(
        {"rev-parse": Behavior(stdout=f"{HEAD_SHA}\n", fail_first=2)}
    )

    assert await get_head_sha(repo) == HEAD_SHA

    assert fake.subcommands() == ["rev-parse"] * 3
    assert sleeps == [2, 4]


_MALFORMED_OUTPUT = {
    "get_head_sha": ("rev-parse", "f" * 64 + "\n", get_head_sha, "40-hex"),
    "get_commit_date": (
        "log",
        "2026-01-01T00:00:00+00:00\n",
        lambda repo: get_commit_date(repo, "HEAD"),
        "committer epoch",
    ),
    "rev_list_before": (
        "rev-list",
        "not-a-sha\n",
        lambda repo: rev_list_before(repo, "2026-01-01"),
        "40-hex",
    ),
    "fetch_origin-branch-lookup": (
        "symbolic-ref",
        "refs/heads/main refs/heads/other\n",
        fetch_origin,
        "no local branch",
    ),
}


@pytest.mark.parametrize(
    ("subcommand", "stdout", "call", "detail"),
    _MALFORMED_OUTPUT.values(),
    ids=_MALFORMED_OUTPUT.keys(),
)
async def test_read_unexpected_output_form_retried_then_raises_corruption(
    fake_git: FakeGitFactory,
    repo: Path,
    sleeps: list[float],
    subcommand: str,
    stdout: str,
    call: Callable[[Path], Awaitable[object]],
    detail: str,
) -> None:
    fake = fake_git.install({subcommand: Behavior(stdout=stdout)})

    with pytest.raises(GitCorruptionError, match=detail):
        await call(repo)

    assert fake.subcommands() == [subcommand] * 4
    assert sleeps == RETRY_DELAYS


_UNSTARTABLE = {
    "clone": (lambda repo: clone(SOURCE_URL, repo / "clone"), GitFetchError),
    "fetch_origin": (fetch_origin, GitCorruptionError),
    "get_head_sha": (get_head_sha, GitCorruptionError),
    "show_file": (lambda repo: show_file(repo, "HEAD", "README"), GitFileError),
}


@pytest.mark.parametrize(
    ("call", "error"), _UNSTARTABLE.values(), ids=_UNSTARTABLE.keys()
)
async def test_git_not_startable_raises_phase_error(
    repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    call: Callable[[Path], Awaitable[object]],
    error: type[GitError],
) -> None:
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))

    with pytest.raises(error, match="git could not be started"):
        await call(repo)


# --- Rule 3: every invocation's environment ---------------------------------


_EVERY_OPERATION: list[Callable[[Path], Awaitable[object]]] = [
    lambda repo: clone(SOURCE_URL, repo / "clone"),
    fetch_origin,
    get_head_sha,
    lambda repo: get_commit_date(repo, "HEAD"),
    is_clone_valid,
    lambda repo: check_sha_reachable(repo, HEAD_SHA),
    lambda repo: diff_names(repo, HEAD_SHA, HEAD_SHA),
    lambda repo: rev_list_before(repo, "2026-01-01"),
    lambda repo: show_file(repo, "HEAD", "README"),
]


async def test_every_invocation_receives_filtered_environment(
    fake_git: FakeGitFactory, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_git.install(
        {
            "symbolic-ref": _BRANCH,
            "rev-parse": Behavior(stdout=f"{HEAD_SHA}\n"),
            "log": Behavior(stdout="1767225600\n"),
        },
        default=Behavior(),
    )
    for name in git_operations._GIT_LOCAL_ENV_VARS:
        monkeypatch.setenv(name, str(repo / "inherited"))
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "1")
    monkeypatch.setenv("TZ", "Europe/Rome")
    monkeypatch.setenv("SENTINEL_EXAMPLE_UNRELATED", "kept")

    for operation in _EVERY_OPERATION:
        await operation(repo)

    environments = fake.environments()
    assert fake.subcommands() == [
        "clone",
        "symbolic-ref",
        "fetch",
        "rev-parse",
        "log",
        # is_clone_valid: `--is-bare-repository` does not print `true`.
        *["rev-parse"] * 4,
        "rev-parse",
        "diff",
        "rev-list",
        "show",
    ]
    for env in environments:
        assert not env.keys() & git_operations._GIT_LOCAL_ENV_VARS
        assert (env["LC_ALL"], env["GIT_TERMINAL_PROMPT"], env["TZ"]) == (
            "C",
            "0",
            "UTC",
        )
        assert env["SENTINEL_EXAMPLE_UNRELATED"] == "kept"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
