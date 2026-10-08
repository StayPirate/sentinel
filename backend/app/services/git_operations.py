"""Policy-free async helper for git operations on bare clones.

Implements docs/features/platform/git-fetcher-infrastructure.md (Bare Clone
Pattern, Runtime Dependencies, Error Classification, Implementation
Location, Design Principles, Responsibility Separation, Function Catalog).

This is the only module in `app/` that starts a process. Every git command
is passed to `asyncio.create_subprocess_exec` as an argument list, addresses
its repository with `--git-dir` (no repository discovery), places
`--end-of-options` before its positional arguments (Module Invariants,
Rule 2), and runs with the filtered environment of Rule 3. The module is
bare-only and otherwise applies no domain defaults; it has no database
access, performs no business logic, and logs no repository content.

Failures are classified by phase. Clone and fetch failures raise
`GitFetchError` without retry. Local reads are retried with a 2/4/8 second
backoff before `GitCorruptionError`. A `git show` failure raises
`GitFileError` without retry. Exceptions carry git's stderr for diagnostics
only; sanitizing it for public messages is the caller's responsibility.

The git process started by a call never outlives it: on timeout,
cancellation, or any other exception while it runs, its process group is
terminated (SIGTERM, then SIGKILL after a short grace period) and the
process is reaped before the exception propagates. Git's own detached
automatic maintenance after a fetch is not managed here (Fetch Operations,
Automatic maintenance).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import signal
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import structlog

logger = structlog.get_logger(__name__)

CLONE_TIMEOUT_SECONDS: Final[float] = 30 * 60
FETCH_TIMEOUT_SECONDS: Final[float] = 5 * 60
READ_TIMEOUT_SECONDS: Final[float] = 30
SHOW_TIMEOUT_SECONDS: Final[float] = 30
READ_RETRY_DELAYS_SECONDS: Final[tuple[float, ...]] = (2, 4, 8)

# Seconds a terminated git process group gets to exit after SIGTERM (so git
# can remove its lock files and partial clone) before it receives SIGKILL.
_TERMINATION_GRACE_SECONDS: Final[float] = 5

# Upper bound of the stderr text carried by an exception.
_STDERR_LIMIT: Final[int] = 4096

_SHA_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
_EPOCH_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9]+")
_BRANCH_PREFIX: Final[str] = "refs/heads/"
_MISSING_PATH_MARKERS: Final[tuple[str, ...]] = ("does not exist in", "path not found")

# The repository-local variables printed by `git rev-parse --local-env-vars`.
# An inherited value would redirect or reconfigure the target repository.
_GIT_LOCAL_ENV_VARS: Final[frozenset[str]] = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_PREFIX",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)

_GIT_ENV_OVERRIDES: Final[dict[str, str]] = {
    "LC_ALL": "C",
    "GIT_TERMINAL_PROMPT": "0",
    "TZ": "UTC",
}


class GitError(Exception):
    """Base class of every git operation failure."""


class GitFetchError(GitError):
    """A clone or fetch failed; an existing clone is intact."""


class GitCorruptionError(GitError):
    """A local read failed persistently; the clone must be re-created."""


class GitFileError(GitError):
    """Reading one file's content failed; other files are unaffected."""


@dataclass(frozen=True, slots=True)
class _Completed:
    returncode: int
    stdout: bytes
    stderr: str


class _AttemptFailedError(Exception):
    """One failed attempt of an operation; `detail` describes it."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


# Indirection so tests can replace the backoff wait without real delays.
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


def _git_subprocess_env() -> dict[str, str]:
    """Process environment without git's repository-local variables, plus
    the git-specific overrides (Module Invariants, Rule 3)."""
    inherited = {
        name: value
        for name, value in os.environ.items()
        if name not in _GIT_LOCAL_ENV_VARS
    }
    return inherited | _GIT_ENV_OVERRIDES


def _git_dir(repo_path: Path) -> str:
    return f"--git-dir={repo_path}"


def _describe(args: tuple[str, ...], completed: _Completed) -> str:
    command = args[1] if args[0].startswith("--git-dir=") else args[0]
    stderr = completed.stderr.strip()
    return f"git {command} exited with {completed.returncode}: {stderr}"


def _signal_group(pid: int, signum: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signum)


def _held(held: BaseException | None, new: BaseException) -> BaseException:
    """The interruption to raise after reaping: the first that is not a
    cancellation, else the latest cancellation."""
    if held is None or isinstance(held, asyncio.CancelledError):
        return new
    return held


async def _terminate(process: asyncio.subprocess.Process) -> None:
    """Terminate the git process group and reap the git process.

    A further interruption (cancellation, whole-run signal) while this runs
    is held until the process is reaped, then raised; the first one that is
    not a cancellation takes precedence."""
    if process.returncode is not None:
        return
    _signal_group(process.pid, signal.SIGTERM)
    interruption: BaseException | None = None
    try:
        async with asyncio.timeout(_TERMINATION_GRACE_SECONDS):
            await asyncio.shield(process.wait())
    except TimeoutError:
        pass
    except BaseException as exc:
        interruption = _held(interruption, exc)
    # Also removes helpers (remote transport, index-pack) that outlive the
    # git process itself.
    _signal_group(process.pid, signal.SIGKILL)
    while True:
        try:
            await asyncio.shield(process.wait())
            break
        except BaseException as exc:
            interruption = _held(interruption, exc)
    if interruption is not None:
        raise interruption


async def _run(args: tuple[str, ...], *, limit_seconds: float) -> _Completed:
    """Run one git command; a spawn failure or the timeout is a failed
    attempt. Every other exception propagates after the process is gone."""
    try:
        process = await asyncio.create_subprocess_exec(
            "git",
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_git_subprocess_env(),
            start_new_session=True,
        )
    except OSError as exc:
        raise _AttemptFailedError(f"git could not be started: {exc}") from exc
    try:
        async with asyncio.timeout(limit_seconds):
            stdout, stderr = await process.communicate()
    except BaseException as exc:
        await _terminate(process)
        if isinstance(exc, TimeoutError):
            raise _AttemptFailedError(
                f"git timed out after {limit_seconds:g} seconds"
            ) from exc
        raise
    return _Completed(
        returncode=await process.wait(),
        stdout=stdout,
        stderr=stderr[:_STDERR_LIMIT].decode("utf-8", errors="replace"),
    )


async def _read_with_retries[T](attempt: Callable[[], Awaitable[T]]) -> T:
    """Apply the read retry policy: 4 attempts with 2/4/8 second backoff,
    then `GitCorruptionError`. `attempt` raises `_AttemptFailedError`."""
    for delay in READ_RETRY_DELAYS_SECONDS:
        try:
            return await attempt()
        except _AttemptFailedError:
            await _sleep(delay)
    try:
        return await attempt()
    except _AttemptFailedError as failure:
        raise GitCorruptionError(failure.detail) from None


async def _read(repo_path: Path, *args: str) -> _Completed:
    return await _run((_git_dir(repo_path), *args), limit_seconds=READ_TIMEOUT_SECONDS)


# --- Clone operations -------------------------------------------------------


async def clone(
    url: str,
    dest: Path,
    *,
    filter_spec: str | None = None,
    single_branch: bool = False,
) -> None:
    """Create a bare clone of `url` at `dest`. Raises `GitFetchError`."""
    args = ["clone", "--bare"]
    if filter_spec is not None:
        args.append(f"--filter={filter_spec}")
    if single_branch:
        args.append("--single-branch")
    args += ["--", url, str(dest)]
    command = tuple(args)
    try:
        completed = await _run(command, limit_seconds=CLONE_TIMEOUT_SECONDS)
    except _AttemptFailedError as failure:
        raise GitFetchError(failure.detail) from None
    if completed.returncode != 0:
        raise GitFetchError(_describe(command, completed))


# --- Fetch operations -------------------------------------------------------


async def _branch_ref(repo_path: Path) -> str:
    """The clone's own branch (`refs/heads/...`) that `HEAD` names."""

    async def attempt() -> str:
        args = ("symbolic-ref", "--end-of-options", "HEAD")
        completed = await _read(repo_path, *args)
        if completed.returncode != 0:
            raise _AttemptFailedError(_describe(args, completed))
        ref = completed.stdout.decode("utf-8", errors="replace").strip()
        if not ref.startswith(_BRANCH_PREFIX) or len(ref.split()) != 1:
            raise _AttemptFailedError("git symbolic-ref HEAD named no local branch")
        return ref

    return await _read_with_retries(attempt)


async def fetch_origin(repo_path: Path) -> None:
    """Update the clone's own branch, and therefore `HEAD`, from the remote's
    `HEAD`. Raises `GitCorruptionError` (branch lookup) or `GitFetchError`."""
    ref = await _branch_ref(repo_path)
    command = (
        _git_dir(repo_path),
        "fetch",
        "--end-of-options",
        "origin",
        f"+HEAD:{ref}",
    )
    try:
        completed = await _run(command, limit_seconds=FETCH_TIMEOUT_SECONDS)
    except _AttemptFailedError as failure:
        raise GitFetchError(failure.detail) from None
    if completed.returncode != 0:
        raise GitFetchError(_describe(command, completed))


# --- Read operations --------------------------------------------------------


async def get_head_sha(repo_path: Path) -> str:
    """The commit SHA that `HEAD` points to. Raises `GitCorruptionError`."""

    async def attempt() -> str:
        args = ("rev-parse", "--verify", "--end-of-options", "HEAD")
        completed = await _read(repo_path, *args)
        if completed.returncode != 0:
            raise _AttemptFailedError(_describe(args, completed))
        sha = completed.stdout.decode("ascii", errors="replace").strip()
        if _SHA_PATTERN.fullmatch(sha) is None:
            raise _AttemptFailedError("git rev-parse HEAD printed no 40-hex SHA")
        return sha

    return await _read_with_retries(attempt)


async def get_commit_date(repo_path: Path, ref: str) -> str:
    """The committer date of `ref` as an ISO 8601 UTC string with `+00:00`.
    Raises `GitCorruptionError`."""

    async def attempt() -> str:
        args = ("log", "-1", "--format=%ct", "--end-of-options", ref)
        completed = await _read(repo_path, *args)
        if completed.returncode != 0:
            raise _AttemptFailedError(_describe(args, completed))
        epoch = completed.stdout.decode("ascii", errors="replace").strip()
        if _EPOCH_PATTERN.fullmatch(epoch) is None:
            raise _AttemptFailedError("git log printed no committer epoch")
        return datetime.fromtimestamp(int(epoch), UTC).isoformat()

    return await _read_with_retries(attempt)


def _is_absent_or_not_directory(path: Path) -> bool:
    """Whether `path` definitively is no directory. Any other failure to
    inspect it (for example a transient I/O error) is left to the retried
    git check."""
    try:
        return not stat.S_ISDIR(path.stat().st_mode)
    except FileNotFoundError, NotADirectoryError, ValueError:
        return True
    except OSError:
        return False


async def is_clone_valid(repo_path: Path) -> bool:
    """Whether `repo_path` is a bare repository whose `HEAD` names a commit.
    Never raises for a git or filesystem failure."""
    if await asyncio.to_thread(_is_absent_or_not_directory, repo_path):
        return False

    async def attempt() -> None:
        bare_args = ("rev-parse", "--is-bare-repository")
        completed = await _read(repo_path, *bare_args)
        if completed.returncode != 0 or completed.stdout.strip() != b"true":
            raise _AttemptFailedError(_describe(bare_args, completed))
        head_args = (
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            "HEAD^{commit}",
        )
        completed = await _read(repo_path, *head_args)
        if completed.returncode != 0:
            raise _AttemptFailedError(_describe(head_args, completed))

    try:
        await _read_with_retries(attempt)
    except GitCorruptionError:
        return False
    return True


async def check_sha_reachable(repo_path: Path, sha: str) -> bool:
    """Whether `sha` names a commit in the local object store. A malformed
    SHA is unreachable without invoking git (Module Invariants, Rule 1).
    Raises `GitCorruptionError` only for unexpected failures."""
    if _SHA_PATTERN.fullmatch(sha) is None:
        logger.warning("git_invalid_sha_format")
        return False

    async def attempt() -> bool:
        args = (
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{sha}^{{commit}}",
        )
        completed = await _read(repo_path, *args)
        if completed.returncode == 0:
            return True
        if completed.returncode == 1:
            return False
        raise _AttemptFailedError(_describe(args, completed))

    return await _read_with_retries(attempt)


async def diff_names(
    repo_path: Path,
    from_sha: str,
    to_sha: str,
    *,
    path_filter: str | None = None,
) -> list[str]:
    """Paths added or modified between two commits, renames as delete plus
    add. Raises `GitCorruptionError`, or `ValueError` for an empty
    `path_filter` without invoking git."""
    if path_filter == "":
        raise ValueError("path_filter must not be empty")
    args = [
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        "--diff-filter=AM",
        "--end-of-options",
        f"{from_sha}..{to_sha}",
    ]
    if path_filter is not None:
        args += ["--", path_filter]
    command = tuple(args)

    async def attempt() -> list[str]:
        completed = await _read(repo_path, *command)
        if completed.returncode != 0:
            raise _AttemptFailedError(_describe(command, completed))
        return [os.fsdecode(path) for path in completed.stdout.split(b"\0") if path]

    return await _read_with_retries(attempt)


async def rev_list_before(repo_path: Path, before_date: str) -> str | None:
    """The most recent commit on `HEAD` before `before_date`, or `None` when
    no commit precedes it. Raises `GitCorruptionError`."""

    async def attempt() -> str | None:
        args = ("rev-list", "-1", f"--before={before_date}", "--end-of-options", "HEAD")
        completed = await _read(repo_path, *args)
        if completed.returncode != 0:
            raise _AttemptFailedError(_describe(args, completed))
        sha = completed.stdout.decode("ascii", errors="replace").strip()
        if not sha:
            return None
        if _SHA_PATTERN.fullmatch(sha) is None:
            raise _AttemptFailedError("git rev-list printed no 40-hex SHA")
        return sha

    return await _read_with_retries(attempt)


# --- Show operations --------------------------------------------------------


async def show_file(repo_path: Path, ref: str, file_path: str) -> bytes | None:
    """The content of `file_path` at `ref`, or `None` if the path does not
    exist there. Raises `GitFileError` for any other failure (no retry)."""
    command = (_git_dir(repo_path), "show", "--end-of-options", f"{ref}:{file_path}")
    try:
        completed = await _run(command, limit_seconds=SHOW_TIMEOUT_SECONDS)
    except _AttemptFailedError as failure:
        raise GitFileError(failure.detail) from None
    if completed.returncode == 0:
        return completed.stdout
    if completed.returncode == 128 and any(
        marker in completed.stderr for marker in _MISSING_PATH_MARKERS
    ):
        return None
    raise GitFileError(_describe(command, completed))


# --- Filesystem operations --------------------------------------------------


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        # Only raised for `path` itself: entries removed concurrently are
        # ignored by `rmtree`.
        if os.path.lexists(path):
            raise


async def delete_clone(path: Path) -> None:
    """Recursively delete the directory at `path`; no-op if it does not
    exist. Raises `OSError` unchanged for a filesystem rejection."""
    await asyncio.to_thread(_remove_tree, path)
