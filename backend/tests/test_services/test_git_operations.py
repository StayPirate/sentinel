"""Hermetic tests of `app.services.git_operations` against real git.

Contract: `docs/features/platform/git-fetcher-infrastructure.md` (Bare Clone
Pattern, Cursor SHA Unreachable, Runtime Dependencies, Error Classification,
Function Catalog). Every repository lives under `tmp_path`; an autouse
fixture removes every inherited `GIT_*` variable and the user and system Git
configuration from the module's processes, so the tests also pass inside the
Git hooks (see `docs/features/platform/testing-strategy.md`, Tier 1 — Unit
Tests). The retry backoff is recorded instead of awaited.

Process lifecycle, timeouts, and invocation counts that need a controllable
`git` live in `test_git_operations_process.py`.
"""

from __future__ import annotations

import errno
import inspect
import os
import shutil
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from structlog.testing import capture_logs

from app.services import git_operations
from app.services.git_operations import (
    CLONE_TIMEOUT_SECONDS,
    FETCH_TIMEOUT_SECONDS,
    READ_RETRY_DELAYS_SECONDS,
    READ_TIMEOUT_SECONDS,
    SHOW_TIMEOUT_SECONDS,
    GitCorruptionError,
    GitError,
    GitFetchError,
    GitFileError,
    check_sha_reachable,
    clone,
    delete_clone,
    diff_names,
    fetch_origin,
    get_commit_date,
    get_head_sha,
    is_clone_valid,
    rev_list_before,
    show_file,
)
from tests.support.git_repos import (
    HERMETIC_GIT_CONFIG,
    automatic_maintenance_runs,
    commit_files,
    foreground_maintenance_config,
    git,
    init_bare,
    init_upstream,
    isolate_process_environment,
    loose_object_path,
    rev_parse,
    traced_commands,
)

pytestmark = pytest.mark.unit

type GitCall = tuple[tuple[str, ...], float]

RETRY_DELAYS = [2, 4, 8]


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
def git_calls(monkeypatch: pytest.MonkeyPatch) -> list[GitCall]:
    """Every git command the module runs, with its timeout."""
    calls: list[GitCall] = []
    real_run = git_operations._run

    async def spy(
        args: tuple[str, ...], *, limit_seconds: float
    ) -> git_operations._Completed:
        calls.append((args, limit_seconds))
        return await real_run(args, limit_seconds=limit_seconds)

    monkeypatch.setattr(git_operations, "_run", spy)
    return calls


def _subcommands(calls: list[GitCall]) -> list[str]:
    return [
        args[1] if args[0].startswith("--git-dir=") else args[0] for args, _ in calls
    ]


def _entries(directory: Path, pattern: str = "*") -> list[str]:
    return sorted(path.name for path in directory.glob(pattern))


def _clone_bare(upstream: Path, dest: Path) -> Path:
    git(None, "clone", "--quiet", "--bare", "--", upstream.as_uri(), str(dest))
    return dest


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
    repo = init_upstream(tmp_path / "upstream")
    commit_files(repo, {"README": b"initial\n"}, message="initial")
    return repo


@pytest.fixture
def bare(upstream: Path, tmp_path: Path) -> Path:
    return _clone_bare(upstream, tmp_path / "clone")


# --- Exported interface -----------------------------------------------------


def test_timeout_and_retry_constants_match_operation_categories() -> None:
    assert (
        CLONE_TIMEOUT_SECONDS,
        FETCH_TIMEOUT_SECONDS,
        READ_TIMEOUT_SECONDS,
        SHOW_TIMEOUT_SECONDS,
    ) == (1800, 300, 30, 30)
    assert READ_RETRY_DELAYS_SECONDS == (2, 4, 8)


@pytest.mark.parametrize("error", [GitFetchError, GitCorruptionError, GitFileError])
def test_exception_hierarchy_phase_error_subclasses_git_error(
    error: type[GitError],
) -> None:
    assert issubclass(error, GitError)
    assert issubclass(GitError, Exception)


def test_clone_signature_without_bare_parameter_takes_keyword_only_flags() -> None:
    parameters = inspect.signature(clone).parameters

    assert list(parameters) == ["url", "dest", "filter_spec", "single_branch"]
    assert parameters["filter_spec"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["filter_spec"].default is None
    assert parameters["single_branch"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["single_branch"].default is False


async def test_operations_command_shapes_use_their_category_timeout(
    bare: Path, upstream: Path, tmp_path: Path, git_calls: list[GitCall]
) -> None:
    head = rev_parse(bare, "HEAD")
    second = tmp_path / "second"
    git_dir = f"--git-dir={bare}"

    await clone(upstream.as_uri(), second)
    await fetch_origin(bare)
    await get_head_sha(bare)
    await get_commit_date(bare, head)
    await is_clone_valid(bare)
    await check_sha_reachable(bare, head)
    await diff_names(bare, head, head, path_filter="cves/")
    await rev_list_before(bare, "2100-01-01T00:00:00+00:00")
    await show_file(bare, head, "README")

    read = READ_TIMEOUT_SECONDS
    verify = ("rev-parse", "--verify", "--quiet", "--end-of-options")
    diff = ("diff", "--name-only", "-z", "--no-renames", "--diff-filter=AM")
    before = "--before=2100-01-01T00:00:00+00:00"
    assert git_calls == [
        (
            ("clone", "--bare", "--", upstream.as_uri(), str(second)),
            CLONE_TIMEOUT_SECONDS,
        ),
        ((git_dir, "symbolic-ref", "--end-of-options", "HEAD"), read),
        (
            (git_dir, "fetch", "--end-of-options", "origin", "+HEAD:refs/heads/main"),
            FETCH_TIMEOUT_SECONDS,
        ),
        ((git_dir, "rev-parse", "--verify", "--end-of-options", "HEAD"), read),
        ((git_dir, "log", "-1", "--format=%ct", "--end-of-options", head), read),
        ((git_dir, "rev-parse", "--is-bare-repository"), read),
        ((git_dir, *verify, "HEAD^{commit}"), read),
        ((git_dir, *verify, f"{head}^{{commit}}"), read),
        (
            (git_dir, *diff, "--end-of-options", f"{head}..{head}", "--", "cves/"),
            read,
        ),
        ((git_dir, "rev-list", "-1", before, "--end-of-options", "HEAD"), read),
        ((git_dir, "show", "--end-of-options", f"{head}:README"), SHOW_TIMEOUT_SECONDS),
    ]


# --- Rule 3: subprocess environment -----------------------------------------


def test_git_subprocess_env_inherited_local_variables_removed_and_overrides_applied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in git_operations._GIT_LOCAL_ENV_VARS:
        monkeypatch.setenv(name, "/inherited/value")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SENTINEL_EXAMPLE_UNRELATED", "kept")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "1")
    monkeypatch.setenv("TZ", "Europe/Rome")

    env = git_operations._git_subprocess_env()

    assert not env.keys() & git_operations._GIT_LOCAL_ENV_VARS
    assert env["PATH"] == os.environ["PATH"]
    assert env["HOME"] == str(tmp_path)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == str(HERMETIC_GIT_CONFIG)
    assert env["SENTINEL_EXAMPLE_UNRELATED"] == "kept"
    assert (env["LC_ALL"], env["GIT_TERMINAL_PROMPT"], env["TZ"]) == ("C", "0", "UTC")


def test_git_local_env_vars_constant_contains_every_name_git_prints(
    tmp_path: Path,
) -> None:
    printed = set(git(tmp_path, "rev-parse", "--local-env-vars").stdout.split())

    assert printed
    assert printed <= git_operations._GIT_LOCAL_ENV_VARS


async def test_inherited_repository_variables_do_not_affect_target_clone(
    bare: Path, upstream: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _clone_bare(upstream, tmp_path / "decoy")
    rewrite = f"'url.file:///nonexistent/.insteadof'='{upstream.as_uri()}'"
    # Precondition: the injected rewrite really redirects a plain fetch.
    redirected = git(
        None,
        f"--git-dir={bare}",
        "fetch",
        "--end-of-options",
        "origin",
        "+HEAD:refs/heads/main",
        env_extra={"GIT_CONFIG_PARAMETERS": rewrite},
        check=False,
    )
    assert redirected.returncode != 0
    assert "/nonexistent/" in redirected.stderr
    commit_files(upstream, {"README": b"decoy\n"})
    git(None, f"--git-dir={decoy}", "fetch", "origin", "+HEAD:refs/heads/main")
    decoy_head = rev_parse(decoy, "HEAD")
    old_head = rev_parse(bare, "HEAD")
    new_head = commit_files(upstream, {"README": b"updated\n"})
    monkeypatch.setenv("GIT_DIR", str(decoy))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "nonexistent-index"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "nonexistent-objects"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", rewrite)

    assert await get_head_sha(bare) == old_head
    await fetch_origin(bare)
    assert await get_head_sha(bare) == new_head
    assert await show_file(bare, "HEAD", "README") == b"updated\n"
    assert rev_parse(decoy, "HEAD") == decoy_head


@pytest.mark.parametrize(
    ("configuration", "expected_runs"),
    [
        pytest.param("hermetic", 0, id="hermetic"),
        # Control: with git's default, the same fetch starts maintenance.
        pytest.param("git-default", 1, id="git-default"),
    ],
)
async def test_fetch_origin_automatic_maintenance_follows_global_configuration(
    bare: Path,
    upstream: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configuration: str,
    expected_runs: int,
) -> None:
    # Rule 3 keeps `GIT_CONFIG_GLOBAL`, so the harness configuration reaches
    # the module's own `git fetch`; production keeps git's default (Fetch
    # Operations, Automatic maintenance).
    commit_files(upstream, {"README": b"updated\n"})
    trace = tmp_path / "trace.json"
    monkeypatch.setenv("GIT_TRACE2_EVENT", str(trace))
    if configuration == "git-default":
        config = foreground_maintenance_config(tmp_path)
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))

    await fetch_origin(bare)

    assert ["fetch"] in [argv[2:3] for argv in traced_commands(trace)]
    assert len(automatic_maintenance_runs(trace)) == expected_runs


# --- Clone operations -------------------------------------------------------


async def test_clone_valid_source_creates_bare_clone_with_resolvable_head(
    upstream: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "clone"

    await clone(upstream.as_uri(), dest)

    config = git(None, f"--git-dir={dest}", "config", "--get", "core.bare")
    assert config.stdout.strip() == "true"
    assert rev_parse(dest, "HEAD") == rev_parse(upstream / ".git", "HEAD")


@pytest.mark.parametrize(
    ("filter_spec", "single_branch", "flags"),
    [
        (None, False, ()),
        ("blob:none", False, ("--filter=blob:none",)),
        (None, True, ("--single-branch",)),
        ("blob:none", True, ("--filter=blob:none", "--single-branch")),
    ],
)
async def test_clone_flag_combination_builds_documented_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filter_spec: str | None,
    single_branch: bool,
    flags: tuple[str, ...],
) -> None:
    calls: list[GitCall] = []

    async def fake_run(
        args: tuple[str, ...], *, limit_seconds: float
    ) -> git_operations._Completed:
        calls.append((args, limit_seconds))
        return git_operations._Completed(returncode=0, stdout=b"", stderr="")

    monkeypatch.setattr(git_operations, "_run", fake_run)
    url = "https://git.example.invalid/source.git"
    dest = tmp_path / "clone"

    await clone(url, dest, filter_spec=filter_spec, single_branch=single_branch)

    expected = ("clone", "--bare", *flags, "--", url, str(dest))
    assert calls == [(expected, CLONE_TIMEOUT_SECONDS)]


async def test_clone_url_beginning_with_dash_is_not_parsed_as_option(
    tmp_path: Path, git_calls: list[GitCall], sleeps: list[float]
) -> None:
    marker = tmp_path / "pwn"
    url = f"--upload-pack=touch {marker}"
    dest = tmp_path / "clone"

    with pytest.raises(GitFetchError, match="does not exist") as excinfo:
        await clone(url, dest)

    assert f"'{url}'" in str(excinfo.value)
    assert _entries(tmp_path) == []
    assert len(git_calls) == 1
    assert sleeps == []


async def test_clone_nonexistent_source_raises_fetch_error_after_one_attempt(
    tmp_path: Path, git_calls: list[GitCall], sleeps: list[float]
) -> None:
    dest = tmp_path / "clone"

    with pytest.raises(GitFetchError, match="git clone exited with 128"):
        await clone((tmp_path / "missing").as_uri(), dest)

    assert len(git_calls) == 1
    assert sleeps == []
    assert not dest.exists()


# --- Fetch operations (K-a) -------------------------------------------------


@pytest.mark.parametrize("single_branch", [False, True])
async def test_fetch_origin_after_upstream_commit_advances_head(
    upstream: Path, tmp_path: Path, single_branch: bool
) -> None:
    dest = tmp_path / "clone"
    await clone(upstream.as_uri(), dest, single_branch=single_branch)
    new_head = commit_files(upstream, {"cves/added.json": b"{}\n"})

    await fetch_origin(dest)

    assert await get_head_sha(dest) == new_head


async def test_fetch_origin_forced_upstream_rewrite_is_followed_and_cursor_kept(
    bare: Path, upstream: Path
) -> None:
    base = rev_parse(bare, "HEAD")
    cursor = commit_files(upstream, {"cves/a.json": b"a\n"})
    await fetch_origin(bare)
    git(upstream, "reset", "--quiet", "--hard", base)
    rewritten = commit_files(upstream, {"cves/b.json": b"b\n"})

    await fetch_origin(bare)

    assert await get_head_sha(bare) == rewritten
    assert await check_sha_reachable(bare, cursor) is True
    assert await diff_names(bare, cursor, rewritten) == ["cves/b.json"]


async def test_fetch_origin_upstream_default_branch_switch_follows_new_branch(
    bare: Path, upstream: Path
) -> None:
    frozen = rev_parse(upstream / ".git", "HEAD")
    git(upstream, "switch", "--quiet", "--create", "trunk")
    trunk_head = commit_files(upstream, {"cves/trunk.json": b"t\n"})

    await fetch_origin(bare)

    assert await get_head_sha(bare) == trunk_head
    assert rev_parse(upstream / ".git", "refs/heads/main") == frozen


async def test_fetch_origin_upstream_branch_rename_is_followed(
    bare: Path, upstream: Path
) -> None:
    git(upstream, "branch", "--move", "main", "trunk")
    renamed_head = commit_files(upstream, {"cves/renamed.json": b"r\n"})

    await fetch_origin(bare)

    assert await get_head_sha(bare) == renamed_head


async def test_fetch_origin_local_branch_name_differs_from_upstream_updates_head(
    tmp_path: Path,
) -> None:
    upstream = init_upstream(tmp_path / "upstream", branch="trunk")
    upstream_head = commit_files(upstream, {"README": b"trunk\n"})
    dest = init_bare(tmp_path / "clone", branch="master")
    git(None, f"--git-dir={dest}", "config", "remote.origin.url", upstream.as_uri())

    await fetch_origin(dest)

    assert await get_head_sha(dest) == upstream_head
    assert rev_parse(dest, "refs/heads/master") == upstream_head


def _remove_upstream(upstream: Path) -> None:
    shutil.rmtree(upstream)


def _point_upstream_head_to_missing_branch(upstream: Path) -> None:
    git(upstream, "symbolic-ref", "HEAD", "refs/heads/missing")


@pytest.mark.parametrize(
    "break_upstream",
    [
        pytest.param(_remove_upstream, id="unreachable-remote"),
        pytest.param(_point_upstream_head_to_missing_branch, id="unresolvable-head"),
    ],
)
async def test_fetch_origin_fetch_failure_raises_fetch_error_without_retry(
    bare: Path,
    upstream: Path,
    git_calls: list[GitCall],
    sleeps: list[float],
    break_upstream: Callable[[Path], None],
) -> None:
    head = rev_parse(bare, "HEAD")
    break_upstream(upstream)

    with pytest.raises(GitFetchError, match="git fetch exited with 128"):
        await fetch_origin(bare)

    assert _subcommands(git_calls) == ["symbolic-ref", "fetch"]
    assert sleeps == []
    assert rev_parse(bare, "HEAD") == head


def _detach_head(bare: Path) -> None:
    git(None, f"--git-dir={bare}", "update-ref", "--no-deref", "HEAD", "HEAD")


def _point_head_to_tag(bare: Path) -> None:
    git(None, f"--git-dir={bare}", "tag", "v1", "HEAD")
    git(None, f"--git-dir={bare}", "symbolic-ref", "HEAD", "refs/tags/v1")


@pytest.mark.parametrize(
    "damage_head",
    [
        pytest.param(_detach_head, id="detached-head"),
        pytest.param(_point_head_to_tag, id="head-names-a-tag"),
    ],
)
async def test_fetch_origin_head_naming_no_branch_retries_then_raises_corruption(
    bare: Path,
    git_calls: list[GitCall],
    sleeps: list[float],
    damage_head: Callable[[Path], None],
) -> None:
    damage_head(bare)

    with pytest.raises(GitCorruptionError):
        await fetch_origin(bare)

    assert _subcommands(git_calls) == ["symbolic-ref"] * 4
    assert sleeps == RETRY_DELAYS


# --- Read operations --------------------------------------------------------


async def test_get_head_sha_bare_clone_returns_head_commit(
    bare: Path, upstream: Path
) -> None:
    assert await get_head_sha(bare) == rev_parse(upstream / ".git", "HEAD")


async def test_get_head_sha_unborn_head_retries_then_raises_corruption(
    tmp_path: Path, git_calls: list[GitCall], sleeps: list[float]
) -> None:
    repo = init_bare(tmp_path / "unborn")

    with pytest.raises(GitCorruptionError):
        await get_head_sha(repo)

    assert _subcommands(git_calls) == ["rev-parse"] * 4
    assert sleeps == RETRY_DELAYS


async def test_get_commit_date_non_utc_committer_offset_returns_same_instant_in_utc(
    upstream: Path, tmp_path: Path
) -> None:
    sha = commit_files(upstream, {"a": b"a\n"}, date="2026-01-01T12:00:00+02:00")
    bare = _clone_bare(upstream, tmp_path / "clone")

    assert await get_commit_date(bare, sha) == "2026-01-01T10:00:00+00:00"


async def test_get_commit_date_unknown_ref_retries_then_raises_corruption(
    bare: Path, sleeps: list[float]
) -> None:
    with pytest.raises(GitCorruptionError, match="git log exited with 128"):
        await get_commit_date(bare, "refs/heads/nonexistent")

    assert sleeps == RETRY_DELAYS


async def test_diff_names_added_and_modified_returned_deleted_excluded(
    upstream: Path, tmp_path: Path
) -> None:
    base = commit_files(
        upstream, {"cves/modified.json": b"1\n", "cves/gone.json": b"x\n"}
    )
    head = commit_files(
        upstream,
        {"cves/modified.json": b"2\n", "cves/gone.json": None, "cves/new.json": b"n\n"},
    )
    bare = _clone_bare(upstream, tmp_path / "clone")

    assert await diff_names(bare, base, head) == ["cves/modified.json", "cves/new.json"]


async def test_diff_names_rename_returns_only_new_path(
    upstream: Path, tmp_path: Path
) -> None:
    content = b'{"id": "CVE-2026-0001", "padding": "' + b"x" * 200 + b'"}\n'
    base = commit_files(upstream, {"cves/old.json": content})
    head = commit_files(upstream, {"cves/old.json": None, "cves/new.json": content})
    bare = _clone_bare(upstream, tmp_path / "clone")

    assert await diff_names(bare, base, head) == ["cves/new.json"]


async def test_diff_names_path_filter_restricts_to_prefix(
    upstream: Path, tmp_path: Path
) -> None:
    base = rev_parse(upstream / ".git", "HEAD")
    head = commit_files(upstream, {"cves/a.json": b"a\n", "other/b.json": b"b\n"})
    bare = _clone_bare(upstream, tmp_path / "clone")

    assert await diff_names(bare, base, head) == ["cves/a.json", "other/b.json"]
    assert await diff_names(bare, base, head, path_filter="cves/") == ["cves/a.json"]


async def test_diff_names_empty_path_filter_raises_value_error_without_git(
    bare: Path, git_calls: list[GitCall]
) -> None:
    head = rev_parse(bare, "HEAD")

    with pytest.raises(ValueError, match="path_filter"):
        await diff_names(bare, head, head, path_filter="")

    assert git_calls == []


async def test_diff_names_unusual_path_returned_verbatim_and_readable_by_show_file(
    upstream: Path, tmp_path: Path
) -> None:
    path = 'cves/ünïcödé "quoted"\tname.json'
    base = rev_parse(upstream / ".git", "HEAD")
    head = commit_files(upstream, {path: b"unusual\n"})
    bare = _clone_bare(upstream, tmp_path / "clone")

    names = await diff_names(bare, base, head)

    assert names == [path]
    assert await show_file(bare, head, names[0]) == b"unusual\n"


async def test_rev_list_before_returns_latest_commit_before_date_or_none(
    tmp_path: Path,
) -> None:
    upstream = init_upstream(tmp_path / "upstream")
    first = commit_files(upstream, {"a": b"1\n"}, date="2026-01-01T00:00:00+00:00")
    second = commit_files(upstream, {"a": b"2\n"}, date="2026-02-01T00:00:00+00:00")
    commit_files(upstream, {"a": b"3\n"}, date="2026-03-01T00:00:00+00:00")
    bare = _clone_bare(upstream, tmp_path / "clone")

    assert await rev_list_before(bare, "2026-02-15T00:00:00+00:00") == second
    assert await rev_list_before(bare, "2026-01-15T00:00:00+00:00") == first
    assert await rev_list_before(bare, "2025-12-01T00:00:00+00:00") is None


# --- is_clone_valid (K-g) ---------------------------------------------------


async def test_is_clone_valid_bare_clone_returns_true(bare: Path) -> None:
    assert await is_clone_valid(bare) is True


def _regular_file(tmp_path: Path, bare: Path) -> Path:
    path = tmp_path / "file"
    path.write_bytes(b"not a repository\n")
    return path


def _absent(tmp_path: Path, bare: Path) -> Path:
    return tmp_path / "absent"


@pytest.mark.parametrize(
    "make_path",
    [
        pytest.param(_absent, id="absent"),
        pytest.param(_regular_file, id="regular-file"),
    ],
)
async def test_is_clone_valid_non_directory_returns_false_without_git(
    tmp_path: Path,
    bare: Path,
    git_calls: list[GitCall],
    sleeps: list[float],
    make_path: Callable[[Path, Path], Path],
) -> None:
    assert await is_clone_valid(make_path(tmp_path, bare)) is False
    assert git_calls == []
    assert sleeps == []


async def test_is_clone_valid_transient_inspection_error_leaves_decision_to_git(
    bare: Path, monkeypatch: pytest.MonkeyPatch, git_calls: list[GitCall]
) -> None:
    real_stat = Path.stat

    def failing_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == bare:
            raise OSError(errno.EIO, "Input/output error", str(self))
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", failing_stat)

    assert await is_clone_valid(bare) is True
    assert _subcommands(git_calls) == ["rev-parse", "rev-parse"]


def _empty_directory(tmp_path: Path, bare: Path) -> Path:
    path = tmp_path / "empty"
    path.mkdir()
    return path


def _corrupted_head(tmp_path: Path, bare: Path) -> Path:
    (bare / "HEAD").write_bytes(b"garbage\n")
    return bare


def _work_tree_root(tmp_path: Path, bare: Path) -> Path:
    return tmp_path / "upstream"


def _work_tree_git_dir(tmp_path: Path, bare: Path) -> Path:
    return tmp_path / "upstream" / ".git"


def _nested_non_repository(tmp_path: Path, bare: Path) -> Path:
    path = tmp_path / "upstream" / "nested"
    path.mkdir()
    return path


def _bare_without_commit(tmp_path: Path, bare: Path) -> Path:
    return init_bare(tmp_path / "interrupted")


@pytest.mark.parametrize(
    "make_path",
    [
        pytest.param(_empty_directory, id="empty-directory"),
        pytest.param(_corrupted_head, id="corrupted-head"),
        pytest.param(_work_tree_root, id="non-bare-work-tree"),
        pytest.param(_work_tree_git_dir, id="non-bare-git-dir"),
        pytest.param(_nested_non_repository, id="nested-in-repository"),
        pytest.param(_bare_without_commit, id="bare-without-commit"),
    ],
)
async def test_is_clone_valid_invalid_directory_retries_then_returns_false(
    tmp_path: Path,
    bare: Path,
    sleeps: list[float],
    make_path: Callable[[Path, Path], Path],
) -> None:
    assert await is_clone_valid(make_path(tmp_path, bare)) is False
    assert sleeps == RETRY_DELAYS


# --- check_sha_reachable (K-f, Rule 1) --------------------------------------


async def test_check_sha_reachable_existing_commit_returns_true(bare: Path) -> None:
    assert await check_sha_reachable(bare, rev_parse(bare, "HEAD")) is True


async def test_check_sha_reachable_absent_sha_returns_false_without_retry(
    bare: Path, git_calls: list[GitCall], sleeps: list[float]
) -> None:
    assert await check_sha_reachable(bare, "0123456789abcdef" * 2 + "01234567") is False
    assert len(git_calls) == 1
    assert sleeps == []


async def test_check_sha_reachable_blob_sha_returns_false(
    bare: Path, sleeps: list[float]
) -> None:
    blob = rev_parse(bare, "HEAD:README")

    assert await check_sha_reachable(bare, blob) is False
    assert sleeps == []


@pytest.mark.parametrize(
    "malformed",
    [
        pytest.param("0123abc", id="short"),
        pytest.param("0123456789ABCDEF" * 2 + "01234567", id="uppercase"),
        pytest.param("0123456789abcdef" * 2 + "01234567\n", id="trailing-newline"),
        pytest.param("-" + "0123456789abcdef" * 2 + "0123456", id="leading-dash"),
    ],
)
async def test_check_sha_reachable_malformed_sha_logs_bounded_warning_without_git(
    bare: Path, git_calls: list[GitCall], malformed: str
) -> None:
    with capture_logs() as logs:
        reachable = await check_sha_reachable(bare, malformed)

    assert reachable is False
    assert git_calls == []
    assert logs == [{"event": "git_invalid_sha_format", "log_level": "warning"}]


# --- Read retry policy ------------------------------------------------------


_READS: dict[str, Callable[[Path], Awaitable[object]]] = {
    "fetch_origin-branch-lookup": fetch_origin,
    "get_head_sha": get_head_sha,
    "get_commit_date": lambda repo: get_commit_date(repo, "HEAD"),
    "check_sha_reachable": lambda repo: check_sha_reachable(repo, "a" * 40),
    "diff_names": lambda repo: diff_names(repo, "a" * 40, "b" * 40),
    "rev_list_before": lambda repo: rev_list_before(repo, "2026-01-01"),
}


@pytest.mark.parametrize("read", _READS.values(), ids=_READS.keys())
async def test_read_operation_on_non_repository_retries_then_raises_corruption(
    tmp_path: Path,
    git_calls: list[GitCall],
    sleeps: list[float],
    read: Callable[[Path], Awaitable[object]],
) -> None:
    # `git diff` words it "Not a git repository" (implicit `--no-index`).
    with pytest.raises(GitCorruptionError, match=r"(?i)not a git repository"):
        await read(tmp_path)

    assert len(git_calls) == 4
    assert sleeps == RETRY_DELAYS


# --- Rule 2: values beginning with "-" --------------------------------------


_DASH_ARGUMENTS: dict[
    str, tuple[Callable[[Path, str], Awaitable[object]], type[GitError]]
] = {
    "diff_names-from": (
        lambda repo, value: diff_names(repo, value, "HEAD"),
        GitCorruptionError,
    ),
    "get_commit_date-ref": (get_commit_date, GitCorruptionError),
    "show_file-ref": (
        lambda repo, value: show_file(repo, value, "README"),
        GitFileError,
    ),
}


@pytest.mark.parametrize(
    ("operation", "error"), _DASH_ARGUMENTS.values(), ids=_DASH_ARGUMENTS.keys()
)
async def test_caller_value_beginning_with_dash_is_not_parsed_as_option(
    bare: Path,
    tmp_path: Path,
    operation: Callable[[Path, str], Awaitable[object]],
    error: type[GitError],
) -> None:
    output = tmp_path / "pwn"

    with pytest.raises(error):
        await operation(bare, f"--output={output}")

    assert _entries(tmp_path, "pwn*") == []


_NUL_ARGUMENTS: dict[str, Callable[[Path], Awaitable[object]]] = {
    "clone-url": lambda repo: clone("file:///source\0.git", repo.parent / "nul"),
    "get_commit_date-ref": lambda repo: get_commit_date(repo, "HE\0AD"),
    "diff_names-path_filter": lambda repo: diff_names(
        repo, "a" * 40, "b" * 40, path_filter="cves\0/"
    ),
    "rev_list_before-date": lambda repo: rev_list_before(repo, "2026\0-01-01"),
    "show_file-path": lambda repo: show_file(repo, "HEAD", "READ\0ME"),
}


@pytest.mark.parametrize(
    "operation", _NUL_ARGUMENTS.values(), ids=_NUL_ARGUMENTS.keys()
)
async def test_argument_with_nul_raises_value_error_without_retry(
    bare: Path, sleeps: list[float], operation: Callable[[Path], Awaitable[object]]
) -> None:
    with pytest.raises(ValueError, match="null byte"):
        await operation(bare)

    assert sleeps == []


async def test_nul_values_unreachable_or_invalid_without_raising(
    bare: Path, sleeps: list[float]
) -> None:
    with capture_logs():
        assert await check_sha_reachable(bare, "a" * 39 + "\0") is False
    assert await is_clone_valid(Path(f"{bare}\0")) is False
    assert sleeps == []


# --- show_file (K-d) --------------------------------------------------------


async def test_show_file_existing_path_returns_exact_blob_bytes(
    upstream: Path, tmp_path: Path
) -> None:
    content = b"\x00\x01binary\xff\xfe\x80 not utf-8\r\n\x00"
    head = commit_files(upstream, {"data/blob.bin": content})
    bare = _clone_bare(upstream, tmp_path / "clone")

    assert await show_file(bare, head, "data/blob.bin") == content


async def test_show_file_missing_path_returns_none(bare: Path) -> None:
    assert await show_file(bare, "HEAD", "cves/missing.json") is None


async def test_show_file_unknown_ref_raises_file_error_after_one_attempt(
    bare: Path, git_calls: list[GitCall], sleeps: list[float]
) -> None:
    with pytest.raises(GitFileError, match="git show exited with 128"):
        await show_file(bare, "refs/heads/nonexistent", "README")

    assert len(git_calls) == 1
    assert sleeps == []


async def test_show_file_missing_blob_object_raises_file_error_after_one_attempt(
    upstream: Path, tmp_path: Path, git_calls: list[GitCall], sleeps: list[float]
) -> None:
    # A local clone keeps the upstream's loose objects, so one blob can be
    # removed from the clone's object store alone.
    bare = tmp_path / "clone"
    git(None, "clone", "--quiet", "--bare", "--", str(upstream), str(bare))
    blob = loose_object_path(bare, rev_parse(bare, "HEAD:README"))
    assert blob.is_file()
    blob.unlink()

    with pytest.raises(GitFileError):
        await show_file(bare, "HEAD", "README")

    assert len(git_calls) == 1
    assert sleeps == []


# --- delete_clone -----------------------------------------------------------


async def test_delete_clone_existing_clone_removes_it_recursively(
    bare: Path, tmp_path: Path
) -> None:
    await delete_clone(bare)

    assert _entries(tmp_path) == ["upstream"]


async def test_delete_clone_absent_path_is_noop(tmp_path: Path) -> None:
    await delete_clone(tmp_path / "absent")

    assert _entries(tmp_path) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses directory permissions")
async def test_delete_clone_read_only_parent_raises_permission_error_unchanged(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    target = parent / "clone"
    (target / "objects").mkdir(parents=True)
    parent.chmod(0o555)
    try:
        with pytest.raises(PermissionError) as excinfo:
            await delete_clone(target)
    finally:
        parent.chmod(0o755)

    assert type(excinfo.value) is PermissionError
    assert excinfo.value.errno == errno.EACCES
    assert target.is_dir()


async def test_delete_clone_dangling_symlink_raises_os_error_unchanged(
    tmp_path: Path,
) -> None:
    link = tmp_path / "clone"
    link.symlink_to(tmp_path / "missing-target")

    with pytest.raises(FileNotFoundError):
        await delete_clone(link)

    assert link.is_symlink()
