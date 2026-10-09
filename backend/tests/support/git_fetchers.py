"""Shared harness of the `BaseGitFetcher` tests over real temporary Git
repositories and the real database (backend/app/services/base_git_fetcher.py).

Consumers:

- `tests/test_services/test_base_git_fetcher_execute.py` (the template
  `execute()` through the real `BaseFetcher.run()`);
- `tests/test_services/test_base_git_fetcher_fetch_single.py` (the default
  `fetch_single()` over real bare clones);
- `tests/test_services/test_base_git_fetcher_wrappers.py` (the on-demand and
  catch-up wrappers with a test-only Git fetcher);
- `tests/test_services/test_base_git_fetcher_registration.py` (the
  `GitCalls` spy for utility delegation);
- the production `SyncKernelCves` tests
  (`tests/test_services/test_tickets/test_sync_kernel_cves_execute.py` and
  `test_sync_kernel_cves_reachability.py`, through
  `tests/support/kernel_fetcher.py`), which pass the production class as a
  `GitFetcherProbe` instead of defining a test-only fetcher.

The fetcher factory, the item steps, the workspace, and the `git_operations`
spy carry no run-specific assumption, so the other `BaseGitFetcher` tests
(single-item fetch, registration) can reuse them.

Provided here:

- `define_git_fetcher()`, which registers a concrete test-only
  `BaseGitFetcher` subclass (the consumer requests
  `isolated_fetcher_registries`; the owned `CVESourceType` is popped from
  `_CVE_SOURCE_TYPE_MAP` first). Its `process_item()` runs a per-path or
  default `ItemStep` and records every call; its hooks record the raw delta
  and apply optional overrides; its `commit_and_dispatch()` and
  `_isolated_status_commit()` record, then delegate unchanged to the real
  implementations. The returned `GitFetcherProbe` holds the observations;
- item steps: `token()`, `raises()`, `record_success()` (one committed
  per-CVE write), `duplicate_cve()` (a write whose flush fails), and
  `ingest()`, the real `cve_service.upsert_cve()` and
  `reference_service.upsert_references()` ingestion of a fictional JSON file
  (`cve_file()`);
- `install_git_workspace()`: the hermetic process environment (no inherited
  `GIT_*` variable, no user or system Git configuration, no automatic
  maintenance; see docs/features/platform/testing-strategy.md, Tier 1 —
  Unit Tests), the recorded instead of awaited read-retry backoff, an
  `Upstream` work-tree repository under `tmp_path` served through a
  `file://` URL (so a clone transfers only reachable objects), and
  `GIT_CLONE_BASE_DIR` redirected to `tmp_path`;
- `GitCalls`, a recording spy over the `git_operations` functions the class
  delegates to, with per-function errors and replacements;
- `open_git_run_harness()`: committed `FetcherConfig` and `FetcherRun` rows
  for `BaseFetcher.run()`, seeded previous runs with any stored cursor, the
  run, execution, finalization, and isolated status sessions over
  `real_session_factory` with recorded `flush`/`commit`/`rollback`, the
  publication substitute and the drain spy, and leak-proof cleanup of every
  `FetcherRun`, `FetcherConfig`, CVE, and Ticket row a test caused.

Nothing here computes an expectation with the module under test. All
identifiers, names, and hosts are fictional.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple, cast

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import config
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services import (
    base_cve_fetcher,
    base_fetcher,
    cve_service,
    git_operations,
    reference_service,
    task_publication,
)
from app.services.base_cve_fetcher import _CVE_SOURCE_TYPE_MAP, CVEFetchResult
from app.services.base_fetcher import FetcherRunConfig
from app.services.base_git_fetcher import CLONE_DELETE_FAILED_EVENT, BaseGitFetcher
from app.services.cve_ingest import CVEIngestPayload, PostIngestTasks, UpsertAction
from app.services.reference_service import AutomaticReferenceInput
from tests.support.cve_catch_up import Publications, RecordingSessions, watch_drain
from tests.support.cve_ingest import IngestionWorld
from tests.support.git_repos import (
    commit_files,
    git,
    init_upstream,
    isolate_process_environment,
    rev_parse,
)

SOURCE = CVESourceType.MITRE
"""The default `cve_source_type` of a test-only Git fetcher."""

DEFAULT_PREFIX = "cves/"
SOURCE_REFERENCE_URL = "https://cve.example.test/record/{cve_id}"

RUN_CONFIG = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)

ItemStep = Callable[[BaseGitFetcher, str, bytes, AsyncSession], Awaitable[Any]]
"""One scripted `process_item(path, content, session)` body; receives the
fetcher instance first. It may return anything, so a non-token return can be
scripted."""

PathHook = Callable[[list[str]], list[str]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]


# ---------------------------------------------------------------------------
# Test-only Git fetcher
# ---------------------------------------------------------------------------


@dataclass
class GitFetcherProbe:
    """Observations of one test-only `BaseGitFetcher` class.

    `events` is shared with the harness recorders: each `process_item()`
    appends `process_item:<path>` before its step and
    `process_item_returned:<path>` after a normal return; each
    `commit_and_dispatch()` appends `commit_and_dispatch`. `calls` holds
    every `(path, content)`; `counters_at_call` and `counters_after_step`
    the `(succeeded, created, updated, failed)` counters at entry and after
    the step returned; `deltas` every raw list `filter_delta_files()`
    received; `results` every returned value; `isolated` every
    `_isolated_status_commit()` argument pair; `flushed_at_finalization`,
    per finalization, whether the session had no new, dirty, or deleted
    instance left.
    """

    cls: type[BaseGitFetcher]
    name: str
    clone_dir_name: str
    events: list[str]
    step: ItemStep | None = None
    steps: dict[str, ItemStep] = field(default_factory=dict)
    instances: list[BaseGitFetcher] = field(default_factory=list)
    calls: list[tuple[str, bytes]] = field(default_factory=list)
    counters_at_call: list[tuple[int, int, int, int]] = field(default_factory=list)
    counters_after_step: list[tuple[int, int, int, int]] = field(default_factory=list)
    deltas: list[list[str]] = field(default_factory=list)
    results: list[Any] = field(default_factory=list)
    isolated: list[tuple[str, CVESourceFetchStatus]] = field(default_factory=list)
    flushed_at_finalization: list[bool] = field(default_factory=list)

    @property
    def paths(self) -> list[str]:
        """The path of every `process_item()` call, in call order."""
        return [path for path, _ in self.calls]

    @property
    def fetcher(self) -> BaseGitFetcher:
        """The latest instance that processed an item."""
        return self.instances[-1]


def counters(fetcher: BaseGitFetcher) -> tuple[int, int, int, int]:
    """(succeeded, created, updated, failed)."""
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


def default_candidate_paths(prefix: str) -> Callable[[str], list[str]]:
    """`<prefix><year>/<item_id>.json` for a `CVE-<year>-<n>` item, else
    `ValueError`."""

    def construct(item_id: str) -> list[str]:
        parts = item_id.split("-")
        if len(parts) != 3 or parts[0] != "CVE":
            raise ValueError("Unrecognizable item_id format for the test source")
        return [f"{prefix}{parts[1]}/{item_id}.json"]

    return construct


def define_git_fetcher(
    *,
    repo_url: str,
    clone_dir_name: str | None = None,
    delta_path_prefix: str = DEFAULT_PREFIX,
    recovery_path_prefix: str = DEFAULT_PREFIX,
    source: CVESourceType = SOURCE,
    step: ItemStep | None = None,
    filter_delta_files: PathHook | None = None,
    deduplicate_items: PathHook | None = None,
    construct_candidate_paths: Callable[[str], list[str]] | None = None,
    events: list[str] | None = None,
) -> GitFetcherProbe:
    """Register a concrete test-only `BaseGitFetcher` owning `source`.

    Call it under `isolated_fetcher_registries`: a production owner of
    `source`, if any, is restored at teardown. The name is a unique
    `test_git_fetcher_<hex>`, and the clone directory defaults to it.
    """
    _CVE_SOURCE_TYPE_MAP.pop(source, None)
    probe_name = f"test_git_fetcher_{uuid.uuid4().hex[:12]}"
    probe_dir = clone_dir_name if clone_dir_name is not None else probe_name
    probe_url = repo_url
    probe_delta_prefix = delta_path_prefix
    probe_recovery_prefix = recovery_path_prefix
    filter_override = filter_delta_files
    deduplicate_override = deduplicate_items
    candidates = construct_candidate_paths or default_candidate_paths(delta_path_prefix)
    holder: list[GitFetcherProbe] = []

    class _TestGitFetcher(BaseGitFetcher):
        # `execute()` is the inherited template; nothing below overrides it.
        name = probe_name
        description = "Test-only Git CVE fetcher"
        default_schedule = "0 * * * *"
        cve_source_type = source
        repo_url = probe_url
        clone_dir_name = probe_dir
        delta_path_prefix = probe_delta_prefix
        recovery_path_prefix = probe_recovery_prefix

        async def process_item(
            self, path: str, content: bytes, session: AsyncSession
        ) -> CVEFetchResult:
            probe = holder[0]
            probe.instances.append(self)
            probe.calls.append((path, content))
            probe.counters_at_call.append(counters(self))
            probe.events.append(f"process_item:{path}")
            item_step = probe.steps.get(path, probe.step)
            if item_step is None:
                raise AssertionError("process_item() called without a step")
            result = await item_step(self, path, content, session)
            probe.counters_after_step.append(counters(self))
            probe.results.append(result)
            probe.events.append(f"process_item_returned:{path}")
            return cast(CVEFetchResult, result)

        def filter_delta_files(self, file_list: list[str]) -> list[str]:
            holder[0].deltas.append(list(file_list))
            if filter_override is None:
                return super().filter_delta_files(file_list)
            return filter_override(file_list)

        def deduplicate_items(self, file_list: list[str]) -> list[str]:
            if deduplicate_override is None:
                return super().deduplicate_items(file_list)
            return deduplicate_override(file_list)

        def _construct_candidate_paths(self, item_id: str) -> list[str]:
            return candidates(item_id)

        async def commit_and_dispatch(
            self, session: AsyncSession, result: CVEFetchResult
        ) -> None:
            probe = holder[0]
            probe.events.append("commit_and_dispatch")
            probe.flushed_at_finalization.append(
                not (session.new or session.dirty or session.deleted)
            )
            await super().commit_and_dispatch(session, result)

        async def _isolated_status_commit(
            self, cve_id: str, status: CVESourceFetchStatus
        ) -> None:
            holder[0].isolated.append((cve_id, status))
            await super()._isolated_status_commit(cve_id, status)

    probe = GitFetcherProbe(
        cls=_TestGitFetcher,
        name=probe_name,
        clone_dir_name=probe_dir,
        events=[] if events is None else events,
        step=step,
    )
    holder.append(probe)
    return probe


# ---------------------------------------------------------------------------
# Item steps
# ---------------------------------------------------------------------------


def item_id(path: str) -> str:
    """The file stem, as the template's default `_extract_item_id()`."""
    return Path(path).stem


def token(
    action: UpsertAction = UpsertAction.UNCHANGED,
    *,
    post_ingest: PostIngestTasks | None = None,
) -> ItemStep:
    """Return a fresh token without any database write."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        return CVEFetchResult(action, post_ingest)

    return step


def raises(error: BaseException) -> ItemStep:
    """Raise `error` without any database write."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        raise error

    return step


def returns(value: object) -> ItemStep:
    """Return `value` as is (for example a non-token)."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> Any:
        return value

    return step


def record_success(
    action: UpsertAction = UpsertAction.UPDATED,
    *,
    post_ingest: PostIngestTasks | None = None,
    then: BaseException | None = None,
    before_return: Callable[[], None] | None = None,
) -> ItemStep:
    """Write the `success` source status of the committed CVE named by the
    file stem, then raise `then` or return a token. `before_return` runs
    just before the token is returned."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        cve_uuid = await session.scalar(
            select(CVE.id).where(CVE.cve_id == item_id(path))
        )
        assert cve_uuid is not None, "record_success() needs a committed CVE"
        await cve_service.record_source_status(
            session, cve_uuid, fetcher.cve_source_type, CVESourceFetchStatus.SUCCESS
        )
        if then is not None:
            raise then
        if before_return is not None:
            before_return()
        return CVEFetchResult(action, post_ingest)

    return step


def duplicate_cve() -> ItemStep:
    """Add a second CVE row with the stem's CVE-ID: the template's flush
    raises the unique-constraint `IntegrityError`."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        session.add(CVE(cve_id=item_id(path)))
        return CVEFetchResult(UpsertAction.UPDATED, None)

    return step


def cve_file(
    title: str,
    *,
    description: str | None = None,
    resolved_packages: list[str] | None = None,
    indent: int | None = None,
) -> bytes:
    """A fictional CVE file: a JSON object of `CVEIngestPayload` fields.
    `indent` changes only the formatting."""
    data: dict[str, Any] = {"title": title}
    if description is not None:
        data["description"] = description
    if resolved_packages is not None:
        data["resolved_packages"] = resolved_packages
    return json.dumps(data, indent=indent).encode()


def ingest(*, fail_after: BaseException | None = None) -> ItemStep:
    """The real ingestion of a `cve_file()`: payload validation, upsert,
    the automatic source reference, then the token with the pure handoff.
    `fail_after` is raised after the reference write."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        cve_id = item_id(path)
        payload = CVEIngestPayload.model_validate_json(content)
        result = await cve_service.upsert_cve(
            session, cve_id, fetcher.cve_source_type, payload
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve_id,
            fetcher.name,
            AutomaticReferenceInput(url=SOURCE_REFERENCE_URL.format(cve_id=cve_id)),
            [],
        )
        if fail_after is not None:
            raise fail_after
        return CVEFetchResult(
            result.action, cve_service.build_post_ingest_tasks(result, payload)
        )

    return step


def handoff(ticket_id: str = "00000000-0000-4000-8000-000000000002") -> PostIngestTasks:
    """A minimal non-NULL package handoff with one fictional package."""
    return PostIngestTasks(
        ticket_id=ticket_id,
        cpe_matches=[],
        affected_cpes=[],
        vendor_products=[],
        resolved_packages=["example-package"],
    )


# ---------------------------------------------------------------------------
# Temporary repositories
# ---------------------------------------------------------------------------


class Upstream:
    """A work-tree upstream repository (branch `main`) under `tmp_path`."""

    def __init__(self, path: Path) -> None:
        self.path = init_upstream(path)

    @property
    def url(self) -> str:
        """The `file://` URL: a clone transfers only reachable objects."""
        return self.path.as_uri()

    def commit(
        self,
        files: Mapping[str, bytes | None],
        *,
        date: str,
        message: str = "change",
    ) -> str:
        """Write (`bytes`) or delete (`None`) paths and commit at `date`."""
        return commit_files(self.path, files, message=message, date=date)

    def amend(
        self,
        files: Mapping[str, bytes | None],
        *,
        date: str,
        message: str = "rewritten",
    ) -> str:
        """Rewrite the branch: replace its last commit by one with the given
        changes (the old commit is no longer reachable from `main`)."""
        for relative, content in files.items():
            target = self.path / relative
            if content is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        git(self.path, "add", "--all")
        git(
            self.path,
            "commit",
            "--quiet",
            "--amend",
            "--allow-empty",
            "-m",
            message,
            env_extra={"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date},
        )
        return self.head()

    def head(self) -> str:
        return rev_parse(self.path / ".git", "HEAD")


def has_commit(git_dir: Path, sha: str) -> bool:
    """Whether `sha` names a commit in the repository at `git_dir`."""
    completed = git(
        None,
        f"--git-dir={git_dir}",
        "rev-parse",
        "--verify",
        "--quiet",
        f"{sha}^{{commit}}",
        check=False,
    )
    return completed.returncode == 0


def is_bare_clone(git_dir: Path) -> bool:
    """Whether `git_dir` is a bare repository whose `HEAD` names a commit."""
    bare = git(
        None, f"--git-dir={git_dir}", "rev-parse", "--is-bare-repository", check=False
    )
    return bare.stdout.strip() == "true" and has_commit(git_dir, "HEAD")


@dataclass
class GitWorkspace:
    """The temporary Git state of one test."""

    root: Path
    upstream: Upstream
    clone_base: Path
    sleeps: list[float]

    def clone_path(self, probe: GitFetcherProbe) -> Path:
        return self.clone_base / probe.clone_dir_name

    def clone(self, probe: GitFetcherProbe) -> Path:
        """Create the probe's bare clone outside the code under test."""
        target = self.clone_path(probe)
        git(
            None,
            "clone",
            "--quiet",
            "--bare",
            "--single-branch",
            "--",
            self.upstream.url,
            str(target),
        )
        return target

    def follow_upstream(self, git_dir: Path) -> None:
        """Force-update the clone's branch from the upstream `HEAD`."""
        git(
            None,
            f"--git-dir={git_dir}",
            "fetch",
            "--quiet",
            "origin",
            "+HEAD:refs/heads/main",
        )

    def prune_unreachable(self, git_dir: Path) -> None:
        """Remove every object no longer reachable from a ref."""
        git(None, f"--git-dir={git_dir}", "reflog", "expire", "--expire=now", "--all")
        git(None, f"--git-dir={git_dir}", "gc", "--quiet", "--prune=now")

    def forbidden_texts(self) -> tuple[str, ...]:
        """Values no bounded log or public message may contain."""
        return (str(self.root), self.upstream.url, os.fspath(self.clone_base))


def install_git_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> GitWorkspace:
    """Hermetic Git processes, recorded backoff, an upstream with no commit
    yet, and `GIT_CLONE_BASE_DIR` under `tmp_path` (restored by
    `monkeypatch`)."""
    isolate_process_environment(monkeypatch)
    sleeps: list[float] = []

    async def record(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(git_operations, "_sleep", record)
    clone_base = tmp_path / "clones"
    clone_base.mkdir()
    monkeypatch.setattr(config.settings, "git_clone_base_dir", str(clone_base))
    return GitWorkspace(
        root=tmp_path,
        upstream=Upstream(tmp_path / "upstream"),
        clone_base=clone_base,
        sleeps=sleeps,
    )


GitReplacement = Callable[..., Awaitable[Any]]


class GitCalls:
    """Recording spy over the `git_operations` functions `BaseGitFetcher`
    delegates to (it dereferences the module at call time).

    `calls` holds every `(name, args, kwargs)` in order. `errors[name]` is
    raised instead of the real call; `replacements[name]` is awaited with
    the real function as first argument instead of calling it directly.
    """

    FUNCTIONS = (
        "clone",
        "fetch_origin",
        "get_head_sha",
        "get_commit_date",
        "is_clone_valid",
        "check_sha_reachable",
        "diff_names",
        "rev_list_before",
        "show_file",
        "delete_clone",
    )

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.errors: dict[str, BaseException] = {}
        self.replacements: dict[str, GitReplacement] = {}
        for name in self.FUNCTIONS:
            self._wrap(monkeypatch, name)

    def _wrap(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        real = getattr(git_operations, name)

        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            if name in self.errors:
                raise self.errors[name]
            if name in self.replacements:
                return await self.replacements[name](real, *args, **kwargs)
            return await real(*args, **kwargs)

        monkeypatch.setattr(git_operations, name, wrapper)

    def names(self) -> list[str]:
        return [name for name, _, _ in self.calls]

    def of(self, name: str) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
        return [(args, kwargs) for called, args, kwargs in self.calls if called == name]

    def clear(self) -> None:
        self.calls.clear()


def show_missing(*paths: str) -> GitReplacement:
    """A `show_file` replacement returning `None` for `paths`."""

    async def replacement(
        real: GitReplacement, repo_path: Path, ref: str, file_path: str
    ) -> bytes | None:
        if file_path in paths:
            return None
        result: bytes | None = await real(repo_path, ref, file_path)
        return result

    return replacement


def show_failing(error: BaseException, *paths: str) -> GitReplacement:
    """A `show_file` replacement raising `error` for `paths`."""

    async def replacement(
        real: GitReplacement, repo_path: Path, ref: str, file_path: str
    ) -> bytes | None:
        if file_path in paths:
            raise error
        result: bytes | None = await real(repo_path, ref, file_path)
        return result

    return replacement


# ---------------------------------------------------------------------------
# Log observation
# ---------------------------------------------------------------------------

LogEntry = Mapping[str, Any]


def events_named(logs: list[Any], event: str) -> list[dict[str, Any]]:
    """The captured entries of `event`, as plain dicts."""
    return [dict(entry) for entry in logs if entry.get("event") == event]


def assert_bounded_logs(logs: list[Any], *forbidden: str) -> None:
    """No entry carries a forbidden value, a traceback, or `exc_info`. The
    `repo_path` field of `git_clone_delete_failed` is the one specified
    path-bearing field and is exempt."""
    for entry in logs:
        fields = dict(entry)
        if fields.get("event") == CLONE_DELETE_FAILED_EVENT:
            fields.pop("repo_path", None)
        rendered = repr(fields)
        for value in (*forbidden, "Traceback"):
            assert value not in rendered, (value, fields.get("event"))
        assert "exc_info" not in fields


# ---------------------------------------------------------------------------
# Periodic runs
# ---------------------------------------------------------------------------


class RunSessions:
    """Substitute for `app.services.base_fetcher.async_session_factory`.

    `BaseFetcher.run()` opens, in order, the previous-cursor session, the
    execution session passed to `execute()`, and the finalization session
    (fetcher-infrastructure.md, `run()` lifecycle); `reset()` starts a new
    run. Explicit `flush`, `commit`, and `rollback` calls of the execution
    session append the bare operation name to `events`; those of the other
    two append `cursor:<op>` or `finalize:<op>`. `fail_once[op]` makes the
    next execution-session `op` raise its error, before the real operation
    or, when the flag is `True`, after it (an ambiguous commit).
    """

    ROLES = ("cursor", "execute", "finalize")

    def __init__(
        self, factory: async_sessionmaker[AsyncSession], events: list[str]
    ) -> None:
        self._factory = factory
        self.events = events
        self.opened: list[AsyncSession] = []
        self.fail_once: dict[str, tuple[BaseException, bool]] = {}

    def reset(self) -> None:
        self.opened = []

    def __call__(self) -> AsyncSession:
        session = self._factory()
        index = len(self.opened)
        role = self.ROLES[index] if index < len(self.ROLES) else f"extra{index}"
        self.opened.append(session)
        for operation in ("flush", "commit", "rollback"):
            self._record(session, operation, role)
        return session

    @property
    def execution(self) -> AsyncSession:
        return self.opened[1]

    def _record(self, session: AsyncSession, operation: str, role: str) -> None:
        original = getattr(session, operation)
        label = operation if role == "execute" else f"{role}:{operation}"

        async def recorded(*args: Any, **kwargs: Any) -> None:
            self.events.append(label)
            failure = self.fail_once.pop(operation, None) if role == "execute" else None
            if failure is not None and not failure[1]:
                raise failure[0]
            await original(*args, **kwargs)
            if failure is not None:
                raise failure[0]

        setattr(session, operation, recorded)


class RunRow(NamedTuple):
    status: str
    items_succeeded: int
    items_created: int
    items_updated: int
    items_failed: int
    cursor: Any
    error_message: str | None
    error_detail: str | None
    error_traceback: str | None

    @property
    def metrics(self) -> tuple[int, int, int, int]:
        """(succeeded, created, updated, failed)."""
        return (
            self.items_succeeded,
            self.items_created,
            self.items_updated,
            self.items_failed,
        )


@dataclass
class RunResult:
    row: RunRow
    fetcher: BaseGitFetcher
    raised: BaseException | None


@dataclass
class GitRunHarness:
    """The periodic-run substitutes of one test sharing `events`.

    `sessions` replaces `base_fetcher.async_session_factory`; `status` (a
    `RecordingSessions` with the `status:` label) replaces
    `base_cve_fetcher.async_session_factory`, so isolated status writes use
    independent real sessions; `published` replaces
    `task_publication.publish_task`; the real convergence drain is wrapped
    to append `drain`. `world` owns the committed CVEs and Tickets.
    """

    factory: async_sessionmaker[AsyncSession]
    world: IngestionWorld
    events: list[str]
    sessions: RunSessions
    status: RecordingSessions
    published: Publications
    cve_baseline: int
    names: list[str] = field(default_factory=list)
    clock: datetime = field(
        default_factory=lambda: datetime.now(UTC) - timedelta(hours=1)
    )

    def _tick(self) -> datetime:
        """A strictly increasing `started_at`, so the latest seeded or
        finished run is the previous cursor."""
        self.clock += timedelta(seconds=1)
        return self.clock

    async def register(self, probe: GitFetcherProbe) -> None:
        async with self.factory() as session:
            session.add(FetcherConfig(fetcher_name=probe.name, enabled=True))
            await session.commit()
        self.names.append(probe.name)

    async def seed_run(
        self, probe: GitFetcherProbe, cursor: object, *, status: str = "success"
    ) -> None:
        """A finished previous run of `probe` storing `cursor` verbatim
        (any JSON value)."""
        started_at = self._tick()
        async with self.factory() as session:
            session.add(
                FetcherRun(
                    fetcher_name=probe.name,
                    started_at=started_at,
                    finished_at=started_at,
                    status=status,
                    triggered_by="schedule",
                    cursor=cast(Any, cursor),
                )
            )
            await session.commit()

    async def start(self, probe: GitFetcherProbe) -> tuple[BaseGitFetcher, uuid.UUID]:
        """A fresh instance and a committed `running` row, as the atomic run
        acquisition leaves them before `run()`."""
        async with self.factory() as session:
            run = FetcherRun(
                fetcher_name=probe.name,
                started_at=self._tick(),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            run_id = run.id
        self.sessions.reset()
        return probe.cls(), run_id

    async def run(
        self,
        probe: GitFetcherProbe,
        *,
        raises: type[Exception] | None = None,
        run_config: FetcherRunConfig = RUN_CONFIG,
    ) -> RunResult:
        """One complete `run()`. An exception propagates unless it is an
        instance of `raises`, which must then occur."""
        fetcher, run_id = await self.start(probe)
        raised: BaseException | None = None
        try:
            await fetcher.run(run_id=run_id, config=run_config)
        except Exception as exc:
            if raises is None or not isinstance(exc, raises):
                raise
            raised = exc
        if raises is not None:
            assert raised is not None, f"run() did not raise {raises.__name__}"
        return RunResult(await self.row(run_id), fetcher, raised)

    async def row(self, run_id: uuid.UUID) -> RunRow:
        async with self.factory() as session:
            run = await session.get(FetcherRun, run_id)
            assert run is not None
            return RunRow(
                run.status,
                run.items_succeeded,
                run.items_created,
                run.items_updated,
                run.items_failed,
                run.cursor,
                run.error_message,
                run.error_detail,
                run.error_traceback,
            )

    async def cve(self) -> CVE:
        """A committed CVE (deleted at teardown)."""
        return await self.world.cve_in()

    async def cve_named(self, cve_id: str) -> CVE | None:
        async with self.factory() as session:
            cve: CVE | None = await session.scalar(
                select(CVE).where(CVE.cve_id == cve_id)
            )
        return cve

    async def cleanup(self) -> None:
        try:
            await self.world.cleanup()
        finally:
            if self.names:
                async with self.factory() as session:
                    await session.execute(
                        delete(FetcherRun).where(
                            FetcherRun.fetcher_name.in_(self.names)
                        )
                    )
                    await session.execute(
                        delete(FetcherConfig).where(
                            FetcherConfig.fetcher_name.in_(self.names)
                        )
                    )
                    await session.commit()
        assert await _cve_count(self.factory) == self.cve_baseline, "a CVE leaked"
        assert await _fetcher_rows(self.factory, self.names) == 0


async def _cve_count(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        return int(await session.scalar(select(func.count()).select_from(CVE)) or 0)


async def _fetcher_rows(
    factory: async_sessionmaker[AsyncSession], names: list[str]
) -> int:
    if not names:
        return 0
    async with factory() as session:
        runs = await session.scalar(
            select(func.count())
            .select_from(FetcherRun)
            .where(FetcherRun.fetcher_name.in_(names))
        )
        configs = await session.scalar(
            select(func.count())
            .select_from(FetcherConfig)
            .where(FetcherConfig.fetcher_name.in_(names))
        )
    return int(runs or 0) + int(configs or 0)


STATUS_LOCK_TIMEOUT = "10s"


def _bound_lock_wait(session: AsyncSession) -> None:
    """Bound the isolated status write's lock wait: a regression that
    leaves the execution session's per-CVE locks held (no rollback before
    the write) then fails, through the write's own suppressed-failure path,
    instead of hanging the suite."""
    original = session.scalar

    async def scalar(*args: Any, **kwargs: Any) -> Any:
        await session.execute(text(f"SET LOCAL lock_timeout = '{STATUS_LOCK_TIMEOUT}'"))
        return await original(*args, **kwargs)

    session.scalar = scalar  # type: ignore[method-assign]


async def open_git_run_harness(
    monkeypatch: pytest.MonkeyPatch,
    factory: async_sessionmaker[AsyncSession],
    session_factory: SessionFactory,
) -> GitRunHarness:
    """Install every `GitRunHarness` substitute; `factory` is
    `real_session_factory` and `session_factory` is `db_session_factory`
    (the committed world's sessions). Call `cleanup()` at teardown."""
    events: list[str] = []
    world = IngestionWorld(session_factory, await session_factory())
    world.probe = await world.open_session()
    harness = GitRunHarness(
        factory=factory,
        world=world,
        events=events,
        sessions=RunSessions(factory, events),
        status=RecordingSessions(factory, events, label="status:"),
        published=Publications(events),
        cve_baseline=await _cve_count(factory),
    )
    monkeypatch.setattr(base_fetcher, "async_session_factory", harness.sessions)
    harness.status.hooks.append(_bound_lock_wait)
    harness.status.install(monkeypatch, base_cve_fetcher)
    monkeypatch.setattr(task_publication, "publish_task", harness.published)
    watch_drain(monkeypatch, events)
    return harness


def cve_path(cve_id: str, prefix: str = DEFAULT_PREFIX) -> str:
    """`<prefix><year>/<cve_id>.json`."""
    return f"{prefix}{cve_id.split('-')[1]}/{cve_id}.json"
