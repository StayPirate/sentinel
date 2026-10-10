"""The template `BaseGitFetcher.execute()` through the real `BaseFetcher.run()`
(backend/app/services/base_git_fetcher.py).

Owning specifications:

- docs/features/platform/git-fetcher-infrastructure.md (Cursor Persistence;
  Write Mechanism; Empty Delta; First-Run Detection; Recovery; Cursor SHA
  Unreachable; Error Classification; Template Method: `execute()` steps
  1-11, Infrastructure errors, Error Handling Strategy, Status
  Determination; Hook Methods; `_compute_recovery_delta()`).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Per-CVE Finalization; Batch Error Handling, the `cve_fetch_item_failed`
  event; Metric Definitions).
- docs/features/platform/testing-strategy.md (Tier 1 — Unit Tests, the
  hermetic Git subprocess rules; CVE Fetcher Infrastructure: Typed result,
  One-shot finalization, Periodic metrics, Isolated statuses, Git
  boundaries; Test Independence).

Every repository is a real temporary one under `tmp_path`: a work-tree
upstream served through a `file://` URL and the fetcher's bare clone under
the redirected `GIT_CLONE_BASE_DIR`. No Git process inherits a `GIT_*`
variable or a user or system Git configuration, and the read-retry backoff
is recorded instead of awaited. `git_operations` functions are wrapped by a
recording spy; a few cases replace one function's result to reach a branch
that real Git cannot produce deterministically (named per test).

Runs use the real database: `run()`, its sessions, and the isolated status
writes go through `real_session_factory`, the broker call is substituted
through `task_publication.publish_task`, and every committed `FetcherRun`,
`FetcherConfig`, CVE, and Ticket row is deleted at teardown, which also
asserts that no CVE leaked. Test-only fetchers are defined per test under
`isolated_fetcher_registries`. The harness lives in
`tests/support/git_fetchers.py`. All identifiers are fictional.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from celery.exceptions import OperationalError, SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import CVESourceFetchStatus
from app.models.ticket import Ticket
from app.services import ticket_convergence_publication
from app.services.base_cve_fetcher import (
    CVE_FETCH_ITEM_FAILED_EVENT,
    HANDOFF_PUBLICATION_FAILED_EVENT,
    CVEFetchResult,
)
from app.services.base_fetcher import FetcherError
from app.services.base_git_fetcher import (
    CLONE_CORRUPTION_DETECTED_EVENT,
    CLONE_DELETE_FAILED_EVENT,
    CLONE_FAILED_MESSAGE,
    CLONE_INVALID_REBUILDING_EVENT,
    CORRUPTION_MESSAGE,
    CURSOR_COMMITTED_AT_UNUSABLE_EVENT,
    CURSOR_MALFORMED_EVENT,
    CURSOR_SHA_UNREACHABLE_EVENT,
    DELETE_FAILED_GUIDANCE,
    DELETE_FAILED_MESSAGE,
    DELTA_FILE_MISSING_AT_HEAD_EVENT,
    FETCH_FAILED_MESSAGE,
    RECOVERY_BOUNDARY_NOT_FOUND_EVENT,
    BaseGitFetcher,
)
from app.services.cve_ingest import UpsertAction
from app.services.git_operations import GitCorruptionError, GitFetchError, GitFileError
from tests.support.cve_catch_up import RESOLVE, source_state
from tests.support.git_fetchers import (
    RUN_CONFIG,
    SOURCE,
    GitCalls,
    GitFetcherProbe,
    GitRunHarness,
    GitWorkspace,
    ItemStep,
    RunResult,
    SessionFactory,
    assert_bounded_logs,
    cve_file,
    cve_path,
    define_git_fetcher,
    duplicate_cve,
    events_named,
    handoff,
    has_commit,
    ingest,
    install_git_workspace,
    is_bare_clone,
    open_git_run_harness,
    raises,
    record_success,
    returns,
    show_failing,
    token,
)
from tests.support.git_repos import git, init_bare

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("isolated_fetcher_registries"),
]

D_BASE = "2024-01-05T00:00:00+00:00"
D_MARGIN = "2024-01-09T12:00:00+00:00"
D_CURSOR = "2024-01-10T00:00:00+00:00"
D_REWRITE = "2024-01-11T00:00:00+00:00"
D_LATER = "2024-01-12T00:00:00+00:00"
BEFORE_DATE = "2024-01-09T00:00:00+00:00"
"""`D_CURSOR` minus the one-day recovery margin."""

UNREACHABLE = "0123456789abcdef0123456789abcdef01234567"
"""A well-formed SHA that names no object of any test repository."""

SECRET = "upstream-secret-detail"
"""Text carried by injected exceptions; never logged or public."""

FIRST_RUN_CALLS = ["is_clone_valid", "delete_clone", "clone"]
HEAD_CALLS = ["get_head_sha", "get_commit_date"]


class _CommitFailureError(Exception):
    """An injected commit exception."""


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    return install_git_workspace(tmp_path, monkeypatch)


@pytest.fixture
def git_calls(workspace: GitWorkspace, monkeypatch: pytest.MonkeyPatch) -> GitCalls:
    return GitCalls(monkeypatch)


@pytest.fixture
async def harness(
    monkeypatch: pytest.MonkeyPatch,
    real_session_factory: async_sessionmaker[AsyncSession],
    db_session_factory: SessionFactory,
) -> AsyncIterator[GitRunHarness]:
    opened = await open_git_run_harness(
        monkeypatch, real_session_factory, db_session_factory
    )
    try:
        yield opened
    finally:
        await opened.cleanup()


async def _fetcher(
    workspace: GitWorkspace, harness: GitRunHarness, **options: Any
) -> GitFetcherProbe:
    options.setdefault("repo_url", workspace.upstream.url)
    probe = define_git_fetcher(events=harness.events, **options)
    await harness.register(probe)
    return probe


async def _first_run(harness: GitRunHarness, probe: GitFetcherProbe) -> RunResult:
    """A successful first run that records HEAD (the clone then exists)."""
    result = await harness.run(probe)
    assert result.row.status == "success"
    assert isinstance(result.row.cursor, dict)
    return result


def _reset(harness: GitRunHarness, git_calls: GitCalls) -> None:
    harness.events.clear()
    git_calls.clear()


def _warnings(logs: list[Any]) -> list[str]:
    return [
        entry["event"]
        for entry in logs
        if entry.get("log_level") in ("warning", "error", "critical")
    ]


def _bounded(logs: list[Any], workspace: GitWorkspace, *more: str) -> None:
    assert_bounded_logs(
        logs, *workspace.forbidden_texts(), SECRET, "fatal:", "exited with", *more
    )


def _public(message: str | None, workspace: GitWorkspace) -> None:
    """The public `error_message` names no path, URL, or Git stderr."""
    assert message is not None
    for text in (*workspace.forbidden_texts(), SECRET, "fatal", "exited with", "/"):
        assert text not in message


def _execution_ops(events: list[str]) -> list[str]:
    """The execution session's flush/commit/rollback and the finalizer."""
    kept = {"flush", "commit", "rollback", "commit_and_dispatch"}
    return [event for event in events if event in kept]


def _after(events: list[str], marker: str) -> list[str]:
    """The events after `marker` up to the next item, without the cursor
    and finalization sessions of `run()`."""
    start = events.index(marker) + 1
    end = next(
        (i for i in range(start, len(events)) if events[i].startswith("process_item:")),
        len(events),
    )
    return [
        event
        for event in events[start:end]
        if not event.startswith(("cursor:", "finalize:"))
    ]


def _make_invalid(path: Path, kind: str) -> Path:
    """An invalid clone directory of `kind` holding a stale marker file."""
    if kind == "plain-directory":
        path.mkdir(parents=True)
    else:
        init_bare(path)
    marker = path / "stale-marker.txt"
    marker.write_bytes(b"stale\n")
    return marker


def _prefer_rejected(files: list[str]) -> list[str]:
    """One path per stem; a `rejected/` path wins."""
    chosen: dict[str, str] = {}
    for path in files:
        stem = Path(path).stem
        if stem not in chosen or "/rejected/" in path:
            chosen[stem] = path
    return list(chosen.values())


def _json_only(files: list[str]) -> list[str]:
    return [path for path in files if path.endswith(".json")]


class _RecoveryHistory:
    """Three upstream commits with one file under `cves/` and one under
    `other/` each: `base` (the recovery boundary), `margin` (after the
    boundary but before the cursor date), and `head`."""

    def __init__(self, workspace: GitWorkspace) -> None:
        self.cves_base = cve_path("CVE-2024-0001")
        self.other_base = cve_path("CVE-2024-0002", "other/")
        self.cves_margin = cve_path("CVE-2024-0003")
        self.other_margin = cve_path("CVE-2024-0004", "other/")
        self.cves_head = cve_path("CVE-2024-0005")
        self.other_head = cve_path("CVE-2024-0006", "other/")
        upstream = workspace.upstream
        self.base = upstream.commit(
            {self.cves_base: b"{}", self.other_base: b"{}"}, date=D_BASE
        )
        self.margin = upstream.commit(
            {self.cves_margin: b"{}", self.other_margin: b"{}"}, date=D_MARGIN
        )
        self.head = upstream.commit(
            {self.cves_head: b"{}", self.other_head: b"{}"}, date=D_LATER
        )


async def _recovery_fetcher(
    workspace: GitWorkspace, harness: GitRunHarness
) -> GitFetcherProbe:
    """A fetcher whose recovery prefix (`other/`) differs from its delta
    prefix (`cves/`), after its first run over a `_RecoveryHistory`."""
    probe = await _fetcher(
        workspace,
        harness,
        delta_path_prefix="cves/",
        recovery_path_prefix="other/",
        step=token(),
    )
    await _first_run(harness, probe)
    return probe


async def _ticket_of(harness: GitRunHarness, cve_id: str) -> str:
    cve = await harness.cve_named(cve_id)
    assert cve is not None
    async with harness.factory() as session:
        ticket_id = await session.scalar(
            select(Ticket.id).where(Ticket.cve_id == cve.id)
        )
    return str(ticket_id)


# ---------------------------------------------------------------------------
# First-run detection
# ---------------------------------------------------------------------------


class TestFirstRun:
    async def test_absent_clone_is_cloned_and_head_recorded_without_processing(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        head = workspace.upstream.commit(
            {cve_path("CVE-2024-0001"): b"{}", "README": b"example\n"}, date=D_CURSOR
        )
        probe = await _fetcher(workspace, harness)
        clone = workspace.clone_path(probe)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert git_calls.names() == [*FIRST_RUN_CALLS, *HEAD_CALLS]
        assert git_calls.of("clone") == [
            (
                (workspace.upstream.url, clone),
                {"filter_spec": None, "single_branch": True},
            )
        ]
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_CURSOR}
        assert probe.calls == []
        assert probe.deltas == []
        assert is_bare_clone(clone)
        assert _warnings(logs) == []
        assert harness.published.calls == []
        _bounded(logs, workspace)

    async def test_valid_clone_without_cursor_is_reused_without_clone_or_fetch(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        """The previous attempt cloned but persisted no cursor: HEAD of the
        existing clone is recorded, so a later upstream commit is not seen."""
        cloned = workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        workspace.clone(probe)
        workspace.upstream.commit({cve_path("CVE-2024-0001"): b"{}"}, date=D_CURSOR)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert git_calls.names() == ["is_clone_valid", *HEAD_CALLS]
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": cloned, "committed_at": D_BASE}
        assert probe.calls == []
        assert _warnings(logs) == []

    @pytest.mark.parametrize("kind", ["plain-directory", "empty-bare-repository"])
    async def test_invalid_directory_without_cursor_is_deleted_then_cloned(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        kind: str,
    ) -> None:
        head = workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        clone = workspace.clone_path(probe)
        marker = _make_invalid(clone, kind)

        with capture_logs() as logs:
            result = await harness.run(probe)

        # The deletion precedes the clone.
        assert git_calls.names() == [*FIRST_RUN_CALLS, *HEAD_CALLS]
        assert git_calls.of("delete_clone") == [((clone,), {})]
        assert not marker.exists()
        assert is_bare_clone(clone)
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_BASE}
        assert probe.calls == []
        # Rebuilding is only reported when a cursor exists.
        assert _warnings(logs) == []


# ---------------------------------------------------------------------------
# Subsequent runs
# ---------------------------------------------------------------------------


class TestSubsequentRun:
    async def test_valid_clone_fetches_then_processes_delta_under_prefix(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        cursor = (await _first_run(harness, probe)).row.cursor
        new = cve_path("CVE-2024-0002")
        head = workspace.upstream.commit(
            {
                new: b'{"title": "example"}',
                "docs/notes.md": b"notes\n",
                cve_path("CVE-2024-0003", "other/"): b"{}",
            },
            date=D_CURSOR,
        )
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert git_calls.names() == [
            "is_clone_valid",
            "fetch_origin",
            *HEAD_CALLS,
            "check_sha_reachable",
            "diff_names",
            "show_file",
        ]
        clone = workspace.clone_path(probe)
        assert git_calls.of("check_sha_reachable") == [((clone, cursor["sha"]), {})]
        assert git_calls.of("diff_names") == [
            ((clone, cursor["sha"], head), {"path_filter": "cves/"})
        ]
        assert probe.deltas == [[new]]
        assert probe.calls == [(new, b'{"title": "example"}')]
        assert result.row.status == "success"
        assert result.row.metrics == (1, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_CURSOR}
        assert result.fetcher.previous_cursor == cursor
        assert _warnings(logs) == []

    async def test_empty_delta_succeeds_with_zero_metrics_and_advances_cursor(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        await _first_run(harness, probe)
        head = workspace.upstream.commit({"docs/notes.md": b"notes\n"}, date=D_CURSOR)
        _reset(harness, git_calls)

        result = await harness.run(probe)

        assert probe.deltas == [[]]
        assert probe.calls == []
        assert _execution_ops(harness.events) == []
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_CURSOR}

    async def test_filtered_and_deduplicated_paths_record_no_metric(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(
            workspace,
            harness,
            step=token(),
            filter_delta_files=_json_only,
            deduplicate_items=_prefer_rejected,
        )
        await _first_run(harness, probe)
        published = cve_path("CVE-2024-0001")
        rejected = "cves/rejected/2024/CVE-2024-0001.json"
        other = cve_path("CVE-2024-0002")
        notes = "cves/2024/README.md"
        workspace.upstream.commit(
            {published: b"{}", rejected: b"{}", other: b"{}", notes: b"notes\n"},
            date=D_CURSOR,
        )

        result = await harness.run(probe)

        assert sorted(probe.deltas[-1]) == sorted([published, rejected, other, notes])
        assert sorted(probe.paths) == sorted([rejected, other])
        # The filtered README and the deduplication loser are pre-scope.
        assert result.row.status == "success"
        assert result.row.metrics == (2, 0, 0, 0)


class TestCloneRebuild:
    @pytest.mark.parametrize(
        "kind", ["absent", "plain-directory", "empty-bare-repository"]
    )
    async def test_invalid_clone_with_cursor_is_rebuilt_then_normal_delta(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        kind: str,
    ) -> None:
        """Row 4 of First-Run Detection: the re-cloned history still contains
        the cursor commit, so the normal delta applies."""
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        cursor = (await _first_run(harness, probe)).row.cursor
        new = cve_path("CVE-2024-0002")
        head = workspace.upstream.commit({new: b"{}"}, date=D_CURSOR)
        clone = workspace.clone_path(probe)
        shutil.rmtree(clone)
        marker = None if kind == "absent" else _make_invalid(clone, kind)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert git_calls.names() == [
            *FIRST_RUN_CALLS,
            *HEAD_CALLS,
            "check_sha_reachable",
            "diff_names",
            "show_file",
        ]
        assert events_named(logs, CLONE_INVALID_REBUILDING_EVENT) == [
            {
                "event": CLONE_INVALID_REBUILDING_EVENT,
                "log_level": "warning",
                "fetcher_name": probe.name,
            }
        ]
        assert events_named(logs, CURSOR_SHA_UNREACHABLE_EVENT) == []
        assert git_calls.of("diff_names") == [
            ((clone, cursor["sha"], head), {"path_filter": "cves/"})
        ]
        assert marker is None or not marker.exists()
        assert is_bare_clone(clone)
        assert probe.paths == [new]
        assert result.row.status == "success"
        assert result.row.metrics == (1, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_CURSOR}
        _bounded(logs, workspace)


# ---------------------------------------------------------------------------
# Upstream rewrite
# ---------------------------------------------------------------------------


class TestUpstreamRewrite:
    async def test_rewrite_with_cursor_object_present_uses_normal_delta(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        first_file, added = cve_path("CVE-2024-0001"), cve_path("CVE-2024-0002")
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        old = workspace.upstream.commit({first_file: b"1"}, date=D_CURSOR)
        probe = await _fetcher(workspace, harness, step=token())
        assert (await _first_run(harness, probe)).row.cursor["sha"] == old
        new = workspace.upstream.amend({first_file: b"2", added: b"1"}, date=D_REWRITE)
        ancestry = git(
            workspace.upstream.path,
            "merge-base",
            "--is-ancestor",
            old,
            new,
            check=False,
        )
        assert ancestry.returncode == 1  # a rewrite, not a fast-forward
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        clone = workspace.clone_path(probe)
        # The bare clone keeps no reflog; the old commit awaits pruning.
        assert has_commit(clone, old)
        assert "rev_list_before" not in git_calls.names()
        assert events_named(logs, CURSOR_SHA_UNREACHABLE_EVENT) == []
        assert git_calls.of("diff_names") == [
            ((clone, old, new), {"path_filter": "cves/"})
        ]
        assert sorted(probe.paths) == sorted([first_file, added])
        assert result.row.status == "success"
        assert result.row.metrics == (2, 0, 0, 0)
        assert result.row.cursor == {"sha": new, "committed_at": D_REWRITE}

    async def test_pruned_cursor_object_uses_date_recovery(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        first_file, added = cve_path("CVE-2024-0001"), cve_path("CVE-2024-0002")
        unchanged = cve_path("CVE-2024-0003")
        base = workspace.upstream.commit({unchanged: b"0"}, date=D_BASE)
        old = workspace.upstream.commit({first_file: b"1"}, date=D_CURSOR)
        probe = await _fetcher(workspace, harness, step=token())
        assert (await _first_run(harness, probe)).row.cursor == {
            "sha": old,
            "committed_at": D_CURSOR,
        }
        new = workspace.upstream.amend({first_file: b"2", added: b"1"}, date=D_REWRITE)
        clone = workspace.clone_path(probe)
        workspace.follow_upstream(clone)
        workspace.prune_unreachable(clone)
        assert not has_commit(clone, old)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert events_named(logs, CURSOR_SHA_UNREACHABLE_EVENT) == [
            {
                "event": CURSOR_SHA_UNREACHABLE_EVENT,
                "log_level": "warning",
                "fetcher_name": probe.name,
            }
        ]
        assert git_calls.of("rev_list_before") == [((clone, BEFORE_DATE), {})]
        assert git_calls.of("diff_names") == [
            ((clone, base, new), {"path_filter": "cves/"})
        ]
        assert sorted(probe.paths) == sorted([first_file, added])
        assert result.row.status == "success"
        assert result.row.metrics == (2, 0, 0, 0)
        assert result.row.cursor == {"sha": new, "committed_at": D_REWRITE}
        _bounded(logs, workspace, old)


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


class TestRecovery:
    async def test_unreachable_cursor_recovers_from_boundary_with_recovery_prefix(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        history = _RecoveryHistory(workspace)
        probe = await _recovery_fetcher(workspace, harness)
        await harness.seed_run(probe, {"sha": UNREACHABLE, "committed_at": D_CURSOR})
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        clone = workspace.clone_path(probe)
        assert git_calls.of("check_sha_reachable") == [((clone, UNREACHABLE), {})]
        assert git_calls.of("rev_list_before") == [((clone, BEFORE_DATE), {})]
        assert git_calls.of("diff_names") == [
            ((clone, history.base, history.head), {"path_filter": "other/"})
        ]
        # The margin commit precedes the cursor date but follows the boundary;
        # the boundary commit's own files and every `cves/` path are excluded.
        assert sorted(probe.paths) == sorted([history.other_margin, history.other_head])
        assert _warnings(logs) == [CURSOR_SHA_UNREACHABLE_EVENT]
        assert result.row.status == "success"
        assert result.row.metrics == (2, 0, 0, 0)
        assert result.row.cursor == {"sha": history.head, "committed_at": D_LATER}
        _bounded(logs, workspace, UNREACHABLE)

    async def test_no_boundary_commit_records_head_without_processing(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        history = _RecoveryHistory(workspace)
        probe = await _recovery_fetcher(workspace, harness)
        # One day before this date precedes every upstream commit.
        await harness.seed_run(
            probe, {"sha": UNREACHABLE, "committed_at": "2024-01-05T12:00:00+00:00"}
        )
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert git_calls.names()[-2:] == ["check_sha_reachable", "rev_list_before"]
        assert "diff_names" not in git_calls.names()
        assert _warnings(logs) == [
            CURSOR_SHA_UNREACHABLE_EVENT,
            RECOVERY_BOUNDARY_NOT_FOUND_EVENT,
        ]
        assert events_named(logs, RECOVERY_BOUNDARY_NOT_FOUND_EVENT) == [
            {
                "event": RECOVERY_BOUNDARY_NOT_FOUND_EVENT,
                "log_level": "warning",
                "fetcher_name": probe.name,
            }
        ]
        assert probe.deltas == [[]]
        assert probe.calls == []
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": history.head, "committed_at": D_LATER}

    @pytest.mark.parametrize(
        ("cursor", "reason"),
        [
            pytest.param({"sha": UNREACHABLE}, "absent", id="missing"),
            pytest.param(
                {"sha": UNREACHABLE, "committed_at": None}, "absent", id="null"
            ),
            pytest.param(
                {"sha": UNREACHABLE, "committed_at": 1704844800},
                "invalid",
                id="non-string",
            ),
            pytest.param(
                {"sha": UNREACHABLE, "committed_at": "last-tuesday"},
                "invalid",
                id="unparseable",
            ),
            pytest.param(
                {"sha": UNREACHABLE, "committed_at": "2024-01-10T00:00:00"},
                "invalid",
                id="naive",
            ),
            pytest.param(
                {"sha": UNREACHABLE, "committed_at": "0001-01-01T00:00:00+00:00"},
                "invalid",
                id="overflow",
            ),
        ],
    )
    async def test_unusable_committed_at_records_head_without_processing(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        cursor: dict[str, Any],
        reason: str,
    ) -> None:
        history = _RecoveryHistory(workspace)
        probe = await _recovery_fetcher(workspace, harness)
        await harness.seed_run(probe, cursor)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert events_named(logs, CURSOR_COMMITTED_AT_UNUSABLE_EVENT) == [
            {
                "event": CURSOR_COMMITTED_AT_UNUSABLE_EVENT,
                "log_level": "error",
                "fetcher_name": probe.name,
                "reason": reason,
            }
        ]
        assert _warnings(logs) == [CURSOR_COMMITTED_AT_UNUSABLE_EVENT]
        assert "rev_list_before" not in git_calls.names()
        assert "diff_names" not in git_calls.names()
        assert probe.deltas == [[]]
        assert probe.calls == []
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": history.head, "committed_at": D_LATER}
        _bounded(logs, workspace, UNREACHABLE, "last-tuesday", "1704844800")

    async def test_reachable_cursor_after_reclone_uses_normal_delta(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        """Volume loss between runs: the cursor's `committed_at` is never
        needed because the fresh clone contains the cursor commit."""
        history = _RecoveryHistory(workspace)
        probe = await _fetcher(
            workspace,
            harness,
            delta_path_prefix="cves/",
            recovery_path_prefix="other/",
            step=token(),
        )
        await harness.seed_run(probe, {"sha": history.margin, "committed_at": D_MARGIN})

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert "rev_list_before" not in git_calls.names()
        assert _warnings(logs) == [CLONE_INVALID_REBUILDING_EVENT]
        assert git_calls.of("diff_names") == [
            (
                (workspace.clone_path(probe), history.margin, history.head),
                {"path_filter": "cves/"},
            )
        ]
        assert probe.paths == [history.cves_head]
        assert result.row.status == "success"
        assert result.row.cursor == {"sha": history.head, "committed_at": D_LATER}

    async def test_malformed_sha_string_is_unreachable_and_recovers(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        history = _RecoveryHistory(workspace)
        probe = await _recovery_fetcher(workspace, harness)
        await harness.seed_run(probe, {"sha": "not-a-sha", "committed_at": D_CURSOR})
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert _warnings(logs) == [
            "git_invalid_sha_format",
            CURSOR_SHA_UNREACHABLE_EVENT,
        ]
        assert events_named(logs, CURSOR_MALFORMED_EVENT) == []
        assert git_calls.of("rev_list_before") == [
            ((workspace.clone_path(probe), BEFORE_DATE), {})
        ]
        assert sorted(probe.paths) == sorted([history.other_margin, history.other_head])
        assert result.row.status == "success"
        assert result.row.cursor == {"sha": history.head, "committed_at": D_LATER}
        _bounded(logs, workspace, "not-a-sha")

    @pytest.mark.parametrize(
        "cursor",
        [
            pytest.param(["not", "an", "object"], id="list"),
            pytest.param(UNREACHABLE, id="string"),
            pytest.param({}, id="empty-object"),
            pytest.param({"committed_at": D_BASE}, id="missing-sha"),
            pytest.param({"sha": None, "committed_at": D_BASE}, id="null-sha"),
            pytest.param(
                {"sha": 987654321, "committed_at": D_BASE}, id="non-string-sha"
            ),
        ],
    )
    async def test_malformed_cursor_takes_first_run_branch(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        cursor: object,
    ) -> None:
        recorded = workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        await _first_run(harness, probe)
        await harness.seed_run(probe, cursor)
        workspace.upstream.commit({cve_path("CVE-2024-0001"): b"{}"}, date=D_CURSOR)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert events_named(logs, CURSOR_MALFORMED_EVENT) == [
            {
                "event": CURSOR_MALFORMED_EVENT,
                "log_level": "error",
                "fetcher_name": probe.name,
            }
        ]
        assert _warnings(logs) == [CURSOR_MALFORMED_EVENT]
        # First-run branch on the valid clone: no fetch, so the old HEAD.
        assert git_calls.names() == ["is_clone_valid", *HEAD_CALLS]
        assert probe.calls == []
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": recorded, "committed_at": D_BASE}
        _bounded(logs, workspace, UNREACHABLE, "987654321")


# ---------------------------------------------------------------------------
# Per-item loop
# ---------------------------------------------------------------------------


class TestPerItemLoop:
    @pytest.mark.parametrize(
        ("ghost", "logged_id"),
        [
            pytest.param(cve_path("CVE-2024-0009"), "CVE-2024-0009", id="canonical"),
            pytest.param("cves/2024/withdrawn-entry.json", None, id="non-canonical"),
        ],
    )
    async def test_file_missing_at_head_is_stale_success_without_effect(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        ghost: str,
        logged_id: str | None,
    ) -> None:
        """A selected path absent at HEAD (here injected by the filter hook;
        the real `git show` reports it missing)."""
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(
            workspace,
            harness,
            step=token(),
            filter_delta_files=lambda files: [*files, ghost],
        )
        await _first_run(harness, probe)
        present = cve_path("CVE-2024-0001")
        workspace.upstream.commit({present: b"{}"}, date=D_CURSOR)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert [args[2] for args, _ in git_calls.of("show_file")] == [present, ghost]
        assert probe.paths == [present]
        expected: dict[str, Any] = {
            "event": DELTA_FILE_MISSING_AT_HEAD_EVENT,
            "log_level": "warning",
            "fetcher_name": probe.name,
        }
        if logged_id is not None:
            expected["cve_id"] = logged_id
        assert events_named(logs, DELTA_FILE_MISSING_AT_HEAD_EVENT) == [expected]
        assert _warnings(logs) == [DELTA_FILE_MISSING_AT_HEAD_EVENT]
        # The stale unit adds no flush, commit, or finalization of its own.
        assert _execution_ops(harness.events) == [
            "flush",
            "commit_and_dispatch",
            "commit",
        ]
        assert probe.isolated == []
        assert harness.status.opened == []
        assert result.row.status == "success"
        assert result.row.metrics == (2, 0, 0, 0)
        _bounded(logs, workspace, ghost, "withdrawn-entry")

    async def test_success_flushes_once_then_template_finalizes_and_counts(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        """Git boundaries: `process_item()` returns the token and records no
        metric; the template flushes, then finalizes outside its catch, and
        counts each committed unit once."""
        cves = [await harness.cve(), await harness.cve()]
        paths = [cve_path(cve.cve_id) for cve in cves]
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        await _first_run(harness, probe)
        workspace.upstream.commit(dict.fromkeys(paths, b"{}"), date=D_CURSOR)
        probe.step = record_success(UpsertAction.UPDATED)
        harness.events.clear()

        result = await harness.run(probe)

        assert sorted(probe.paths) == sorted(paths)
        for path in probe.paths:
            assert _after(harness.events, f"process_item_returned:{path}") == [
                "flush",
                "commit_and_dispatch",
                "commit",
                "drain",
            ]
        assert probe.flushed_at_finalization == [True, True]
        assert all(type(value) is CVEFetchResult for value in probe.results)
        assert probe.counters_at_call == [(0, 0, 0, 0), (1, 0, 1, 0)]
        assert probe.counters_after_step == probe.counters_at_call
        assert result.row.status == "success"
        assert result.row.metrics == (2, 0, 2, 0)
        for cve in cves:
            state = await source_state(harness.factory, cve.id, SOURCE)
            assert state is not None
            assert state.status == CVESourceFetchStatus.SUCCESS
        assert harness.status.opened == []

    async def test_real_ingestion_maps_created_updated_unchanged_across_runs(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        cve_id = harness.world.new_cve_id()
        path = cve_path(cve_id)
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=ingest())
        await _first_run(harness, probe)
        packages = ["example-package"]
        revisions = [
            (cve_file("Example title", resolved_packages=packages), D_CURSOR),
            (cve_file("Example title, revised", resolved_packages=packages), D_REWRITE),
            # A formatting-only change: selected again, but no CVE effect.
            (
                cve_file(
                    "Example title, revised", resolved_packages=packages, indent=2
                ),
                D_LATER,
            ),
        ]
        expected = [
            (UpsertAction.CREATED, (1, 1, 0, 0), "Example title"),
            (UpsertAction.UPDATED, (1, 0, 1, 0), "Example title, revised"),
            (UpsertAction.UNCHANGED, (1, 0, 0, 0), "Example title, revised"),
        ]

        for (content, date), (action, metrics, title) in zip(
            revisions, expected, strict=True
        ):
            head = workspace.upstream.commit({path: content}, date=date)
            harness.events.clear()
            harness.published.calls.clear()
            probe.results.clear()

            result = await harness.run(probe)

            assert result.row.status == "success"
            assert result.row.metrics == metrics
            assert result.row.cursor == {"sha": head, "committed_at": date}
            assert [value.action for value in probe.results] == [action]
            # Ingestion flushes internally; the template's one flush follows
            # the return and precedes the finalization.
            assert _after(harness.events, f"process_item_returned:{path}")[:4] == [
                "flush",
                "commit_and_dispatch",
                "commit",
                "drain",
            ]
            assert [
                call["kwargs"]["ticket_id"]
                for call in harness.published.calls
                if call["task_name"] == RESOLVE
            ] == [await _ticket_of(harness, cve_id)]
            cve = await harness.cve_named(cve_id)
            assert cve is not None
            assert cve.title == title
            state = await source_state(harness.factory, cve.id, SOURCE)
            assert state is not None
            assert state.status == CVESourceFetchStatus.SUCCESS

    @pytest.mark.parametrize(
        "case",
        [
            "parse-error",
            "write-then-raise",
            "ingest-then-raise",
            "flush-failure",
            "show-file-failure",
            "non-token-return",
        ],
    )
    async def test_pre_finalization_failure_is_isolated(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        case: str,
    ) -> None:
        cve = await harness.cve()
        path = cve_path(cve.cve_id)
        content = cve_file("Example title")
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        cursor = (await _first_run(harness, probe)).row.cursor
        clone = workspace.clone_path(probe)
        cause = {
            "parse-error": "ValidationError",
            "write-then-raise": "ValueError",
            "ingest-then-raise": "RuntimeError",
            "flush-failure": "IntegrityError",
            "show-file-failure": "GitFileError",
            "non-token-return": "TypeError",
        }[case]
        if case == "parse-error":
            content = b'{"title": ' + SECRET.encode()
            probe.step = ingest()
        elif case == "write-then-raise":
            probe.step = record_success(then=ValueError(SECRET))
        elif case == "ingest-then-raise":
            probe.step = ingest(fail_after=RuntimeError(SECRET))
        elif case == "flush-failure":
            probe.step = duplicate_cve()
        elif case == "show-file-failure":
            probe.step = token()
            git_calls.replacements["show_file"] = show_failing(
                GitFileError(f"git show exited with 128: fatal: {clone} {SECRET}"),
                path,
            )
        else:
            probe.step = returns(None)
        workspace.upstream.commit({path: content}, date=D_CURSOR)
        harness.events.clear()

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "fetcher_name": probe.name,
                "cause": cause,
            }
        ]
        assert _warnings(logs) == [CVE_FETCH_ITEM_FAILED_EVENT]
        assert probe.paths == ([] if case == "show-file-failure" else [path])
        # Rolled back first, then the independent failure status; never
        # finalized.
        ops = [e for e in harness.events if e in ("rollback", "status:commit")]
        assert ops == ["rollback", "status:commit"]
        assert "commit_and_dispatch" not in harness.events
        assert probe.isolated == [(cve.cve_id, CVESourceFetchStatus.FAILURE)]
        state = await source_state(harness.factory, cve.id, SOURCE)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        stored = await harness.cve_named(cve.cve_id)
        assert stored is not None
        assert stored.title is None
        assert harness.published.calls == []
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 1)
        assert result.row.error_message == "All 1 items failed"
        assert result.row.cursor is None
        assert (await harness.run(probe)).fetcher.previous_cursor == cursor
        _bounded(logs, workspace)

    @pytest.mark.parametrize(
        "path",
        [
            pytest.param("cves/2024/not-a-cve.json", id="non-canonical"),
            pytest.param(os.fsdecode(b"cves/2024/\xff\xfe.json"), id="non-utf8"),
        ],
    )
    async def test_non_canonical_item_skips_isolated_status_and_omits_cve_id(
        self, workspace: GitWorkspace, harness: GitRunHarness, path: str
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=raises(ValueError(SECRET)))
        await _first_run(harness, probe)
        workspace.upstream.commit({path: b"{}"}, date=D_CURSOR)

        with capture_logs() as logs:
            result = await harness.run(probe)

        # The raw delta name (surrogate-escaped when not UTF-8) reaches the
        # hook and is readable at HEAD.
        assert probe.calls == [(path, b"{}")]
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "fetcher_name": probe.name,
                "cause": "ValueError",
            }
        ]
        assert probe.isolated == []
        assert harness.status.opened == []
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 1)
        _bounded(logs, workspace, Path(path).stem)

    @pytest.mark.parametrize("ambiguous", [False, True], ids=["definite", "ambiguous"])
    async def test_commit_failure_terminates_run_without_item_handling(
        self, workspace: GitWorkspace, harness: GitRunHarness, ambiguous: bool
    ) -> None:
        cves = [await harness.cve(), await harness.cve()]
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        await _first_run(harness, probe)
        workspace.upstream.commit(
            {cve_path(cve.cve_id): b"{}" for cve in cves}, date=D_CURSOR
        )
        failure = _CommitFailureError(SECRET)
        write = record_success(UpsertAction.UPDATED)

        async def step(
            fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
        ) -> CVEFetchResult:
            result: CVEFetchResult = await write(fetcher, path, content, session)
            if len(probe.calls) == 2:
                harness.sessions.fail_once["commit"] = (failure, ambiguous)
            return result

        probe.step = step

        with capture_logs() as logs:
            result = await harness.run(probe, raises=_CommitFailureError)

        assert result.raised is failure
        assert len(probe.calls) == 2
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert probe.isolated == []
        assert harness.status.opened == []
        # Only the first, committed unit is counted.
        assert result.row.status == "failure"
        assert result.row.metrics == (1, 0, 1, 0)
        assert result.row.error_message == "Unexpected error"
        assert result.row.cursor is None
        by_id = {cve.cve_id: cve for cve in cves}
        first, second = (by_id[Path(path).stem] for path in probe.paths)
        first_state = await source_state(harness.factory, first.id, SOURCE)
        assert first_state is not None
        assert first_state.status == CVESourceFetchStatus.SUCCESS
        second_state = await source_state(harness.factory, second.id, SOURCE)
        if ambiguous:
            assert second_state is not None
            assert second_state.status == CVESourceFetchStatus.SUCCESS
        else:
            assert second_state is None
        _bounded(logs, workspace)

    @pytest.mark.parametrize("failing", ["package-handoff", "convergence-drain"])
    async def test_post_commit_error_fails_run_and_keeps_success_and_effect(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        monkeypatch: pytest.MonkeyPatch,
        failing: str,
    ) -> None:
        cves = [await harness.cve(), await harness.cve()]
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(
            workspace,
            harness,
            step=record_success(UpsertAction.UPDATED, post_ingest=handoff()),
        )
        await _first_run(harness, probe)
        workspace.upstream.commit(
            {cve_path(cve.cve_id): b"{}" for cve in cves}, date=D_CURSOR
        )
        error: Exception
        if failing == "package-handoff":
            error = TypeError(SECRET)
            harness.published.errors[RESOLVE] = error
        else:
            error = RuntimeError(SECRET)

            async def drain(session: AsyncSession) -> None:
                raise error

            monkeypatch.setattr(
                ticket_convergence_publication, "drain_ticket_convergence", drain
            )

        with capture_logs() as logs:
            result = await harness.run(probe, raises=type(error))

        assert result.raised is error
        # The run ends with the first committed unit.
        assert len(probe.calls) == 1
        assert result.row.status == "failure"
        assert result.row.metrics == (1, 0, 1, 0)
        assert result.row.error_message == "Unexpected error"
        assert result.row.cursor is None
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert probe.isolated == []
        assert harness.status.opened == []
        committed = next(cve for cve in cves if cve_path(cve.cve_id) == probe.paths[0])
        state = await source_state(harness.factory, committed.id, SOURCE)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        _bounded(logs, workspace)

    async def test_broker_operational_handoff_failure_keeps_success(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        cve = await harness.cve()
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(
            workspace,
            harness,
            step=record_success(UpsertAction.UPDATED, post_ingest=handoff()),
        )
        await _first_run(harness, probe)
        head = workspace.upstream.commit({cve_path(cve.cve_id): b"{}"}, date=D_CURSOR)
        harness.published.errors[RESOLVE] = OperationalError(SECRET)

        with capture_logs() as logs:
            result = await harness.run(probe)

        assert events_named(logs, HANDOFF_PUBLICATION_FAILED_EVENT) == [
            {
                "event": HANDOFF_PUBLICATION_FAILED_EVENT,
                "log_level": "error",
                "ticket_id": handoff().ticket_id,
                "fetcher_name": probe.name,
                "cause": "OperationalError",
            }
        ]
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert probe.isolated == []
        assert result.row.status == "success"
        assert result.row.metrics == (1, 0, 1, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_CURSOR}
        state = await source_state(harness.factory, cve.id, SOURCE)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        _bounded(logs, workspace)

    @pytest.mark.parametrize(
        "signal",
        [SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    async def test_whole_run_signal_propagates_without_item_handling(
        self, workspace: GitWorkspace, harness: GitRunHarness, signal: Exception
    ) -> None:
        cve = await harness.cve()
        path = cve_path(cve.cve_id)
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=raises(signal))
        await _first_run(harness, probe)
        workspace.upstream.commit({path: b"{}"}, date=D_CURSOR)
        harness.events.clear()

        with capture_logs() as logs:
            result = await harness.run(probe, raises=type(signal))

        assert result.raised is signal
        # Only `run()`'s own rollback of the execution session; no per-item
        # rollback, isolated status, warning, or metric.
        assert _after(harness.events, f"process_item:{path}") == ["rollback"]
        assert probe.isolated == []
        assert harness.status.opened == []
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor is None

    async def test_cancellation_propagates_without_item_handling(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        cve = await harness.cve()
        path = cve_path(cve.cve_id)
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        cancelled = asyncio.CancelledError()
        probe = await _fetcher(workspace, harness, step=raises(cancelled))
        await _first_run(harness, probe)
        workspace.upstream.commit({path: b"{}"}, date=D_CURSOR)
        fetcher, run_id = await harness.start(probe)

        with capture_logs() as logs, pytest.raises(asyncio.CancelledError) as raised:
            await fetcher.run(run_id=run_id, config=RUN_CONFIG)

        assert raised.value is cancelled
        assert _after(harness.events, f"process_item:{path}") == []
        assert probe.isolated == []
        assert harness.status.opened == []
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        # Cancellation bypasses `run()` finalization as well.
        assert (await harness.row(run_id)).status == "running"


# ---------------------------------------------------------------------------
# Run status and cursor
# ---------------------------------------------------------------------------


def _nth_call_raises(
    probe: GitFetcherProbe, nth: int, error: BaseException
) -> ItemStep:
    """A step that raises `error` on the `nth` processed item (whatever its
    path, since the delta order is not significant) and otherwise returns an
    `unchanged` token."""

    async def step(
        fetcher: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        if len(probe.calls) == nth:
            raise error
        return CVEFetchResult(UpsertAction.UNCHANGED, None)

    return step


class TestStatusAndCursor:
    async def test_mixed_outcome_is_partial_and_advances_cursor(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        await _first_run(harness, probe)
        probe.step = _nth_call_raises(probe, 2, ValueError(SECRET))
        head = workspace.upstream.commit(
            {cve_path("CVE-2024-0001"): b"{}", cve_path("CVE-2024-0002"): b"{}"},
            date=D_CURSOR,
        )

        result = await harness.run(probe)

        assert result.row.status == "partial"
        assert result.row.metrics == (1, 0, 0, 1)
        assert result.row.cursor == {"sha": head, "committed_at": D_CURSOR}

    async def test_all_failed_keeps_previous_cursor_for_next_run(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=raises(ValueError(SECRET)))
        cursor = (await _first_run(harness, probe)).row.cursor
        paths = [cve_path("CVE-2024-0001"), cve_path("CVE-2024-0002")]
        head = workspace.upstream.commit(dict.fromkeys(paths, b"{}"), date=D_CURSOR)

        failed = await harness.run(probe)

        assert failed.row.status == "failure"
        assert failed.row.metrics == (0, 0, 0, 2)
        assert failed.row.error_message == "All 2 items failed"
        assert failed.row.cursor is None

        probe.step = token()
        probe.calls.clear()
        retried = await harness.run(probe)

        assert retried.fetcher.previous_cursor == cursor
        assert sorted(probe.paths) == sorted(paths)
        assert retried.row.status == "success"
        assert retried.row.cursor == {"sha": head, "committed_at": D_CURSOR}

    async def test_soft_time_limit_mid_loop_fails_and_keeps_cursor(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness)
        cursor = (await _first_run(harness, probe)).row.cursor
        probe.step = _nth_call_raises(probe, 2, SoftTimeLimitExceeded())
        paths = [cve_path("CVE-2024-0001"), cve_path("CVE-2024-0002")]
        workspace.upstream.commit(dict.fromkeys(paths, b"{}"), date=D_CURSOR)

        timed_out = await harness.run(probe, raises=SoftTimeLimitExceeded)

        assert timed_out.row.status == "failure"
        assert timed_out.row.metrics == (1, 0, 0, 0)
        assert timed_out.row.cursor is None
        message = timed_out.row.error_message
        assert message is not None
        assert message.startswith("Execution reached the soft time limit")
        assert "1 items processed" in message

        probe.step = token()
        probe.calls.clear()
        resumed = await harness.run(probe)

        assert resumed.fetcher.previous_cursor == cursor
        assert sorted(probe.paths) == sorted(paths)
        assert resumed.row.status == "success"


# ---------------------------------------------------------------------------
# Infrastructure errors
# ---------------------------------------------------------------------------


class TestInfrastructureErrors:
    async def test_clone_failure_is_public_message_with_chained_stderr(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        missing = workspace.root / "missing-upstream"
        probe = await _fetcher(workspace, harness, repo_url=missing.as_uri())

        with capture_logs() as logs:
            result = await harness.run(probe, raises=FetcherError)

        assert isinstance(result.raised, FetcherError)
        assert isinstance(result.raised.__cause__, GitFetchError)
        assert git_calls.names() == FIRST_RUN_CALLS
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor is None
        assert result.row.error_message == CLONE_FAILED_MESSAGE
        _public(result.row.error_message, workspace)
        detail = result.row.error_detail
        assert detail is not None
        assert detail.startswith("git clone exited with 128")
        assert "missing-upstream" in detail
        assert result.row.error_traceback is not None
        assert "GitFetchError" in result.row.error_traceback
        assert not workspace.clone_path(probe).exists()
        _bounded(logs, workspace, "missing-upstream")

    async def test_rebuild_clone_failure_is_public_message_and_keeps_cursor(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        """Row 4 of First-Run Detection with the upstream unreachable: the
        rebuild's clone failure is the fixed clone message, not a corruption
        or a generic error, and the stored cursor is kept."""
        missing = workspace.root / "missing-upstream"
        probe = await _fetcher(workspace, harness, repo_url=missing.as_uri())
        cursor = {"sha": "a" * 40, "committed_at": D_CURSOR}
        await harness.seed_run(probe, cursor)

        with capture_logs() as logs:
            result = await harness.run(probe, raises=FetcherError)

        assert isinstance(result.raised, FetcherError)
        assert isinstance(result.raised.__cause__, GitFetchError)
        assert git_calls.names() == FIRST_RUN_CALLS
        assert _warnings(logs) == [CLONE_INVALID_REBUILDING_EVENT]
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor is None
        assert result.row.error_message == CLONE_FAILED_MESSAGE
        _public(result.row.error_message, workspace)
        assert result.row.error_detail is not None
        assert "missing-upstream" in result.row.error_detail
        assert not workspace.clone_path(probe).exists()
        _bounded(logs, workspace, "missing-upstream")

    async def test_fetch_failure_keeps_clone_and_cursor(
        self, workspace: GitWorkspace, harness: GitRunHarness, git_calls: GitCalls
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        cursor = (await _first_run(harness, probe)).row.cursor
        original = workspace.upstream.path
        moved = original.rename(workspace.root / "moved-upstream")
        _reset(harness, git_calls)

        with capture_logs() as logs:
            failed = await harness.run(probe, raises=FetcherError)

        assert failed.raised is not None
        assert isinstance(failed.raised.__cause__, GitFetchError)
        assert git_calls.names() == ["is_clone_valid", "fetch_origin"]
        assert failed.row.status == "failure"
        assert failed.row.cursor is None
        assert failed.row.error_message == FETCH_FAILED_MESSAGE
        _public(failed.row.error_message, workspace)
        detail = failed.row.error_detail
        assert detail is not None
        assert detail.startswith("git fetch exited with")
        assert is_bare_clone(workspace.clone_path(probe))
        assert _warnings(logs) == []
        _bounded(logs, workspace)

        moved.rename(original)
        new = cve_path("CVE-2024-0001")
        workspace.upstream.commit({new: b"{}"}, date=D_CURSOR)
        recovered = await harness.run(probe)

        assert recovered.fetcher.previous_cursor == cursor
        assert probe.paths == [new]
        assert recovered.row.status == "success"

    @pytest.mark.parametrize(
        "failing",
        [
            "detached-head",
            "get_head_sha",
            "check_sha_reachable",
            "diff_names",
            "rev_list_before",
        ],
    )
    async def test_corruption_deletes_clone_then_next_run_reclones(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        failing: str,
    ) -> None:
        head = workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        await _first_run(harness, probe)
        clone = workspace.clone_path(probe)
        injected = f"git {failing} exited with 128: fatal: {clone} {SECRET}"
        if failing == "detached-head":
            # The branch lookup inside `fetch_origin` finds no branch.
            git(None, f"--git-dir={clone}", "update-ref", "--no-deref", "HEAD", head)
            injected = "git symbolic-ref exited with 128"
        else:
            git_calls.errors[failing] = GitCorruptionError(injected)
        if failing == "rev_list_before":
            await harness.seed_run(
                probe, {"sha": UNREACHABLE, "committed_at": D_CURSOR}
            )
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe, raises=FetcherError)

        assert result.raised is not None
        assert isinstance(result.raised.__cause__, GitCorruptionError)
        assert events_named(logs, CLONE_CORRUPTION_DETECTED_EVENT) == [
            {
                "event": CLONE_CORRUPTION_DETECTED_EVENT,
                "log_level": "warning",
                "fetcher_name": probe.name,
                "cause": "GitCorruptionError",
            }
        ]
        assert git_calls.names()[-1] == "delete_clone"
        assert not clone.exists()
        assert result.row.status == "failure"
        assert result.row.cursor is None
        assert result.row.error_message == CORRUPTION_MESSAGE
        _public(result.row.error_message, workspace)
        assert result.row.error_detail is not None
        assert injected in result.row.error_detail
        if failing == "detached-head":
            assert workspace.sleeps == [2, 4, 8]
        _bounded(logs, workspace)

        git_calls.errors.clear()
        healed = await harness.run(probe)

        assert healed.row.status == "success"
        assert "clone" in git_calls.names()
        assert is_bare_clone(clone)

    @pytest.mark.parametrize(
        "phase", ["first-run-invalid", "rebuild-invalid", "after-corruption"]
    )
    async def test_delete_failure_is_bounded_error_and_public_message(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        git_calls: GitCalls,
        phase: str,
    ) -> None:
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(workspace, harness, step=token())
        clone = workspace.clone_path(probe)
        if phase == "first-run-invalid":
            _make_invalid(clone, "plain-directory")
        else:
            await _first_run(harness, probe)
            if phase == "rebuild-invalid":
                shutil.rmtree(clone)
                _make_invalid(clone, "plain-directory")
            else:
                git_calls.errors["diff_names"] = GitCorruptionError(SECRET)
        git_calls.errors["delete_clone"] = PermissionError(
            13, "Permission denied", str(clone)
        )
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(probe, raises=FetcherError)

        assert result.raised is not None
        assert isinstance(result.raised.__cause__, PermissionError)
        assert events_named(logs, CLONE_DELETE_FAILED_EVENT) == [
            {
                "event": CLONE_DELETE_FAILED_EVENT,
                "log_level": "error",
                "fetcher_name": probe.name,
                "repo_path": str(clone),
                "errno": 13,
                "guidance": DELETE_FAILED_GUIDANCE,
            }
        ]
        expected_before = {
            "first-run-invalid": [],
            "rebuild-invalid": [CLONE_INVALID_REBUILDING_EVENT],
            "after-corruption": [CLONE_CORRUPTION_DETECTED_EVENT],
        }[phase]
        assert _warnings(logs) == [*expected_before, CLONE_DELETE_FAILED_EVENT]
        # Nothing is cloned after the failed deletion.
        assert git_calls.names()[-1] == "delete_clone"
        assert "clone" not in git_calls.names()
        assert clone.exists()
        assert result.row.status == "failure"
        assert result.row.cursor is None
        assert result.row.error_message == DELETE_FAILED_MESSAGE
        _public(result.row.error_message, workspace)
        assert result.row.error_detail is not None
        assert "Permission denied" in result.row.error_detail
        _bounded(logs, workspace)


class TestPublishedTasks:
    async def test_isolated_failure_publishes_nothing(
        self, workspace: GitWorkspace, harness: GitRunHarness
    ) -> None:
        """A failed unit's rolled-back transaction registers no convergence
        effect and no package handoff."""
        cve_id = harness.world.new_cve_id()
        workspace.upstream.commit({"README": b"one\n"}, date=D_BASE)
        probe = await _fetcher(
            workspace, harness, step=ingest(fail_after=RuntimeError(SECRET))
        )
        await _first_run(harness, probe)
        workspace.upstream.commit(
            {cve_path(cve_id): cve_file("Example", resolved_packages=["example-x"])},
            date=D_CURSOR,
        )

        result = await harness.run(probe)

        assert result.row.metrics == (0, 0, 0, 1)
        assert harness.published.calls == []
        # The rolled-back ingestion created no CVE row.
        assert await harness.cve_named(cve_id) is None
        assert probe.isolated == [(cve_id, CVESourceFetchStatus.FAILURE)]
