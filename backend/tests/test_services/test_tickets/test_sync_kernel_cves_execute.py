"""The real `SyncKernelCves` through its inherited `BaseGitFetcher.execute()`
and the real `BaseFetcher.run()` (backend/app/services/tickets/
sync_kernel_cves.py).

Owning specifications:

- docs/features/tickets/cve-sync-kernel.md (Algorithm steps 1-4; Rejection
  Handling, rejection revert and the preserved `date_rejected`; CVE JSON
  Field Mapping, `provider_name = "Linux"`, additive CVSS retention, CVSS
  deduplication through the External Base Reduction, External String
  Admissibility; Error Handling; Work unit and metric mapping).
- docs/features/platform/git-fetcher-infrastructure.md (First-Run
  Detection; Template Method: `execute()` steps 8-11, Status
  Determination; Hook Methods; `process_item`).
- docs/features/platform/cve-fetcher-infrastructure.md (Automatic Reference
  Caller Contract; `CVEFetchResult`; Per-CVE Finalization; Batch Error
  Handling, the `cve_fetch_item_failed` event; First Run Behavior; Metric
  Definitions).
- docs/features/tickets/cve-tracking.md (CVE Rejection Handling: Rejection
  handling, Rejection revert handling, the `PUBLISHED => date_rejected IS
  NULL` invariant).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, Concrete mappings for `sync_kernel_cves`; External String
  Admissibility; CVE Fetcher Infrastructure, Git boundaries; Tier 1 — Unit
  Tests, the hermetic Git rules).

Every repository is a real temporary one under `tmp_path`: a work-tree
upstream served through a `file://` URL (`SyncKernelCves.repo_url` is
substituted with it) and the fetcher's bare `vulns.git` clone under the
redirected `GIT_CLONE_BASE_DIR`. No Git process inherits a `GIT_*` variable
or a user or system Git configuration. Upstream commits carry a fictional
author identity (`tests/support/kernel_fetcher.py`). Records are the
sanitized fixtures of `tests/support/kernel.py` at their real repository
paths, or fixtures re-keyed to fictional `CVE-2099-*` IDs. The
`git_operations` spy records every Git call; one case replaces `show_file`
to reach the missing-at-HEAD branch, which a real `--diff-filter=AM` delta
cannot produce.

Runs use the real database through `open_git_run_harness()`
(`tests/support/git_fetchers.py`): the run, execution, finalization, and
isolated status sessions over `real_session_factory`, the publication spy
over `task_publication.publish_task`, and teardown deleting every committed
`FetcherRun`, `FetcherConfig`, CVE, and Ticket row and asserting no CVE
leaked. Before seeding, no committed run or configuration of
`sync_kernel_cves` may exist, because the cursor is read from every
committed run of that name.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import (
    CVESourceFetchStatus,
    CVESourceType,
    CveState,
    ReferenceType,
    TicketAuditEventType,
    TicketStatus,
)
from app.models.cve import CVE
from app.services.base_git_fetcher import (
    CVE_FETCH_ITEM_FAILED_EVENT,
    DELTA_FILE_MISSING_AT_HEAD_EVENT,
)
from app.services.tickets.sync_kernel_cves import SyncKernelCves
from tests.support.cve_catch_up import RESOLVE, source_state
from tests.support.git_fetchers import (
    GitCalls,
    GitFetcherProbe,
    GitRunHarness,
    GitWorkspace,
    RunResult,
    SessionFactory,
    assert_bounded_logs,
    events_named,
    install_git_workspace,
    is_bare_clone,
    open_git_run_harness,
    show_missing,
)
from tests.support.kernel import RECORD_SOURCES, load_raw_record, load_record
from tests.support.kernel_fetcher import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    NAME,
    AssessmentRow,
    ReferenceRow,
    assessments,
    audit_events,
    cna,
    commit,
    committed_fetcher_rows,
    derived_record,
    kernel_probe,
    record_path,
    references,
    ticket_of,
)

pytestmark = pytest.mark.integration

KERNEL: Final = CVESourceType.KERNEL

D_BASE: Final = "2026-10-01T00:00:00+00:00"
D_1: Final = "2026-10-02T00:00:00+00:00"
D_2: Final = "2026-10-03T00:00:00+00:00"
D_3: Final = "2026-10-04T00:00:00+00:00"

SEED_FILES: Final = {
    "cve/README": b"example: fictional README\n",
    "cve/published/.empty": b"",
    "cve/rejected/.empty": b"",
}
"""The base commit: no record file."""

VULNS_TREE: Final = "https://git.kernel.org/pub/scm/linux/security/vulns.git/tree"
BASE_VECTOR: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
"""The strict Base vector of `published_cvss_v3_1` (and the fixture whose
non-Base form the reduction test derives)."""

CREATED_COMMENT: Final = "CVE ingested from Linux Kernel CNA"
REJECTED_COMMENT: Final = "CVE rejected"
PRIOR_REJECTION: Final = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
"""A `date_rejected` previously supplied by another source."""

RECORD_TEXTS: Final = (
    "fictional title",
    "fictional subject",
    "Fictional commit message",
    "Fictional scenario",
    "Fictional description",
)
"""Fragments of every fixture title, description, and scenario."""


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    created = install_git_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(SyncKernelCves, "repo_url", created.upstream.url)
    return created


@pytest.fixture
def git_calls(workspace: GitWorkspace, monkeypatch: pytest.MonkeyPatch) -> GitCalls:
    return GitCalls(monkeypatch)


@pytest.fixture
async def harness(
    monkeypatch: pytest.MonkeyPatch,
    real_session_factory: async_sessionmaker[AsyncSession],
    db_session_factory: SessionFactory,
) -> AsyncIterator[GitRunHarness]:
    # The previous cursor is read from every committed run of the name.
    assert await committed_fetcher_rows(real_session_factory) == 0
    opened = await open_git_run_harness(
        monkeypatch, real_session_factory, db_session_factory
    )
    try:
        await opened.world.ensure_default_setting()
        yield opened
    finally:
        await opened.cleanup()


@pytest.fixture
async def kernel(harness: GitRunHarness) -> GitFetcherProbe:
    """The production class with its committed, enabled `FetcherConfig`."""
    probe = kernel_probe(harness.events)
    await harness.register(probe)
    return probe


async def _first_run(
    workspace: GitWorkspace, harness: GitRunHarness, kernel: GitFetcherProbe
) -> RunResult:
    """Commit the base files and record HEAD with a first run."""
    head = commit(workspace.upstream, SEED_FILES, date=D_BASE)
    result = await harness.run(kernel)
    assert result.row.status == "success"
    assert result.row.cursor == {"sha": head, "committed_at": D_BASE}
    return result


async def _claim(harness: GitRunHarness, cve_id: str) -> None:
    """Own a real fixture CVE-ID: none may exist yet, and teardown deletes
    the CVE and Ticket the run creates for it."""
    assert await harness.cve_named(cve_id) is None
    harness.world.cve_id_strings.append(cve_id)


async def _cve(harness: GitRunHarness, cve_id: str) -> CVE:
    cve = await harness.cve_named(cve_id)
    assert cve is not None
    return cve


def _reset(harness: GitRunHarness, git_calls: GitCalls | None = None) -> None:
    harness.events.clear()
    harness.published.calls.clear()
    if git_calls is not None:
        git_calls.clear()


def _shown(git_calls: GitCalls) -> list[str]:
    """The path of every `show_file` call, in order."""
    return [args[2] for args, _ in git_calls.of("show_file")]


def _bounded(logs: list[Any], workspace: GitWorkspace, *more: str) -> None:
    """No log carries record text, a commit author, a URL, or a path."""
    assert_bounded_logs(
        logs,
        *workspace.forbidden_texts(),
        *RECORD_TEXTS,
        AUTHOR_NAME,
        AUTHOR_EMAIL,
        "Example Author",
        "://",
        "git.kernel.org",
        "cve/published",
        "cve/rejected",
        ".json",
        *more,
    )


def _problems(logs: list[Any]) -> list[str]:
    return [
        entry["event"]
        for entry in logs
        if entry.get("log_level") in ("warning", "error", "critical")
    ]


def _without_metrics(record: dict[str, Any]) -> None:
    del cna(record)["metrics"]


# ---------------------------------------------------------------------------
# First run
# ---------------------------------------------------------------------------


class TestFirstRun:
    async def test_first_run_clones_records_head_and_processes_no_record(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
        git_calls: GitCalls,
    ) -> None:
        """First Run Behavior (Git-based): the existing record files are
        not ingested; only HEAD is recorded."""
        for cve_path in RECORD_SOURCES.values():
            await _claim(harness, Path(cve_path).stem)
        files = {
            **SEED_FILES,
            **{path: load_raw_record(name) for name, path in RECORD_SOURCES.items()},
        }
        head = commit(workspace.upstream, files, date=D_BASE)

        with capture_logs() as logs:
            result = await harness.run(kernel)

        assert type(result.fetcher) is SyncKernelCves
        assert result.row.status == "success"
        assert result.row.metrics == (0, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_BASE}
        assert git_calls.names() == [
            "is_clone_valid",
            "delete_clone",
            "clone",
            "get_head_sha",
            "get_commit_date",
        ]
        assert git_calls.of("clone") == [
            (
                (workspace.upstream.url, workspace.clone_path(kernel)),
                {"filter_spec": None, "single_branch": True},
            )
        ]
        assert is_bare_clone(workspace.clone_path(kernel))
        for cve_path in RECORD_SOURCES.values():
            assert await harness.cve_named(Path(cve_path).stem) is None
        assert harness.published.calls == []
        assert _problems(logs) == []
        _bounded(logs, workspace)


# ---------------------------------------------------------------------------
# Published records
# ---------------------------------------------------------------------------


class TestPublishedRecord:
    async def test_added_published_record_creates_cve_ticket_and_handoff(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        name = "published_cvss_v3_1"
        path = RECORD_SOURCES[name]
        cve_id = Path(path).stem
        await _claim(harness, cve_id)
        await _first_run(workspace, harness, kernel)
        head = commit(workspace.upstream, {path: load_raw_record(name)}, date=D_1)
        _reset(harness)

        with capture_logs() as logs:
            result = await harness.run(kernel)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_1}
        cve = await _cve(harness, cve_id)
        fixture = cna(load_record(name))
        assert cve.cve_state == CveState.PUBLISHED
        assert cve.title == fixture["title"]
        assert cve.description == fixture["descriptions"][0]["value"]
        assert cve.date_rejected is None
        # Dates are never read from kernel JSON.
        assert cve.published_date is None
        assert cve.modified_date is None
        state = await source_state(harness.factory, cve.id, KERNEL)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS

        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.NEW
        created = [
            event
            for event in await audit_events(harness.factory, ticket.id)
            if event.event_type == TicketAuditEventType.TICKET_CREATED
        ]
        assert [(event.user_id, event.comment) for event in created] == [
            (None, CREATED_COMMENT)
        ]

        stored = await references(harness.factory, ticket.id)
        assert stored[0] == ReferenceRow(
            url=f"{VULNS_TREE}/{path}",
            title="Linux Kernel CNA",
            type=ReferenceType.ADVISORY,
            source=NAME,
        )
        assert [row.url for row in stored[1:]] == [
            reference["url"] for reference in fixture["references"]
        ]
        assert {row.source for row in stored} == {NAME}
        assert {row.title for row in stored[1:]} == {None}

        assert await assessments(harness.factory, cve.id) == [
            AssessmentRow("Linux", "3.1", BASE_VECTOR)
        ]
        [handoff] = harness.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(ticket.id)
        assert "kernel-source" in handoff["resolved_packages"]
        # The finalizer flushes, commits, drains, then hands off.
        events = harness.events
        assert events.count("commit") == 1
        assert events.index("commit") < events.index("drain")
        assert events.index("drain") < events.index(f"publish:{RESOLVE}")
        assert harness.status.opened == []
        assert _problems(logs) == []
        _bounded(logs, workspace)

    async def test_non_base_vector_is_persisted_as_the_strict_base_vector(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        """External Base Reduction: Temporal metrics appended to the
        fixture's Base vector are reduced away before persistence."""
        fixture_vector = cna(load_record("published_cvss_v3_1"))["metrics"][0][
            "cvssV3_1"
        ]["vectorString"]
        assert fixture_vector == BASE_VECTOR

        def append_temporal(record: dict[str, Any]) -> None:
            cna(record)["metrics"][0]["cvssV3_1"]["vectorString"] = (
                f"{BASE_VECTOR}/E:P/RL:O/RC:C"
            )

        cve_id = harness.world.new_cve_id()
        await _first_run(workspace, harness, kernel)
        commit(
            workspace.upstream,
            {
                record_path("published", cve_id): derived_record(
                    "published_cvss_v3_1", cve_id, append_temporal
                )
            },
            date=D_1,
        )

        result = await harness.run(kernel)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        assert await assessments(harness.factory, cve.id) == [
            AssessmentRow("Linux", "3.1", BASE_VECTOR)
        ]

    async def test_later_record_without_metrics_retains_the_assessment(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        """Additive CVSS: an omitted assessment is retained, never deleted;
        nothing else changed, so the unit is `unchanged`."""
        cve_id = harness.world.new_cve_id()
        path = record_path("published", cve_id)
        await _first_run(workspace, harness, kernel)
        commit(
            workspace.upstream,
            {path: derived_record("published_cvss_v3_1", cve_id)},
            date=D_1,
        )
        created = await harness.run(kernel)
        assert created.row.metrics == (1, 1, 0, 0)
        head = commit(
            workspace.upstream,
            {path: derived_record("published_cvss_v3_1", cve_id, _without_metrics)},
            date=D_2,
        )

        result = await harness.run(kernel)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_2}
        cve = await _cve(harness, cve_id)
        assert await assessments(harness.factory, cve.id) == [
            AssessmentRow("Linux", "3.1", BASE_VECTOR)
        ]

    async def test_reformatted_record_is_unchanged_and_edited_record_is_updated(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        cve_id = harness.world.new_cve_id()
        path = record_path("published", cve_id)
        original = derived_record("published_without_metrics", cve_id)
        await _first_run(workspace, harness, kernel)
        commit(workspace.upstream, {path: original}, date=D_1)
        assert (await harness.run(kernel)).row.metrics == (1, 1, 0, 0)

        # A formatting-only modification: selected again, no CVE effect.
        reformatted = json.dumps(json.loads(original), indent=4).encode()
        commit(workspace.upstream, {path: reformatted}, date=D_2)
        _reset(harness)
        unchanged = await harness.run(kernel)

        assert unchanged.row.status == "success"
        assert unchanged.row.metrics == (1, 0, 0, 0)

        def retitle(record: dict[str, Any]) -> None:
            cna(record)["title"] = "example: fictional revised title"

        head = commit(
            workspace.upstream,
            {path: derived_record("published_without_metrics", cve_id, retitle)},
            date=D_3,
        )
        _reset(harness)
        updated = await harness.run(kernel)

        assert updated.row.status == "success"
        assert updated.row.metrics == (1, 0, 1, 0)
        assert updated.row.cursor == {"sha": head, "committed_at": D_3}
        cve = await _cve(harness, cve_id)
        assert cve.title == "example: fictional revised title"
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert [call["ticket_id"] for call in harness.published.published(RESOLVE)] == [
            str(ticket.id)
        ]


# ---------------------------------------------------------------------------
# Rejection and revert
# ---------------------------------------------------------------------------


class TestRejection:
    async def test_move_to_rejected_ignores_new_ticket_then_revert_reopens(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        """The directory is authoritative: the moved file still says
        `PUBLISHED`. The delete of the old path is not in the delta."""
        cve_id = harness.world.new_cve_id()
        published = record_path("published", cve_id)
        rejected = record_path("rejected", cve_id)
        content = derived_record("published_without_metrics", cve_id)
        assert json.loads(content)["cveMetadata"]["state"] == "PUBLISHED"
        await _first_run(workspace, harness, kernel)
        commit(workspace.upstream, {published: content}, date=D_1)
        assert (await harness.run(kernel)).row.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.NEW

        head = commit(
            workspace.upstream, {published: None, rejected: content}, date=D_2
        )
        rejection = await harness.run(kernel)

        assert rejection.row.status == "success"
        assert rejection.row.metrics == (1, 0, 1, 0)
        assert rejection.row.cursor == {"sha": head, "committed_at": D_2}
        cve = await _cve(harness, cve_id)
        assert cve.cve_state == CveState.REJECTED
        # Rejected kernel records carry no rejection date.
        assert cve.date_rejected is None
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.IGNORED
        changes = [
            (event.user_id, event.old_value, event.new_value, event.comment)
            for event in await audit_events(harness.factory, ticket.id)
            if event.event_type == TicketAuditEventType.STATUS_CHANGE
        ]
        assert changes == [
            (None, TicketStatus.NEW, TicketStatus.IGNORED, REJECTED_COMMENT)
        ]
        sources = [
            row
            for row in await references(harness.factory, ticket.id)
            if row.type == ReferenceType.ADVISORY
        ]
        assert [row.url for row in sources] == [
            f"{VULNS_TREE}/{published}",
            f"{VULNS_TREE}/{rejected}",
        ]

        commit(workspace.upstream, {rejected: None, published: content}, date=D_3)
        revert = await harness.run(kernel)

        assert revert.row.status == "success"
        assert revert.row.metrics == (1, 0, 1, 0)
        cve = await _cve(harness, cve_id)
        assert cve.cve_state == CveState.PUBLISHED
        assert cve.date_rejected is None
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        # Reopened from `Ignored` to the `Analysis` floor; no package gate
        # holds, so the upward evaluation keeps it there.
        assert ticket.status == TicketStatus.ANALYSIS

    async def test_rejected_record_preserves_a_prior_date_until_republished(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        """A rejected kernel record omits `date_rejected`, preserving the
        one another source supplied; republication clears it."""
        cve = await harness.world.cve_in(
            state=CveState.REJECTED, date_rejected=PRIOR_REJECTION
        )
        rejected = record_path("rejected", cve.cve_id)
        published = record_path("published", cve.cve_id)
        content = derived_record("rejected_cvss_v3_1", cve.cve_id)
        await _first_run(workspace, harness, kernel)
        commit(workspace.upstream, {rejected: content}, date=D_1)

        rejection = await harness.run(kernel)

        assert rejection.row.status == "success"
        stored = await _cve(harness, cve.cve_id)
        assert stored.cve_state == CveState.REJECTED
        assert stored.date_rejected == PRIOR_REJECTION
        # The rejected orphan's new Ticket enters `Ignored` immediately.
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.IGNORED

        commit(workspace.upstream, {rejected: None, published: content}, date=D_2)
        revert = await harness.run(kernel)

        assert revert.row.status == "success"
        assert revert.row.metrics == (1, 0, 1, 0)
        stored = await _cve(harness, cve.cve_id)
        assert stored.cve_state == CveState.PUBLISHED
        assert stored.date_rejected is None


# ---------------------------------------------------------------------------
# Selection: deduplication, pre-scope exclusions, missing at HEAD
# ---------------------------------------------------------------------------


class TestSelection:
    async def test_both_directories_in_one_delta_are_one_rejected_unit(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
        git_calls: GitCalls,
    ) -> None:
        cve_id = harness.world.new_cve_id()
        published = record_path("published", cve_id)
        rejected = record_path("rejected", cve_id)
        content = derived_record("published_without_metrics", cve_id)
        await _first_run(workspace, harness, kernel)
        commit(workspace.upstream, {published: content, rejected: content}, date=D_1)
        _reset(harness, git_calls)

        result = await harness.run(kernel)

        # The losing published path is a pre-scope exclusion: never read,
        # never counted.
        assert _shown(git_calls) == [rejected]
        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        assert cve.cve_state == CveState.REJECTED
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.IGNORED
        assert [
            row.url
            for row in await references(harness.factory, ticket.id)
            if row.type == ReferenceType.ADVISORY
        ] == [f"{VULNS_TREE}/{rejected}"]

    async def test_pre_scope_exclusions_are_neither_read_nor_counted(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
        git_calls: GitCalls,
    ) -> None:
        cve_id = harness.world.new_cve_id()
        testing_id = harness.world.new_cve_id()
        mismatch_id = harness.world.new_cve_id()
        reserved_id = harness.world.new_cve_id()
        selected = record_path("published", cve_id)
        stem = selected.removesuffix(".json")
        siblings = (
            "",
            ".sha1",
            ".mbox",
            ".dyad",
            ".vulnerable",
            ".reference",
            ".cvss",
            ".message",
        )
        record = derived_record("published_without_metrics", cve_id)
        files: dict[str, bytes | None] = {
            selected: record,
            **{f"{stem}{suffix}": b"example\n" for suffix in siblings},
            f"cve/rejected/2099/{cve_id}.mbox.rejected": b"example\n",
            "cve/published/2099/.empty": b"",
            f"cve/testing/published/2099/{testing_id}.json": derived_record(
                "published_without_metrics", testing_id
            ),
            # A year directory differing from the CVE-ID year.
            f"cve/published/2098/{mismatch_id}.json": derived_record(
                "published_without_metrics", mismatch_id
            ),
            f"cve/reserved/2099/{reserved_id}": b"",
            f"cve/returned/2099/{reserved_id}": b"",
            "cve/review/proposed/v7.2.9-example": b"example\n",
            "cve/CVE_JSON_5.1.1_schema.json": b"{}",
            "cve/vulnerability.txt": b"example\n",
        }
        await _first_run(workspace, harness, kernel)
        commit(workspace.upstream, files, date=D_1)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(kernel)

        [delta] = [args for args, _ in git_calls.of("diff_names")]
        assert delta[0] == workspace.clone_path(kernel)
        assert _shown(git_calls) == [selected]
        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        assert await harness.cve_named(cve_id) is not None
        for excluded in (testing_id, mismatch_id, reserved_id):
            assert await harness.cve_named(excluded) is None
        assert _problems(logs) == []

    async def test_selected_path_missing_at_head_is_stale_success(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
        git_calls: GitCalls,
    ) -> None:
        """`show_file` is replaced to answer "absent" for the selected path:
        a real `--diff-filter=AM` delta never names a file absent at HEAD."""
        cve_id = harness.world.new_cve_id()
        path = record_path("published", cve_id)
        await _first_run(workspace, harness, kernel)
        head = commit(
            workspace.upstream,
            {path: derived_record("published_without_metrics", cve_id)},
            date=D_1,
        )
        git_calls.replacements["show_file"] = show_missing(path)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(kernel)

        assert _shown(git_calls) == [path]
        assert result.row.status == "success"
        assert result.row.metrics == (1, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_1}
        assert await harness.cve_named(cve_id) is None
        assert events_named(logs, DELTA_FILE_MISSING_AT_HEAD_EVENT) == [
            {
                "event": DELTA_FILE_MISSING_AT_HEAD_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "cve_id": cve_id,
            }
        ]
        assert "commit" not in harness.events
        assert harness.published.calls == []
        _bounded(logs, workspace)


# ---------------------------------------------------------------------------
# Per-item failures
# ---------------------------------------------------------------------------


def _state(value: str) -> Any:
    def edit(record: dict[str, Any]) -> None:
        record["cveMetadata"]["state"] = value

    return edit


def _nul_title(record: dict[str, Any]) -> None:
    cna(record)["title"] = "example: fictional\x00title"


def _nul_description(record: dict[str, Any]) -> None:
    cna(record)["descriptions"][0]["value"] = "Fictional description\x00 text."


def _failing_content(case: str, cve_id: str) -> bytes:
    """Record content whose mapping fails with the case's cause."""
    if case == "invalid-json":
        return b'{"cveMetadata": {"cveId": "' + cve_id.encode() + b'", '
    if case == "not-utf8":
        return b'{"title": "\xff\xfe"}'
    if case == "array-root":
        return b"[]"
    edits = {
        "unrecognized-state": _state("RESERVED"),
        "nul-state": _state("PUBLISHED\x00"),
        "nul-title": _nul_title,
        "nul-description": _nul_description,
    }
    return derived_record("published_without_metrics", cve_id, edits[case])


_FAILURES: Final = [
    ("invalid-json", "KernelRecordDecodeError"),
    ("not-utf8", "KernelRecordDecodeError"),
    ("array-root", "KernelRecordDecodeError"),
    ("unrecognized-state", "KernelRecordStateError"),
    ("nul-state", "KernelRecordStateError"),
    ("nul-title", "ValidationError"),
    ("nul-description", "ValidationError"),
]


class TestPerItemFailure:
    @pytest.mark.parametrize(
        ("case", "cause"), _FAILURES, ids=[case for case, _ in _FAILURES]
    )
    async def test_unmappable_record_is_an_isolated_failure(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
        case: str,
        cause: str,
    ) -> None:
        """An existing CVE: the failure rolls back every write, records the
        isolated `failure` status, logs one bounded WARNING, and counts one
        failure."""
        cve = await harness.world.cve_in()
        path = record_path("published", cve.cve_id)
        await _first_run(workspace, harness, kernel)
        commit(workspace.upstream, {path: _failing_content(case, cve.cve_id)}, date=D_1)
        _reset(harness)

        with capture_logs() as logs:
            result = await harness.run(kernel)

        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "fetcher_name": NAME,
                "cause": cause,
            }
        ]
        assert _problems(logs) == [CVE_FETCH_ITEM_FAILED_EVENT]
        # Rolled back, then the independent status write; never committed.
        assert [
            event
            for event in harness.events
            if event in ("rollback", "commit", "status:commit")
        ] == ["rollback", "status:commit"]
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 1)
        assert result.row.error_message == "All 1 items failed"
        assert result.row.cursor is None
        stored = await _cve(harness, cve.cve_id)
        assert stored.title is None
        assert stored.description is None
        assert stored.cve_state == CveState.PUBLISHED
        assert await ticket_of(harness.factory, cve.id) is None
        assert await assessments(harness.factory, cve.id) == []
        state = await source_state(harness.factory, cve.id, KERNEL)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert harness.published.calls == []
        _bounded(logs, workspace)

    async def test_failure_for_an_absent_cve_writes_nothing(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        cve_id = harness.world.new_cve_id()
        path = record_path("published", cve_id)
        await _first_run(workspace, harness, kernel)
        commit(
            workspace.upstream, {path: _failing_content("nul-title", cve_id)}, date=D_1
        )

        with capture_logs() as logs:
            result = await harness.run(kernel)

        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 1)
        assert [
            entry["cause"] for entry in events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == ["ValidationError"]
        # The isolated status write found no CVE row and wrote nothing.
        assert await harness.cve_named(cve_id) is None
        assert "status:commit" not in harness.events
        _bounded(logs, workspace)


# ---------------------------------------------------------------------------
# Run status and cursor
# ---------------------------------------------------------------------------


class TestStatusAndCursor:
    async def test_mixed_run_is_partial_and_advances_the_cursor(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        good = harness.world.new_cve_id()
        bad = await harness.world.cve_in()
        await _first_run(workspace, harness, kernel)
        head = commit(
            workspace.upstream,
            {
                record_path("published", good): derived_record(
                    "published_external_references", good
                ),
                record_path("published", bad.cve_id): _failing_content(
                    "nul-title", bad.cve_id
                ),
            },
            date=D_1,
        )

        with capture_logs() as logs:
            result = await harness.run(kernel)

        assert result.row.status == "partial"
        assert result.row.metrics == (1, 1, 0, 1)
        assert result.row.cursor == {"sha": head, "committed_at": D_1}
        assert (await _cve(harness, good)).cve_state == CveState.PUBLISHED
        bad_state = await source_state(harness.factory, bad.id, KERNEL)
        assert bad_state is not None
        assert bad_state.status == CVESourceFetchStatus.FAILURE
        assert [
            entry["cve_id"] for entry in events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [bad.cve_id]
        _bounded(logs, workspace, "advisory.example.invalid", "syzkaller")

    async def test_all_failed_run_keeps_the_previous_cursor(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        kernel: GitFetcherProbe,
    ) -> None:
        ids = [harness.world.new_cve_id(), harness.world.new_cve_id()]
        cursor = (await _first_run(workspace, harness, kernel)).row.cursor
        commit(
            workspace.upstream,
            {
                record_path("published", cve_id): _failing_content(
                    "unrecognized-state", cve_id
                )
                for cve_id in ids
            },
            date=D_1,
        )

        failed = await harness.run(kernel)

        assert failed.row.status == "failure"
        assert failed.row.metrics == (0, 0, 0, 2)
        assert failed.row.error_message == "All 2 items failed"
        assert failed.row.cursor is None
        for cve_id in ids:
            assert await harness.cve_named(cve_id) is None

        # The next run recomputes the same delta from the preserved cursor.
        head = commit(
            workspace.upstream,
            {
                record_path("published", cve_id): derived_record(
                    "published_without_metrics", cve_id
                )
                for cve_id in ids
            },
            date=D_2,
        )
        retried = await harness.run(kernel)

        assert retried.fetcher.previous_cursor == cursor
        assert retried.row.status == "success"
        assert retried.row.metrics == (2, 2, 0, 0)
        assert retried.row.cursor == {"sha": head, "committed_at": D_2}
