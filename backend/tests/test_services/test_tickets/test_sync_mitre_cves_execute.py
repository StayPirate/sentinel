"""The real `SyncMitreCves` through its inherited `BaseGitFetcher.execute()`
and the real `BaseFetcher.run()` (backend/app/services/tickets/
sync_mitre_cves.py).

Owning specifications:

- docs/features/tickets/cve-sync-mitre.md (Algorithm steps 1-3; CVE JSON 5.x
  Field Path Mapping: global fields and the `PUBLISHED` + `dateRejected`
  failure, CNA fields and the CNA defensive guard, ADP fields and the ADP
  defensive guard, CISA-ADP SSVC, KEV, and CWE, scoped affected-version
  operations and duplicate scopes, additive child retention; Caller WARNING
  fields; External String Admissibility; Error Handling; Work unit and
  metric mapping).
- docs/features/platform/git-fetcher-infrastructure.md (First-Run
  Detection; Template Method: `execute()` steps 8-11, Status
  Determination; Hook Methods; `process_item`).
- docs/features/platform/cve-fetcher-infrastructure.md (Automatic Reference
  Caller Contract; `CVEFetchResult`; Per-CVE Finalization; Batch Error
  Handling, the `cve_fetch_item_failed` event; First Run Behavior; Metric
  Definitions).
- docs/features/tickets/cvss-scoring.md (External Base Reduction).
- docs/features/tickets/cve-tracking.md (CVE Rejection Handling: Rejection
  handling, Rejection revert handling, the `PUBLISHED => date_rejected IS
  NULL` invariant).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, Concrete mappings for `sync_mitre_cves`; External String
  Admissibility; CVE Fetcher Infrastructure, Git boundaries; Tier 1 — Unit
  Tests, the hermetic Git rules).

Every repository is a real temporary one under `tmp_path`: a work-tree
upstream served through a `file://` URL (`SyncMitreCves.repo_url` is
substituted with it) and the fetcher's bare `cvelistV5` clone under the
redirected `GIT_CLONE_BASE_DIR`. No Git process inherits a `GIT_*` variable
or a user or system Git configuration. Upstream commits carry a fictional
author identity (`tests/support/mitre_fetcher.py`). Records are the
sanitized fixtures of `tests/support/mitre.py` at their real repository
paths, or fixtures re-keyed to fictional `CVE-2099-*` IDs. The
`git_operations` spy records every Git call; one case replaces `show_file`
to reach the missing-at-HEAD branch, which a real `--diff-filter=AM` delta
cannot produce.

Runs use the real database through `open_git_run_harness()`
(`tests/support/git_fetchers.py`): the run, execution, finalization, and
isolated status sessions over `real_session_factory`, the publication spy
over `task_publication.publish_task`, and teardown deleting every committed
`FetcherRun`, `FetcherConfig`, CVE, and Ticket row (CVE children,
`CVESource` rows, and references follow by `ON DELETE CASCADE`) and
asserting no CVE leaked. Before seeding, no committed run or configuration
of `sync_mitre_cves` may exist, because the cursor is read from every
committed run of that name.
"""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Final, NamedTuple

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
from app.services import reference_service
from app.services.base_cve_fetcher import CVE_FETCH_ITEM_FAILED_EVENT
from app.services.base_git_fetcher import DELTA_FILE_MISSING_AT_HEAD_EVENT
from app.services.tickets.sync_mitre_cves import SyncMitreCves
from tests.support.cve_catch_up import RESOLVE, source_state
from tests.support.git_fetcher_state import (
    AssessmentRow,
    ReferenceRow,
    assessments,
    audit_events,
    committed_fetcher_rows,
    references,
    ticket_of,
)
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
from tests.support.mitre import (
    CISA_ADP_ORG_ID,
    RECORD_SOURCES,
    load_raw_record,
    load_record,
)
from tests.support.mitre_fetcher import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    NAME,
    AffectedRow,
    KevRow,
    SsvcRow,
    adps,
    affected_versions,
    cna,
    commit,
    cwes,
    derived_record,
    kev,
    mitre_probe,
    record_path,
    ssvc,
)

pytestmark = pytest.mark.integration

MITRE: Final = CVESourceType.MITRE

D_BASE: Final = "2026-10-01T00:00:00+00:00"
D_1: Final = "2026-10-02T00:00:00+00:00"
D_2: Final = "2026-10-03T00:00:00+00:00"
D_3: Final = "2026-10-04T00:00:00+00:00"

SEED_FILES: Final = {
    "README.md": b"example: fictional README\n",
    "cves/delta.json": b'{"fetchTime": "2026-10-01T00:00:00.000Z"}\n',
    "cves/deltaLog.json": b"[]\n",
}
"""The base commit: no record file."""

CVE_ORG: Final = "https://cve.org/CVERecord?id="
CREATED_COMMENT: Final = "CVE ingested from MITRE"
REJECTED_COMMENT: Final = "CVE rejected"
PRIOR_REJECTION: Final = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
"""A `date_rejected` previously supplied by another source."""

VEEAM_CPE: Final = "cpe:2.3:a:veeam:one:*:*:*:*:*:*:*:*"
ORACLE_VECTOR: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
"""The CNA vector of `cisa_kev_cwe_tags`."""
KEV_CATALOG: Final = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve="
)
NON_BASE_VECTOR: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C"
BASE_VECTOR: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
"""The CNA vector of `cvelistv5_v3_1_non_base_en_us_kev` and its strict Base
reduction."""
ADP_ORG_ID: Final = "66666666-7777-4888-9999-aaaaaaaaaaaa"
NON_UUID_ORG_ID: Final = "Example-Org-Secret-Value"

RECORD_TEXTS: Final = (
    "fictional title",
    "fictional description",
    "Fictional description",
    "Fictional scenario",
    "Fictional rejection reason",
    "fictional revised title",
    NON_UUID_ORG_ID,
)
"""Fragments of every fixture title, description, scenario, and reason, and
the raw values the edits supply."""

Edit = Callable[[dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    created = install_git_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(SyncMitreCves, "repo_url", created.upstream.url)
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
    assert await committed_fetcher_rows(real_session_factory, NAME) == 0
    opened = await open_git_run_harness(
        monkeypatch, real_session_factory, db_session_factory
    )
    try:
        await opened.world.ensure_default_setting()
        yield opened
    finally:
        await opened.cleanup()


@pytest.fixture
async def mitre(harness: GitRunHarness) -> GitFetcherProbe:
    """The production class with its committed, enabled `FetcherConfig`."""
    probe = mitre_probe(harness.events)
    await harness.register(probe)
    return probe


async def _first_run(
    workspace: GitWorkspace, harness: GitRunHarness, mitre: GitFetcherProbe
) -> RunResult:
    """Commit the base files and record HEAD with a first run."""
    head = commit(workspace.upstream, SEED_FILES, date=D_BASE)
    result = await harness.run(mitre)
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


async def _ingest(
    workspace: GitWorkspace,
    harness: GitRunHarness,
    mitre: GitFetcherProbe,
    fixture: str,
    edit: Edit | None = None,
) -> tuple[str, RunResult, list[Any]]:
    """After a first run, commit one fixture re-keyed to a fresh fictional
    CVE-ID and run once under log capture: (CVE-ID, result, logs)."""
    cve_id = harness.world.new_cve_id()
    await _first_run(workspace, harness, mitre)
    commit(
        workspace.upstream,
        {record_path(cve_id): derived_record(fixture, cve_id, edit)},
        date=D_1,
    )
    _reset(harness)
    with capture_logs() as logs:
        result = await harness.run(mitre)
    return cve_id, result, logs


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
        "github.com",
        "CVEProject",
        "cves/",
        ".json",
        *more,
    )


def _problems(logs: list[Any]) -> list[str]:
    return [
        entry["event"]
        for entry in logs
        if entry.get("log_level") in ("warning", "error", "critical")
    ]


def _cisa(record: dict[str, Any]) -> dict[str, Any]:
    [cisa] = [
        adp
        for adp in adps(record)
        if adp["providerMetadata"].get("orgId") == CISA_ADP_ORG_ID
    ]
    return cisa


def _ssvc_content(record: dict[str, Any]) -> dict[str, Any]:
    [content] = [
        metric["other"]["content"]
        for metric in _cisa(record)["metrics"]
        if metric.get("other", {}).get("type") == "ssvc"
    ]
    assert isinstance(content, dict)
    return content


class Children(NamedTuple):
    """The committed CVSS, CWE, SSVC, and KEV rows of one CVE."""

    assessments: list[AssessmentRow]
    cwes: list[tuple[str, str]]
    ssvc: list[SsvcRow]
    kev: list[KevRow]


async def _children(harness: GitRunHarness, cve: CVE) -> Children:
    return Children(
        await assessments(harness.factory, cve.id),
        await cwes(harness.factory, cve.id),
        await ssvc(harness.factory, cve.id),
        await kev(harness.factory, cve.id),
    )


# ---------------------------------------------------------------------------
# First run
# ---------------------------------------------------------------------------


class TestFirstRun:
    async def test_first_run_clones_records_head_and_processes_no_record(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
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
            result = await harness.run(mitre)

        assert type(result.fetcher) is SyncMitreCves
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
                (workspace.upstream.url, workspace.clone_base / "cvelistV5"),
                {"filter_spec": None, "single_branch": True},
            )
        ]
        assert is_bare_clone(workspace.clone_path(mitre))
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
        mitre: GitFetcherProbe,
    ) -> None:
        """`cisa_adp_affected`: a CNA `cvssV3_0` vector and `affected`, and
        a CISA-ADP container with SSVC, a CWE, and its own `affected`."""
        name = "cisa_adp_affected"
        path = RECORD_SOURCES[name]
        cve_id = Path(path).stem
        await _claim(harness, cve_id)
        await _first_run(workspace, harness, mitre)
        head = commit(workspace.upstream, {path: load_raw_record(name)}, date=D_1)
        _reset(harness)

        with capture_logs() as logs:
            result = await harness.run(mitre)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_1}
        cve = await _cve(harness, cve_id)
        fixture = cna(load_record(name))
        assert cve.cve_state == CveState.PUBLISHED
        assert cve.title is None
        assert cve.description == fixture["descriptions"][0]["value"]
        assert cve.published_date == datetime(2024, 9, 7, 16, 11, 22, 220000, UTC)
        assert cve.modified_date == datetime(2024, 9, 9, 14, 15, 21, 746000, UTC)
        assert cve.date_rejected is None
        state = await source_state(harness.factory, cve.id, MITRE)
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
        assert stored == [
            ReferenceRow(
                url=f"{CVE_ORG}{cve_id}",
                title="MITRE",
                type=ReferenceType.ADVISORY,
                source=NAME,
            ),
            ReferenceRow(
                url="https://www.veeam.com/kb4649",
                title=None,
                type=stored[1].type,
                source=NAME,
            ),
        ]

        assert await _children(harness, cve) == Children(
            assessments=[
                AssessmentRow(
                    "hackerone", "3.0", "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H"
                )
            ],
            cwes=[("CWE-284", "adp:CISA-ADP")],
            ssvc=[
                SsvcRow(
                    "none",
                    "no",
                    "total",
                    "2.0.3",
                    datetime(2024, 9, 9, 14, 12, 31, 245292, UTC),
                )
            ],
            kev=[],
        )
        assert await affected_versions(harness.factory, cve.id) == [
            AffectedRow(
                "adp:CISA-ADP",
                "veeam",
                "one",
                "12",
                "semver",
                "12.1.0.3208",
                True,
                VEEAM_CPE,
                "affected",
                "unaffected",
            ),
            AffectedRow(
                "cna",
                "Veeam",
                "One",
                "12.1",
                "semver",
                "12.1",
                True,
                None,
                "affected",
                "unaffected",
            ),
        ]
        # The package-candidate handoff of both affected-version scopes.
        assert harness.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [],
                "affected_cpes": [VEEAM_CPE],
                "vendor_products": [["Veeam", "One"], ["veeam", "one"]],
                "resolved_packages": [],
            }
        ]
        # The finalizer flushes, commits, drains, then hands off.
        events = harness.events
        assert events.count("commit") == 1
        assert events.index("commit") < events.index("drain")
        assert events.index("drain") < events.index(f"publish:{RESOLVE}")
        assert harness.status.opened == []
        assert _problems(logs) == []
        _bounded(logs, workspace)

    @pytest.mark.parametrize(
        ("fixture", "children", "urls"),
        [
            (
                "cvelistv5_kev_ssvc_offset_n_a",
                Children(
                    assessments=[
                        AssessmentRow(
                            "adp:CISA-ADP",
                            "3.1",
                            "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
                        )
                    ],
                    cwes=[("CWE-119", "adp:CISA-ADP")],
                    ssvc=[
                        SsvcRow(
                            "active",
                            "no",
                            "total",
                            "2.0.3",
                            datetime(2022, 3, 14, tzinfo=UTC),
                        )
                    ],
                    kev=[KevRow(date(2022, 3, 15), f"{KEV_CATALOG}CVE-2015-2546")],
                ),
                # Stored normalized: the `http` scheme becomes `https`.
                [
                    "https://www.securitytracker.com/id/1033485",
                    "https://docs.microsoft.com/en-us/security-updates/"
                    "securitybulletins/2015/ms15-097",
                    "https://www.securityfocus.com/bid/76608",
                ],
            ),
            (
                "cna_suse_reserved_provider",
                Children(
                    # The reserved CNA provider `suse` contributes no CVSS.
                    assessments=[],
                    cwes=[("CWE-276", "cna:suse")],
                    ssvc=[
                        SsvcRow(
                            "none",
                            "no",
                            "total",
                            "2.0.3",
                            datetime(2025, 3, 18, 19, 24, 52, 978311, UTC),
                        )
                    ],
                    kev=[],
                ),
                ["https://bugzilla.suse.com/show_bug.cgi?id=1205990"],
            ),
        ],
        ids=["cisa-adp-cvss-ssvc-kev-cwe", "reserved-cna-provider"],
    )
    async def test_cisa_adp_and_cna_children_are_persisted(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        fixture: str,
        children: Children,
        urls: list[str],
    ) -> None:
        cve_id, result, logs = await _ingest(workspace, harness, mitre, fixture)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        assert await _children(harness, cve) == children
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        stored = await references(harness.factory, ticket.id)
        # The source reference first, then the CNA references in array
        # order; ADP references are not candidates.
        assert [row.url for row in stored] == [f"{CVE_ORG}{cve_id}", *urls]
        assert {row.source for row in stored} == {NAME}
        assert _problems(logs) == []
        _bounded(logs, workspace)

    async def test_non_base_vector_is_persisted_as_the_strict_base_vector(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        """External Base Reduction: the fixture's Temporal metrics are
        reduced away before persistence."""
        fixture = "cvelistv5_v3_1_non_base_en_us_kev"
        [metric] = cna(load_record(fixture))["metrics"]
        assert metric["cvssV3_1"]["vectorString"] == NON_BASE_VECTOR

        cve_id, result, _ = await _ingest(workspace, harness, mitre, fixture)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        assert await assessments(harness.factory, cve.id) == [
            AssessmentRow("microsoft", "3.1", BASE_VECTOR)
        ]

    async def test_later_record_without_enrichment_retains_the_children(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        """Additive child retention: CVSS, SSVC, and KEV omitted by a later
        record are retained, never deleted; nothing else changed, so the
        unit is `unchanged`."""
        fixture = "cvelistv5_kev_ssvc_offset_n_a"
        cve_id, created, _ = await _ingest(workspace, harness, mitre, fixture)
        assert created.row.metrics == (1, 1, 0, 0)
        before = await _children(harness, await _cve(harness, cve_id))
        assert before.assessments
        assert before.ssvc
        assert before.kev

        def without_metrics(record: dict[str, Any]) -> None:
            del _cisa(record)["metrics"]

        head = commit(
            workspace.upstream,
            {record_path(cve_id): derived_record(fixture, cve_id, without_metrics)},
            date=D_2,
        )

        result = await harness.run(mitre)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 0, 0, 0)
        assert result.row.cursor == {"sha": head, "committed_at": D_2}
        assert await _children(harness, await _cve(harness, cve_id)) == before

    async def test_reformatted_record_is_unchanged_and_edited_record_is_updated(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        fixture = "cisa_kev_cwe_tags"
        cve_id = harness.world.new_cve_id()
        path = record_path(cve_id)
        original = derived_record(fixture, cve_id)
        await _first_run(workspace, harness, mitre)
        commit(workspace.upstream, {path: original}, date=D_1)
        assert (await harness.run(mitre)).row.metrics == (1, 1, 0, 0)

        # A formatting-only modification: selected again, no CVE effect.
        reformatted = json.dumps(json.loads(original), indent=4).encode()
        commit(workspace.upstream, {path: reformatted}, date=D_2)
        _reset(harness)
        unchanged = await harness.run(mitre)

        assert unchanged.row.status == "success"
        assert unchanged.row.metrics == (1, 0, 0, 0)

        def retitle(record: dict[str, Any]) -> None:
            cna(record)["title"] = "example: fictional revised title"

        head = commit(
            workspace.upstream,
            {path: derived_record(fixture, cve_id, retitle)},
            date=D_3,
        )
        _reset(harness)
        updated = await harness.run(mitre)

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
    async def test_rejected_record_ignores_new_ticket_then_republication_reopens(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        """`cveMetadata.state` is authoritative; the record stays at its
        one path."""
        cve_id = harness.world.new_cve_id()
        path = record_path(cve_id)
        published = derived_record("cisa_kev_cwe_tags", cve_id)
        await _first_run(workspace, harness, mitre)
        commit(workspace.upstream, {path: published}, date=D_1)
        assert (await harness.run(mitre)).row.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.NEW

        head = commit(
            workspace.upstream,
            {path: derived_record("cvelistv5_5_2_rejected", cve_id)},
            date=D_2,
        )
        rejection = await harness.run(mitre)

        assert rejection.row.status == "success"
        assert rejection.row.metrics == (1, 0, 1, 0)
        assert rejection.row.cursor == {"sha": head, "committed_at": D_2}
        cve = await _cve(harness, cve_id)
        assert cve.cve_state == CveState.REJECTED
        assert cve.date_rejected == datetime(2026, 4, 22, 14, 12, 14, 465000, UTC)
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

        commit(workspace.upstream, {path: published}, date=D_3)
        revert = await harness.run(mitre)

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

    async def test_rejected_record_without_date_preserves_a_prior_date(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        """A REJECTED record without `dateRejected` omits the date,
        preserving the one another source supplied; the rejected orphan's
        new Ticket enters `Ignored` immediately."""
        cve = await harness.world.cve_in(
            state=CveState.REJECTED, date_rejected=PRIOR_REJECTION
        )
        await _first_run(workspace, harness, mitre)
        commit(
            workspace.upstream,
            {
                record_path(cve.cve_id): derived_record(
                    "cvelistv5_5_1_rejected_without_date_rejected", cve.cve_id
                )
            },
            date=D_1,
        )

        rejection = await harness.run(mitre)

        assert rejection.row.status == "success"
        stored = await _cve(harness, cve.cve_id)
        assert stored.cve_state == CveState.REJECTED
        assert stored.date_rejected == PRIOR_REJECTION
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert ticket.status == TicketStatus.IGNORED


# ---------------------------------------------------------------------------
# Selection: pre-scope exclusions, missing at HEAD
# ---------------------------------------------------------------------------


class TestSelection:
    async def test_pre_scope_exclusions_are_neither_read_nor_counted(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        git_calls: GitCalls,
    ) -> None:
        cve_id = harness.world.new_cve_id()
        unbucketed_id = harness.world.new_cve_id()
        outside_id = harness.world.new_cve_id()
        selected = record_path(cve_id)
        year = cve_id.split("-")[1]
        files: dict[str, bytes | None] = {
            selected: derived_record("cisa_kev_cwe_tags", cve_id),
            # The automation metadata files change in every upstream commit.
            "cves/delta.json": b'{"fetchTime": "2026-10-02T00:00:00.000Z"}\n',
            "cves/deltaLog.json": b'[{"fetchTime": "2026-10-02T00:00:00.000Z"}]\n',
            f"{selected}.orig": b"example\n",
            # A record without the `NNNxxx` bucket directory.
            f"cves/{year}/{unbucketed_id}.json": derived_record(
                "cisa_kev_cwe_tags", unbucketed_id
            ),
            # A record outside `cves/`.
            f"review/{year}/0xxx/{outside_id}.json": derived_record(
                "cisa_kev_cwe_tags", outside_id
            ),
            "README.md": b"example: fictional revised README\n",
            ".github/workflows/baseline.yml": b"name: example\n",
        }
        await _first_run(workspace, harness, mitre)
        commit(workspace.upstream, files, date=D_1)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(mitre)

        [delta] = [args for args, _ in git_calls.of("diff_names")]
        assert delta[0] == workspace.clone_path(mitre)
        assert _shown(git_calls) == [selected]
        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        assert await harness.cve_named(cve_id) is not None
        for excluded in (unbucketed_id, outside_id):
            assert await harness.cve_named(excluded) is None
        assert _problems(logs) == []

    async def test_selected_path_missing_at_head_is_stale_success(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        git_calls: GitCalls,
    ) -> None:
        """`show_file` is replaced to answer "absent" for the selected path:
        a real `--diff-filter=AM` delta never names a file absent at HEAD."""
        cve_id = harness.world.new_cve_id()
        path = record_path(cve_id)
        await _first_run(workspace, harness, mitre)
        head = commit(
            workspace.upstream,
            {path: derived_record("cisa_kev_cwe_tags", cve_id)},
            date=D_1,
        )
        git_calls.replacements["show_file"] = show_missing(path)
        _reset(harness, git_calls)

        with capture_logs() as logs:
            result = await harness.run(mitre)

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
# Caller WARNINGs and External String Admissibility of entry values
# ---------------------------------------------------------------------------


def _malformed_adps(record: dict[str, Any]) -> None:
    """Two ADP entries the ADP defensive guard skips: a UUID-shaped `orgId`
    without `shortName`, and a non-UUID `orgId` with an empty one."""
    adps(record).extend(
        [
            {"providerMetadata": {"orgId": ADP_ORG_ID}, "affected": []},
            {"providerMetadata": {"orgId": NON_UUID_ORG_ID, "shortName": ""}},
        ]
    )


def _incomplete_ssvc(record: dict[str, Any]) -> None:
    del _ssvc_content(record)["version"]


class TestCallerWarnings:
    async def test_cna_guard_warns_and_keeps_the_other_cna_data(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        name = "cna_short_name_missing"
        fixture = load_record(name)
        container = cna(fixture)

        cve_id, result, logs = await _ingest(workspace, harness, mitre, name)

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        assert events_named(logs, "mitre_cna_provider_skipped") == [
            {
                "event": "mitre_cna_provider_skipped",
                "log_level": "warning",
                "cve_id": cve_id,
                "fetcher_name": NAME,
                "reason": "cna_short_name_missing",
                "org_id": container["providerMetadata"]["orgId"],
            }
        ]
        assert _problems(logs) == ["mitre_cna_provider_skipped"]
        cve = await _cve(harness, cve_id)
        assert cve.title == container["title"]
        assert cve.description == container["descriptions"][0]["value"]
        # No CNA CVSS or CWE without the CNA short name; the CISA-ADP SSVC
        # and the CNA affected versions are unaffected.
        assert await assessments(harness.factory, cve.id) == []
        assert await cwes(harness.factory, cve.id) == []
        assert len(await ssvc(harness.factory, cve.id)) == 1
        assert [
            (row.source_container, row.product, row.version)
            for row in await affected_versions(harness.factory, cve.id)
        ] == [("cna", "OpenHarmony", "3.0.0"), ("cna", "OpenHarmony", "3.1.0")]
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert [row.url for row in await references(harness.factory, ticket.id)] == [
            f"{CVE_ORG}{cve_id}",
            container["references"][0]["url"],
        ]
        _bounded(logs, workspace)

    async def test_adp_guard_and_ssvc_skip_warn_and_keep_the_other_data(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        def edit(record: dict[str, Any]) -> None:
            _malformed_adps(record)
            _incomplete_ssvc(record)

        cve_id, result, logs = await _ingest(
            workspace, harness, mitre, "cisa_kev_cwe_tags", edit
        )

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        common = {"log_level": "warning", "cve_id": cve_id, "fetcher_name": NAME}
        assert events_named(logs, "mitre_adp_entry_skipped") == [
            {"event": "mitre_adp_entry_skipped", **common, "org_id": ADP_ORG_ID},
            {"event": "mitre_adp_entry_skipped", **common},
        ]
        assert events_named(logs, "mitre_ssvc_assessment_skipped") == [
            {
                "event": "mitre_ssvc_assessment_skipped",
                **common,
                "reason": "incomplete",
                "missing_fields": ["version"],
            }
        ]
        assert _problems(logs) == [
            "mitre_adp_entry_skipped",
            "mitre_adp_entry_skipped",
            "mitre_ssvc_assessment_skipped",
        ]
        # Only the SSVC is omitted; the KEV and the CNA CVSS persist.
        cve = await _cve(harness, cve_id)
        assert await _children(harness, cve) == Children(
            assessments=[AssessmentRow("oracle", "3.1", ORACLE_VECTOR)],
            cwes=[],
            ssvc=[],
            kev=[KevRow(date(2026, 6, 1), f"{KEV_CATALOG}CVE-2024-21182")],
        )
        _bounded(logs, workspace)

    async def test_nul_in_entry_values_skips_only_those_entries(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        """External String Admissibility: U+0000 in the CNA `shortName`
        skips the CNA CVSS candidate (`invalid_provider`) and its CWE
        source; in a reference URL, the candidate (`control_character`); in
        an `affected[]` value, only that entry. No database error, and the
        rest of the record is ingested."""

        def edit(record: dict[str, Any]) -> None:
            container = cna(record)
            container["providerMetadata"]["shortName"] = "oracle\x00"
            container["problemTypes"][0]["descriptions"][0]["cweId"] = "CWE-200"
            container["references"].append(
                {"url": "https://advisory.example.invalid/upstream/1\x00"}
            )
            container["affected"].append(
                {
                    "vendor": "Example Vendor",
                    "product": "Example\x00Product",
                    "versions": [{"version": "1.0", "status": "affected"}],
                }
            )

        cve_id, result, logs = await _ingest(
            workspace, harness, mitre, "cisa_kev_cwe_tags", edit
        )

        assert result.row.status == "success"
        assert result.row.metrics == (1, 1, 0, 0)
        assert [
            (entry["event"], entry["reason"])
            for entry in logs
            if entry.get("log_level") in ("warning", "error", "critical")
        ] == [
            ("cve_cvss_candidate_skipped", "invalid_provider"),
            ("automatic_reference_rejected", "control_character"),
        ]
        cve = await _cve(harness, cve_id)
        assert await assessments(harness.factory, cve.id) == []
        assert await cwes(harness.factory, cve.id) == []
        assert len(await ssvc(harness.factory, cve.id)) == 1
        assert len(await kev(harness.factory, cve.id)) == 1
        assert {
            (row.vendor, row.product)
            for row in await affected_versions(harness.factory, cve.id)
        } == {("Oracle Corporation", "WebLogic Server")}
        ticket = await ticket_of(harness.factory, cve.id)
        assert ticket is not None
        assert [row.url for row in await references(harness.factory, ticket.id)] == [
            f"{CVE_ORG}{cve_id}",
            "https://www.oracle.com/security-alerts/cpujul2024.html",
        ]
        _bounded(logs, workspace, "oracle\\x00", "Example\\x00Product")


# ---------------------------------------------------------------------------
# Per-item failures
# ---------------------------------------------------------------------------


def _set_state(value: str) -> Edit:
    def edit(record: dict[str, Any]) -> None:
        record["cveMetadata"]["state"] = value

    return edit


def _published_with_rejection_date(record: dict[str, Any]) -> None:
    record["cveMetadata"]["dateRejected"] = "2026-09-20T10:00:00.000Z"


def _conflicting_cisa(record: dict[str, Any]) -> None:
    """A second CISA-ADP container whose KEV differs from the first."""
    duplicate = copy.deepcopy(_cisa(record))
    for metric in duplicate["metrics"]:
        if metric["other"]["type"] == "kev":
            metric["other"]["content"]["dateAdded"] = "2026-06-02"
    adps(record).append(duplicate)


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
    edits: dict[str, Edit] = {
        "unrecognized-state": _set_state("RESERVED"),
        "nul-state": _set_state("PUBLISHED\x00"),
        "published-with-date-rejected": _published_with_rejection_date,
        "conflicting-adp": _conflicting_cisa,
        "nul-title": _nul_title,
        "nul-description": _nul_description,
    }
    return derived_record("cisa_kev_cwe_tags", cve_id, edits[case])


_FAILURES: Final = [
    ("invalid-json", "MitreRecordDecodeError"),
    ("not-utf8", "MitreRecordDecodeError"),
    ("array-root", "MitreRecordDecodeError"),
    ("unrecognized-state", "MitreRecordStateError"),
    ("nul-state", "MitreRecordStateError"),
    ("published-with-date-rejected", "MitreRecordRejectionDateError"),
    ("conflicting-adp", "MitreRecordConflictError"),
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
        mitre: GitFetcherProbe,
        case: str,
        cause: str,
    ) -> None:
        """An existing CVE: the failure rolls back every write, records the
        isolated `failure` status, logs one bounded WARNING, and counts one
        failure."""
        cve = await harness.world.cve_in()
        path = record_path(cve.cve_id)
        await _first_run(workspace, harness, mitre)
        commit(workspace.upstream, {path: _failing_content(case, cve.cve_id)}, date=D_1)
        _reset(harness)

        with capture_logs() as logs:
            result = await harness.run(mitre)

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
        assert stored.published_date is None
        assert stored.cve_state == CveState.PUBLISHED
        assert await ticket_of(harness.factory, cve.id) is None
        assert await assessments(harness.factory, cve.id) == []
        assert await kev(harness.factory, cve.id) == []
        assert await affected_versions(harness.factory, cve.id) == []
        state = await source_state(harness.factory, cve.id, MITRE)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert harness.published.calls == []
        _bounded(logs, workspace)

    async def test_reference_failure_rolls_back_the_whole_cve_transaction(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Algorithm step 2: the reference write is part of the per-CVE
        transaction, so its failure after `upsert_cve()` rolls back the CVE,
        Ticket, and child writes and is one isolated per-item failure."""
        cve = await harness.world.cve_in()
        await _first_run(workspace, harness, mitre)
        commit(
            workspace.upstream,
            {
                record_path(cve.cve_id): derived_record(
                    "cvelistv5_kev_ssvc_offset_n_a", cve.cve_id
                )
            },
            date=D_1,
        )
        _reset(harness)
        calls: list[str] = []

        async def failing_upsert_references(*args: Any, **kwargs: Any) -> None:
            calls.append(args[2])
            raise RuntimeError("example: fictional reference write failure")

        monkeypatch.setattr(
            reference_service, "upsert_references", failing_upsert_references
        )

        with capture_logs() as logs:
            result = await harness.run(mitre)

        assert calls == [cve.cve_id]
        assert events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "fetcher_name": NAME,
                "cause": "RuntimeError",
            }
        ]
        assert [
            event
            for event in harness.events
            if event in ("rollback", "commit", "status:commit")
        ] == ["rollback", "status:commit"]
        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 1)
        assert result.row.cursor is None
        stored = await _cve(harness, cve.cve_id)
        assert stored.description is None
        assert await ticket_of(harness.factory, cve.id) is None
        assert await _children(harness, cve) == Children([], [], [], [])
        state = await source_state(harness.factory, cve.id, MITRE)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert harness.published.calls == []
        _bounded(logs, workspace, "fictional reference write failure")

    @pytest.mark.parametrize("case", ["nul-title", "nul-description", "array-root"])
    async def test_failure_for_an_absent_cve_writes_nothing(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        case: str,
    ) -> None:
        cve_id = harness.world.new_cve_id()
        await _first_run(workspace, harness, mitre)
        commit(
            workspace.upstream,
            {record_path(cve_id): _failing_content(case, cve_id)},
            date=D_1,
        )

        with capture_logs() as logs:
            result = await harness.run(mitre)

        assert result.row.status == "failure"
        assert result.row.metrics == (0, 0, 0, 1)
        assert [
            entry["cve_id"] for entry in events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [cve_id]
        assert _problems(logs) == [CVE_FETCH_ITEM_FAILED_EVENT]
        # The isolated status write found no CVE row and wrote nothing.
        assert await harness.cve_named(cve_id) is None
        assert "status:commit" not in harness.events
        _bounded(logs, workspace)

    async def test_warnings_precede_a_failure_of_the_same_record(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The caller WARNINGs describe the upstream record, so a later
        write failure does not suppress them."""

        async def failing_upsert_references(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("example: fictional reference write failure")

        monkeypatch.setattr(
            reference_service, "upsert_references", failing_upsert_references
        )

        cve_id, result, logs = await _ingest(
            workspace, harness, mitre, "cna_short_name_missing"
        )

        assert result.row.metrics == (0, 0, 0, 1)
        assert _problems(logs) == [
            "mitre_cna_provider_skipped",
            CVE_FETCH_ITEM_FAILED_EVENT,
        ]
        assert await harness.cve_named(cve_id) is None
        _bounded(logs, workspace, "fictional reference write failure")


# ---------------------------------------------------------------------------
# Run status and cursor
# ---------------------------------------------------------------------------


class TestStatusAndCursor:
    async def test_mixed_run_is_partial_and_advances_the_cursor(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        good = harness.world.new_cve_id()
        bad = await harness.world.cve_in()
        await _first_run(workspace, harness, mitre)
        head = commit(
            workspace.upstream,
            {
                record_path(good): derived_record("references_x_tags", good),
                record_path(bad.cve_id): _failing_content(
                    "published-with-date-rejected", bad.cve_id
                ),
            },
            date=D_1,
        )

        with capture_logs() as logs:
            result = await harness.run(mitre)

        assert result.row.status == "partial"
        assert result.row.metrics == (1, 1, 0, 1)
        assert result.row.cursor == {"sha": head, "committed_at": D_1}
        assert (await _cve(harness, good)).cve_state == CveState.PUBLISHED
        bad_state = await source_state(harness.factory, bad.id, MITRE)
        assert bad_state is not None
        assert bad_state.status == CVESourceFetchStatus.FAILURE
        assert [
            entry["cve_id"] for entry in events_named(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [bad.cve_id]
        _bounded(logs, workspace)

    async def test_all_failed_run_keeps_the_previous_cursor(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        ids = [harness.world.new_cve_id(), harness.world.new_cve_id()]
        cursor = (await _first_run(workspace, harness, mitre)).row.cursor
        commit(
            workspace.upstream,
            {
                record_path(cve_id): _failing_content("unrecognized-state", cve_id)
                for cve_id in ids
            },
            date=D_1,
        )

        failed = await harness.run(mitre)

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
                record_path(cve_id): derived_record("cisa_kev_cwe_tags", cve_id)
                for cve_id in ids
            },
            date=D_2,
        )
        retried = await harness.run(mitre)

        assert retried.fetcher.previous_cursor == cursor
        assert retried.row.status == "success"
        assert retried.row.metrics == (2, 2, 0, 0)
        assert retried.row.cursor == {"sha": head, "committed_at": D_2}
