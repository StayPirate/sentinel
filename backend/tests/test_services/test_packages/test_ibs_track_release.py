"""Tests for the IBS track release reconciliation boundary
(backend/app/services/packages/ibs_track_release.py): candidate selection
and the boundary body's evidence, source-info, diff, fallback, audit, and
log outcomes.

Owning specifications:

- docs/features/packages/ibs-track-release-detection.md (Scope;
  Authoritative IBS Evidence; Track Release Checkpoint; Shared
  Reconciliation Boundary (duplicate IDs once, empty collection without
  IBS or database work, source-info and diff reuse, partitioning with
  every package requested exactly once); Scheduled Reconciliation
  Algorithm steps 1-8 with Source-Info Validation, Source-Diff Validation,
  and Per-Track Local Outcome; First Observation and VA Correction;
  Unavailable History Fallback; Error Handling and its Structured Logs;
  Audit and Transaction Guarantees; Testing Requirements).
- docs/features/integrations/ibs-integration.md (Unavailable Old
  Revision; Service Layer > IBSClient escaping outcomes).
- docs/features/packages/package-service.md (`set_track_status()`
  Track-release composition; Excluded and Non-Actionable Records;
  Architectural Test Requirement: Track release composition, Forward
  transitions, Dimension independence (track part), and the system rows of
  the Affectedness authority matrix).
- docs/features/tickets/tickets.md (Gate: Analyzed -> Resolved).
- docs/features/platform/testing-strategy.md (Audit Trail Testing);
  docs/features/platform/audit-trail-infrastructure.md (Atomicity;
  Idempotent No-ops).

Races, failure conversion, the commit, the per-outcome hook, and the
Ticket convergence drain are covered by `test_ibs_track_release_races.py`.

Selection tests run on the rolled back `db_session`; every boundary test
commits through its own unit sessions, so it seeds a `TrackWorld` whose
rows are deleted explicitly at teardown. The boundary's module-level
`async_session_factory` is replaced by `TrackUnitSessions` over
`real_session_factory`, `task_publication.publish_task` by a recorder,
and every `IBSClient` is a real client of the fake IBS API (`FakeIBS`
over `IBSServer`), so no test reaches a broker or the network. The
package service's evaluation date is pinned to `EVAL`. Unless a test
states otherwise, a Ticket is an `Analysis` Ticket with its own CVE and
every track is an `ANALYSIS`/`PENDING` IBS track of `PROJECT`, and source
info serves `CURRENT`. Expected values are transcribed from the
specifications.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import DeliveryStatus, PackageStatus, TicketStatus, WorkflowType
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, task_publication
from app.services.packages.ibs_track_release import (
    SOURCE_INFO_PARTITION_SIZE,
    TrackReleaseCandidate,
    load_track_release_candidates,
)
from tests.support.ibs_api import (
    chunked_response,
    load_fixture,
    status_response,
    xml_response,
)
from tests.support.ibs_keys import fictional_settings_value
from tests.support.ibs_product_release import Publish
from tests.support.ibs_track_release import (
    CHECKPOINT,
    CURRENT,
    DIFF_FAILED,
    HISTORY_UNAVAILABLE,
    LINK_SRCMD5,
    OTHER_CVE,
    OTHER_PROJECT,
    PACKAGE,
    PACKAGE_SOURCE_INVALID,
    PROJECT,
    SEEN_AT,
    SIBLING_PACKAGE,
    SOURCE_INFO_FAILED,
    TRACK_FAILED,
    FakeIBS,
    Outcomes,
    Seed,
    Track,
    TrackUnitSessions,
    TrackWorld,
    checkpoint_of,
    checkpoint_srcmd5,
    checksum,
    diff_failed,
    events_of,
    history_unavailable,
    install_ibs,
    install_units,
    issue,
    issue_ignored,
    kinds,
    logged,
    own,
    package_source_invalid,
    raising,
    reconcile,
    source_entry,
    source_info_failed,
    ticket_status,
    track_failed,
    track_row,
    track_status,
    unavailable,
)
from tests.support.ticket_mutations import (
    BEFORE_EVAL,
    EVAL,
    RELEASED_AT,
    StatementRecorder,
    status_event,
)
from tests.support.track_status import Spy

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

MARKER: Final = "fictional-private-marker"
"""Fictional upstream text that must never reach a log."""

OLDER: Final = checksum("fictional-older")
"""A second, different persisted checkpoint."""


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the package service's one UTC evaluation date to `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    """Substitute the broker publication call: no test reaches a broker."""
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture(autouse=True)
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> TrackUnitSessions:
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture(autouse=True)
def ibs(monkeypatch: pytest.MonkeyPatch) -> FakeIBS:
    return install_ibs(monkeypatch)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[TrackWorld]:
    created = TrackWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


async def _selected(db: AsyncSession, *tracks: Track) -> list[TrackReleaseCandidate]:
    """The unrestricted selection limited to the given tracks (the shared
    test database may hold other tests' committed rows)."""
    ids = {track.id for track in tracks}
    return [c for c in await load_track_release_candidates(db) if c.track_id in ids]


def _ids(candidates: list[TrackReleaseCandidate]) -> list[uuid.UUID]:
    return [candidate.track_id for candidate in candidates]


async def _seeded(world: TrackWorld, count: int = 1, **kwargs: Any) -> list[Track]:
    """`count` committed tracks, each below its own Ticket, in track-ID
    order."""
    seed = Seed(world.session, world)
    created = []
    for _ in range(count):
        created.append(await seed.track(await seed.ticket(), **kwargs))
    await seed.commit()
    return sorted(created, key=lambda track: track.id)


def _cve(track: Track) -> str:
    assert track.cve_id is not None
    return track.cve_id


def _sorted_logs(entries: list[Any]) -> list[Any]:
    """`entries` in a content order independent of dict key order."""
    return sorted(
        entries,
        key=lambda e: repr(sorted(e.items())) if isinstance(e, dict) else repr(e),
    )


# ---------------------------------------------------------------------------
# 1. Candidate selection (Scope; algorithm step 1)
# ---------------------------------------------------------------------------


class TestSelection:
    async def test_only_active_tickets_are_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        by_status = {}
        for status in TicketStatus:
            by_status[status] = await seed.track(await seed.ticket(status))

        selected = await _selected(db_session, *by_status.values())

        active = (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED)
        assert _ids(selected) == sorted(by_status[status].id for status in active)
        for status in (
            TicketStatus.RESOLVED,
            TicketStatus.IGNORED,
            TicketStatus.DUPLICATED,
        ):
            assert (
                await load_track_release_candidates(
                    db_session, ticket_id=by_status[status].ticket_id
                )
                == []
            )

    async def test_ticket_without_cve_is_not_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        cveless = await seed.ticket(with_cve=False)
        track = await seed.track(cveless)

        assert await _selected(db_session, track) == []
        assert (
            await load_track_release_candidates(db_session, ticket_id=cveless.id) == []
        )

    async def test_git_track_is_not_selected(self, db_session: AsyncSession) -> None:
        """One package with an IBS and a Git track: only the IBS one."""
        seed = Seed(db_session)
        ticket = await seed.ticket()
        ibs = await seed.track(ticket)
        git = await seed.track(ticket, workflow=WorkflowType.GIT)

        assert ibs.package_id == git.package_id
        assert _ids(await _selected(db_session, ibs, git)) == [ibs.id]

    async def test_only_analysis_and_affected_tracks_are_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        by_status = {
            status: await seed.track(
                ticket, package_name=f"example-{status.value.lower()}", status=status
            )
            for status in PackageStatus
        }

        selected = await _selected(db_session, *by_status.values())

        assert _ids(selected) == sorted(
            [by_status[PackageStatus.ANALYSIS].id, by_status[PackageStatus.AFFECTED].id]
        )

    async def test_exclusion_lifecycle_eligibility_release_delivery_never_narrow(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        variants: list[dict[str, Any]] = [
            {"track": {"excluded": "package"}},
            {"track": {"excluded": "track"}},
            {"product": {"general_support_end_date": BEFORE_EVAL}},
            {"product": {"eligible": False}},
            {"product": {"eligible": False, "is_eligible_override": True}},
            {"product": {"eligible": True, "is_eligible_override": True}},
            {"product": {"released_at": RELEASED_AT}},
            {"product": {}},
            *({"track": {"delivery_status": status}} for status in DeliveryStatus),
            {"track": {"status": PackageStatus.AFFECTED}},
        ]
        created = []
        for index, variant in enumerate(variants):
            track = await seed.track(
                ticket, package_name=f"example-{index}", **variant.get("track", {})
            )
            if "product" in variant:
                await seed.product(track, **variant["product"])
            created.append(track)

        selected = await _selected(db_session, *created)

        assert _ids(selected) == sorted(track.id for track in created)

    async def test_candidate_carries_the_locator_and_snapshot(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        first = await seed.track(ticket)
        checked = await seed.track(
            ticket,
            package_name=SIBLING_PACKAGE,
            project=OTHER_PROJECT,
            checkpoint=CHECKPOINT,
        )

        candidates = await load_track_release_candidates(
            db_session, ticket_id=ticket.id
        )

        assert candidates == sorted(
            [first.candidate(), checked.candidate()], key=lambda c: c.track_id
        )
        by_track = {candidate.track_id: candidate for candidate in candidates}
        assert by_track[checked.id].checkpoint == CHECKPOINT
        assert by_track[checked.id].project == OTHER_PROJECT
        assert by_track[first.id].checkpoint is None

    async def test_candidates_are_ordered_by_track_id(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        low, high = sorted([uuid.uuid4(), uuid.uuid4()])
        first = await seed.track(await seed.ticket(), track_id=high)
        second = await seed.track(await seed.ticket(), track_id=low)

        assert _ids(await _selected(db_session, first, second)) == [low, high]

    async def test_ticket_restriction(self, db_session: AsyncSession) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        mine = await seed.track(ticket)
        other = await seed.track(await seed.ticket())
        inactive = await seed.ticket(TicketStatus.RESOLVED)
        await seed.track(inactive)
        cveless = await seed.ticket(with_cve=False)
        await seed.track(cveless)

        assert _ids(
            await load_track_release_candidates(db_session, ticket_id=ticket.id)
        ) == [mine.id]
        assert _ids(await _selected(db_session, mine, other)) == sorted(
            [mine.id, other.id]
        )
        for missing in (uuid.uuid4(), inactive.id, cveless.id):
            assert (
                await load_track_release_candidates(db_session, ticket_id=missing) == []
            )

    async def test_selection_writes_and_locks_nothing(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        await seed.track(ticket, checkpoint=CHECKPOINT)

        with StatementRecorder(db_session) as recorder:
            candidates = await load_track_release_candidates(
                db_session, ticket_id=ticket.id
            )

        assert len(candidates) == 1
        assert recorder.statements
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted


# ---------------------------------------------------------------------------
# 2. Boundary body (Shared Reconciliation Boundary)
# ---------------------------------------------------------------------------


class TestBoundaryBody:
    async def test_empty_input_performs_no_io_or_database_work(
        self, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [], hook)

        assert outcomes == []
        assert ibs.server.requests == []
        assert units.sessions == []
        assert hook.received == []
        assert own(logs) == []

    async def test_duplicate_candidates_are_processed_once(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        (track,) = await _seeded(world)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(track)))
        hook = Outcomes()

        outcomes = await reconcile(ibs, [track.candidate()] * 3, hook)

        assert kinds(outcomes) == {track.id: "updated"}
        assert len(outcomes) == 1
        assert hook.kinds == {track.id: "updated"}
        assert [s.packages for s in ibs.sources()] == [(PACKAGE,)]
        assert ibs.diffs() == [(PROJECT, PACKAGE, "0", CURRENT)]
        assert len(units.sessions) == 1
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]

    async def test_invalid_persisted_identity_fails_alone(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        """A project or package the client rejects, or a malformed
        checkpoint, fails only its own track (`invalid_identity`) before any
        request; no request names it and the valid sibling is released."""
        seed = Seed(world.session, world)
        bad_project = await seed.track(
            await seed.ticket(), project="SUSE:SLE-15 SP6:Update"
        )
        bad_package = await seed.track(
            await seed.ticket(), package_name="example/../other"
        )
        bad_checkpoint = await seed.track(
            await seed.ticket(), package_name=SIBLING_PACKAGE, checkpoint="not-hex"
        )
        sibling = await seed.track(await seed.ticket())
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(sibling)))
        hook = Outcomes()
        reader = await world.probe()
        candidates = [
            c
            for c in await load_track_release_candidates(reader)
            if c.track_id
            in {bad_project.id, bad_package.id, bad_checkpoint.id, sibling.id}
        ]
        await reader.rollback()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, candidates, hook)

        invalid = (bad_project, bad_package, bad_checkpoint)
        assert kinds(outcomes) == {
            **{track.id: "failed" for track in invalid},
            sibling.id: "updated",
        }
        assert hook.kinds == kinds(outcomes)
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(track, "invalid_identity") for track in invalid]
        )
        assert [s.packages for s in ibs.sources()] == [(PACKAGE,)]
        assert ibs.diffs() == [(PROJECT, PACKAGE, "0", CURRENT)]
        requested = " ".join(str(request.url) for request in ibs.server.requests)
        for fragment in ("SP6%20", "SP6 ", "example/..", "other", SIBLING_PACKAGE):
            assert fragment not in requested
        assert "not-hex" not in requested
        assert len(units.sessions) == 1
        assert await checkpoint_of(world, bad_checkpoint) == ("not-hex", SEEN_AT)
        for track in invalid:
            assert await track_status(world, track) == PackageStatus.ANALYSIS.value
            assert await events_of(world, track.ticket_id) == []


# ---------------------------------------------------------------------------
# 3. Evidence (Authoritative IBS Evidence; algorithm steps 4-6)
# ---------------------------------------------------------------------------


class TestEvidence:
    async def test_first_observation_diffs_the_expanded_srcmd5_from_the_empty_tree(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        """The linked package's expanded `srcmd5`, never `lsrcmd5`, is
        `rev`; `orev=0`; `expand=1`; the source info request is targeted."""
        (track,) = await _seeded(world)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(track)))
        started = datetime.now(UTC)

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        (source,) = ibs.sources()
        assert list(source.query) == [
            ("view", "info"),
            ("nofilename", "1"),
            ("package", PACKAGE),
        ]
        diffs = [served for served in ibs.served if served.kind == "diff"]
        assert [list(served.query) for served in diffs] == [
            [
                ("cmd", "diff"),
                ("view", "xml"),
                ("onlyissues", "1"),
                ("expand", "1"),
                ("orev", "0"),
                ("rev", CURRENT),
            ]
        ]
        assert all(LINK_SRCMD5 not in str(r.url) for r in ibs.server.requests)
        accepted = await checkpoint_of(world, track)
        assert accepted is not None
        assert accepted[0] == CURRENT
        assert accepted[1] >= started
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]

    async def test_equal_checkpoint_is_a_no_op_without_diff_or_write(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CURRENT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()], hook)

        assert kinds(outcomes) == {track.id: "no_op"}
        assert hook.kinds == {track.id: "no_op"}
        assert ibs.diffs() == []
        assert units.sessions == []
        assert own(logs) == []
        assert await checkpoint_of(world, track) == (CURRENT, SEEN_AT)
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize("state", ["added", "changed"])
    async def test_incremental_comparison_uses_the_checkpoint_as_orev(
        self, world: TrackWorld, ibs: FakeIBS, state: str
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(
            PROJECT, PACKAGE, CHECKPOINT, CURRENT, issue(_cve(track), state=state)
        )

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        assert ibs.diffs() == [(PROJECT, PACKAGE, CHECKPOINT, CURRENT)]
        accepted = await checkpoint_of(world, track)
        assert accepted is not None
        assert accepted[0] == CURRENT
        assert accepted[1] > SEEN_AT
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]

    @pytest.mark.parametrize(
        ("make_issues", "fixed", "ignored"),
        [
            pytest.param(lambda cve: [issue(cve)], True, 0, id="added"),
            pytest.param(
                lambda cve: [issue(cve, state="changed")], True, 0, id="changed"
            ),
            pytest.param(
                lambda cve: [issue(cve, state="deleted")], False, 0, id="deleted"
            ),
            pytest.param(lambda cve: [issue(cve, tracker="bnc")], False, 0, id="bnc"),
            pytest.param(
                lambda cve: [issue(cve, tracker="fate")], False, 0, id="other-tracker"
            ),
            pytest.param(
                lambda cve: [issue(None, name=cve)], False, 1, id="cve-in-name-only"
            ),
            pytest.param(
                lambda cve: [issue(cve.lower(), name=cve)],
                False,
                1,
                id="non-canonical-label",
            ),
            pytest.param(
                lambda cve: [issue(f"CVE-2099-{MARKER}", name=cve)],
                False,
                1,
                id="label-with-text",
            ),
            pytest.param(
                lambda cve: [issue(f"CVE-2099-{MARKER}", state="deleted")],
                False,
                0,
                id="invalid-label-deleted",
            ),
            pytest.param(
                lambda cve: [issue(f"bsc#{MARKER}", tracker="bnc")],
                False,
                0,
                id="bnc-free-label",
            ),
            pytest.param(lambda cve: [issue(cve), issue(cve)], True, 0, id="duplicate"),
            pytest.param(lambda cve: [], False, 0, id="empty"),
            pytest.param(lambda cve: [issue(OTHER_CVE)], False, 0, id="other-cve-only"),
            pytest.param(
                lambda cve: [
                    issue(OTHER_CVE),
                    issue("CVE-2099-88888888", state="changed"),
                    issue(cve, state="changed"),
                    issue("1234567", tracker="bnc"),
                ],
                True,
                0,
                id="multi-cve",
            ),
            pytest.param(
                lambda cve: [
                    issue(None, name=cve),
                    issue(f"CVE-2099-{MARKER}"),
                    issue("cve-2099-1", state="changed"),
                    issue(cve),
                ],
                True,
                1,
                id="several-invalid-labels-one-warning",
            ),
        ],
    )
    async def test_issue_evidence_matrix(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        make_issues: Callable[[str], list[str]],
        fixed: bool,
        ignored: int,
    ) -> None:
        """Only a `cve`-tracker `added`/`changed` issue whose canonical
        `label` is the Ticket CVE is evidence; a missing or non-canonical
        label of such an issue emits at most one bounded warning per diff
        and no label text; every examination accepts the checkpoint."""
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        cve = _cve(track)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, CHECKPOINT, CURRENT, *make_issues(cve))
        before = await track_row(world, track)
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()], hook)

        expected = "updated" if fixed else "no_op"
        assert kinds(outcomes) == {track.id: expected}
        assert hook.kinds == {track.id: expected}
        assert own(logs) == [issue_ignored()] * ignored
        assert await checkpoint_srcmd5(world, track) == CURRENT
        if fixed:
            assert await track_status(world, track) == PackageStatus.FIXED.value
            assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        else:
            assert await track_row(world, track) == before
            assert await events_of(world, track.ticket_id) == []
        rendered = repr(logs)
        assert MARKER not in rendered
        assert cve.lower() not in rendered


# ---------------------------------------------------------------------------
# 4. Source info (Source-Info Validation; Error Handling)
# ---------------------------------------------------------------------------


class TestSourceInfo:
    @pytest.mark.parametrize(
        ("entries", "category"),
        [
            pytest.param([], "missing", id="missing"),
            pytest.param(
                [source_entry(PACKAGE, CURRENT), source_entry(PACKAGE, CURRENT)],
                "duplicate",
                id="duplicate",
            ),
            pytest.param(
                [source_entry(PACKAGE, CURRENT, error=True)],
                "upstream_error",
                id="error-bearing-with-checksums",
            ),
            pytest.param(
                [source_entry(PACKAGE, "0123")], "invalid_srcmd5", id="invalid-srcmd5"
            ),
        ],
    )
    async def test_unusable_package_fails_only_its_tracks(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        entries: list[str],
        category: str,
    ) -> None:
        first, second = await _seeded(world, 2)
        seed = Seed(world.session, world)
        sibling = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        await seed.commit()
        ibs.entries(PROJECT, PACKAGE, *entries)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.issues(PROJECT, SIBLING_PACKAGE, "0", CURRENT, issue(_cve(sibling)))
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [first.candidate(), second.candidate(), sibling.candidate()], hook
            )

        assert kinds(outcomes) == {
            first.id: "failed",
            second.id: "failed",
            sibling.id: "updated",
        }
        assert hook.kinds == kinds(outcomes)
        assert [sorted(s.packages) for s in ibs.sources()] == [
            sorted([PACKAGE, SIBLING_PACKAGE])
        ]
        assert ibs.diffs() == [(PROJECT, SIBLING_PACKAGE, "0", CURRENT)]
        assert logged(logs, PACKAGE_SOURCE_INVALID) == [
            package_source_invalid(PROJECT, PACKAGE, 2, category)
        ]
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(first, category), track_failed(second, category)]
        )
        assert len(units.sessions) == 1
        for failed in (first, second):
            assert await checkpoint_of(world, failed) is None
            assert await events_of(world, failed.ticket_id) == []
        assert await events_of(world, sibling.ticket_id) == [sibling.fixed_event()]

    @pytest.mark.parametrize(
        ("responder", "category", "http_status"),
        [
            pytest.param(
                xml_response(f"<sourceinfolist><sourceinfo {MARKER}".encode()),
                "malformed_xml",
                None,
                id="malformed",
            ),
            pytest.param(
                chunked_response(
                    [f'<sourceinfolist><sourceinfo package="{PACKAGE}"'.encode()],
                    fail_after=True,
                ),
                "interrupted_response",
                None,
                id="interrupted",
            ),
            pytest.param(
                xml_response(f"<status><summary>{MARKER}</summary></status>".encode()),
                "invalid_document",
                None,
                id="other-root",
            ),
            pytest.param(
                raising(httpx.ConnectError(f"https://jdoe:{MARKER}@ibs refused")),
                "transport",
                None,
                id="transport",
            ),
            pytest.param(
                status_response(500, MARKER.encode()), "http_status", 500, id="5xx"
            ),
            pytest.param(
                status_response(403, MARKER.encode()), "http_status", 403, id="403"
            ),
        ],
    )
    async def test_request_failure_fails_every_dependent_track_once(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        responder: Callable[[httpx.Request], httpx.Response],
        category: str,
        http_status: int | None,
    ) -> None:
        """One request-level warning; every track of that request fails
        once with its checkpoint unchanged; another project's request
        continues."""
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket(), checkpoint=CHECKPOINT)
        second = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        ibs.fail_source(PROJECT, responder)
        ibs.source(OTHER_PROJECT, PACKAGE, CURRENT)
        ibs.issues(OTHER_PROJECT, PACKAGE, "0", CURRENT, issue(_cve(other)))
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [first.candidate(), second.candidate(), other.candidate()], hook
            )

        assert kinds(outcomes) == {
            first.id: "failed",
            second.id: "failed",
            other.id: "updated",
        }
        assert hook.kinds == kinds(outcomes)
        assert logged(logs, SOURCE_INFO_FAILED) == [
            source_info_failed(PROJECT, 2, category, http_status)
        ]
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(first, category), track_failed(second, category)]
        )
        assert logged(logs, DIFF_FAILED) == []
        assert ibs.diffs() == [(OTHER_PROJECT, PACKAGE, "0", CURRENT)]
        assert len(units.sessions) == 1
        assert await checkpoint_of(world, first) == (CHECKPOINT, SEEN_AT)
        assert await checkpoint_of(world, second) is None
        for failed in (first, second):
            assert await events_of(world, failed.ticket_id) == []
        assert MARKER not in repr(logs)


# ---------------------------------------------------------------------------
# 5. Partitioning and reuse (Shared Reconciliation Boundary)
# ---------------------------------------------------------------------------


def _synthetic(project: str, package: str) -> TrackReleaseCandidate:
    """An unchanged-source candidate: never reaches a diff or a session."""
    return TrackReleaseCandidate(
        track_id=uuid.uuid4(),
        package_id=uuid.uuid4(),
        ticket_id=uuid.uuid4(),
        cve_id=OTHER_CVE,
        package_name=package,
        project=project,
        checkpoint=CURRENT,
    )


class TestPartitioningAndReuse:
    async def test_source_info_is_partitioned_and_each_package_requested_once(
        self, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        count = 2 * SOURCE_INFO_PARTITION_SIZE + 1
        assert SOURCE_INFO_PARTITION_SIZE == 100
        packages = [f"example-{index:03d}" for index in range(count)]
        candidates = [_synthetic(PROJECT, package) for package in packages]
        for package in packages:
            ibs.source(PROJECT, package, CURRENT)

        outcomes = await reconcile(ibs, candidates)

        assert kinds(outcomes) == {c.track_id: "no_op" for c in candidates}
        requested = [served.packages for served in ibs.sources()]
        assert all(0 < len(partition) <= 100 for partition in requested)
        flattened = [package for partition in requested for package in partition]
        assert sorted(flattened) == sorted(packages)
        assert len(requested) == 3
        assert {served.project for served in ibs.sources()} == {PROJECT}
        assert ibs.diffs() == []
        assert units.sessions == []

    async def test_one_source_info_request_per_project(self, ibs: FakeIBS) -> None:
        candidates = [
            _synthetic(project, package)
            for project in (PROJECT, OTHER_PROJECT)
            for package in (PACKAGE, SIBLING_PACKAGE)
        ]
        for candidate in candidates:
            ibs.source(candidate.project, candidate.package_name, CURRENT)

        outcomes = await reconcile(ibs, candidates)

        assert set(kinds(outcomes).values()) == {"no_op"}
        assert sorted((s.project, sorted(s.packages)) for s in ibs.sources()) == [
            (PROJECT, [PACKAGE, SIBLING_PACKAGE]),
            (OTHER_PROJECT, [PACKAGE, SIBLING_PACKAGE]),
        ]

    async def test_tracks_sharing_baseline_and_current_share_one_diff(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        """Five tracks of one package (one source-info entry): two first
        observations share the `orev=0` diff, two equal checkpoints share
        one incremental diff, and a different checkpoint needs its own."""
        first_a, first_b = await _seeded(world, 2)
        incremental_a, incremental_b = await _seeded(world, 2, checkpoint=CHECKPOINT)
        (older,) = await _seeded(world, checkpoint=OLDER)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(first_a)))
        ibs.issues(PROJECT, PACKAGE, CHECKPOINT, CURRENT, issue(_cve(incremental_b)))
        ibs.issues(PROJECT, PACKAGE, OLDER, CURRENT, issue(OTHER_CVE))
        tracks = [first_a, first_b, incremental_a, incremental_b, older]

        outcomes = await reconcile(ibs, [t.candidate() for t in tracks])

        assert kinds(outcomes) == {
            first_a.id: "updated",
            first_b.id: "no_op",
            incremental_a.id: "no_op",
            incremental_b.id: "updated",
            older.id: "no_op",
        }
        assert [s.packages for s in ibs.sources()] == [(PACKAGE,)]
        assert sorted(ibs.diffs()) == sorted(
            [
                (PROJECT, PACKAGE, "0", CURRENT),
                (PROJECT, PACKAGE, CHECKPOINT, CURRENT),
                (PROJECT, PACKAGE, OLDER, CURRENT),
            ]
        )
        assert len(units.sessions) == 5
        for track in tracks:
            assert await checkpoint_srcmd5(world, track) == CURRENT

    @pytest.mark.parametrize("outcome", ["examined", "diff-failed"])
    async def test_incremental_diff_requests_no_diff_without_dependent_tracks(
        self, world: TrackWorld, ibs: FakeIBS, outcome: str
    ) -> None:
        """Only an unavailable checkpoint moves a track to the `orev=0`
        diff (algorithm steps 5 and 7): after an examined or failed
        incremental diff no further diff is requested, and no request-level
        warning names zero affected tracks."""
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        if outcome == "examined":
            ibs.issues(PROJECT, PACKAGE, CHECKPOINT, CURRENT, issue(OTHER_CVE))
        else:
            ibs.diff(PROJECT, PACKAGE, CHECKPOINT, CURRENT, status_response(403))

        with capture_logs() as logs:
            await reconcile(ibs, [track.candidate()])

        assert ibs.diffs() == [(PROJECT, PACKAGE, CHECKPOINT, CURRENT)]
        assert ibs.unscripted == []
        assert [e for e in own(logs) if e.get("affected_track_count") == 0] == []


# ---------------------------------------------------------------------------
# 6. Diff failures (Source-Diff Validation; algorithm step 7)
# ---------------------------------------------------------------------------


class TestDiffFailures:
    @pytest.mark.parametrize(
        ("make_responder", "category", "http_status"),
        [
            pytest.param(
                lambda: xml_response(f"<sourcediff><issues>{MARKER}".encode()),
                "malformed_xml",
                None,
                id="malformed",
            ),
            pytest.param(
                lambda: chunked_response([b"<sourcediff><issues>"], fail_after=True),
                "interrupted_response",
                None,
                id="interrupted",
            ),
            pytest.param(
                lambda: xml_response(
                    b'<sourcediff><issues><issue state="added"/></issues></sourcediff>'
                ),
                "invalid_issue",
                None,
                id="invalid-issue-structure",
            ),
            pytest.param(
                lambda: status_response(
                    404, load_fixture("diff_error_no_such_revision")
                ),
                "http_status",
                404,
                id="404-no-such-revision",
            ),
            pytest.param(
                lambda: unavailable(PROJECT, PACKAGE, CURRENT, which="rev"),
                "http_status",
                400,
                id="400-naming-current-rev",
            ),
            pytest.param(
                lambda: status_response(403, MARKER.encode()),
                "http_status",
                403,
                id="403",
            ),
        ],
    )
    async def test_diff_failure_fails_every_dependent_track_without_fallback(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        make_responder: Callable[[], Callable[[httpx.Request], httpx.Response]],
        category: str,
        http_status: int | None,
    ) -> None:
        first, second = await _seeded(world, 2, checkpoint=CHECKPOINT)
        seed = Seed(world.session, world)
        sibling = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.diff(PROJECT, PACKAGE, CHECKPOINT, CURRENT, make_responder())
        ibs.issues(PROJECT, SIBLING_PACKAGE, "0", CURRENT, issue(_cve(sibling)))
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [first.candidate(), second.candidate(), sibling.candidate()], hook
            )

        assert kinds(outcomes) == {
            first.id: "failed",
            second.id: "failed",
            sibling.id: "updated",
        }
        assert hook.kinds == kinds(outcomes)
        assert logged(logs, DIFF_FAILED) == [
            diff_failed(PROJECT, PACKAGE, 2, category, http_status)
        ]
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(first, category), track_failed(second, category)]
        )
        assert logged(logs, HISTORY_UNAVAILABLE) == []
        assert sorted(ibs.diffs()) == sorted(
            [
                (PROJECT, PACKAGE, CHECKPOINT, CURRENT),
                (PROJECT, SIBLING_PACKAGE, "0", CURRENT),
            ]
        )
        assert len(units.sessions) == 1
        for failed in (first, second):
            assert await checkpoint_of(world, failed) == (CHECKPOINT, SEEN_AT)
            assert await events_of(world, failed.ticket_id) == []
        assert MARKER not in repr(logs)


# ---------------------------------------------------------------------------
# 7. Credentials and authentication (Error Handling, T6 row)
# ---------------------------------------------------------------------------


class TestCredentialsAndAuthentication:
    async def test_unconfigured_client_sends_nothing_and_fails_every_track(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket(), checkpoint=CHECKPOINT)
        second = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.source(OTHER_PROJECT, PACKAGE, CURRENT)
        tracks = (first, second, other)
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [t.candidate() for t in tracks], hook, configured=False
            )

        assert kinds(outcomes) == {t.id: "failed" for t in tracks}
        assert len(hook.received) == 3
        assert ibs.server.requests == []
        assert units.sessions == []
        category = "credentials_not_configured"
        assert _sorted_logs(logged(logs, SOURCE_INFO_FAILED)) == _sorted_logs(
            [
                source_info_failed(PROJECT, 2, category),
                source_info_failed(OTHER_PROJECT, 1, category),
            ]
        )
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(t, category) for t in tracks]
        )
        assert await checkpoint_of(world, first) == (CHECKPOINT, SEEN_AT)
        assert await checkpoint_of(world, second) is None
        assert await checkpoint_of(world, other) is None

    @pytest.mark.parametrize("reason", ["signature_rejected", "unsupported_challenge"])
    async def test_rejected_authentication_on_source_info_fails_the_request(
        self, world: TrackWorld, ibs: FakeIBS, reason: str
    ) -> None:
        first, second = await _seeded(world, 2, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        _reject(ibs, reason)

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [first.candidate(), second.candidate()])

        assert kinds(outcomes) == {first.id: "failed", second.id: "failed"}
        assert ibs.served == []
        assert logged(logs, SOURCE_INFO_FAILED) == [
            source_info_failed(PROJECT, 2, reason)
        ]
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(first, reason), track_failed(second, reason)]
        )
        for track in (first, second):
            assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        _assert_no_credentials(logs)

    @pytest.mark.parametrize("reason", ["signature_rejected", "unsupported_challenge"])
    async def test_rejected_authentication_on_a_diff_fails_its_tracks(
        self, world: TrackWorld, ibs: FakeIBS, reason: str
    ) -> None:
        """The session expires after source info and the re-authentication
        of the diff is rejected: a diff failure of its dependent tracks."""
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, CHECKPOINT, CURRENT, issue(_cve(track)))

        def expire() -> None:
            ibs.server.expire_sessions()
            _reject(ibs, reason)

        ibs.after_source = expire

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "failed"}
        assert ibs.diffs() == []
        assert logged(logs, DIFF_FAILED) == [diff_failed(PROJECT, PACKAGE, 1, reason)]
        assert logged(logs, TRACK_FAILED) == [track_failed(track, reason)]
        assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        assert await events_of(world, track.ticket_id) == []
        _assert_no_credentials(logs)


def _reject(ibs: FakeIBS, reason: str) -> None:
    if reason == "signature_rejected":
        ibs.server.reject_signatures = True
    else:
        ibs.server.challenges = ['Basic realm="fictional"']


def _assert_no_credentials(logs: list[Any]) -> None:
    rendered = repr(logs)
    for forbidden in (
        fictional_settings_value(),
        "keyId",
        "Signature",
        "fictional-session",
        "authorization",
        "cookie",
    ):
        assert forbidden not in rendered


# ---------------------------------------------------------------------------
# 8. Unavailable history (Unavailable History Fallback; step 7)
# ---------------------------------------------------------------------------


class TestUnavailableHistory:
    @pytest.mark.parametrize("evidence", [True, False], ids=["fixed", "no-match"])
    async def test_unavailable_checkpoint_falls_back_to_the_empty_tree(
        self, world: TrackWorld, ibs: FakeIBS, evidence: bool
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        ibs.issues(
            PROJECT,
            PACKAGE,
            "0",
            CURRENT,
            issue(_cve(track) if evidence else OTHER_CVE),
        )
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()], hook)

        expected = "updated" if evidence else "no_op"
        assert kinds(outcomes) == {track.id: expected}
        assert hook.kinds == {track.id: expected}
        assert own(logs) == [history_unavailable(track)]
        assert ibs.diffs() == [
            (PROJECT, PACKAGE, CHECKPOINT, CURRENT),
            (PROJECT, PACKAGE, "0", CURRENT),
        ]
        assert await checkpoint_srcmd5(world, track) == CURRENT
        assert await events_of(world, track.ticket_id) == (
            [track.fixed_event()] if evidence else []
        )
        assert "not in repository" not in repr(logs)

    @pytest.mark.parametrize(
        ("make_responder", "category", "http_status"),
        [
            pytest.param(
                lambda: unavailable(PROJECT, PACKAGE, CURRENT, which="rev"),
                "http_status",
                400,
                id="unavailable-current",
            ),
            pytest.param(
                lambda: xml_response(b"<sourcediff><issues>"),
                "malformed_xml",
                None,
                id="malformed",
            ),
        ],
    )
    async def test_fallback_failure_fails_the_track_and_keeps_the_checkpoint(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        make_responder: Callable[[], Callable[[httpx.Request], httpx.Response]],
        category: str,
        http_status: int | None,
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        ibs.diff(PROJECT, PACKAGE, "0", CURRENT, make_responder())

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "failed"}
        assert own(logs) == [
            history_unavailable(track),
            diff_failed(PROJECT, PACKAGE, 1, category, http_status),
            track_failed(track, category),
        ]
        assert units.sessions == []
        assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        assert await events_of(world, track.ticket_id) == []

    async def test_fallback_shares_the_empty_tree_diff_with_a_first_observation(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (fallback,) = await _seeded(world, checkpoint=CHECKPOINT)
        (first,) = await _seeded(world)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        ibs.issues(
            PROJECT, PACKAGE, "0", CURRENT, issue(_cve(fallback)), issue(_cve(first))
        )

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [fallback.candidate(), first.candidate()])

        assert kinds(outcomes) == {fallback.id: "updated", first.id: "updated"}
        assert ibs.diffs() == [
            (PROJECT, PACKAGE, CHECKPOINT, CURRENT),
            (PROJECT, PACKAGE, "0", CURRENT),
        ]
        assert own(logs) == [history_unavailable(fallback)]
        for track in (fallback, first):
            assert await checkpoint_srcmd5(world, track) == CURRENT
            assert await events_of(world, track.ticket_id) == [track.fixed_event()]

    async def test_va_corrected_track_is_fixed_again_after_unavailable_history(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        """The accepted ambiguity: the retained old reference in current
        source sets the VA-corrected `AFFECTED` track to `FIXED` again,
        observable through the warning."""
        (track,) = await _seeded(
            world, status=PackageStatus.AFFECTED, checkpoint=CHECKPOINT
        )
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(track)))

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        assert own(logs) == [history_unavailable(track)]
        assert await events_of(world, track.ticket_id) == [
            track.fixed_event(PackageStatus.AFFECTED)
        ]
        assert await checkpoint_srcmd5(world, track) == CURRENT


# ---------------------------------------------------------------------------
# 9. First Observation and VA Correction
# ---------------------------------------------------------------------------


class TestVACorrectionPreservation:
    @pytest.mark.parametrize(
        "status", [PackageStatus.AFFECTED, PackageStatus.ANALYSIS], ids=str
    )
    async def test_unchanged_source_never_reapplies_the_old_reference(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        status: PackageStatus,
    ) -> None:
        (track,) = await _seeded(world, status=status, checkpoint=CURRENT)
        ibs.source(PROJECT, PACKAGE, CURRENT)

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "no_op"}
        assert ibs.diffs() == []
        assert units.sessions == []
        assert await track_status(world, track) == status.value
        assert await events_of(world, track.ticket_id) == []

    async def test_later_state_without_new_evidence_keeps_the_correction(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (track,) = await _seeded(
            world, status=PackageStatus.AFFECTED, checkpoint=CHECKPOINT
        )
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            issue("1234567", tracker="bnc"),
            issue(OTHER_CVE),
        )

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "no_op"}
        assert await track_status(world, track) == PackageStatus.AFFECTED.value
        assert await checkpoint_srcmd5(world, track) == CURRENT
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize("state", ["added", "changed"])
    async def test_later_state_with_new_evidence_fixes_again(
        self, world: TrackWorld, ibs: FakeIBS, state: str
    ) -> None:
        (track,) = await _seeded(
            world, status=PackageStatus.AFFECTED, checkpoint=CHECKPOINT
        )
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(
            PROJECT, PACKAGE, CHECKPOINT, CURRENT, issue(_cve(track), state=state)
        )

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        assert await events_of(world, track.ticket_id) == [
            track.fixed_event(PackageStatus.AFFECTED)
        ]
        assert await checkpoint_srcmd5(world, track) == CURRENT


# ---------------------------------------------------------------------------
# 10. Local outcome and audit (Per-Track Local Outcome; Audit)
# ---------------------------------------------------------------------------


class TestLocalOutcomeAndAudit:
    @pytest.mark.parametrize(
        "old", [PackageStatus.ANALYSIS, PackageStatus.AFFECTED], ids=str
    )
    async def test_effective_fixed_has_one_event_reconciliation_and_checkpoint(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        old: PackageStatus,
    ) -> None:
        (track,) = await _seeded(world, status=old)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(track)))
        reconciliation = Spy(monkeypatch, "reconcile_ticket_status")
        assert await events_of(world, track.ticket_id) == []
        started = datetime.now(UTC)

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        assert await events_of(world, track.ticket_id) == [track.fixed_event(old)]
        assert len(reconciliation.calls) == 1
        assert await track_status(world, track) == PackageStatus.FIXED.value
        accepted = await checkpoint_of(world, track)
        assert accepted is not None
        assert accepted[0] == CURRENT
        assert accepted[1] >= started
        assert len(units.sessions) == 1
        assert units.closed == units.sessions
        assert own(logs) == []

    @pytest.mark.parametrize(
        "checkpoint", [None, CHECKPOINT], ids=["created", "advanced"]
    )
    async def test_checkpoint_only_outcome_has_no_event_and_keeps_updated_at(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        checkpoint: str | None,
    ) -> None:
        (track,) = await _seeded(world, checkpoint=checkpoint)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, checkpoint or "0", CURRENT, issue(OTHER_CVE))
        reconciliation = Spy(monkeypatch, "reconcile_ticket_status")
        before = await track_row(world, track)
        started = datetime.now(UTC)

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "no_op"}
        assert await track_row(world, track) == before
        assert await events_of(world, track.ticket_id) == []
        assert reconciliation.calls == []
        accepted = await checkpoint_of(world, track)
        assert accepted is not None
        assert accepted[0] == CURRENT
        assert accepted[1] >= started

    async def test_failed_outcome_creates_no_event_or_write(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(PROJECT, PACKAGE, CHECKPOINT, CURRENT, status_response(403))
        before = await track_row(world, track)

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "failed"}
        assert await track_row(world, track) == before
        assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        assert await events_of(world, track.ticket_id) == []

    async def test_repeated_invocation_is_an_idempotent_no_op(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        """After the first run the `FIXED` track leaves the selection and
        the no-match track's checkpoint equals current source. Replaying
        the stale first-run snapshot finds the checkpoint already advanced
        to the examined state: a no-op without a write or a second event."""
        fixed, no_match = await _seeded(world, 2)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(fixed)))
        first = await reconcile(ibs, [fixed.candidate(), no_match.candidate()])
        assert kinds(first) == {fixed.id: "updated", no_match.id: "no_op"}
        first_checkpoints = [await checkpoint_of(world, t) for t in (fixed, no_match)]
        reader = await world.probe()
        reselected = [
            c
            for c in await load_track_release_candidates(reader)
            if c.track_id in {fixed.id, no_match.id}
        ]
        await reader.rollback()
        served = len(ibs.served)
        opened = len(units.sessions)

        assert _ids(reselected) == [no_match.id]
        assert reselected[0].checkpoint == CURRENT
        again = await reconcile(ibs, reselected)

        assert kinds(again) == {no_match.id: "no_op"}
        assert len(units.sessions) == opened
        assert [s.kind for s in ibs.served[served:]] == ["source"]

        replay = await reconcile(ibs, [fixed.candidate()])

        assert kinds(replay) == {fixed.id: "no_op"}
        assert [await checkpoint_of(world, t) for t in (fixed, no_match)] == (
            first_checkpoints
        )
        assert await events_of(world, fixed.ticket_id) == [fixed.fixed_event()]
        assert await events_of(world, no_match.ticket_id) == []


# ---------------------------------------------------------------------------
# 11. Forward transitions (package-service.md, Architectural Test
#     Requirement; tickets.md, Gate: Analyzed -> Resolved)
# ---------------------------------------------------------------------------


class TestForwardTransitions:
    @pytest.mark.parametrize(
        ("released", "expected"),
        [
            pytest.param(True, TicketStatus.RESOLVED, id="all-released"),
            pytest.param(False, TicketStatus.ANALYZED, id="one-unreleased"),
        ],
    )
    async def test_fixing_the_last_open_track_of_an_analyzed_ticket(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        released: bool,
        expected: TicketStatus,
    ) -> None:
        """The last non-final track (`AFFECTED`) of an `Analyzed` Ticket
        with an assessed CVE; its actionable eligible Products are released
        (or one is not). A finished sibling track keeps the gate otherwise
        satisfied."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket(TicketStatus.ANALYZED, assessed=True)
        track = await seed.track(ticket, status=PackageStatus.AFFECTED)
        await seed.product(track, released_at=RELEASED_AT)
        await seed.product(track, released_at=RELEASED_AT if released else None)
        await seed.product(track, eligible=False)
        done = await seed.track(
            ticket, package_name=SIBLING_PACKAGE, status=PackageStatus.NOT_AFFECTED
        )
        await seed.product(done)
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(_cve(track)))

        outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        events = [track.fixed_event(PackageStatus.AFFECTED)]
        if released:
            events.append(
                status_event(TicketStatus.ANALYZED.value, TicketStatus.RESOLVED.value)
            )
        assert await events_of(world, ticket.id) == events
        assert await ticket_status(world, ticket.id) == expected.value


# ---------------------------------------------------------------------------
# 12. Dimension independence (track part)
# ---------------------------------------------------------------------------


async def _dimensions(world: TrackWorld, ticket_id: uuid.UUID) -> list[Any]:
    """Every track's delivery and exclusion (with its package's) and every
    occurrence's eligibility, override, release, and exclusion."""
    probe = await world.probe()
    tracks = (
        await probe.execute(
            select(
                TicketPackageTrack.id,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
                TicketPackage.deleted_at,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackage.ticket_id == ticket_id)
            .order_by(TicketPackageTrack.id)
        )
    ).all()
    occurrences = (
        await probe.execute(
            select(
                TicketPackageProduct.id,
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at,
                TicketPackageProduct.deleted_at,
            )
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackage.ticket_id == ticket_id)
            .order_by(TicketPackageProduct.id)
        )
    ).all()
    await probe.rollback()
    return [tuple(row) for row in tracks] + [tuple(row) for row in occurrences]


class TestDimensionIndependence:
    async def test_every_dimension_value_is_selected_and_fixed_unchanged(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        variants: list[dict[str, Any]] = [
            *({"track": {"delivery_status": status}} for status in DeliveryStatus),
            {"product": {"eligible": False}},
            {"product": {"eligible": False, "is_eligible_override": True}},
            {"product": {"eligible": True, "is_eligible_override": True}},
            {"product": {"released_at": RELEASED_AT}},
            {"product": {}},
            {"product": {"general_support_end_date": BEFORE_EVAL}},
            {"track": {"excluded": "package"}},
            {"track": {"excluded": "track"}},
        ]
        created = []
        for index, variant in enumerate(variants):
            track = await seed.track(
                ticket, package_name=f"example-{index}", **variant.get("track", {})
            )
            if "product" in variant:
                await seed.product(track, **variant["product"])
            created.append(track)
        await seed.commit()
        before = await _dimensions(world, ticket.id)
        for track in created:
            ibs.source(PROJECT, track.package_name, CURRENT)
            ibs.issues(PROJECT, track.package_name, "0", CURRENT, issue(_cve(track)))
        reader = await world.probe()
        candidates = await load_track_release_candidates(reader, ticket_id=ticket.id)
        await reader.rollback()

        outcomes = await reconcile(ibs, candidates)

        assert _ids(candidates) == sorted(track.id for track in created)
        assert kinds(outcomes) == {track.id: "updated" for track in created}
        for track in created:
            assert await track_status(world, track) == PackageStatus.FIXED.value
        assert _sorted_logs(await events_of(world, ticket.id)) == _sorted_logs(
            [track.fixed_event() for track in created]
        )
        assert await _dimensions(world, ticket.id) == before
