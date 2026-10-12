"""Tests for the IBS Product release reconciliation boundary
(backend/app/services/packages/ibs_product_release.py): candidate selection
and the boundary body's outcomes, transactions, audit, and logs.

Owning specifications:

- docs/features/packages/ibs-product-release-detection.md (Scope;
  Repository Traversal (current then historical tiers); Issued time
  (earliest matching advisory, advisory-ID tiebreak); Reconciliation
  Boundary (duplicate IDs once, empty collection without HTTP or mutation
  work, per-invocation repository reuse, terminal outcomes) and its Local
  mutation and concurrency (all repository I/O before any Ticket lock; one
  independent transaction per matching occurrence); Irreversibility,
  Audit, and Observability (one service-owned `product_released` event; no
  event for every non-mutating outcome; the bounded occurrence and run
  events); Error Handling (one shared repository failure counts each
  dependent occurrence once); Catch-Up (an advisory predating the Ticket
  keeps its original issued time); Testing Requirements).
- docs/features/packages/package-model.md (IBS Workflow Applicability and
  Convergence: strict workflow applicability; active Tickets only;
  exclusion, lifecycle, and EOL never narrow factual release observation).
- docs/features/platform/testing-strategy.md (Audit Trail Testing;
  Concurrency Testing).

Races, failure conversion, and the commit and Ticket convergence drain
are covered by `test_ibs_product_release_races.py`; the repository
download boundary itself by `test_ibs_product_download_*.py`.

Selection tests run on the rolled back `db_session`; every boundary test
commits through its own unit sessions, so it seeds a `ReleaseWorld` whose
rows are deleted explicitly at teardown. The boundary's module-level
`async_session_factory` is replaced by `UnitSessions` over
`real_session_factory`, `task_publication.publish_task` by a recorder, and
`IBS_DOWNLOAD_BASE_URL` by the fictional `TEST_BASE_URL` served by
`DownloadServer`, so no test reaches a broker or the network. The
package service's evaluation date is pinned to `EVAL`. Unless a test
states otherwise, a Ticket is an `Analysis` Ticket with its own CVE and
every occurrence sits below an `ANALYSIS`/`PENDING` IBS track, holds an
eligible in-support Product, and has `REPOSITORY` as its only current
association. Expected values are transcribed from the specifications.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import DeliveryStatus, PackageStatus, TicketStatus, WorkflowType
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, task_publication
from app.services.packages.ibs_product_release import (
    ProductReleaseCandidate,
    load_product_release_candidates,
    reconcile_ibs_product_releases,
)
from tests.support.ibs_download import (
    REDIRECT_HOST,
    TEST_BASE_URL,
    DownloadServer,
)
from tests.support.ibs_product_release import (
    ADVISORY_ID,
    EARLIER,
    FETCHER,
    HISTORICAL_REPOSITORY,
    ISSUED_AT,
    ISSUED_Z,
    OTHER_ADVISORY_ID,
    OTHER_REPOSITORY,
    PACKAGE,
    REPOSITORY,
    REPOSITORY_FAILED,
    RUN_COMPLETED,
    SIBLING_PACKAGE,
    WAIT,
    Occurrence,
    Outcomes,
    Publish,
    ReleaseWorld,
    Seed,
    UnitSessions,
    between_phases,
    events_of,
    install_units,
    logged,
    matching,
    occurrence_failed,
    reconcile_from,
    recording_client,
    released_at,
    released_events,
    repository,
    run_completed,
    status_response,
    summary,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    StatementRecorder,
)

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

MARKER: Final = "fictional-private-marker"
"""Fictional sensitive text that must never reach a log."""


@pytest.fixture(autouse=True)
def configured_base(monkeypatch: pytest.MonkeyPatch) -> None:
    """The boundary builds `ProductRepositoryDownloads` without `base_url`,
    so the configured `IBS_DOWNLOAD_BASE_URL` points at the fake server."""
    monkeypatch.setattr(settings, "ibs_download_base_url", TEST_BASE_URL)


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
) -> UnitSessions:
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[ReleaseWorld]:
    created = ReleaseWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


async def _selected(
    db: AsyncSession, *occurrences: Occurrence
) -> list[ProductReleaseCandidate]:
    """The unrestricted selection limited to the given occurrences (the
    shared test database may hold other tests' committed rows)."""
    ids = {occurrence.id for occurrence in occurrences}
    return [
        c for c in await load_product_release_candidates(db) if c.occurrence_id in ids
    ]


def _ids(candidates: list[ProductReleaseCandidate]) -> list[uuid.UUID]:
    return [candidate.occurrence_id for candidate in candidates]


def _sorted(*occurrences: Occurrence) -> list[Occurrence]:
    return sorted(occurrences, key=lambda occurrence: occurrence.id)


async def _seeded(
    world: ReleaseWorld, count: int = 1, **kwargs: Any
) -> list[Occurrence]:
    """`count` committed occurrences, each below its own Ticket and
    Product, in occurrence-ID order."""
    seed = Seed(world.session, world)
    created = []
    for _ in range(count):
        ticket = await seed.ticket()
        created.append(await seed.occurrence(ticket, await seed.product(), **kwargs))
    await seed.commit()
    return _sorted(*created)


# ---------------------------------------------------------------------------
# 1. Candidate selection (Scope; Repository Traversal tiers)
# ---------------------------------------------------------------------------


class TestSelection:
    async def test_only_active_tickets_are_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        by_status = {}
        for status in TicketStatus:
            ticket = await seed.ticket(status)
            by_status[status] = await seed.occurrence(ticket, await seed.product())

        selected = await _selected(db_session, *by_status.values())

        active = (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED)
        assert _ids(selected) == sorted(by_status[status].id for status in active)
        for status in (
            TicketStatus.RESOLVED,
            TicketStatus.IGNORED,
            TicketStatus.DUPLICATED,
        ):
            ticket_id = by_status[status].ticket_id
            assert (
                await load_product_release_candidates(db_session, ticket_id=ticket_id)
                == []
            )

    async def test_ticket_without_cve_is_not_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        cveless = await seed.ticket(with_cve=False)
        occurrence = await seed.occurrence(cveless, await seed.product())

        assert await _selected(db_session, occurrence) == []
        assert (
            await load_product_release_candidates(db_session, ticket_id=cveless.id)
            == []
        )

    async def test_released_occurrence_is_not_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        released = await seed.occurrence(
            ticket, await seed.product(), released_at=ISSUED_AT
        )
        unreleased = await seed.occurrence(ticket, await seed.product())

        assert _ids(await _selected(db_session, released, unreleased)) == [
            unreleased.id
        ]

    async def test_same_product_below_a_git_track_is_not_selected(
        self, db_session: AsyncSession
    ) -> None:
        """A catalog Product below both an IBS and a Git track of one
        package yields two occurrences; only the IBS one is in scope."""
        seed = Seed(db_session)
        ticket = await seed.ticket()
        product = await seed.product()
        ibs = await seed.occurrence(ticket, product)
        git = await seed.occurrence(ticket, product, workflow=WorkflowType.GIT)

        assert ibs.package_id == git.package_id
        assert ibs.track_id != git.track_id
        assert _ids(await _selected(db_session, ibs, git)) == [ibs.id]

    async def test_exclusion_eol_eligibility_affectedness_delivery_never_narrow(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        variants: list[dict[str, Any]] = [
            {"excluded": "package"},
            {"excluded": "track"},
            {"excluded": "product"},
            {"eol": True},
            {"eligible": False},
            {"eligible": False, "is_eligible_override": True},
            {"eligible": True, "is_eligible_override": True},
            *({"track_status": status} for status in PackageStatus),
            *({"delivery_status": status} for status in DeliveryStatus),
        ]
        created = []
        for index, variant in enumerate(variants):
            eol = variant.pop("eol", False)
            product = await seed.product(
                general_support_end_date=BEFORE_EVAL if eol else AFTER_EVAL
            )
            created.append(
                await seed.occurrence(
                    ticket, product, package_name=f"example-{index}", **variant
                )
            )

        selected = await _selected(db_session, *created)

        assert _ids(selected) == sorted(occurrence.id for occurrence in created)

    async def test_candidate_carries_the_locator_cve_package_and_tiers(
        self, db_session: AsyncSession
    ) -> None:
        """Associations seen in the latest snapshot are current, older ones
        historical; each tier is in repository-name order."""
        seed = Seed(db_session)
        ticket = await seed.ticket()
        product = await seed.product(
            current=[REPOSITORY, OTHER_REPOSITORY], historical=[HISTORICAL_REPOSITORY]
        )
        occurrence = await seed.occurrence(ticket, product)

        assert await load_product_release_candidates(
            db_session, ticket_id=ticket.id
        ) == [
            occurrence.candidate(
                current=(OTHER_REPOSITORY, REPOSITORY),
                historical=(HISTORICAL_REPOSITORY,),
            )
        ]

    async def test_product_without_current_snapshot_or_associations(
        self, db_session: AsyncSession
    ) -> None:
        """A Product last seen in an earlier snapshot keeps only historical
        associations; a Product without associations has empty tiers."""
        seed = Seed(db_session)
        ticket = await seed.ticket()
        earlier = await seed.product(
            current=[], historical=[REPOSITORY], seen_at=EARLIER
        )
        bare = await seed.product(current=[])
        with_history = await seed.occurrence(ticket, earlier)
        without = await seed.occurrence(ticket, bare, package_name=SIBLING_PACKAGE)

        candidates = await load_product_release_candidates(
            db_session, ticket_id=ticket.id
        )

        assert sorted(candidates, key=lambda c: c.occurrence_id) == sorted(
            [
                with_history.candidate(current=(), historical=(REPOSITORY,)),
                without.candidate(current=(), historical=()),
            ],
            key=lambda c: c.occurrence_id,
        )

    async def test_candidates_are_ordered_by_occurrence_id(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        low, high = sorted([uuid.uuid4(), uuid.uuid4()])
        first = await seed.occurrence(
            await seed.ticket(), await seed.product(), occurrence_id=high
        )
        second = await seed.occurrence(
            await seed.ticket(), await seed.product(), occurrence_id=low
        )

        assert _ids(await _selected(db_session, first, second)) == [low, high]

    async def test_ticket_restriction(self, db_session: AsyncSession) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        mine = await seed.occurrence(ticket, await seed.product())
        other = await seed.occurrence(await seed.ticket(), await seed.product())

        assert _ids(
            await load_product_release_candidates(db_session, ticket_id=ticket.id)
        ) == [mine.id]
        assert _ids(await _selected(db_session, mine, other)) == sorted(
            [mine.id, other.id]
        )
        assert (
            await load_product_release_candidates(db_session, ticket_id=uuid.uuid4())
            == []
        )

    async def test_selection_writes_and_locks_nothing(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        await seed.occurrence(ticket, await seed.product())

        with StatementRecorder(db_session) as recorder:
            candidates = await load_product_release_candidates(
                db_session, ticket_id=ticket.id
            )

        assert len(candidates) == 1
        assert recorder.statements
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted

    async def test_selection_does_not_wait_for_a_held_ticket_lock(
        self, world: ReleaseWorld
    ) -> None:
        """Committed data: an independent holder keeps the Ticket and the
        occurrence locked; the read-only selection completes regardless."""
        (occurrence,) = await _seeded(world)
        holder = await world.open_session()
        await holder.execute(
            select(Ticket.id).where(Ticket.id == occurrence.ticket_id).with_for_update()
        )
        await holder.execute(
            select(TicketPackageProduct.id)
            .where(TicketPackageProduct.id == occurrence.id)
            .with_for_update()
        )
        reader = await world.open_session()

        with SessionStatementRecorder(reader) as recorder:
            candidates = await asyncio.wait_for(
                load_product_release_candidates(reader, ticket_id=occurrence.ticket_id),
                timeout=WAIT,
            )

        assert _ids(candidates) == [occurrence.id]
        assert recorder.row_locks() == []
        assert recorder.writes() == []
        await holder.rollback()


# ---------------------------------------------------------------------------
# 2. Boundary body (Reconciliation Boundary)
# ---------------------------------------------------------------------------


class TestBoundaryBody:
    async def test_empty_collection_performs_no_http_or_database_work(
        self, units: UnitSessions
    ) -> None:
        server = DownloadServer()
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(server, [], hook)

        assert result == summary()
        assert server.requests == []
        assert units.sessions == []
        assert hook.received == []
        assert logs == [run_completed()]

    async def test_duplicate_candidates_are_processed_once(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(occurrence.cve_id)))
        hook = Outcomes()
        candidate = occurrence.candidate()

        with capture_logs() as logs:
            result = await reconcile_from(server, [candidate] * 3, hook)

        assert result == summary(selected=1, updated=1)
        assert hook.kinds == [(occurrence.id, "updated")]
        assert len(units.sessions) == 1
        assert logged(logs, RUN_COMPLETED) == [run_completed(selected=1, updated=1)]
        assert await released_events(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]

    async def test_one_advisory_releases_sibling_packages_below_one_product(
        self, world: ReleaseWorld
    ) -> None:
        """A match for one package never suppresses its sibling package's
        occurrence of the same Product."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        product = await seed.product()
        first, second = _sorted(
            await seed.occurrence(ticket, product),
            await seed.occurrence(ticket, product, package_name=SIBLING_PACKAGE),
        )
        await seed.commit()
        server = DownloadServer()
        server.add(
            REPOSITORY,
            repository(matching(first.cve_id, sources=[PACKAGE, SIBLING_PACKAGE])),
        )
        hook = Outcomes()

        result = await reconcile_from(
            server, [first.candidate(), second.candidate()], hook
        )

        assert result == summary(selected=2, updated=2)
        assert hook.kinds == [(first.id, "updated"), (second.id, "updated")]
        assert await released_at(world, first) == ISSUED_AT
        assert await released_at(world, second) == ISSUED_AT
        assert await released_events(world, ticket.id) == [
            first.released_event(),
            second.released_event(),
        ]

    async def test_one_advisory_releases_two_products_sharing_a_repository(
        self, world: ReleaseWorld
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        first, second = _sorted(
            await seed.occurrence(ticket, await seed.product()),
            await seed.occurrence(ticket, await seed.product()),
        )
        await seed.commit()
        assert first.track_id == second.track_id
        server = DownloadServer()
        item = repository(matching(first.cve_id))
        server.add(REPOSITORY, item)

        result = await reconcile_from(server, [first.candidate(), second.candidate()])

        assert result == summary(selected=2, updated=2)
        assert await released_events(world, ticket.id) == [
            first.released_event(),
            second.released_event(),
        ]
        assert len(server.requests) == 4

    async def test_shared_repository_is_examined_once_per_invocation(
        self, world: ReleaseWorld
    ) -> None:
        """Three occurrences of different Tickets depend on one repository:
        exactly one R1/artifact/R2 examination serves all of them."""
        occurrences = await _seeded(world, 3)
        server = DownloadServer()
        item = repository(matching(*(o.cve_id for o in occurrences)))
        server.add(REPOSITORY, item)

        result = await reconcile_from(server, [o.candidate() for o in occurrences])

        assert result == summary(selected=3, updated=3)
        assert [str(request.url) for request in server.requests] == [
            server.repomd_url(REPOSITORY),
            server.artifact_url(REPOSITORY, item),
            server.artifact_url(REPOSITORY, item, host=REDIRECT_HOST),
            server.repomd_url(REPOSITORY),
        ]
        for occurrence in occurrences:
            assert await released_at(world, occurrence) == ISSUED_AT

    async def test_shared_failing_repository_fails_each_occurrence_once(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        occurrences = await _seeded(world, 3)
        server = DownloadServer()
        server.script(server.repomd_url(REPOSITORY), status_response(403))
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(
                server, [o.candidate() for o in occurrences], hook
            )

        assert result == summary(selected=3, failed=3)
        assert hook.kinds == [(o.id, "failed") for o in occurrences]
        assert [str(r.url) for r in server.requests] == [server.repomd_url(REPOSITORY)]
        assert units.sessions == []
        assert logs == [
            {
                "event": REPOSITORY_FAILED,
                "log_level": "warning",
                "repository": REPOSITORY,
                "affected_occurrence_count": 3,
                "reason_category": "http_status",
                "http_status": 403,
            },
            *(occurrence_failed(o, REPOSITORY, "http_status") for o in occurrences),
            run_completed(selected=3, failed=3),
        ]
        for occurrence in occurrences:
            assert await released_at(world, occurrence) is None
            assert await events_of(world, occurrence.ticket_id) == []


# ---------------------------------------------------------------------------
# 3. Outcomes and transactions (Local mutation and concurrency)
# ---------------------------------------------------------------------------


class TestOutcomes:
    async def test_match_records_the_issued_instant_with_one_event(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(occurrence.cve_id)))
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(server, [occurrence.candidate()], hook)

        assert result == summary(selected=1, updated=1)
        assert hook.kinds == [(occurrence.id, "updated")]
        assert await released_at(world, occurrence) == ISSUED_AT
        assert await events_of(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]
        assert len(units.sessions) == 1
        assert units.closed == units.sessions
        assert logs == [run_completed(selected=1, updated=1)]

    @pytest.mark.parametrize(
        ("advisories", "expected"),
        [
            pytest.param(
                [(ADVISORY_ID, "1720000000"), (OTHER_ADVISORY_ID, "1710000000")],
                (OTHER_ADVISORY_ID, "2024-03-09T16:00:00Z"),
                id="earliest-issued",
            ),
            pytest.param(
                [(OTHER_ADVISORY_ID, "1717068854"), (ADVISORY_ID, "1717068854")],
                (ADVISORY_ID, ISSUED_Z),
                id="equal-time-smallest-id",
            ),
        ],
    )
    async def test_selected_advisory_is_the_earliest_with_id_tiebreak(
        self,
        world: ReleaseWorld,
        advisories: list[tuple[str, str]],
        expected: tuple[str, str],
    ) -> None:
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.add(
            REPOSITORY,
            repository(
                *(
                    matching(occurrence.cve_id, advisory_id=advisory_id, issued=issued)
                    for advisory_id, issued in advisories
                )
            ),
        )

        await reconcile_from(server, [occurrence.candidate()])

        advisory_id, new_value = expected
        assert await released_events(world, occurrence.ticket_id) == [
            occurrence.released_event(new_value, advisory_id)
        ]

    @pytest.mark.parametrize(
        "case", ["other-cve", "other-package", "absent-repository", "no-updateinfo"]
    )
    async def test_no_match_is_a_no_op_without_session(
        self, world: ReleaseWorld, units: UnitSessions, case: str
    ) -> None:
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        if case == "other-cve":
            server.add(REPOSITORY, repository(matching("CVE-2099-99999999")))
        elif case == "other-package":
            server.add(
                REPOSITORY,
                repository(matching(occurrence.cve_id, sources=["example-other"])),
            )
        elif case == "no-updateinfo":
            server.add(REPOSITORY, None)
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(server, [occurrence.candidate()], hook)

        assert result == summary(selected=1, no_op=1)
        assert hook.kinds == [(occurrence.id, "no_op")]
        assert units.sessions == []
        assert logs == [run_completed(selected=1, no_op=1)]
        assert await released_at(world, occurrence) is None
        assert await events_of(world, occurrence.ticket_id) == []

    async def test_historical_tier_match_releases(self, world: ReleaseWorld) -> None:
        """No current association matched, so the retained historical
        association is examined and its advisory releases."""
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching("CVE-2099-99999999")))
        server.add(HISTORICAL_REPOSITORY, repository(matching(occurrence.cve_id)))

        result = await reconcile_from(
            server,
            [
                occurrence.candidate(
                    current=(REPOSITORY,), historical=(HISTORICAL_REPOSITORY,)
                )
            ],
        )

        assert result == summary(selected=1, updated=1)
        assert await released_at(world, occurrence) == ISSUED_AT

    async def test_incomplete_observation_fails_without_mutation(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        """An incomplete current repository suppresses a matching
        historical one: `failed`, no session, no mutation."""
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.script(server.repomd_url(REPOSITORY), status_response(503))
        server.add(HISTORICAL_REPOSITORY, repository(matching(occurrence.cve_id)))
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(
                server,
                [
                    occurrence.candidate(
                        current=(REPOSITORY,), historical=(HISTORICAL_REPOSITORY,)
                    )
                ],
                hook,
            )

        assert result == summary(selected=1, failed=1)
        assert hook.kinds == [(occurrence.id, "failed")]
        assert units.sessions == []
        assert logged(logs, "ibs_product_release_occurrence_failed") == [
            occurrence_failed(occurrence, REPOSITORY, "http_status")
        ]
        assert await released_at(world, occurrence) is None
        assert await events_of(world, occurrence.ticket_id) == []

    async def test_advisory_predating_the_ticket_keeps_its_issued_time(
        self, world: ReleaseWorld
    ) -> None:
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.add(
            REPOSITORY, repository(matching(occurrence.cve_id, issued="1000000000"))
        )
        old = datetime(2001, 9, 9, 1, 46, 40, tzinfo=UTC)
        probe = await world.probe()
        created_at = (
            await probe.execute(
                select(Ticket.created_at).where(Ticket.id == occurrence.ticket_id)
            )
        ).scalar_one()
        await probe.rollback()
        assert created_at > old

        await reconcile_from(server, [occurrence.candidate()])

        assert await released_at(world, occurrence) == old
        assert await released_events(world, occurrence.ticket_id) == [
            occurrence.released_event("2001-09-09T01:46:40Z")
        ]

    async def test_each_match_is_an_independent_transaction(
        self,
        world: ReleaseWorld,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The second occurrence's pre-finalization database failure rolls
        back only its own unit; the first stays committed."""
        first, second = await _seeded(world, 2)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(first.cve_id, second.cve_id)))
        original = package_service.set_product_released_at

        async def failing_second(db: AsyncSession, **kwargs: Any) -> Any:
            result = await original(db, **kwargs)
            if kwargs["ticket_package_product_id"] == second.id:
                raise OperationalError("UPDATE", None, Exception(MARKER))
            return result

        monkeypatch.setattr(package_service, "set_product_released_at", failing_second)

        result = await reconcile_from(server, [first.candidate(), second.candidate()])

        assert result == summary(selected=2, updated=1, failed=1)
        assert len(units.sessions) == 2
        assert units.sessions[0] is not units.sessions[1]
        assert await released_at(world, first) == ISSUED_AT
        assert await released_events(world, first.ticket_id) == [first.released_event()]
        assert await released_at(world, second) is None
        assert await events_of(world, second.ticket_id) == []

    async def test_all_repository_io_precedes_the_first_unit(
        self,
        world: ReleaseWorld,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Every request, including the later occurrences' repositories,
        completes and the download context closes before the first unit
        session (and so the first Ticket lock) is opened."""
        first, second = await _seeded(world, 2)
        (no_match,) = await _seeded(world)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(first.cve_id, second.cve_id)))
        server.add(OTHER_REPOSITORY, repository(matching("CVE-2099-99999999")))
        events: list[str] = []
        units.events = events

        async def closed() -> None:
            events.append("phase-one-closed")

        between_phases(monkeypatch, closed)

        async with recording_client(server, events) as client:
            result = await reconcile_ibs_product_releases(
                [
                    no_match.candidate(current=(OTHER_REPOSITORY,)),
                    second.candidate(),
                    first.candidate(),
                ],
                client=client,
                fetcher_name=FETCHER,
            )

        assert result == summary(selected=3, updated=2, no_op=1)
        assert events == [
            *["http"] * 8,
            "phase-one-closed",
            *["unit", "commit", "close"] * 2,
        ]


# ---------------------------------------------------------------------------
# 7. Audit (Irreversibility, Audit, and Observability)
# ---------------------------------------------------------------------------


class TestAudit:
    async def test_duplicate_evidence_creates_one_event(
        self, world: ReleaseWorld
    ) -> None:
        """An advisory repeated with identical content and a second
        matching advisory still produce one mutation and one event."""
        (occurrence,) = await _seeded(world)
        advisory = matching(occurrence.cve_id)
        server = DownloadServer()
        server.add(
            REPOSITORY,
            repository(
                advisory,
                advisory,
                matching(
                    occurrence.cve_id,
                    advisory_id=OTHER_ADVISORY_ID,
                    issued="1720000000",
                ),
            ),
        )

        result = await reconcile_from(
            server, [occurrence.candidate(), occurrence.candidate()]
        )

        assert result == summary(selected=1, updated=1)
        assert await events_of(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]

    async def test_no_match_and_failed_outcomes_create_no_event(
        self, world: ReleaseWorld
    ) -> None:
        no_match, failed = await _seeded(world, 2)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching("CVE-2099-99999999")))
        server.script(server.repomd_url(OTHER_REPOSITORY), status_response(403))
        assert await events_of(world, no_match.ticket_id) == []
        assert await events_of(world, failed.ticket_id) == []

        result = await reconcile_from(
            server,
            [
                no_match.candidate(),
                failed.candidate(current=(OTHER_REPOSITORY,)),
            ],
        )

        assert result == summary(selected=2, no_op=1, failed=1)
        assert await events_of(world, no_match.ticket_id) == []
        assert await events_of(world, failed.ticket_id) == []

    async def test_repeated_invocation_selects_nothing_and_replays_as_no_op(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        """After a committed release, the next selection is empty; replaying
        the old candidate against an earlier advisory is an irreversible
        no-op without a write or a second event."""
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(occurrence.cve_id)))
        await reconcile_from(server, [occurrence.candidate()])
        reader = await world.probe()
        assert (
            await load_product_release_candidates(
                reader, ticket_id=occurrence.ticket_id
            )
            == []
        )
        await reader.rollback()
        replay = DownloadServer()
        replay.add(
            REPOSITORY,
            repository(
                matching(
                    occurrence.cve_id,
                    advisory_id=OTHER_ADVISORY_ID,
                    issued="1000000000",
                )
            ),
        )
        hook = Outcomes()

        result = await reconcile_from(replay, [occurrence.candidate()], hook)

        assert result == summary(selected=1, no_op=1)
        assert hook.kinds == [(occurrence.id, "no_op")]
        assert len(units.sessions) == 2
        assert await released_at(world, occurrence) == ISSUED_AT
        assert await events_of(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]


# ---------------------------------------------------------------------------
# 8. Dimension independence (Product release part)
# ---------------------------------------------------------------------------


async def _dimensions(world: ReleaseWorld, ticket_id: uuid.UUID) -> list[Any]:
    """Every track's affectedness, delivery, and exclusion and every
    occurrence's eligibility, override, and exclusion of the Ticket."""
    probe = await world.probe()
    rows = (
        await probe.execute(
            select(
                TicketPackage.deleted_at,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
                TicketPackageProduct.id,
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.deleted_at,
            )
            .join(
                TicketPackageTrack,
                TicketPackageTrack.ticket_package_id == TicketPackage.id,
            )
            .join(
                TicketPackageProduct,
                TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id,
            )
            .where(TicketPackage.ticket_id == ticket_id)
            .order_by(TicketPackageProduct.id)
        )
    ).all()
    await probe.rollback()
    return [tuple(row) for row in rows]


class TestDimensionIndependence:
    async def test_every_dimension_value_is_selected_and_released_unchanged(
        self, world: ReleaseWorld
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        variants: list[dict[str, Any]] = [
            *({"track_status": status} for status in PackageStatus),
            *({"delivery_status": status} for status in DeliveryStatus),
            {"eligible": False},
            {"eligible": False, "is_eligible_override": True},
            {"eligible": True, "is_eligible_override": True},
            {"excluded": "package"},
            {"excluded": "track"},
            {"excluded": "product"},
            {"eol": True},
        ]
        names = []
        created = []
        for index, variant in enumerate(variants):
            eol = variant.pop("eol", False)
            product = await seed.product(
                general_support_end_date=BEFORE_EVAL if eol else AFTER_EVAL
            )
            names.append(f"example-{index}")
            created.append(
                await seed.occurrence(
                    ticket, product, package_name=names[-1], **variant
                )
            )
        await seed.commit()
        before = await _dimensions(world, ticket.id)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(created[0].cve_id, sources=names)))
        reader = await world.probe()
        candidates = await load_product_release_candidates(reader, ticket_id=ticket.id)
        await reader.rollback()

        result = await reconcile_from(server, candidates)

        assert _ids(candidates) == sorted(o.id for o in created)
        assert result == summary(selected=len(created), updated=len(created))
        for occurrence in created:
            assert await released_at(world, occurrence) == ISSUED_AT
        assert await released_events(world, ticket.id) == [
            occurrence.released_event() for occurrence in _sorted(*created)
        ]
        assert await _dimensions(world, ticket.id) == before


# ---------------------------------------------------------------------------
# 9. Logs (Irreversibility, Audit, and Observability: bounded logging)
# ---------------------------------------------------------------------------


def _raise(error: BaseException) -> Callable[[httpx.Request], httpx.Response]:
    def respond(_: httpx.Request) -> httpx.Response:
        raise error

    return respond


class TestLogs:
    async def test_mixed_run_events_are_exact_and_bounded(
        self, world: ReleaseWorld
    ) -> None:
        """One updated, one no-match, and one transport-failed occurrence:
        exactly one `occurrence_failed` and one `run_completed` with exact
        fields and counts; no URL, advisory title, XML, or exception text
        reaches these events."""
        updated, no_match, failed = await _seeded(world, 3)
        server = DownloadServer()
        server.add(REPOSITORY, repository(matching(updated.cve_id)))
        server.add(OTHER_REPOSITORY, repository(matching("CVE-2099-99999999")))
        server.script(
            server.repomd_url(HISTORICAL_REPOSITORY),
            _raise(
                httpx.ConnectError(
                    f"https://user:{MARKER}@download.example.test refused"
                )
            ),
        )

        with capture_logs() as logs:
            result = await reconcile_from(
                server,
                [
                    updated.candidate(),
                    no_match.candidate(current=(OTHER_REPOSITORY,)),
                    failed.candidate(current=(HISTORICAL_REPOSITORY,)),
                ],
            )

        assert result == summary(selected=3, updated=1, no_op=1, failed=1)
        own = [
            entry
            for entry in logs
            if entry["event"].startswith("ibs_product_release_occurrence")
            or entry["event"] == RUN_COMPLETED
        ]
        assert own == [
            occurrence_failed(failed, HISTORICAL_REPOSITORY, "transport"),
            run_completed(selected=3, updated=1, no_op=1, failed=1),
        ]
        assert logs[-1] == run_completed(selected=3, updated=1, no_op=1, failed=1)
        rendered = repr(own)
        for forbidden in (MARKER, "https://", "Fictional", "<", ADVISORY_ID):
            assert forbidden not in rendered
        assert MARKER not in repr(logs)

    async def test_occurrence_failed_is_logged_once_per_failed_occurrence(
        self, world: ReleaseWorld
    ) -> None:
        """Both current repositories fail; traversal stops at the first
        (`x86_64` before `aarch64`), so one event names it."""
        (occurrence,) = await _seeded(world)
        server = DownloadServer()
        server.script(server.repomd_url(REPOSITORY), status_response(500))
        server.script(server.repomd_url(OTHER_REPOSITORY), status_response(500))

        with capture_logs() as logs:
            result = await reconcile_from(
                server,
                [
                    occurrence.candidate(
                        current=(OTHER_REPOSITORY, REPOSITORY),
                        historical=(HISTORICAL_REPOSITORY,),
                    ),
                    occurrence.candidate(),
                ],
            )

        assert result == summary(selected=1, failed=1)
        assert logged(logs, "ibs_product_release_occurrence_failed") == [
            occurrence_failed(occurrence, REPOSITORY, "http_status")
        ]
        assert len(logged(logs, REPOSITORY_FAILED)) == 1
        assert len(logged(logs, RUN_COMPLETED)) == 1
