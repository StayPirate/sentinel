"""Integration tests for the shared IBS request reconciliation boundary
(backend/app/services/packages/ibs_request_reconciliation.py): scope
selection, evidence persistence, delivery derivation, stale and
inapplicable scopes, outcomes and failures, audit, logs, and structure.

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Request States; Data
  Model, including the stored form of projects outside `SUSE:` and the
  retained-root index; Retention and Deletion; Observation Outcomes;
  Delivery Derivation; Shared Authoritative Reconciliation > Scope
  Identity, Algorithm steps 1 and 4-10, and Structured Logs; Fetcher >
  Error Handling and Metrics (the outcome kinds); Security and Privacy;
  Testing Requirements).
- docs/features/packages/package-service.md (`set_track_delivery_status()`;
  Excluded and Non-Actionable Records; Architectural Test Requirement:
  Dimension independence, reconciliation rows).
- docs/features/packages/package-model.md (Axis 3; Affectedness-Delivery
  Independence; Automatic Transitions: the delivery table, Delivery status
  regression, RELEASED is irreversible).
- docs/features/platform/testing-strategy.md (Audit Trail Testing;
  Structural Tests).

The observation matrix (roots, proofs, effective SRs, evidence reuse) is
covered by `test_ibs_request_observation.py`; independent-session races
by their own module. Every test here runs one reconciliation at a time.

Selection and index tests run on the rolled back `db_session`. Every
boundary test commits through the boundary's own sessions: the
module-level `async_session_factory` is replaced by `UnitSessions` over
`real_session_factory` (index 0 is the step-1 snapshot session, then one
unit per complete scope), so each test seeds a `RequestWorld` whose rows,
and the evidence of its registered request numbers, are deleted
explicitly at teardown. Every `IBSClient` is a real client of the
authenticating fake IBS API (`FakeRequests`). Unless a test states
otherwise, a scope is an `ANALYSIS`/`PENDING` IBS track of `CODESTREAM`
below an `Analysis` Ticket with its own CVE and a fresh logical package.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, ClassVar, Final
from unittest.mock import AsyncMock

import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, event, select, text, update
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    PackageStatus,
    TicketStatus,
    WorkflowType,
)
from app.models.cve import CVE
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.track_release_checkpoint import TrackReleaseCheckpoint
from app.services import package_service
from app.services.packages import ibs_request_observation, ibs_request_reconciliation
from app.services.packages.ibs_request_reconciliation import (
    IBSRequestOutcome,
    IBSRequestScope,
    load_ibs_request_scopes,
    read_retained_actions,
    reconcile_ibs_requests,
)
from tests.support.ibs_api import status_response, xml_response
from tests.support.ibs_product_release import UnitSessions
from tests.support.ibs_request_reconciliation import (
    CODESTREAM,
    CREATED,
    OTHER_CODESTREAM,
    OTHER_CVE,
    SCOPE_FAILED,
    SCOPE_STALE,
    WHEN,
    WHEN_AT,
    Accept,
    Action,
    EvidenceRow,
    FakeRequests,
    Outcomes,
    RequestSeed,
    RequestWorld,
    checksum,
    committed_number,
    cve_issue,
    delivery_of,
    evidence_of,
    install_fake_requests,
    install_request_units,
    kinds,
    next_incident,
    origin,
    proven_release,
    reconcile,
    release,
    request_document,
    request_rows,
    seed_evidence,
    submission,
    unique_package,
)
from tests.support.ibs_track_release import (
    CHECKPOINT,
    Seed,
    Track,
    events_of,
    logged,
    raising,
)
from tests.support.ticket_mutations import BEFORE_EVAL, RELEASED_AT, StatementRecorder

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

MI: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
MR: Final = IBSRequestActionType.MAINTENANCE_RELEASE
NEW: Final = IBSRequestState.NEW
REVIEW: Final = IBSRequestState.REVIEW
ACCEPTED: Final = IBSRequestState.ACCEPTED
DECLINED: Final = IBSRequestState.DECLINED
REVOKED: Final = IBSRequestState.REVOKED
SUPERSEDED: Final = IBSRequestState.SUPERSEDED
DELETED: Final = IBSRequestState.DELETED

PENDING: Final = DeliveryStatus.PENDING
IN_PROGRESS: Final = DeliveryStatus.IN_PROGRESS
RELEASED: Final = DeliveryStatus.RELEASED

LATER: Final = "2026-10-02T11:00:00"
"""A current-state time newer than the seeded `WHEN_AT`."""
LATER_AT: Final = datetime(2026, 10, 2, 11, 0, 0, tzinfo=UTC)
EARLIER: Final = "2026-10-01T08:00:00"
"""A current-state time older than the seeded `WHEN_AT`."""

RELEASE_REV: Final = "3"
"""The acceptinfo `rev` of every accepted release action built here."""
INDEX_POPULATION: Final = 50
"""Other actions present when the retained-root plan is explained."""

HOME_PROJECT: Final = "home:jdoe:branches:SUSE:SLE-15-SP6:Update"
"""A fictional personal project outside the `SUSE:` namespace."""

MARKER: Final = "fictional-private-marker"
"""Fictional upstream text that must never reach a log or a row."""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    return install_fake_requests(monkeypatch)


@pytest.fixture(autouse=True)
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> UnitSessions:
    return install_request_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RequestWorld]:
    created = RequestWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
def package() -> str:
    return unique_package()


@pytest.fixture
def delivery_calls(monkeypatch: pytest.MonkeyPatch) -> list[DeliveryStatus]:
    """Every value requested from `set_track_delivery_status()`, in order;
    the real function still runs."""
    calls: list[DeliveryStatus] = []
    original = package_service.set_track_delivery_status

    async def spy(
        db: AsyncSession, **kwargs: Any
    ) -> package_service.DeliveryStatusResult:
        calls.append(kwargs["delivery_status"])
        return await original(db, **kwargs)

    monkeypatch.setattr(package_service, "set_track_delivery_status", spy)
    return calls


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def cve_of(scope: IBSRequestScope) -> str:
    assert scope.cve_id is not None
    return scope.cve_id


async def seeded(
    world: RequestWorld,
    count: int = 1,
    *,
    delivery: DeliveryStatus = PENDING,
) -> list[IBSRequestScope]:
    """`count` committed scopes, each below its own Ticket with its own
    package, in track-ID order (the boundary's processing order)."""
    seed = RequestSeed(world)
    created = [
        await seed.track(
            await seed.ticket(), package=unique_package(), delivery=delivery
        )
        for _ in range(count)
    ]
    await seed.commit()
    return sorted(created, key=lambda scope: scope.track_id)


async def correlated(
    seed: RequestSeed,
    scope: IBSRequestScope,
    state: IBSRequestState = REVIEW,
    *,
    upstream_updated_at: datetime = WHEN_AT,
    superseded_by: int | None = None,
) -> tuple[int, Action]:
    """A retained SR of `scope`'s package and codestream in the open form,
    correlated to its track (not committed)."""
    number = seed.world.number()
    action = submission(scope.package_name, number, codestream=scope.codestream)
    await seed.evidence(
        number,
        state,
        action,
        tracks=[scope],
        upstream_updated_at=upstream_updated_at,
        superseded_by=superseded_by,
    )
    return number, action


def open_submission(
    fake: FakeRequests,
    world: RequestWorld,
    scope: IBSRequestScope,
    *issues: str,
    state: IBSRequestState = REVIEW,
    when: str = WHEN,
    created: str = CREATED,
) -> tuple[int, Action]:
    """Route the detail of a new SR of `scope` and its not-accepted diff
    (the Ticket CVE unless `issues` are given). The searches are routed by
    the caller."""
    number = world.number()
    action = submission(scope.package_name, number, codestream=scope.codestream)
    fake.request(number, state, action, when=when, created=created)
    fake.action_diff(
        number,
        action,
        *(issues or (cve_issue(cve_of(scope)),)),
        codestream_package=scope.package_name,
    )
    return number, action


def positive(
    fake: FakeRequests, world: RequestWorld, scope: IBSRequestScope
) -> tuple[int, Action]:
    """One open SR with a positive diff found by the open-SR search, and
    current release evidence without the CVE: a complete `IN_PROGRESS`."""
    number, action = open_submission(fake, world, scope)
    fake.quiet(scope.package_name, scope.codestream, open_submissions=[number])
    return number, action


class _DriverError(Exception):
    """A fictional driver exception, optionally carrying an SQLSTATE."""

    sqlstate: str

    def __init__(self, sqlstate: str | None) -> None:
        super().__init__("fictional driver failure")
        if sqlstate is not None:
            self.sqlstate = sqlstate


def commit_error(
    sqlstate: str | None, *, connection_invalidated: bool = False
) -> OperationalError:
    return OperationalError(
        "COMMIT",
        None,
        _DriverError(sqlstate),
        connection_invalidated=connection_invalidated,
    )


@dataclass
class EventHook:
    """The per-outcome hook appending `hook:<kind>` to the same event list
    as `UnitSessions`."""

    events: list[str]

    def __call__(self, outcome: IBSRequestOutcome) -> None:
        self.events.append(f"hook:{outcome.kind}")


# ---------------------------------------------------------------------------
# Committed state and logs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StoredAction:
    id: uuid.UUID
    request_number: int
    action_type: str
    source_project: str | None
    source_package: str | None
    target_project: str | None
    target_package: str | None
    target_release_project: str | None
    logical_package: str
    codestream_name: str
    incident_number: int | None
    accepted_revision: str | None
    accepted_srcmd5: str | None
    updated_at: datetime


async def stored_actions(world: RequestWorld, *numbers: int) -> list[StoredAction]:
    """Every committed action of the given requests, correlated or not,
    ordered by request number, source package, and ID."""
    probe = await world.probe()
    rows = (
        await probe.execute(
            select(
                IBSRequestAction.id,
                IBSRequest.request_number,
                IBSRequestAction.action_type,
                IBSRequestAction.source_project,
                IBSRequestAction.source_package,
                IBSRequestAction.target_project,
                IBSRequestAction.target_package,
                IBSRequestAction.target_release_project,
                IBSRequestAction.logical_package,
                IBSRequestAction.codestream_name,
                IBSRequestAction.incident_number,
                IBSRequestAction.accepted_revision,
                IBSRequestAction.accepted_srcmd5,
                IBSRequestAction.updated_at,
            )
            .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            .where(IBSRequest.request_number.in_(numbers))
            .order_by(
                IBSRequest.request_number,
                IBSRequestAction.source_package,
                IBSRequestAction.id,
            )
        )
    ).all()
    await probe.rollback()
    return [StoredAction(**row._asdict()) for row in rows]


async def correlations(
    world: RequestWorld, *numbers: int
) -> set[tuple[int, uuid.UUID]]:
    """`(action ID's request number, track ID)` of every committed
    correlation of the given requests' actions."""
    probe = await world.probe()
    rows = (
        await probe.execute(
            select(
                IBSRequest.request_number, IBSRequestActionTrack.ticket_package_track_id
            )
            .join(
                IBSRequestAction,
                IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
            )
            .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            .where(IBSRequest.request_number.in_(numbers))
        )
    ).all()
    await probe.rollback()
    return {(row[0], row[1]) for row in rows}


async def requests_of(
    world: RequestWorld, *numbers: int
) -> dict[int, tuple[str, int | None, datetime, datetime, datetime]]:
    return await request_rows(await world.probe(), numbers)


async def delivery(world: RequestWorld, scope: IBSRequestScope) -> str | None:
    return await delivery_of(await world.probe(), scope.track_id)


async def evidence(world: RequestWorld, scope: IBSRequestScope) -> list[EvidenceRow]:
    return await evidence_of(await world.probe(), scope.track_id)


def scope_fields(scope: IBSRequestScope) -> dict[str, Any]:
    return {
        "log_level": "warning",
        "ticket_id": str(scope.ticket_id),
        "track_id": str(scope.track_id),
        "package_name": scope.package_name,
        "codestream": scope.codestream,
    }


def failed_entry(
    scope: IBSRequestScope,
    reason_category: str,
    *,
    request_number: int | None = None,
    http_status: int | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "event": SCOPE_FAILED,
        **scope_fields(scope),
        "reason_category": reason_category,
    }
    if request_number is not None:
        entry["request_number"] = request_number
    if http_status is not None:
        entry["http_status"] = http_status
    return entry


def stale_entry(scope: IBSRequestScope, reason_category: str) -> dict[str, Any]:
    return {
        "event": SCOPE_STALE,
        **scope_fields(scope),
        "reason_category": reason_category,
    }


def action_diff_count(fake: FakeRequests) -> int:
    return sum(
        1
        for method, _, query in fake.served
        if method == "POST" and ("withissues", "1") in query
    )


# ---------------------------------------------------------------------------
# 1. Scope selection (Scope Identity; Fetcher > Algorithm step 1)
# ---------------------------------------------------------------------------


def scope_of(track: Track) -> IBSRequestScope:
    """The semantic locator of a seeded track."""
    return IBSRequestScope(
        ticket_id=track.ticket_id,
        cve_id=track.cve_id,
        package_id=track.package_id,
        package_name=track.package_name,
        track_id=track.id,
        codestream=track.project,
    )


async def selected(db: AsyncSession, *tracks: Track) -> list[IBSRequestScope]:
    """The unrestricted selection limited to the given tracks (the shared
    test database may hold other tests' committed rows)."""
    ids = {track.id for track in tracks}
    return [
        scope for scope in await load_ibs_request_scopes(db) if scope.track_id in ids
    ]


class TestScopeSelection:
    async def test_every_ibs_track_of_an_active_ticket_is_selected_in_every_state(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        variants: list[dict[str, Any]] = [
            *({"track": {"status": status}} for status in PackageStatus),
            *({"track": {"delivery_status": status}} for status in DeliveryStatus),
            {"track": {"excluded": "package"}},
            {"track": {"excluded": "track"}},
            {"product": {"eligible": False}},
            {"product": {"eligible": False, "is_eligible_override": True}},
            {"product": {"released_at": RELEASED_AT}},
            {"product": {"general_support_end_date": BEFORE_EVAL}},
        ]
        created: list[Track] = []
        for status in (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED):
            ticket = await seed.ticket(status)
            for index, variant in enumerate(variants):
                track = await seed.track(
                    ticket, package_name=f"example-{index}", **variant.get("track", {})
                )
                if "product" in variant:
                    await seed.product(track, **variant["product"])
                created.append(track)
        cveless = await seed.track(await seed.ticket(with_cve=False))
        created.append(cveless)

        scopes = await selected(db_session, *created)

        assert scopes == sorted(
            (scope_of(track) for track in created), key=lambda s: s.track_id
        )
        assert [s for s in scopes if s.track_id == cveless.id] == [
            IBSRequestScope(
                ticket_id=cveless.ticket_id,
                cve_id=None,
                package_id=cveless.package_id,
                package_name=cveless.package_name,
                track_id=cveless.id,
                codestream=CODESTREAM,
            )
        ]

    async def test_git_tracks_and_inactive_tickets_are_not_selected(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        ibs = await seed.track(ticket)
        git = await seed.track(ticket, workflow=WorkflowType.GIT)
        inactive = [
            await seed.track(await seed.ticket(status))
            for status in (
                TicketStatus.RESOLVED,
                TicketStatus.IGNORED,
                TicketStatus.DUPLICATED,
            )
        ]

        assert ibs.package_id == git.package_id
        assert await selected(db_session, ibs, git, *inactive) == [scope_of(ibs)]
        for track in inactive:
            assert (
                await load_ibs_request_scopes(db_session, ticket_id=track.ticket_id)
                == []
            )

    async def test_ticket_scoped_form_returns_its_tracks_in_track_id_order(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        low, high = sorted([uuid.uuid4(), uuid.uuid4()])
        ticket = await seed.ticket()
        later = await seed.track(ticket, track_id=high)
        earlier = await seed.track(
            ticket, package_name="example-other", project=OTHER_CODESTREAM, track_id=low
        )
        other = await seed.track(await seed.ticket())
        await seed.track(ticket, package_name="example-git", workflow=WorkflowType.GIT)

        assert await load_ibs_request_scopes(db_session, ticket_id=ticket.id) == [
            scope_of(earlier),
            scope_of(later),
        ]
        assert [
            s.track_id for s in await selected(db_session, later, earlier, other)
        ] == (sorted([low, high, other.id]))
        assert await load_ibs_request_scopes(db_session, ticket_id=uuid.uuid4()) == []

    async def test_selection_writes_and_locks_nothing(
        self, db_session: AsyncSession
    ) -> None:
        seed = Seed(db_session)
        ticket = await seed.ticket()
        await seed.track(ticket)

        with StatementRecorder(db_session) as recorder:
            scopes = await load_ibs_request_scopes(db_session, ticket_id=ticket.id)

        assert len(scopes) == 1
        assert recorder.statements
        assert recorder.writes() == []
        assert recorder.row_locks() == []


# ---------------------------------------------------------------------------
# 2. Persistence of request evidence (Request States; Data Model; Retention
#    and Deletion; Algorithm steps 6-7)
# ---------------------------------------------------------------------------


class TestEvidencePersistence:
    async def test_open_submission_creates_request_action_correlation_in_progress(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """Upstream times come from detail even when older than the local
        row timestamps."""
        (scope,) = await seeded(world)
        number, _ = open_submission(
            fake,
            world,
            scope,
            created="2019-03-04T05:06:07",
            when="2019-03-05T06:07:08",
        )
        fake.quiet(scope.package_name, open_submissions=[number])

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        rows = await requests_of(world, number)
        state, successor, upstream_created, upstream_updated, updated_at = rows[number]
        assert (state, successor, upstream_created, upstream_updated) == (
            REVIEW.value,
            None,
            datetime(2019, 3, 4, 5, 6, 7, tzinfo=UTC),
            datetime(2019, 3, 5, 6, 7, 8, tzinfo=UTC),
        )
        assert updated_at > upstream_updated
        physical = f"{scope.package_name}.{origin(CODESTREAM)}"
        [action] = await stored_actions(world, number)
        assert action == StoredAction(
            id=action.id,
            request_number=number,
            action_type=MI.value,
            source_project=f"SUSE:Maintenance:REQUEST:{number}",
            source_package=physical,
            target_project="SUSE:Maintenance",
            target_package=None,
            target_release_project=CODESTREAM,
            logical_package=scope.package_name,
            codestream_name=CODESTREAM,
            incident_number=None,
            accepted_revision=None,
            accepted_srcmd5=None,
            updated_at=action.updated_at,
        )
        assert await correlations(world, number) == {(number, scope.track_id)}
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_rerun_of_unchanged_evidence_is_a_no_op_without_write(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await seeded(world)
        number, _ = positive(fake, world, scope)
        await reconcile(fake, [scope])
        requests_before = await requests_of(world, number)
        actions_before = await stored_actions(world, number)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert await requests_of(world, number) == requests_before
        assert await stored_actions(world, number) == actions_before
        assert await correlations(world, number) == {(number, scope.track_id)}
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_review_request_observed_declined_later_is_updated_and_kept(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, action = await correlated(seed, scope)
        await seed.commit()
        fake.request(number, DECLINED, action, when=LATER)
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert (await requests_of(world, number))[number][:4] == (
            DECLINED.value,
            None,
            datetime(2026, 10, 1, 5, 20, 43, tzinfo=UTC),
            LATER_AT,
        )
        assert [row.state for row in await evidence(world, scope)] == [DECLINED.value]
        assert await delivery(world, scope) == PENDING.value

    async def test_declined_request_observed_back_in_review_is_in_progress(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await correlated(seed, scope, DECLINED)
        await seed.commit()
        fake.request(number, REVIEW, action, when=LATER)
        fake.quiet(scope.package_name, open_submissions=[number])

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert [row.state for row in await evidence(world, scope)] == [REVIEW.value]
        assert await delivery(world, scope) == IN_PROGRESS.value
        assert action_diff_count(fake) == 0

    @pytest.mark.parametrize(
        ("retained_state", "current_state", "derived"),
        [
            pytest.param(REVIEW, REVOKED, PENDING, id="review-revoked"),
            pytest.param(REVOKED, NEW, IN_PROGRESS, id="revoked-new"),
            pytest.param(DELETED, REVIEW, IN_PROGRESS, id="deleted-review"),
            pytest.param(SUPERSEDED, NEW, IN_PROGRESS, id="superseded-new"),
            pytest.param(NEW, SUPERSEDED, PENDING, id="new-superseded"),
            pytest.param(DECLINED, DELETED, PENDING, id="declined-deleted"),
        ],
    )
    async def test_any_known_state_replaces_any_other(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        retained_state: IBSRequestState,
        current_state: IBSRequestState,
        derived: DeliveryStatus,
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await correlated(
            seed,
            scope,
            retained_state,
            superseded_by=world.number() if retained_state is SUPERSEDED else None,
        )
        await seed.commit()
        successor = None
        if current_state is SUPERSEDED:
            successor = world.number()
            fake.request(successor, REVOKED, submission(scope.package_name, successor))
        fake.request(number, current_state, action, when=LATER, superseded_by=successor)
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        state, stored_successor, _, upstream_updated, _ = (
            await requests_of(world, number)
        )[number]
        assert (state, stored_successor, upstream_updated) == (
            current_state.value,
            successor,
            LATER_AT,
        )
        assert await correlations(world, number) == {(number, scope.track_id)}
        assert await delivery(world, scope) == derived.value
        assert fake.unrouted == []

    async def test_explicit_deleted_updates_only_the_request_row(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, action = await correlated(seed, scope)
        await seed.commit()
        actions_before = await stored_actions(world, number)
        fake.request(number, DELETED, action, when=LATER)
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        state, _, _, upstream_updated, _ = (await requests_of(world, number))[number]
        assert (state, upstream_updated) == (DELETED.value, LATER_AT)
        assert await stored_actions(world, number) == actions_before
        assert await correlations(world, number) == {(number, scope.track_id)}

    async def test_correlated_request_detail_404_fails_without_write(
        self, world: RequestWorld, fake: FakeRequests, units: UnitSessions
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, _ = await correlated(seed, scope)
        await seed.commit()
        before = await requests_of(world, number)
        fake.respond("GET", f"/request/{number}", [], 404)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "not_found", request_number=number)
        ]
        assert len(units.sessions) == 1
        assert await requests_of(world, number) == before
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_retained_open_sr_observed_accepted_gains_provenance_and_target(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, _ = await correlated(seed, scope)
        await seed.commit()
        incident = next_incident()
        srcmd5 = checksum(f"sr-commit-{number}")
        accepted = submission(
            scope.package_name,
            number,
            incident=incident,
            accept=Accept(rev="2", srcmd5=srcmd5, xsrcmd5=checksum(f"x-{number}")),
        )
        physical = f"{scope.package_name}.{origin(CODESTREAM)}"
        fake.request(number, ACCEPTED, accepted, when=LATER)
        fake.history(
            f"SUSE:Maintenance:{incident}",
            physical,
            [(1, checksum("branch"), None), (2, srcmd5, number)],
        )
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert await evidence(world, scope) == [
            EvidenceRow(
                request_number=number,
                state=ACCEPTED.value,
                superseded_by_request_number=None,
                action_type=MI.value,
                logical_package=scope.package_name,
                codestream_name=CODESTREAM,
                incident_number=incident,
                accepted_revision="2",
                accepted_srcmd5=srcmd5,
                target_project=f"SUSE:Maintenance:{incident}",
                target_package=physical,
                source_project=f"SUSE:Maintenance:REQUEST:{number}",
            )
        ]
        assert len(await stored_actions(world, number)) == 1
        assert await delivery(world, scope) == IN_PROGRESS.value
        assert fake.unrouted == []

    async def test_provenance_omitted_by_detail_is_retained(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """A retained release action has a `target_release_project`; the
        current detail omits it."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, incident = world.number(), next_incident()
        action = release(scope.package_name, incident)
        await seed.evidence(
            number,
            REVIEW,
            action,
            tracks=[scope],
            retained_action={"target_release_project": CODESTREAM},
        )
        await seed.commit()
        fake.request(number, REVIEW, action, when=LATER)
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        [stored] = await stored_actions(world, number)
        assert stored.target_release_project == CODESTREAM
        assert stored.incident_number == incident
        assert (await requests_of(world, number))[number][3] == LATER_AT
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_conflicting_acceptinfo_fails_and_writes_nothing(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The retained accepted RR action carries another `srcmd5` than its
        current detail, whose release is otherwise proven."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, incident = world.number(), next_incident()
        retained_srcmd5 = checksum(f"retained-{number}")
        current_srcmd5 = checksum(f"current-{number}")
        await seed.evidence(
            number,
            ACCEPTED,
            release(
                scope.package_name,
                incident,
                accept=Accept(rev=RELEASE_REV, srcmd5=retained_srcmd5),
            ),
            tracks=[scope],
        )
        await seed.commit()
        current = release(
            scope.package_name,
            incident,
            accept=Accept(rev=RELEASE_REV, srcmd5=current_srcmd5),
        )
        fake.request(number, ACCEPTED, current)
        fake.history(
            CODESTREAM,
            f"{scope.package_name}.{incident}",
            [(int(RELEASE_REV), current_srcmd5, number)],
            revision=RELEASE_REV,
        )
        fake.action_diff(
            number,
            current,
            cve_issue(cve_of(scope)),
            codestream_package=scope.package_name,
        )
        before = await stored_actions(world, number)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "conflicting_provenance", request_number=number)
        ]
        assert await stored_actions(world, number) == before
        assert before[0].accepted_srcmd5 == retained_srcmd5
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_changed_semantic_identity_creates_a_distinct_action(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, old = await correlated(seed, scope)
        await seed.commit()
        renamed = submission(
            scope.package_name,
            number,
            source_package=f"{scope.package_name}.SUSE_Maintenance_{next_incident()}",
        )
        fake.request(number, REVIEW, renamed)
        fake.action_diff(
            number,
            renamed,
            cve_issue(cve_of(scope)),
            codestream_package=scope.package_name,
        )
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        stored = await stored_actions(world, number)
        assert sorted(a.source_package or "" for a in stored) == sorted(
            [old.source_package, renamed.source_package]
        )
        assert {a.logical_package for a in stored} == {scope.package_name}
        assert len(await evidence(world, scope)) == 2
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_project_outside_suse_is_persisted_only_as_the_redaction_token(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """An SR from a personal project, found open by the search and now
        accepted; its diff is the accepted form through the incident."""
        (scope,) = await seeded(world)
        number, incident = world.number(), next_incident()
        srcmd5 = checksum(f"sr-commit-{number}")
        action = submission(
            scope.package_name,
            number,
            incident=incident,
            accept=Accept(rev="2", srcmd5=srcmd5),
            source_project=HOME_PROJECT,
        )
        fake.request(number, ACCEPTED, action)
        fake.action_diff(
            number,
            action,
            cve_issue(cve_of(scope)),
            codestream_package=scope.package_name,
        )
        assert action.target_package is not None
        fake.history(
            f"SUSE:Maintenance:{incident}",
            action.target_package,
            [(1, checksum("branch"), None), (2, srcmd5, number)],
        )
        fake.quiet(scope.package_name, open_submissions=[number])

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        [stored] = await stored_actions(world, number)
        assert stored.source_project == "_redacted_"
        assert stored.target_project == f"SUSE:Maintenance:{incident}"
        persisted = repr(stored) + repr(await requests_of(world, number))
        assert "home:" not in persisted
        assert "jdoe" not in persisted
        assert all("home:" not in str(request.url) for request in fake.server.requests)
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_one_action_correlates_to_tracks_of_two_tickets(
        self, world: RequestWorld, fake: FakeRequests, package: str
    ) -> None:
        seed = RequestSeed(world)
        first = await seed.track(await seed.ticket(), package=package)
        second = await seed.track(await seed.ticket(), package=package)
        await seed.commit()
        number, _ = open_submission(
            fake, world, first, cve_issue(cve_of(first)), cve_issue(cve_of(second))
        )
        fake.quiet(package, open_submissions=[number])

        outcomes = await reconcile(fake, [first, second])

        assert kinds(outcomes) == {
            first.track_id: "created",
            second.track_id: "created",
        }
        assert len(await stored_actions(world, number)) == 1
        assert await correlations(world, number) == {
            (number, first.track_id),
            (number, second.track_id),
        }
        assert action_diff_count(fake) == 1
        for scope in (first, second):
            assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_several_actions_correlate_to_one_track(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await seeded(world)
        first, _ = open_submission(fake, world, scope)
        second, _ = open_submission(fake, world, scope, state=NEW)
        fake.quiet(scope.package_name, open_submissions=[first, second])

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert await correlations(world, first, second) == {
            (first, scope.track_id),
            (second, scope.track_id),
        }

    async def test_correlation_is_retained_across_a_later_complete_no_match(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The correlated SR is revoked and a new SR's valid diff names
        another CVE: the old correlation stays, the new SR is not
        persisted."""
        (scope,) = await seeded(world)
        number, action = positive(fake, world, scope)
        await reconcile(fake, [scope])
        fake.request(number, REVOKED, action, when=LATER)
        unrelated, _ = open_submission(fake, world, scope, cve_issue(OTHER_CVE))
        fake.quiet(scope.package_name, open_submissions=[unrelated])

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert await correlations(world, number, unrelated) == {
            (number, scope.track_id)
        }
        assert unrelated not in await requests_of(world, number, unrelated)
        assert await delivery(world, scope) == PENDING.value

    async def test_equal_time_conflicting_detail_fails_and_writes_nothing(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, action = await correlated(seed, scope)
        await seed.commit()
        before = await requests_of(world, number)
        fake.request(number, DECLINED, action, when=WHEN)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "conflicting_observation", request_number=number)
        ]
        assert await requests_of(world, number) == before
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_older_detail_than_the_stored_request_fails_as_stale(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, action = await correlated(seed, scope)
        await seed.commit()
        before = await requests_of(world, number)
        fake.request(number, DECLINED, action, when=EARLIER)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "stale_request_observation", request_number=number)
        ]
        assert await requests_of(world, number) == before
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_action_insert_meeting_an_existing_identity_reloads_it(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the action insert finds the identity already present, the
        winner is reloaded and the same comparison applies; nothing is
        replaced or duplicated."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await correlated(seed, scope)
        await seed.commit()
        fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name)
        original = ibs_request_reconciliation._lock_actions
        calls: list[int] = []

        async def first_misses(db: AsyncSession, request_ids: Any) -> Any:
            calls.append(len(calls))
            locked = await original(db, request_ids)
            return {} if len(calls) == 1 else locked

        monkeypatch.setattr(ibs_request_reconciliation, "_lock_actions", first_misses)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert calls == [0, 1]
        assert len(await stored_actions(world, number)) == 1
        assert [row.request_number for row in await evidence(world, scope)] == [number]

    async def test_identity_still_absent_after_the_reload_fails_the_scope(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The insert met an existing identity that the reload cannot find
        (inconsistent locked state): the scope fails and writes nothing."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await correlated(seed, scope)
        await seed.commit()
        fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name)

        async def always_misses(db: AsyncSession, request_ids: Any) -> Any:
            return {}

        monkeypatch.setattr(ibs_request_reconciliation, "_lock_actions", always_misses)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "conflicting_provenance", request_number=number)
        ]
        assert len(await stored_actions(world, number)) == 1
        assert await delivery(world, scope) == PENDING.value

    async def test_multi_action_request_persists_only_its_relevant_action(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await seeded(world)
        package_name = scope.package_name
        number, incident = world.number(), next_incident()
        matching = release(package_name, incident)
        patchinfo = Action(
            type=MR.value,
            source_project=f"SUSE:Maintenance:{incident}",
            source_package="patchinfo",
            rev=checksum(f"patchinfo-{incident}"),
            target_project=CODESTREAM,
            target_package=f"patchinfo.{incident}",
        )
        other_codestream = release(package_name, incident, codestream=OTHER_CODESTREAM)
        submit = (
            f'<action type="submit"><source project="SUSE:Maintenance:{incident}" '
            f'package="{package_name}-channel"/></action>'
        )
        fake.request(
            number,
            REVIEW,
            patchinfo,
            matching,
            other_codestream,
            extra_actions=[submit],
        )
        fake.action_diff(
            number, matching, cve_issue(cve_of(scope)), codestream_package=package_name
        )
        fake.quiet(package_name, open_releases=[number])

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        [stored] = await stored_actions(world, number)
        assert (stored.action_type, stored.target_project, stored.target_package) == (
            MR.value,
            CODESTREAM,
            f"{package_name}.{incident}",
        )
        assert await delivery(world, scope) == IN_PROGRESS.value


# ---------------------------------------------------------------------------
# 3. Delivery derivation (Delivery Derivation; package-model.md Automatic
#    Transitions)
# ---------------------------------------------------------------------------


class TestDeliveryDerivation:
    async def test_pending_to_in_progress(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        (scope,) = await seeded(world)
        positive(fake, world, scope)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert delivery_calls == [IN_PROGRESS]
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_in_progress_to_released_through_a_proven_release(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        (scope,) = await seeded(world, delivery=IN_PROGRESS)
        number, _ = proven_release(fake, world, scope)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert delivery_calls == [RELEASED]
        assert await delivery(world, scope) == RELEASED.value
        assert await correlations(world, number) == {(number, scope.track_id)}
        assert fake.unrouted == []

    async def test_pending_to_released_applies_both_transitions_in_one_unit(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        (scope,) = await seeded(world)
        proven_release(fake, world, scope)
        units.events = []

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert delivery_calls == [IN_PROGRESS, RELEASED]
        assert units.events == ["unit", "close", "unit", "commit", "close"]
        assert await delivery(world, scope) == RELEASED.value

    async def test_delivery_change_alone_is_an_update(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """A `PENDING` track correlated to an open SR whose detail is
        unchanged: no evidence write, one delivery change, `updated`."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await correlated(seed, scope)
        await seed.commit()
        before = await requests_of(world, number)
        fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == [IN_PROGRESS]
        assert await requests_of(world, number) == before
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_released_baseline_refreshes_evidence_and_stays_released(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=RELEASED
        )
        number, action = await correlated(seed, scope)
        await seed.commit()
        fake.request(number, DECLINED, action, when=LATER)
        fake.quiet(scope.package_name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert (await requests_of(world, number))[number][0] == DECLINED.value
        assert delivery_calls == []
        assert await delivery(world, scope) == RELEASED.value

    @pytest.mark.parametrize(
        ("status", "reason"),
        [
            pytest.param(404, "not_found", id="incomplete"),
            pytest.param(500, "http_status", id="failed"),
        ],
    )
    async def test_incomplete_or_failed_observation_never_changes_delivery(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        delivery_calls: list[DeliveryStatus],
        status: int,
        reason: str,
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, _ = await correlated(seed, scope)
        await seed.commit()
        fake.respond("GET", f"/request/{number}", [], status)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        [entry] = logged(logs, SCOPE_FAILED)
        assert entry["reason_category"] == reason
        assert delivery_calls == []
        assert len(units.sessions) == 1
        assert await delivery(world, scope) == IN_PROGRESS.value

    async def test_cve_less_scope_is_a_no_op_without_ibs_request(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(with_cve=False), package=unique_package()
        )
        await seed.commit()

        outcomes = await reconcile(fake, [scope])

        assert scope.cve_id is None
        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert fake.server.requests == []
        assert delivery_calls == []
        assert await delivery(world, scope) == PENDING.value
        assert await evidence(world, scope) == []


# ---------------------------------------------------------------------------
# 4. Stale and inapplicable scopes (Algorithm step 5; Structured Logs)
# ---------------------------------------------------------------------------


Change = Callable[[RequestSeed, IBSRequestScope], Awaitable[None]]


async def _set_ticket(seed: RequestSeed, scope: IBSRequestScope, **values: Any) -> None:
    await seed.session.execute(
        update(Ticket).where(Ticket.id == scope.ticket_id).values(**values)
    )


async def _resolved(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await _set_ticket(seed, scope, status=TicketStatus.RESOLVED.value)


async def _ignored(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await _set_ticket(seed, scope, status=TicketStatus.IGNORED.value)


async def _duplicated(seed: RequestSeed, scope: IBSRequestScope) -> None:
    canonical = await seed.ticket(with_cve=False)
    await _set_ticket(
        seed, scope, status=TicketStatus.DUPLICATED.value, duplicate_of_id=canonical.id
    )


async def _set_track(seed: RequestSeed, scope: IBSRequestScope, **values: Any) -> None:
    await seed.session.execute(
        update(TicketPackageTrack)
        .where(TicketPackageTrack.id == scope.track_id)
        .values(**values)
    )


async def _git_workflow(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await _set_track(seed, scope, workflow_type=WorkflowType.GIT.value)


async def _other_reference(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await _set_track(seed, scope, reference=OTHER_CODESTREAM)


async def _renamed_package(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await seed.session.execute(
        update(TicketPackage)
        .where(TicketPackage.id == scope.package_id)
        .values(package_name=f"{scope.package_name}-renamed")
    )


async def _other_cve(seed: RequestSeed, scope: IBSRequestScope) -> None:
    cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
    seed.session.add(cve)
    await seed.session.flush()
    seed.world.cve_ids.append(cve.id)
    await _set_ticket(seed, scope, cve_id=cve.id)


async def _removed_cve(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await _set_ticket(seed, scope, cve_id=None)


async def _deleted_track(seed: RequestSeed, scope: IBSRequestScope) -> None:
    await seed.session.execute(
        delete(TicketPackageTrack).where(TicketPackageTrack.id == scope.track_id)
    )


class TestStaleScopes:
    @pytest.mark.parametrize(
        ("change", "reason"),
        [
            pytest.param(_resolved, "scope_changed", id="ticket-resolved"),
            pytest.param(_ignored, "ticket_not_operable", id="ticket-ignored"),
            pytest.param(_duplicated, "ticket_not_operable", id="ticket-duplicated"),
            pytest.param(_git_workflow, "scope_changed", id="workflow-git"),
            pytest.param(_other_reference, "scope_changed", id="reference-changed"),
            pytest.param(_renamed_package, "scope_changed", id="package-renamed"),
            pytest.param(_other_cve, "scope_changed", id="cve-changed"),
            pytest.param(_removed_cve, "scope_changed", id="cve-removed"),
            pytest.param(_deleted_track, "scope_changed", id="track-deleted"),
        ],
    )
    async def test_changed_scope_is_a_stale_no_op_without_write(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
        change: Change,
        reason: str,
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        await seed.commit()
        number, _ = positive(fake, world, scope)
        await change(seed, scope)
        await seed.commit()

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert logged(logs, SCOPE_STALE) == [stale_entry(scope, reason)]
        assert logged(logs, SCOPE_FAILED) == []
        assert await requests_of(world, number) == {}
        assert await evidence(world, scope) == []
        assert delivery_calls == []
        expected = None if change is _deleted_track else PENDING.value
        assert await delivery(world, scope) == expected


# ---------------------------------------------------------------------------
# 5. Outcomes, hook, and failures (Algorithm step 10; Fetcher > Error
#    Handling and Metrics)
# ---------------------------------------------------------------------------


class TestMissingTicket:
    async def test_scope_of_a_missing_ticket_is_a_stale_no_op(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """A scope whose Ticket (and track) no longer exist: no IBS request,
        then a stale `scope_changed` no-op under the locked revalidation."""
        scope = IBSRequestScope(
            ticket_id=uuid.uuid4(),
            cve_id=f"CVE-2099-{committed_number() % 10**8:08d}",
            package_id=uuid.uuid4(),
            package_name=unique_package(),
            track_id=uuid.uuid4(),
            codestream=CODESTREAM,
        )

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert fake.server.requests == []
        assert logged(logs, SCOPE_STALE) == [stale_entry(scope, "scope_changed")]


class TestOutcomesAndFailures:
    async def test_empty_selection_performs_no_request_and_opens_no_session(
        self, fake: FakeRequests, units: UnitSessions
    ) -> None:
        hook = Outcomes()

        outcomes = await reconcile(fake, [], hook)

        assert outcomes == []
        assert hook.received == []
        assert fake.server.requests == []
        assert units.sessions == []

    async def test_duplicate_scopes_are_processed_once(
        self, world: RequestWorld, fake: FakeRequests, units: UnitSessions
    ) -> None:
        (scope,) = await seeded(world)
        positive(fake, world, scope)
        hook = Outcomes()

        outcomes = await reconcile(fake, [scope, scope, scope], hook)

        assert outcomes == [IBSRequestOutcome(scope.track_id, "created")]
        assert hook.received == outcomes
        assert len(units.sessions) == 2
        assert action_diff_count(fake) == 1

    async def test_each_scope_receives_one_created_updated_or_no_op_outcome(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        created = await seed.track(await seed.ticket(), package=unique_package())
        updated = await seed.track(await seed.ticket(), package=unique_package())
        unchanged = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        declined, declined_action = await correlated(seed, updated)
        kept, kept_action = await correlated(seed, unchanged)
        await seed.commit()
        positive(fake, world, created)
        fake.request(declined, DECLINED, declined_action, when=LATER)
        fake.quiet(updated.package_name)
        fake.request(kept, REVIEW, kept_action)
        fake.quiet(unchanged.package_name, open_submissions=[kept])
        hook = Outcomes()

        outcomes = await reconcile(fake, [unchanged, updated, created], hook)

        assert kinds(outcomes) == {
            created.track_id: "created",
            updated.track_id: "updated",
            unchanged.track_id: "no_op",
        }
        assert [o.track_id for o in outcomes] == sorted(
            [created.track_id, updated.track_id, unchanged.track_id]
        )
        assert hook.received == outcomes

    async def test_hook_runs_after_the_commit_and_before_the_session_close(
        self, world: RequestWorld, fake: FakeRequests, units: UnitSessions
    ) -> None:
        (scope,) = await seeded(world)
        positive(fake, world, scope)
        events: list[str] = []
        units.events = events

        await reconcile(fake, [scope], EventHook(events))

        assert events == ["unit", "close", "unit", "commit", "hook:created", "close"]

    async def test_failed_observation_calls_the_hook_without_a_unit(
        self, world: RequestWorld, fake: FakeRequests, units: UnitSessions
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, _ = await correlated(seed, scope)
        await seed.commit()
        fake.respond("GET", f"/request/{number}", [], 404)
        fake.quiet(scope.package_name)
        events: list[str] = []
        units.events = events

        await reconcile(fake, [scope], EventHook(events))

        assert events == ["unit", "close", "hook:failed"]

    async def test_incomplete_scope_leaves_a_committed_sibling(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        failing = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        sibling = await seed.track(await seed.ticket(), package=unique_package())
        number, _ = await correlated(seed, failing)
        await seed.commit()
        fake.respond("GET", f"/request/{number}", [], 404)
        fake.quiet(failing.package_name)
        created, _ = positive(fake, world, sibling)

        outcomes = await reconcile(fake, [failing, sibling])

        assert kinds(outcomes) == {
            failing.track_id: "failed",
            sibling.track_id: "created",
        }
        assert await correlations(world, created) == {(created, sibling.track_id)}
        assert await delivery(world, sibling) == IN_PROGRESS.value
        assert await delivery(world, failing) == IN_PROGRESS.value

    async def test_definitely_rejected_commit_fails_the_scope_and_continues(
        self, world: RequestWorld, fake: FakeRequests, units: UnitSessions
    ) -> None:
        first, second = await seeded(world, 2)
        rejected, _ = positive(fake, world, first)
        committed, _ = positive(fake, world, second)
        units.failing_commit = (1, commit_error("40001"))
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [first, second], hook)

        assert kinds(outcomes) == {first.track_id: "failed", second.track_id: "created"}
        assert hook.received == outcomes
        assert logged(logs, SCOPE_FAILED) == [failed_entry(first, "database")]
        assert await requests_of(world, rejected) == {}
        assert await delivery(world, first) == PENDING.value
        assert await correlations(world, committed) == {(committed, second.track_id)}
        assert units.closed == units.sessions

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(commit_error(None), id="no-sqlstate"),
            pytest.param(
                commit_error("40001", connection_invalidated=True),
                id="connection-invalidated",
            ),
            pytest.param(commit_error("08006"), id="connection-class-sqlstate"),
        ],
    )
    async def test_commit_with_unknown_outcome_ends_the_invocation(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        error: OperationalError,
    ) -> None:
        first, second, third = await seeded(world, 3)
        committed, _ = positive(fake, world, first)
        unknown, _ = positive(fake, world, second)
        untouched, _ = positive(fake, world, third)
        units.failing_commit = (2, error)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await reconcile(fake, [first, second, third], hook)

        assert raised.value is error
        assert hook.received == [IBSRequestOutcome(first.track_id, "created")]
        assert logged(logs, SCOPE_FAILED) == []
        assert len(units.sessions) == 3
        assert units.closed == units.sessions
        assert await correlations(world, committed) == {(committed, first.track_id)}
        assert await requests_of(world, unknown, untouched) == {}
        assert third.package_name not in repr(fake.served)

    async def test_rejected_delivery_transition_fails_the_scope(
        self, world: RequestWorld, fake: FakeRequests, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (scope,) = await seeded(world)
        number, _ = positive(fake, world, scope)

        async def rejecting(db: AsyncSession, **kwargs: Any) -> Any:
            raise package_service.InvalidDeliveryStatusTransition(
                PENDING, kwargs["delivery_status"]
            )

        monkeypatch.setattr(package_service, "set_track_delivery_status", rejecting)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "invalid_delivery_transition")
        ]
        assert await requests_of(world, number) == {}
        assert await delivery(world, scope) == PENDING.value

    async def test_database_error_in_the_unit_fails_the_scope(
        self, world: RequestWorld, fake: FakeRequests, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (scope,) = await seeded(world)
        number, _ = positive(fake, world, scope)

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise SQLAlchemyError("fictional database failure")

        monkeypatch.setattr(package_service, "set_track_delivery_status", failing)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [failed_entry(scope, "database")]
        assert await requests_of(world, number) == {}
        assert await delivery(world, scope) == PENDING.value

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_whole_run_signal_from_ibs_propagates(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        make_error: Callable[[], BaseException],
    ) -> None:
        first, second, third = await seeded(world, 3)
        committed, _ = positive(fake, world, first)
        error = make_error()
        fake.release_evidence(CODESTREAM, second.package_name)
        fake.search(MI, second.package_name, responder=raising(error))
        untouched, _ = positive(fake, world, third)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await reconcile(fake, [first, second, third], hook)

        assert raised.value is error
        assert hook.received == [IBSRequestOutcome(first.track_id, "created")]
        assert logged(logs, SCOPE_FAILED) == []
        assert await correlations(world, committed) == {(committed, first.track_id)}
        assert await requests_of(world, untouched) == {}
        assert third.package_name not in repr(fake.served)


# ---------------------------------------------------------------------------
# 6. Credentials and authentication (Structured Logs reason categories)
# ---------------------------------------------------------------------------


class TestCredentialsAndAuthentication:
    async def test_unconfigured_client_fails_every_scope_without_request(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        scopes = await seeded(world, 2)
        numbers = [positive(fake, world, scope)[0] for scope in scopes]

        with capture_logs() as logs:
            outcomes = await reconcile(fake, scopes, configured=False)

        assert kinds(outcomes) == {scope.track_id: "failed" for scope in scopes}
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(scope, "credentials_not_configured") for scope in scopes
        ]
        assert fake.server.requests == []
        assert await requests_of(world, *numbers) == {}

    async def test_rejected_signatures_fail_with_their_reason(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await seeded(world)
        number, _ = positive(fake, world, scope)
        fake.server.reject_signatures = True

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [failed_entry(scope, "signature_rejected")]
        assert fake.served == []
        assert await requests_of(world, number) == {}


# ---------------------------------------------------------------------------
# 7. Audit (Delivery Derivation: no Ticket event; Audit Trail Testing)
# ---------------------------------------------------------------------------


class TestAudit:
    async def test_no_outcome_creates_or_reads_a_ticket_audit_event(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """Effective evidence and delivery change, unchanged re-run, stale
        scope, incomplete scope, and failed unit."""
        seed = RequestSeed(world)
        effective = await seed.track(await seed.ticket(), package=unique_package())
        stale = await seed.track(await seed.ticket(), package=unique_package())
        incomplete = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        failed = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        missing, _ = await correlated(seed, incomplete)
        conflicting, conflicting_action = await correlated(seed, failed)
        await seed.commit()
        positive(fake, world, effective)
        positive(fake, world, stale)
        await _resolved(seed, stale)
        await seed.commit()
        fake.respond("GET", f"/request/{missing}", [], 404)
        fake.quiet(incomplete.package_name)
        fake.request(conflicting, DECLINED, conflicting_action, when=WHEN)
        fake.quiet(failed.package_name)
        scopes = [effective, stale, incomplete, failed]
        for scope in scopes:
            assert await events_of(world, scope.ticket_id) == []

        with StatementRecorder(world.session) as recorder:
            first = await reconcile(fake, scopes)
            rerun = await reconcile(fake, [effective])

        assert kinds(first) == {
            effective.track_id: "created",
            stale.track_id: "no_op",
            incomplete.track_id: "failed",
            failed.track_id: "failed",
        }
        assert kinds(rerun) == {effective.track_id: "no_op"}
        assert await delivery(world, effective) == IN_PROGRESS.value
        for scope in scopes:
            assert await events_of(world, scope.ticket_id) == []
        assert any("INSERT INTO ibs_request" in s for s in recorder.statements)
        assert [s for s in recorder.statements if "ticket_audit_event" in s] == []


# ---------------------------------------------------------------------------
# 8. Logs and privacy (Structured Logs; Security and Privacy)
# ---------------------------------------------------------------------------


class TestLogsAndPrivacy:
    async def test_scope_outside_suse_fails_without_request_or_codestream_field(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(),
            package=unique_package(),
            codestream="openSUSE:Leap:15.6:Update",
        )
        await seed.commit()

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert fake.server.requests == []
        assert logged(logs, SCOPE_FAILED) == [
            {
                "event": SCOPE_FAILED,
                "log_level": "warning",
                "ticket_id": str(scope.ticket_id),
                "track_id": str(scope.track_id),
                "package_name": scope.package_name,
                "reason_category": "outside_suse_namespace",
            }
        ]

    async def test_logs_carry_no_personal_project_account_credential_or_text(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """A redacted personal-project SR, a detail with a fictional private
        description, and a failing detail whose body carries the same
        marker."""
        seed = RequestSeed(world)
        redacted = await seed.track(await seed.ticket(), package=unique_package())
        described = await seed.track(await seed.ticket(), package=unique_package())
        failing = await seed.track(await seed.ticket(), package=unique_package())
        broken, _ = await correlated(seed, failing)
        await seed.commit()
        number, incident = world.number(), next_incident()
        srcmd5 = checksum(f"sr-commit-{number}")
        personal = submission(
            redacted.package_name,
            number,
            incident=incident,
            accept=Accept(rev="2", srcmd5=srcmd5),
            source_project=HOME_PROJECT,
        )
        fake.request(number, ACCEPTED, personal)
        fake.action_diff(
            number,
            personal,
            cve_issue(cve_of(redacted)),
            codestream_package=redacted.package_name,
        )
        assert personal.target_package is not None
        fake.history(
            f"SUSE:Maintenance:{incident}",
            personal.target_package,
            [(1, checksum("branch"), None), (2, srcmd5, number)],
        )
        fake.quiet(redacted.package_name, open_submissions=[number])
        described_number = world.number()
        described_action = submission(described.package_name, described_number)
        document = request_document(described_number, REVIEW, described_action).replace(
            b"<state", f"<description>{MARKER}</description><state".encode()
        )
        fake.raw_request(described_number, xml_response(document))
        fake.action_diff(
            described_number,
            described_action,
            cve_issue(cve_of(described)),
            codestream_package=described.package_name,
        )
        fake.quiet(described.package_name, open_submissions=[described_number])
        fake.raw_request(broken, status_response(500, MARKER.encode()))
        fake.quiet(failing.package_name)

        with capture_logs() as logs:
            outcomes = await reconcile(fake, [redacted, described, failing])

        assert kinds(outcomes) == {
            redacted.track_id: "created",
            described.track_id: "created",
            failing.track_id: "failed",
        }
        rendered = repr(logs)
        for forbidden in ("home:", "jdoe", MARKER, "_redacted_"):
            assert forbidden not in rendered
        assert "authorization" not in rendered.lower()
        assert "signature" not in rendered.lower()
        assert logged(logs, SCOPE_FAILED) == [
            failed_entry(failing, "http_status", request_number=broken, http_status=500)
        ]
        persisted = repr(await stored_actions(world, number, described_number))
        assert MARKER not in persisted
        assert "home:" not in persisted

    @pytest.mark.parametrize(
        "fetcher_name",
        [
            pytest.param(None, id="without-fetcher-name"),
            pytest.param("sync_ibs_requests", id="with-fetcher-name"),
        ],
    )
    @pytest.mark.parametrize("failure", ["incomplete-observation", "local-failure"])
    async def test_scope_failed_carries_fetcher_name_only_when_given(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        fetcher_name: str | None,
        failure: str,
    ) -> None:
        """Structured Logs: the optional `fetcher_name` of
        `ibs_request_scope_failed` accompanies every failed scope of an
        invocation that names its fetcher, and is absent otherwise; the
        stale and other events never carry it."""
        incomplete = failure == "incomplete-observation"
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(),
            package=unique_package(),
            delivery=IN_PROGRESS if incomplete else PENDING,
        )
        number, action = await correlated(seed, scope)
        await seed.commit()
        if incomplete:
            fake.respond("GET", f"/request/{number}", [], 404)
            fake.quiet(scope.package_name)
            expected = failed_entry(scope, "not_found", request_number=number)
        else:
            # The correlated SR is still open: a complete positive whose
            # delivery mutation is rejected inside the locked unit.
            fake.request(number, REVIEW, action)
            fake.quiet(scope.package_name)

            async def rejecting(db: AsyncSession, **kwargs: Any) -> Any:
                raise package_service.InvalidDeliveryStatusTransition(
                    PENDING, kwargs["delivery_status"]
                )

            monkeypatch.setattr(package_service, "set_track_delivery_status", rejecting)
            expected = failed_entry(scope, "invalid_delivery_transition")
        if fetcher_name is not None:
            expected["fetcher_name"] = fetcher_name

        with capture_logs() as logs:
            async with fake.client() as client:
                outcomes = await reconcile_ibs_requests(
                    [scope], client=client, fetcher_name=fetcher_name
                )

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert logged(logs, SCOPE_FAILED) == [expected]
        assert [e for e in logs if "fetcher_name" in e] == (
            [expected] if fetcher_name is not None else []
        )


# ---------------------------------------------------------------------------
# 9. Structure (Algorithm: no IBS I/O under the Ticket lock; Structural
#    Tests)
# ---------------------------------------------------------------------------


class TestStructure:
    async def test_request_delay_spaces_every_later_request_outside_sessions(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The caller's delay precedes every IBS request of the invocation
        but the first, across scopes, and never runs while the snapshot
        session or a unit is open."""
        scopes = await seeded(world, 2)
        for scope in scopes:
            positive(fake, world, scope)
        open_while_waiting: list[bool] = []

        async def wait(_: float) -> None:
            open_while_waiting.append(len(units.sessions) != len(units.closed))

        recorder = AsyncMock(side_effect=wait)
        monkeypatch.setattr(
            ibs_request_observation, "asyncio", SimpleNamespace(sleep=recorder)
        )

        outcomes = await reconcile(fake, scopes, request_delay=0.25)

        assert kinds(outcomes) == {scope.track_id: "created" for scope in scopes}
        assert recorder.await_count == len(fake.served) - 1
        assert {call.args for call in recorder.await_args_list} == {(0.25,)}
        assert open_while_waiting == [False] * recorder.await_count

    async def test_no_ibs_request_is_served_while_a_session_is_open(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Neither the step-1 snapshot session nor a unit (which holds the
        Ticket lock) is open while IBS serves a request."""
        scopes = await seeded(world, 2)
        for scope in scopes:
            positive(fake, world, scope)
        state = {"locked": False, "units": 0}
        original = ibs_request_reconciliation._reconcile_scope

        async def wrapped(db: AsyncSession, *args: Any) -> Any:
            state["locked"] = True
            state["units"] += 1
            try:
                return await original(db, *args)
            finally:
                state["locked"] = False

        monkeypatch.setattr(ibs_request_reconciliation, "_reconcile_scope", wrapped)
        violations: list[Any] = []

        def check(served: Any) -> None:
            if state["locked"] or len(units.sessions) != len(units.closed):
                violations.append(served)

        fake.on_request = check

        outcomes = await reconcile(fake, scopes)

        assert kinds(outcomes) == {scope.track_id: "created" for scope in scopes}
        assert state["units"] == 2
        assert fake.served
        assert violations == []


class TestInFlightSelection:
    """Required Roots root 1: the uncorrelated retained accepted SRs that
    step 1 selects as in flight for a scope."""

    @pytest.mark.parametrize(
        ("variant", "examined"),
        [
            pytest.param("in-flight", True, id="in-flight"),
            pytest.param("released-other-incident", True, id="other-incident"),
            pytest.param("released-same-incident", False, id="same-incident"),
            pytest.param("not-accepted", False, id="not-accepted"),
            pytest.param("correlated", False, id="correlated-to-the-track"),
        ],
    )
    async def test_selection_of_retained_submissions_of_another_ticket(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        variant: str,
        examined: bool,
    ) -> None:
        """Another Ticket's track of the same package and codestream is
        correlated to an accepted SR. It is examined for this scope unless
        a retained accepted release action of its own incident exists, it
        is not accepted, or it is already correlated to this track (then
        it is root-1 evidence, evaluated from retained provenance without
        point detail)."""
        seed = RequestSeed(world)
        package = unique_package()
        other = await seed.track(await seed.ticket(), package=package)
        scope = await seed.track(await seed.ticket(), package=package)
        number, incident = world.number(), next_incident()
        srcmd5 = checksum(f"sr-commit-{number}")
        accepted = submission(
            package,
            number,
            incident=incident,
            accept=Accept(rev="2", srcmd5=srcmd5, xsrcmd5=checksum(f"x-{number}")),
        )
        state = REVIEW if variant == "not-accepted" else ACCEPTED
        retained = submission(package, number) if state is REVIEW else accepted
        tracks = [other, scope] if variant == "correlated" else [other]
        await seed.evidence(number, state, retained, tracks=tracks)
        if variant.startswith("released"):
            released = world.number()
            source = (
                incident if variant == "released-same-incident" else next_incident()
            )
            await seed.evidence(
                released,
                ACCEPTED,
                release(
                    package,
                    source,
                    accept=Accept(rev="1", srcmd5=checksum(f"rr-{released}")),
                ),
                tracks=[other],
            )
        await seed.commit()
        fake.request(number, ACCEPTED, accepted)
        fake.action_diff(
            number,
            accepted,
            cve_issue(cve_of(scope)),
            cve_issue(cve_of(other)),
            codestream_package=package,
        )
        assert accepted.target_package is not None
        fake.history(
            f"SUSE:Maintenance:{incident}",
            accepted.target_package,
            [(1, checksum("branch"), None), (2, srcmd5, number)],
        )
        fake.quiet(package)

        outcomes = await reconcile(fake, [scope])

        fetched = f"/request/{number}" in fake.paths()
        assert fetched is examined
        correlated_numbers = [
            row.request_number for row in await evidence(world, scope)
        ]
        if examined:
            assert kinds(outcomes) == {scope.track_id: "created"}
            assert correlated_numbers == [number]
            assert await delivery(world, scope) == IN_PROGRESS.value
        elif variant == "correlated":
            assert kinds(outcomes) == {scope.track_id: "updated"}
            assert correlated_numbers == [number]
            assert await delivery(world, scope) == IN_PROGRESS.value
        else:
            assert kinds(outcomes) == {scope.track_id: "no_op"}
            assert correlated_numbers == []
            assert await delivery(world, scope) == PENDING.value


# ---------------------------------------------------------------------------
# 10. Retained-root index (Data Model > IBSRequestAction)
# ---------------------------------------------------------------------------


class TestRetainedRootIndex:
    async def test_retained_root_reader_can_use_the_package_codestream_index(
        self, db_session: AsyncSession, package: str
    ) -> None:
        """With a population of other packages' actions and fresh statistics
        (both rolled back with the test), so the plan does not depend on
        what earlier tests left in the worker database's statistics."""
        for _ in range(INDEX_POPULATION):
            other = committed_number()
            await seed_evidence(
                db_session, other, REVIEW, submission(unique_package(), other)
            )
        number = committed_number()
        await seed_evidence(db_session, number, REVIEW, submission(package, number))
        await db_session.execute(text("ANALYZE ibs_request"))
        await db_session.execute(text("ANALYZE ibs_request_action"))
        captured: list[tuple[str, Any]] = []

        def _record(*args: Any) -> None:
            captured.append((args[2], args[3]))

        sync_engine = db_session.get_bind().engine
        event.listen(sync_engine, "before_cursor_execute", _record)
        try:
            retained = await read_retained_actions(
                db_session, package_name=package, codestream=CODESTREAM
            )
        finally:
            event.remove(sync_engine, "before_cursor_execute", _record)
        assert [action.request.request_number for action in retained] == [number]
        assert len(captured) == 1
        statement, parameters = captured[0]

        connection = await db_session.connection()
        await connection.exec_driver_sql("SET LOCAL enable_seqscan = off")
        plan = await connection.exec_driver_sql(f"EXPLAIN {statement}", parameters)

        assert "ix_ibs_request_action_logical_package_codestream_name" in "\n".join(
            row[0] for row in plan.all()
        )


# ---------------------------------------------------------------------------
# 11. Dimension independence (package-service.md Architectural Test
#     Requirement; package-model.md Affectedness-Delivery Independence)
# ---------------------------------------------------------------------------


async def _dimensions(
    world: RequestWorld, ticket_id: uuid.UUID
) -> list[tuple[Any, ...]]:
    """Every non-delivery dimension of the Ticket's tree: track status and
    markers, package markers, Product occurrences, checkpoints, and the
    Ticket status."""
    probe = await world.probe()
    packages = select(TicketPackage.id).where(TicketPackage.ticket_id == ticket_id)
    tracks = (
        await probe.execute(
            select(
                TicketPackageTrack.id,
                TicketPackageTrack.status,
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
    track_ids = select(TicketPackageTrack.id).where(
        TicketPackageTrack.ticket_package_id.in_(packages)
    )
    occurrences = (
        await probe.execute(
            select(
                TicketPackageProduct.id,
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at,
                TicketPackageProduct.deleted_at,
            )
            .where(TicketPackageProduct.ticket_package_track_id.in_(track_ids))
            .order_by(TicketPackageProduct.id)
        )
    ).all()
    checkpoints = (
        await probe.execute(
            select(
                TrackReleaseCheckpoint.ticket_package_track_id,
                TrackReleaseCheckpoint.srcmd5,
                TrackReleaseCheckpoint.last_seen_at,
            )
            .where(TrackReleaseCheckpoint.ticket_package_track_id.in_(track_ids))
            .order_by(TrackReleaseCheckpoint.ticket_package_track_id)
        )
    ).all()
    ticket = (
        await probe.execute(
            select(Ticket.status, Ticket.cve_id).where(Ticket.id == ticket_id)
        )
    ).one()
    await probe.rollback()
    return [
        *(tuple(row) for row in tracks),
        *(tuple(row) for row in occurrences),
        *(tuple(row) for row in checkpoints),
        tuple(ticket),
    ]


class TestDimensionIndependence:
    _VARIANTS: ClassVar[list[dict[str, Any]]] = [
        *({"track": {"status": status}} for status in PackageStatus),
        {"product": {"eligible": False}},
        {"product": {"eligible": False, "is_eligible_override": True}},
        {"product": {"released_at": RELEASED_AT}},
        {"product": {}},
        {"product": {"general_support_end_date": BEFORE_EVAL}},
        {"track": {"excluded": "package"}},
        {"track": {"excluded": "track"}},
        {"track": {"checkpoint": CHECKPOINT}},
    ]

    @pytest.mark.parametrize(
        ("path", "derived"),
        [("open-submission", IN_PROGRESS), ("proven-release", RELEASED)],
        ids=["in-progress", "released"],
    )
    async def test_every_dimension_value_is_selected_and_derives_the_same_delivery(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        path: str,
        derived: DeliveryStatus,
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        base = unique_package()
        created: list[Track] = []
        for index, variant in enumerate(self._VARIANTS):
            track = await seed.track(
                ticket, package_name=f"{base}-{index}", **variant.get("track", {})
            )
            if "product" in variant:
                await seed.product(track, **variant["product"])
            created.append(track)
        await seed.commit()
        before = await _dimensions(world, ticket.id)
        reader = await world.probe()
        scopes = await load_ibs_request_scopes(reader, ticket_id=ticket.id)
        await reader.rollback()
        for scope in scopes:
            if path == "open-submission":
                positive(fake, world, scope)
            else:
                proven_release(fake, world, scope)

        outcomes = await reconcile(fake, scopes)

        assert [scope.track_id for scope in scopes] == sorted(t.id for t in created)
        assert kinds(outcomes) == {track.id: "created" for track in created}
        for scope in scopes:
            assert await delivery(world, scope) == derived.value
        assert await _dimensions(world, ticket.id) == before
        assert await events_of(world, ticket.id) == []
