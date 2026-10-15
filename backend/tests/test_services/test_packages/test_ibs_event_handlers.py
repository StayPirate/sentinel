"""Tests for the application handling of IBS RabbitMQ deliveries
(backend/app/services/packages/ibs_event_handlers.py).

Owning specifications:

- docs/features/integrations/ibs-rabbitmq-integration.md (Ownership
  Boundaries; Message Encoding; Consumed Events > Package Commit;
  Per-Delivery Processing > Correlation Scope (sanitized identity),
  One-Attempt Rule, Settlement Policy outcomes; Fatal and Transient
  Failures: the delivery exception boundary; Error and Recovery Summary;
  Security; Testing Requirements).
- docs/features/packages/ibs-track-release-detection.md (RabbitMQ
  Package-Commit Acceleration; Shared Reconciliation Boundary: consumer
  mode; Checkpoint Concurrency (event part); Audit and Transaction
  Guarantees; Testing Requirements: "ignored unrepresented linked-target
  events", event anti-regression).
- docs/conventions.md (External String Admissibility) and
  docs/features/platform/testing-strategy.md (External String
  Admissibility; Concurrency Testing; Audit Trail Testing).

Unit classes use the hostile and observed fixtures of
`tests/fixtures/ibs_rabbitmq/`. Integration classes share the setup of
`test_ibs_track_release.py`: a `TrackWorld` with explicit teardown, the
boundary's unit sessions and the handler's selection session over
`real_session_factory`, a recorder for `task_publication.publish_task`,
and a real `IBSClient` of the fake IBS API.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, cast

import pytest
from sqlalchemy import update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import PackageStatus, TicketStatus, WorkflowType
from app.models.ticket import Ticket
from app.models.track_release_checkpoint import TrackReleaseCheckpoint
from app.services import package_service, task_publication
from app.services.ibs_client import IBSClient
from app.services.ibs_event_decoding import (
    BOUND_ROUTING_KEYS,
    CONTENT_TYPE,
    PACKAGE_COMMIT_ROUTING_KEY,
    DeliveryOutcome,
    DeliveryResult,
    MalformedDeliveryError,
    decode_delivery,
)
from app.services.packages import ibs_event_handlers
from app.services.packages.ibs_event_handlers import (
    HANDLERS,
    PackageCommit,
    handle_delivery,
    log_identity,
    parse_package_commit,
)
from app.services.packages.ibs_track_release import TrackReleaseCandidate
from tests.support.ibs_api import status_response
from tests.support.ibs_product_release import Publish
from tests.support.ibs_rabbitmq import (
    HOME_PROJECT_FIXTURE,
    PACKAGE_COMMIT_FIXTURES,
    HostileCase,
    hostile_cases,
    load_delivery,
)
from tests.support.ibs_track_release import (
    CHECKPOINT,
    CURRENT,
    NEWER,
    OTHER_CVE,
    PACKAGE,
    PROJECT,
    SIBLING_PACKAGE,
    TRACK_FAILED,
    FakeIBS,
    Seed,
    Track,
    TrackUnitSessions,
    TrackWorld,
    before_local_unit,
    checkpoint_srcmd5,
    events_of,
    install_ibs,
    install_units,
    issue,
    logged,
    reconcile,
    ticket_status,
    track_status,
)
from tests.support.ticket_mutations import EVAL, RELEASED_AT

Factory = Callable[[], Awaitable[AsyncSession]]

_SCHEMA_REASONS = {"invalid_project", "invalid_package"}


def _commit_body(project: str = PROJECT, package: str = PACKAGE, **extra: Any) -> bytes:
    """A compact package-commit body in the observed member order."""
    body = {"project": project, "package": package, "user": "example-user"}
    body.update(extra)
    body.setdefault("rev", "46")
    return json.dumps(body, separators=(",", ":")).encode()


def _parse(case: HostileCase) -> PackageCommit:
    delivery = case.delivery
    return parse_package_commit(
        decode_delivery(delivery.routing_key, delivery.content_type, delivery.body)
    )


def _schema_cases() -> list[HostileCase]:
    return [case for case in hostile_cases() if case.reason in _SCHEMA_REASONS]


def _valid_cases() -> list[HostileCase]:
    return [case for case in hostile_cases() if case.outcome == "valid"]


def _malformed_cases() -> list[HostileCase]:
    return [case for case in hostile_cases() if case.outcome == "malformed"]


# ---------------------------------------------------------------------------
# Parsing, identity, and dispatch (unit)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParsePackageCommit:
    @pytest.mark.parametrize("name", [*PACKAGE_COMMIT_FIXTURES, HOME_PROJECT_FIXTURE])
    def test_observed_deliveries_yield_their_identity(self, name: str) -> None:
        delivery = load_delivery(name)
        body = json.loads(delivery.body)

        commit = parse_package_commit(
            decode_delivery(delivery.routing_key, delivery.content_type, delivery.body)
        )

        assert commit == PackageCommit(body["project"], body["package"])

    @pytest.mark.parametrize("case", _schema_cases(), ids=lambda case: case.id)
    def test_invalid_identity_raises_its_member_reason(self, case: HostileCase) -> None:
        with pytest.raises(MalformedDeliveryError) as raised:
            _parse(case)

        assert raised.value.reason.value == case.reason

    @pytest.mark.parametrize("case", _valid_cases(), ids=lambda case: case.id)
    def test_valid_cases_keep_the_exact_values(self, case: HostileCase) -> None:
        assert _parse(case) == PackageCommit(
            cast(str, case.project), cast(str, case.package)
        )

    def test_project_is_checked_before_package(self) -> None:
        event = decode_delivery(
            PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, b'{"project":"","package":1}'
        )

        with pytest.raises(MalformedDeliveryError) as raised:
            parse_package_commit(event)

        assert raised.value.reason.value == "invalid_project"


@pytest.mark.unit
class TestLogIdentity:
    def test_suse_project_with_ibs_names_is_logged(self) -> None:
        assert log_identity(PackageCommit(PROJECT, PACKAGE)) == {
            "project": PROJECT,
            "package": PACKAGE,
        }

    @pytest.mark.parametrize(
        ("project", "package"),
        [
            ("home:example-user", PACKAGE),
            ("home:example-user:branches:SUSE:SLE-15-SP6:Update", PACKAGE),
            ("devel:example", PACKAGE),
            ("SUSE:Example Project", PACKAGE),
            (PROJECT, "example pkg"),
            (PROJECT, "example\npkg"),
            (f" {PROJECT}", PACKAGE),
        ],
    )
    def test_other_or_unsanitized_identities_are_omitted(
        self, project: str, package: str
    ) -> None:
        assert log_identity(PackageCommit(project, package)) == {}


@pytest.mark.unit
class TestDispatch:
    def test_every_bound_routing_key_has_one_handler(self) -> None:
        assert set(HANDLERS) == set(BOUND_ROUTING_KEYS)

    @pytest.mark.parametrize("case", _malformed_cases(), ids=lambda case: case.id)
    async def test_malformed_delivery_does_no_database_or_ibs_work(
        self, case: HostileCase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_session() -> None:
            raise AssertionError("no database work for a malformed delivery")

        monkeypatch.setattr(ibs_event_handlers, "async_session_factory", no_session)
        delivery = case.delivery

        result = await handle_delivery(
            delivery.routing_key,
            delivery.content_type,
            delivery.body,
            client=cast(IBSClient, object()),
        )

        assert result == DeliveryResult(DeliveryOutcome.MALFORMED, case.reason)

    async def test_unclassified_handler_exception_is_an_unexpected_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken(*_: Any) -> DeliveryResult:
            raise RuntimeError("fictional bug")

        monkeypatch.setitem(HANDLERS, PACKAGE_COMMIT_ROUTING_KEY, broken)

        result = await handle_delivery(
            PACKAGE_COMMIT_ROUTING_KEY,
            CONTENT_TYPE,
            _commit_body(),
            client=cast(IBSClient, object()),
        )

        assert result == DeliveryResult(DeliveryOutcome.FAILED, "unexpected_error")

    @pytest.mark.parametrize(
        "error", [MemoryError(), asyncio.CancelledError(), KeyboardInterrupt()]
    )
    async def test_memory_error_and_base_exceptions_propagate(
        self, error: BaseException, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def raising(*_: Any) -> DeliveryResult:
            raise error

        monkeypatch.setitem(HANDLERS, PACKAGE_COMMIT_ROUTING_KEY, raising)

        with pytest.raises(type(error)):
            await handle_delivery(
                PACKAGE_COMMIT_ROUTING_KEY,
                CONTENT_TYPE,
                _commit_body(),
                client=cast(IBSClient, object()),
            )


# ---------------------------------------------------------------------------
# The package-commit path (integration)
# ---------------------------------------------------------------------------


@pytest.fixture
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> TrackUnitSessions:
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)
    monkeypatch.setattr(
        ibs_event_handlers, "async_session_factory", real_session_factory
    )
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture
def ibs(monkeypatch: pytest.MonkeyPatch) -> FakeIBS:
    return install_ibs(monkeypatch)


@pytest.fixture
async def world(
    db_session_factory: Factory, units: TrackUnitSessions, publication: Publish
) -> AsyncIterator[TrackWorld]:
    created = TrackWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


async def _handle(ibs: FakeIBS, body: bytes) -> DeliveryResult:
    async with ibs.client() as client:
        return await handle_delivery(
            PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body, client=client
        )


async def _tracks(
    world: TrackWorld,
    count: int = 1,
    *,
    package_name: str = PACKAGE,
    **kwargs: Any,
) -> list[Track]:
    """`count` committed tracks of one package, each below its own Ticket,
    in track-ID order."""
    seed = Seed(world.session, world)
    created = [
        await seed.track(await seed.ticket(), package_name=package_name, **kwargs)
        for _ in range(count)
    ]
    await seed.commit()
    return sorted(created, key=lambda track: track.id)


def _cve(track: Track) -> str:
    assert track.cve_id is not None
    return track.cve_id


def _evidence(ibs: FakeIBS, *tracks: Track, baseline: str = "0") -> None:
    ibs.source(PROJECT, PACKAGE, CURRENT)
    ibs.issues(
        PROJECT, PACKAGE, baseline, CURRENT, *(issue(_cve(track)) for track in tracks)
    )


_IDENTITY = {"project": PROJECT, "package": PACKAGE}


@pytest.mark.integration
class TestRelevance:
    @pytest.mark.parametrize(
        "package_name",
        [
            f"{PACKAGE}.12345",
            f"{PACKAGE}_snapshot",
            f"{PACKAGE}-debuginfo",
            SIBLING_PACKAGE,
        ],
        ids=["linked-target", "snapshot", "related", "other"],
    )
    async def test_unrepresented_package_is_irrelevant_without_ibs_io(
        self, world: TrackWorld, ibs: FakeIBS, package_name: str
    ) -> None:
        """Only `example` is represented: an event for its linked target,
        a snapshot, a related package, or another package selects nothing
        (no reverse-link fan-out)."""
        (track,) = await _tracks(world)

        result = await _handle(ibs, _commit_body(package=package_name))

        assert result.outcome is DeliveryOutcome.IRRELEVANT
        assert ibs.served == []
        assert await checkpoint_srcmd5(world, track) is None

    @pytest.mark.parametrize(
        "variant",
        ["git", "final", "inactive", "cveless"],
    )
    async def test_out_of_scope_tracks_are_never_selected(
        self, world: TrackWorld, ibs: FakeIBS, variant: str
    ) -> None:
        seed = Seed(world.session, world)
        match variant:
            case "git":
                await seed.track(
                    await seed.ticket(), project=PROJECT, workflow=WorkflowType.GIT
                )
            case "final":
                await seed.track(await seed.ticket(), status=PackageStatus.FIXED)
            case "inactive":
                await seed.track(await seed.ticket(TicketStatus.RESOLVED))
            case _:
                await seed.track(await seed.ticket(with_cve=False))
        await seed.commit()

        result = await _handle(ibs, _commit_body())

        assert result == DeliveryResult(DeliveryOutcome.IRRELEVANT, fields=_IDENTITY)
        assert ibs.served == []

    async def test_home_project_is_irrelevant_and_never_logged(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        await _tracks(world)
        delivery = load_delivery(HOME_PROJECT_FIXTURE)

        with capture_logs() as logs:
            result = await _handle(ibs, delivery.body)

        assert result == DeliveryResult(DeliveryOutcome.IRRELEVANT)
        assert ibs.served == []
        assert "home:" not in repr(logs)
        assert "example-user" not in repr(logs)


@pytest.mark.integration
class TestReconciliation:
    async def test_evidence_fixes_the_track_with_one_service_owned_event(
        self, world: TrackWorld, ibs: FakeIBS, publication: Publish
    ) -> None:
        (track,) = await _tracks(world)
        _evidence(ibs, track)

        result = await _handle(ibs, _commit_body())

        assert result == DeliveryResult(
            DeliveryOutcome.PROCESSED, fields={**_IDENTITY, "track_count": 1}
        )
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert await checkpoint_srcmd5(world, track) == CURRENT
        assert publication.calls == []

    async def test_current_checkpoint_is_an_idempotent_no_op(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (track,) = await _tracks(world, checkpoint=CURRENT)
        ibs.source(PROJECT, PACKAGE, CURRENT)

        result = await _handle(ibs, _commit_body())

        assert result.outcome is DeliveryOutcome.PROCESSED
        assert ibs.diffs() == []
        assert await events_of(world, track.ticket_id) == []

    async def test_event_revision_and_checksum_are_never_consumed(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        """The event names `NEWER` and revision 1; source info serves
        `CURRENT`, which alone drives the diff and the checkpoint."""
        (track,) = await _tracks(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, CHECKPOINT, CURRENT)

        result = await _handle(ibs, _commit_body(rev="1", srcmd5=NEWER))

        assert result.outcome is DeliveryOutcome.PROCESSED
        assert ibs.diffs() == [(PROJECT, PACKAGE, CHECKPOINT, CURRENT)]
        assert await checkpoint_srcmd5(world, track) == CURRENT

    async def test_no_match_is_processed_without_event(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (track,) = await _tracks(world)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(OTHER_CVE))

        result = await _handle(ibs, _commit_body())

        assert result.outcome is DeliveryOutcome.PROCESSED
        assert await events_of(world, track.ticket_id) == []
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value

    async def test_ibs_failure_fails_every_track_and_keeps_checkpoints(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        tracks = await _tracks(world, 2, checkpoint=CHECKPOINT)
        ibs.fail_source(PROJECT, status_response(503, b"<status/>"))

        with capture_logs() as logs:
            result = await _handle(ibs, _commit_body())

        assert result == DeliveryResult(
            DeliveryOutcome.FAILED,
            "track_failed",
            {**_IDENTITY, "track_count": 2, "failed_track_count": 2},
        )
        for track in tracks:
            assert await checkpoint_srcmd5(world, track) == CHECKPOINT
        failures = logged(logs, TRACK_FAILED)
        assert len(failures) == 2
        assert all("fetcher_name" not in entry for entry in failures)

    async def test_failed_sibling_keeps_the_committed_sibling(
        self, world: TrackWorld, ibs: FakeIBS, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = await _tracks(world, 2)
        _evidence(ibs, first, second)
        original = package_service.set_track_status

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            result = await original(db, **kwargs)
            if kwargs["track_id"] == second.id:
                raise OperationalError("UPDATE", None, Exception())
            return result

        monkeypatch.setattr(package_service, "set_track_status", failing)

        result = await _handle(ibs, _commit_body())

        assert result == DeliveryResult(
            DeliveryOutcome.FAILED,
            "track_failed",
            {**_IDENTITY, "track_count": 2, "failed_track_count": 1},
        )
        assert await events_of(world, first.ticket_id) == [first.fixed_event()]
        assert await events_of(world, second.ticket_id) == []
        assert await checkpoint_srcmd5(world, second) is None

    async def test_missing_credentials_fail_the_delivery_without_a_request(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (track,) = await _tracks(world)

        async with ibs.client(configured=False) as client:
            result = await handle_delivery(
                PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, _commit_body(), client=client
            )

        assert result.outcome is DeliveryOutcome.FAILED
        assert result.reason_category == "track_failed"
        assert ibs.served == []
        assert await checkpoint_srcmd5(world, track) is None


@pytest.mark.integration
class TestConsumerMode:
    async def test_stale_resolved_regression_fails_without_publication(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """W4 through the package-commit path: the unit rolls back, the
        delivery fails, no event is created, nothing is published."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket(TicketStatus.ANALYZED, assessed=True)
        track = await seed.track(ticket, status=PackageStatus.AFFECTED)
        await seed.product(track, released_at=RELEASED_AT)
        still_open = await seed.track(
            ticket, package_name=SIBLING_PACKAGE, status=PackageStatus.AFFECTED
        )
        await seed.product(still_open)
        await seed.commit()
        _evidence(ibs, track)
        done = False

        async def resolve(_: TrackReleaseCandidate) -> None:
            nonlocal done
            if not done:
                done = True
                session = await world.open_session()
                await session.execute(
                    update(Ticket)
                    .where(Ticket.id == ticket.id)
                    .values(status=TicketStatus.RESOLVED.value)
                )
                await session.commit()

        before_local_unit(monkeypatch, resolve)

        with capture_logs() as logs:
            result = await _handle(ibs, _commit_body())

        assert result.outcome is DeliveryOutcome.FAILED
        assert result.reason_category == "track_failed"
        assert [entry["reason_category"] for entry in logged(logs, TRACK_FAILED)] == [
            "ticket_convergence_required"
        ]
        assert publication.calls == []
        assert await ticket_status(world, ticket.id) == TicketStatus.RESOLVED.value
        assert await events_of(world, ticket.id) == []
        assert await checkpoint_srcmd5(world, track) is None


@pytest.mark.integration
class TestExceptionBoundary:
    async def test_selection_failure_fails_the_delivery_without_ibs_io(
        self, world: TrackWorld, ibs: FakeIBS, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _tracks(world)

        async def failing(*_: Any, **__: Any) -> list[TrackReleaseCandidate]:
            raise OperationalError("SELECT", None, Exception())

        monkeypatch.setattr(
            ibs_event_handlers, "load_track_release_candidates", failing
        )

        result = await _handle(ibs, _commit_body())

        assert result == DeliveryResult(
            DeliveryOutcome.FAILED, "selection_failed", _IDENTITY
        )
        assert ibs.served == []

    async def test_memory_error_in_the_selection_propagates(
        self, world: TrackWorld, ibs: FakeIBS, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def exhausted(*_: Any, **__: Any) -> list[TrackReleaseCandidate]:
            raise MemoryError

        monkeypatch.setattr(
            ibs_event_handlers, "load_track_release_candidates", exhausted
        )

        with pytest.raises(MemoryError):
            await _handle(ibs, _commit_body())

    @pytest.mark.parametrize("ambiguous", [False, True], ids=["failed", "ambiguous"])
    async def test_commit_failure_ends_the_delivery_and_keeps_earlier_units(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        ambiguous: bool,
    ) -> None:
        """The second unit's commit fails (definitely, or committed with an
        exception): the boundary propagates, no further unit runs, the
        delivery fails, the first unit stays committed."""
        first, second, third = await _tracks(world, 3)
        _evidence(ibs, first, second, third)
        error = OperationalError("COMMIT", None, Exception())
        if ambiguous:
            units.after_commit_error = (1, error)
        else:
            units.failing_commit = (1, error)

        result = await _handle(ibs, _commit_body())

        assert result == DeliveryResult(
            DeliveryOutcome.FAILED,
            "reconciliation_failed",
            {**_IDENTITY, "track_count": 3},
        )
        assert len(units.sessions) == 2
        assert units.closed == units.sessions
        assert await events_of(world, first.ticket_id) == [first.fixed_event()]
        assert await checkpoint_srcmd5(world, third) is None
        expected = CURRENT if ambiguous else None
        assert await checkpoint_srcmd5(world, second) == expected

    async def test_rollback_failure_ends_the_delivery(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (track,) = await _tracks(world)
        _evidence(ibs, track)
        original = package_service.set_track_status

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            await original(db, **kwargs)

            async def broken_rollback() -> None:
                raise OperationalError("ROLLBACK", None, Exception())

            monkeypatch.setattr(db, "rollback", broken_rollback)
            raise OperationalError("UPDATE", None, Exception())

        monkeypatch.setattr(package_service, "set_track_status", failing)

        result = await _handle(ibs, _commit_body())

        assert result.outcome is DeliveryOutcome.FAILED
        assert result.reason_category == "reconciliation_failed"
        assert units.closed == units.sessions
        assert await events_of(world, track.ticket_id) == []

    async def test_unexpected_boundary_exception_ends_the_delivery(
        self, world: TrackWorld, ibs: FakeIBS, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (track,) = await _tracks(world)
        _evidence(ibs, track)

        async def broken(*_: Any, **__: Any) -> Any:
            raise RuntimeError("fictional bug")

        monkeypatch.setattr(package_service, "set_track_status", broken)

        result = await _handle(ibs, _commit_body())

        assert result.reason_category == "reconciliation_failed"
        assert await checkpoint_srcmd5(world, track) is None

    async def test_memory_error_propagates_from_the_boundary(
        self, world: TrackWorld, ibs: FakeIBS, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (track,) = await _tracks(world)
        _evidence(ibs, track)

        async def exhausted(*_: Any, **__: Any) -> Any:
            raise MemoryError

        monkeypatch.setattr(package_service, "set_track_status", exhausted)

        with pytest.raises(MemoryError):
            await _handle(ibs, _commit_body())

        assert await checkpoint_srcmd5(world, track) is None


@pytest.mark.integration
class TestAntiRegression:
    async def test_duplicate_events_transition_once(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        (track,) = await _tracks(world)
        _evidence(ibs, track)

        first = await _handle(ibs, _commit_body())
        second = await _handle(ibs, _commit_body())

        assert first.outcome is DeliveryOutcome.PROCESSED
        # The track is final now, so the repeated event selects nothing.
        assert second.outcome is DeliveryOutcome.IRRELEVANT
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert ibs.diffs() == [(PROJECT, PACKAGE, "0", CURRENT)]

    async def test_concurrent_events_and_polling_never_regress(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        """Two events and one periodic invocation race on independent
        sessions: one transition, one event, the current checkpoint."""
        (track,) = await _tracks(world)
        _evidence(ibs, track)

        results = await asyncio.gather(
            _handle(ibs, _commit_body()),
            _handle(ibs, _commit_body(rev="45")),
            reconcile(ibs, [track.candidate()]),
        )

        # An event selected after another invocation's commit sees a final
        # track and is irrelevant; every other outcome is a success.
        for result in results[:2]:
            assert result.outcome in {
                DeliveryOutcome.PROCESSED,
                DeliveryOutcome.IRRELEVANT,
            }
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert await checkpoint_srcmd5(world, track) == CURRENT

    async def test_late_event_never_overwrites_a_newer_checkpoint(
        self, world: TrackWorld, ibs: FakeIBS, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The event examined `CURRENT`; polling accepted `NEWER` before the
        event's unit: the stale event fails and the checkpoint stays."""
        (track,) = await _tracks(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(PROJECT, PACKAGE, CHECKPOINT, CURRENT, issue(_cve(track)))
        done = False

        async def advance(_: TrackReleaseCandidate) -> None:
            nonlocal done
            if not done:
                done = True
                session = await world.open_session()
                await session.execute(
                    update(TrackReleaseCheckpoint)
                    .where(TrackReleaseCheckpoint.ticket_package_track_id == track.id)
                    .values(srcmd5=NEWER)
                )
                await session.commit()

        before_local_unit(monkeypatch, advance)

        result = await _handle(ibs, _commit_body())

        assert result.reason_category == "track_failed"
        assert await checkpoint_srcmd5(world, track) == NEWER
        assert await events_of(world, track.ticket_id) == []
