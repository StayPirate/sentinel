"""Integration tests for the IBS RabbitMQ request wake-ups
(`handle_request_event()` in backend/app/services/packages/ibs_event_handlers.py,
dispatched through `handle_delivery()`).

Owning specifications:

- docs/features/integrations/ibs-rabbitmq-integration.md (Ownership
  Boundaries; Consumed Events > Request Create and State Change; Per-Delivery
  Processing > One-Attempt Rule, Settlement Policy outcomes and relevance;
  Fatal and Transient Failures, the delivery exception boundary; Error and
  Recovery Summary; Security; Testing Requirements).
- docs/features/packages/ibs-submission-tracking.md (Accelerators > RabbitMQ
  Request Wake-Ups; Package and Codestream Identity; Scope Identity;
  Request Delay: no delay for wake-ups; Delivery Derivation: no Ticket
  event; Testing Requirements: the wake-up part of the zero-Ticket-event
  bullet, duplicate/out-of-order event acceleration; Security and Privacy).
- docs/features/packages/package-model.md (Strict workflow applicability;
  Acceleration and permanent recovery ownership).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Audit
  Trail Testing).

Every test seeds a committed `RequestWorld` whose rows, and the evidence of
its registered request numbers, are deleted at teardown. The handler's
selection session and the boundary's sessions come from
`real_session_factory` (the boundary's through `UnitSessions`), so
concurrent invocations use independent sessions and connections. Every
`IBSClient` is a real client of the authenticating fake IBS API
(`FakeRequests`). Selection tests replace `reconcile_ibs_requests()` with a
recorder; every other test runs the real boundary.

All data is fictional: request numbers from `RequestWorld.number()`,
packages from `unique_package()`, the IBS account `jdoe`, and the event
actor `example-user`.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import (
    DeliveryStatus,
    IBSConsumerErrorCategory,
    IBSRequestState,
    TicketStatus,
    WorkflowType,
)
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.services import task_publication
from app.services.ibs_event_decoding import (
    CONTENT_TYPE,
    REQUEST_CREATE_ROUTING_KEY,
    REQUEST_STATE_CHANGE_ROUTING_KEY,
    DeliveryOutcome,
    DeliveryResult,
)
from app.services.packages import (
    ibs_event_handlers,
    ibs_request_observation,
)
from app.services.packages.ibs_event_handlers import handle_delivery
from app.services.packages.ibs_request_observation import IBSRequestScope
from app.services.packages.ibs_request_reconciliation import IBSRequestOutcome
from tests.support.ibs_api import status_response, xml_response
from tests.support.ibs_product_release import Publish, UnitSessions
from tests.support.ibs_request_reconciliation import (
    CODESTREAM,
    OTHER_CODESTREAM,
    SCOPE_FAILED,
    WHEN_AT,
    Action,
    FakeRequests,
    RequestSeed,
    RequestWorld,
    before_lock,
    cve_issue,
    delivery_of,
    evidence_of,
    install_fake_requests,
    install_request_units,
    next_incident,
    reconcile,
    release,
    request_document,
    submission,
    unique_package,
)
from tests.support.ibs_track_release import events_of, logged, raising

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

CREATE: Final = REQUEST_CREATE_ROUTING_KEY
STATE_CHANGE: Final = REQUEST_STATE_CHANGE_ROUTING_KEY
REQUEST_FAILED: Final = IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED

REVIEW: Final = IBSRequestState.REVIEW
ACCEPTED: Final = IBSRequestState.ACCEPTED
DECLINED: Final = IBSRequestState.DECLINED

MARKER: Final = "fictional-private-marker"
"""Fictional event free text that must never reach a log, row, or URL."""
HOME_PROJECT: Final = "home:example-user:branches:SUSE:SLE-15-SP6:Update"
"""A fictional personal project outside the `SUSE:` namespace."""
LATER_AT: Final = WHEN_AT.replace(day=2)
DELETE_ACTION: Final = (
    '<action type="delete"><target project="SUSE:Maintenance:REQUEST:1"/></action>'
)
"""An action of a type Sentinel ignores."""
"""A current-state time newer than the seeded `WHEN_AT`."""


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
    monkeypatch.setattr(
        ibs_event_handlers, "async_session_factory", real_session_factory
    )
    return install_request_units(monkeypatch, real_session_factory)


@pytest.fixture(autouse=True)
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RequestWorld]:
    created = RequestWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass
class Reconciliations:
    """Replaces `reconcile_ibs_requests()` in the handler: records each
    invocation's scopes and keyword arguments and answers `no_op` (or the
    scripted kind) for every scope."""

    calls: list[tuple[list[IBSRequestScope], dict[str, Any]]] = field(
        default_factory=list
    )
    kind: str = "no_op"

    async def __call__(
        self, scopes: Iterable[IBSRequestScope], **kwargs: Any
    ) -> list[IBSRequestOutcome]:
        selected = list(scopes)
        self.calls.append((selected, kwargs))
        return [IBSRequestOutcome(scope.track_id, self.kind) for scope in selected]  # type: ignore[arg-type]

    @property
    def scopes(self) -> list[IBSRequestScope]:
        (call,) = self.calls
        return call[0]


@pytest.fixture
def reconciliations(monkeypatch: pytest.MonkeyPatch) -> Reconciliations:
    recorder = Reconciliations()
    monkeypatch.setattr(ibs_event_handlers, "reconcile_ibs_requests", recorder)
    return recorder


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def event_body(
    number: int,
    *,
    routing_key: str = CREATE,
    state: str = "review",
    actions: list[dict[str, Any]] | None = None,
    event_id: int | None = None,
) -> bytes:
    """A request event in the observed member order with hostile ignored
    members: personal actor fields, free text, and an action array that
    names a personal project and the event's own package claims."""
    event_actions = actions or [
        {
            "action_id": 9200001,
            "type": "maintenance_incident",
            "sourceproject": HOME_PROJECT,
            "sourcepackage": "example-other",
            "sourcerevision": "3",
            "targetproject": "SUSE:Maintenance",
            "target_releaseproject": CODESTREAM,
            "makeoriginolder": False,
        }
    ]
    members: dict[str, Any] = {"author": "example-user"}
    if routing_key == STATE_CHANGE:
        members["comment"] = MARKER
    members.update(
        {
            "description": MARKER,
            "id": event_id if event_id is not None else number + 1,
            "number": number,
            "actions": event_actions,
            "state": state,
        }
    )
    if routing_key == STATE_CHANGE:
        members["oldstate"] = "new"
    members.update(
        {"when": "2026-10-15T09:00:00", "who": "example-user", "namespace": "SUSE"}
    )
    if routing_key == STATE_CHANGE:
        members["duration"] = 60
    return json.dumps(members, separators=(",", ":")).encode()


async def wake(
    fake: FakeRequests,
    number: int,
    *,
    routing_key: str = CREATE,
    body: bytes | None = None,
    configured: bool = True,
) -> DeliveryResult:
    """Handle one request event with the process-wide client form: one open
    client for the delivery."""
    async with fake.client(configured=configured) as client:
        return await handle_delivery(
            routing_key,
            CONTENT_TYPE,
            body if body is not None else event_body(number, routing_key=routing_key),
            client=client,
        )


async def scopes_of(
    world: RequestWorld,
    *specs: tuple[str, str],
    **kwargs: Any,
) -> list[IBSRequestScope]:
    """One committed track per `(package, codestream)` spec, each below its
    own Ticket."""
    seed = RequestSeed(world)
    created = [
        await seed.track(
            await seed.ticket(), package=package, codestream=codestream, **kwargs
        )
        for package, codestream in specs
    ]
    await seed.commit()
    return created


def open_submission(
    fake: FakeRequests,
    world: RequestWorld,
    scope: IBSRequestScope,
    *,
    state: IBSRequestState = REVIEW,
) -> tuple[int, Action]:
    """An open SR of `scope` with a positive diff, found by the open-SR
    search, and current release evidence without the CVE: a complete
    `IN_PROGRESS` observation."""
    assert scope.cve_id is not None
    number = world.number()
    action = submission(scope.package_name, number, codestream=scope.codestream)
    fake.request(number, state, action)
    fake.action_diff(
        number, action, cve_issue(scope.cve_id), codestream_package=scope.package_name
    )
    fake.quiet(scope.package_name, scope.codestream, open_submissions=[number])
    return number, action


def detail_paths(fake: FakeRequests, number: int) -> list[str]:
    return [path for path in fake.paths() if path == f"/request/{number}"]


async def correlated_numbers(world: RequestWorld, scope: IBSRequestScope) -> list[int]:
    return [
        row.request_number
        for row in await evidence_of(await world.probe(), scope.track_id)
    ]


async def delivery(world: RequestWorld, scope: IBSRequestScope) -> str | None:
    return await delivery_of(await world.probe(), scope.track_id)


async def evidence_rows(world: RequestWorld, number: int) -> tuple[int, int, int]:
    """`(requests, actions, correlations)` committed for `number`."""
    probe = await world.probe()
    requests = (
        await probe.scalars(
            select(IBSRequest.id).where(IBSRequest.request_number == number)
        )
    ).all()
    actions = (
        await probe.scalars(
            select(IBSRequestAction.id).where(
                IBSRequestAction.ibs_request_id.in_(requests)
            )
        )
    ).all()
    correlations = (
        await probe.scalars(
            select(IBSRequestActionTrack.id).where(
                IBSRequestActionTrack.ibs_request_action_id.in_(actions)
            )
        )
    ).all()
    await probe.rollback()
    return len(requests), len(actions), len(correlations)


def processed(number: int, track_count: int = 1) -> DeliveryResult:
    return DeliveryResult(
        DeliveryOutcome.PROCESSED,
        fields={"request_number": number, "track_count": track_count},
    )


def failed(number: int, reason: str, **fields: str | int) -> DeliveryResult:
    return DeliveryResult(
        DeliveryOutcome.FAILED,
        reason,
        {"request_number": number, **fields},
        REQUEST_FAILED,
    )


# ---------------------------------------------------------------------------
# 1. Selection (RabbitMQ Request Wake-Ups step 4; Package and Codestream
#    Identity; Strict workflow applicability)
# ---------------------------------------------------------------------------


class TestSelection:
    async def test_current_actions_select_every_active_ibs_track_of_their_identity(
        self, world: RequestWorld, fake: FakeRequests, reconciliations: Reconciliations
    ) -> None:
        """A multi-action request selects every represented scope of every
        identity it names, below any number of Tickets, including a
        CVE-less Ticket and a track without any correlation; a Git track and
        an inactive Ticket's track never."""
        package, other = unique_package(), unique_package()
        number, incident = world.number(), next_incident()
        selected = await scopes_of(
            world,
            (package, CODESTREAM),
            (package, CODESTREAM),
            (package, OTHER_CODESTREAM),
            (other, CODESTREAM),
        )
        seed = RequestSeed(world)
        cveless = await seed.track(
            await seed.ticket(with_cve=False), package=package, codestream=CODESTREAM
        )
        git = await seed.track(
            await seed.ticket(), package=package, workflow=WorkflowType.GIT
        )
        inactive = await seed.track(
            await seed.ticket(TicketStatus.RESOLVED), package=package
        )
        excluded = await seed.track(
            await seed.ticket(), package=package, excluded="track"
        )
        await seed.commit()
        fake.request(
            number,
            REVIEW,
            release(package, incident),
            release(package, incident, codestream=OTHER_CODESTREAM),
            release(other, incident),
        )

        result = await wake(fake, number)

        expected = sorted([*selected, cveless, excluded], key=lambda s: s.track_id)
        assert result == processed(number, len(expected))
        assert sorted(reconciliations.scopes, key=lambda s: s.track_id) == expected
        assert {git.track_id, inactive.track_id}.isdisjoint(
            scope.track_id for scope in reconciliations.scopes
        )

    async def test_reconciliation_is_inline_without_hook_delay_or_fetcher_name(
        self, world: RequestWorld, fake: FakeRequests, reconciliations: Reconciliations
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()
        fake.request(number, REVIEW, submission(scope.package_name, number))

        async with fake.client() as client:
            await handle_delivery(
                CREATE, CONTENT_TYPE, event_body(number), client=client
            )

            ((scopes, kwargs),) = reconciliations.calls
            assert scopes == [scope]
            assert kwargs == {"client": client}

    async def test_retained_actions_of_the_request_number_select_their_scopes(
        self, world: RequestWorld, fake: FakeRequests, reconciliations: Reconciliations
    ) -> None:
        """The current detail no longer names the retained identity (another
        action type replaced it); the retained action still selects. A
        retained action of another request number never does."""
        retained_package, foreign_package = unique_package(), unique_package()
        retained_scope, foreign_scope = await scopes_of(
            world, (retained_package, CODESTREAM), (foreign_package, CODESTREAM)
        )
        number, foreign = world.number(), world.number()
        seed = RequestSeed(world)
        await seed.evidence(number, REVIEW, submission(retained_package, number))
        await seed.evidence(foreign, REVIEW, submission(foreign_package, foreign))
        await seed.commit()
        fake.request(
            number,
            DECLINED,
            extra_actions=[DELETE_ACTION],
        )

        result = await wake(fake, number, routing_key=STATE_CHANGE)

        assert result == processed(number)
        assert reconciliations.scopes == [retained_scope]
        assert foreign_scope not in reconciliations.scopes

    @pytest.mark.parametrize(
        "make_action",
        [
            lambda p, n, i: release(
                p, i, source_project=f"SUSE:Maintenance:REQUEST:{i}"
            ),
            lambda p, n, i: release(p, i, target_package=f"{p}.{i + 1}"),
            lambda p, n, i: release("patchinfo", i),
            lambda p, n, i: submission(p.upper(), n),
            lambda p, n, i: release(p, i, codestream="SUSE:Updates:SLE-15-SP6:x86_64"),
            lambda p, n, i: submission(p, n, codestream=OTHER_CODESTREAM),
        ],
        ids=[
            "unresolved-source",
            "unresolved-suffix",
            "patchinfo",
            "letter-case",
            "non-codestream-target",
            "other-codestream",
        ],
    )
    async def test_actions_that_match_no_represented_scope_are_irrelevant(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        reconciliations: Reconciliations,
        make_action: Callable[[str, int, int], Action],
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()
        fake.request(
            number, REVIEW, make_action(scope.package_name, number, next_incident())
        )

        with capture_logs() as logs:
            result = await wake(fake, number)

        assert result == DeliveryResult(
            DeliveryOutcome.IRRELEVANT, fields={"request_number": number}
        )
        assert reconciliations.calls == []
        assert fake.paths() == [f"/request/{number}"]
        assert logged(logs, SCOPE_FAILED) == []

    async def test_event_fields_are_never_consulted(
        self, world: RequestWorld, fake: FakeRequests, reconciliations: Reconciliations
    ) -> None:
        """The event's actions name the represented package and its `id`
        is a represented request number, but current detail of `number`
        names another package: irrelevant, and only `number` is fetched."""
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, decoy = world.number(), world.number()
        fake.request(number, ACCEPTED, release(unique_package(), next_incident()))
        fake.request(decoy, REVIEW, submission(scope.package_name, decoy))
        body = event_body(
            number,
            routing_key=STATE_CHANGE,
            state="accepted",
            event_id=decoy,
            actions=[
                {
                    "action_id": decoy,
                    "type": "maintenance_incident",
                    "sourceproject": f"SUSE:Maintenance:REQUEST:{decoy}",
                    "sourcepackage": f"{scope.package_name}.SUSE_SLE-15-SP6_Update",
                    "targetproject": "SUSE:Maintenance",
                    "target_releaseproject": CODESTREAM,
                    "makeoriginolder": False,
                }
            ],
        )

        result = await wake(fake, number, routing_key=STATE_CHANGE, body=body)

        assert result.outcome is DeliveryOutcome.IRRELEVANT
        assert reconciliations.calls == []
        assert fake.paths() == [f"/request/{number}"]


# ---------------------------------------------------------------------------
# 2. Reconciliation through the shared boundary (RabbitMQ Request Wake-Ups
#    step 5; Settlement Policy outcomes)
# ---------------------------------------------------------------------------


class TestReconciliation:
    async def test_open_submission_is_correlated_and_derives_in_progress(
        self, world: RequestWorld, fake: FakeRequests, publication: Publish
    ) -> None:
        """The event says `accepted`; current REST detail says `review`,
        which alone is persisted. The boundary fetches its own detail."""
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)

        result = await wake(
            fake,
            number,
            routing_key=STATE_CHANGE,
            body=event_body(number, routing_key=STATE_CHANGE, state="accepted"),
        )

        assert result == processed(number)
        assert await correlated_numbers(world, scope) == [number]
        [row] = await evidence_of(await world.probe(), scope.track_id)
        assert row.state == REVIEW.value
        assert await delivery(world, scope) == DeliveryStatus.IN_PROGRESS.value
        assert len(detail_paths(fake, number)) == 2
        assert fake.unrouted == []
        assert publication.calls == []

    async def test_unchanged_evidence_is_a_processed_no_op(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)
        assert await wake(fake, number) == processed(number)
        before = await evidence_of(await world.probe(), scope.track_id)

        result = await wake(fake, number, routing_key=STATE_CHANGE)

        assert result == processed(number)
        assert await evidence_of(await world.probe(), scope.track_id) == before
        assert await evidence_rows(world, number) == (1, 1, 1)

    async def test_cveless_scope_is_processed_without_ibs_request_of_its_own(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """A complete no-match without any IBS request in the boundary: only
        the wake-up's own point lookup is made."""
        package = unique_package()
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(with_cve=False), package=package, codestream=CODESTREAM
        )
        await seed.commit()
        number = world.number()
        fake.request(number, REVIEW, submission(package, number))

        result = await wake(fake, number)

        assert result == processed(number)
        assert fake.paths() == [f"/request/{number}"]
        assert await evidence_rows(world, number) == (0, 0, 0)
        assert await delivery(world, scope) == DeliveryStatus.PENDING.value

    async def test_failed_sibling_scope_fails_the_delivery_and_keeps_the_committed_one(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """One request with a submission action for each of two codestreams:
        the scope of the second fails on its release evidence (HTTP 503
        after the shared retries), the first commits."""
        package = unique_package()
        first, second = await scopes_of(
            world, (package, CODESTREAM), (package, OTHER_CODESTREAM)
        )
        number = world.number()
        actions = [
            submission(package, number, codestream=scope.codestream)
            for scope in (first, second)
        ]
        fake.request(number, REVIEW, *actions)
        for scope, action in zip((first, second), actions, strict=True):
            assert scope.cve_id is not None
            fake.action_diff(
                number, action, cve_issue(scope.cve_id), codestream_package=package
            )
        fake.quiet(package, CODESTREAM, open_submissions=[number])
        fake.release_evidence(
            OTHER_CODESTREAM, package, source=status_response(503, b"<status/>")
        )

        with capture_logs() as logs:
            result = await wake(fake, number)

        assert result == failed(
            number, "track_failed", track_count=2, failed_track_count=1
        )
        assert await correlated_numbers(world, first) == [number]
        assert await correlated_numbers(world, second) == []
        assert await delivery(world, first) == DeliveryStatus.IN_PROGRESS.value
        assert await delivery(world, second) == DeliveryStatus.PENDING.value
        assert [entry["track_id"] for entry in logged(logs, SCOPE_FAILED)] == [
            str(second.track_id)
        ]
        assert all("fetcher_name" not in entry for entry in logged(logs, SCOPE_FAILED))


# ---------------------------------------------------------------------------
# 3. The delivery exception boundary (Fatal and Transient Failures; Error
#    and Recovery Summary)
# ---------------------------------------------------------------------------


class TestExceptionBoundary:
    async def test_missing_credentials_fail_before_any_request(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()

        result = await wake(fake, number, configured=False)

        assert result == failed(number, "credentials_not_configured")
        assert fake.served == []

    async def test_rejected_signature_fails_the_delivery(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        number = world.number()
        fake.request(number, REVIEW, submission(unique_package(), number))
        fake.server.reject_signatures = True

        assert await wake(fake, number) == failed(number, "signature_rejected")

    @pytest.mark.parametrize(
        ("responder", "reason", "extra"),
        [
            (status_response(404), "not_found", {}),
            (status_response(503, b"<status/>"), "http_status", {"http_status": 503}),
            (raising(httpx.ConnectError("fictional refusal")), "transport", {}),
        ],
        ids=["not-visible-yet-404", "http-503", "transport"],
    )
    async def test_failed_or_incomplete_lookup_fails_without_selection(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        reconciliations: Reconciliations,
        responder: Any,
        reason: str,
        extra: dict[str, int],
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()
        fake.raw_request(number, responder)

        result = await wake(fake, number)

        assert result == failed(number, reason, **extra)
        assert reconciliations.calls == []
        assert await delivery(world, scope) == DeliveryStatus.PENDING.value

    async def test_invalid_detail_document_fails_the_delivery(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        number = world.number()
        fake.raw_request(
            number,
            xml_response(request_document(number + 1, REVIEW)),
        )

        assert await wake(fake, number) == failed(number, "invalid_document")

    @pytest.mark.parametrize(
        "target", ["read_retained_identities", "load_ibs_request_scopes"]
    )
    async def test_selection_failure_fails_the_delivery(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        reconciliations: Reconciliations,
        monkeypatch: pytest.MonkeyPatch,
        target: str,
    ) -> None:
        number = world.number()
        fake.request(number, REVIEW, submission(unique_package(), number))

        async def broken(*_: Any, **__: Any) -> Any:
            raise OperationalError("SELECT", None, Exception())

        monkeypatch.setattr(ibs_event_handlers, target, broken)

        assert await wake(fake, number) == failed(number, "selection_failed")
        assert reconciliations.calls == []

    async def test_ambiguous_commit_ends_the_delivery_and_keeps_earlier_scopes(
        self, world: RequestWorld, fake: FakeRequests, units: UnitSessions
    ) -> None:
        """The second scope's commit has an unknown outcome: the boundary
        propagates, the third scope is not attempted, the delivery fails,
        and the first scope stays committed."""
        package = unique_package()
        scopes = sorted(
            await scopes_of(world, *[(package, CODESTREAM)] * 3),
            key=lambda s: s.track_id,
        )
        number = world.number()
        action = submission(package, number)
        fake.request(number, REVIEW, action)
        fake.action_diff(
            number,
            action,
            *(cve_issue(s.cve_id) for s in scopes if s.cve_id),
            codestream_package=package,
        )
        fake.quiet(package, open_submissions=[number])
        units.failing_commit = (2, OperationalError("COMMIT", None, Exception()))

        result = await wake(fake, number)

        assert result == failed(number, "reconciliation_failed", track_count=3)
        assert await correlated_numbers(world, scopes[0]) == [number]
        assert await correlated_numbers(world, scopes[2]) == []
        assert units.closed == units.sessions

    async def test_unexpected_lookup_exception_fails_the_delivery(
        self, world: RequestWorld, fake: FakeRequests, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        number = world.number()

        async def broken(*_: Any) -> Any:
            raise RuntimeError("fictional bug")

        monkeypatch.setattr(ibs_request_observation.EvidenceCache, "detail", broken)

        assert await wake(fake, number) == failed(number, "unexpected_error")

    @pytest.mark.parametrize(
        "target",
        [
            (ibs_request_observation.EvidenceCache, "detail"),
            (ibs_event_handlers, "load_ibs_request_scopes"),
            (ibs_event_handlers, "reconcile_ibs_requests"),
        ],
        ids=["lookup", "selection", "boundary"],
    )
    async def test_memory_error_propagates(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        target: tuple[Any, str],
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()
        fake.request(number, REVIEW, submission(scope.package_name, number))

        async def exhausted(*_: Any, **__: Any) -> Any:
            raise MemoryError

        monkeypatch.setattr(*target, exhausted)

        with pytest.raises(MemoryError):
            await wake(fake, number)


# ---------------------------------------------------------------------------
# 4. Idempotency, order, and concurrency (Request States; Shared
#    Authoritative Reconciliation > concurrency; Testing Requirements:
#    duplicate/out-of-order event acceleration)
# ---------------------------------------------------------------------------


class TestIdempotencyAndOrder:
    async def test_byte_identical_duplicate_creates_converge_once(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)
        body = event_body(number)

        first = await wake(fake, number, body=body)
        second = await wake(fake, number, body=body)

        assert first == second == processed(number)
        assert await evidence_rows(world, number) == (1, 1, 1)
        assert await delivery(world, scope) == DeliveryStatus.IN_PROGRESS.value

    async def test_state_change_before_create_converges_on_current_detail(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)

        late = await wake(
            fake,
            number,
            routing_key=STATE_CHANGE,
            body=event_body(number, routing_key=STATE_CHANGE, state="declined"),
        )
        early = await wake(fake, number, body=event_body(number, state="new"))

        assert late == early == processed(number)
        [row] = await evidence_of(await world.probe(), scope.track_id)
        assert row.state == REVIEW.value
        assert await evidence_rows(world, number) == (1, 1, 1)

    async def test_concurrent_wake_ups_and_polling_converge_once(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """Two wake-ups and one periodic invocation race on independent
        sessions: one request, one action, one correlation, `IN_PROGRESS`."""
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)

        results = await asyncio.gather(
            wake(fake, number),
            wake(fake, number, routing_key=STATE_CHANGE),
            reconcile(fake, [scope]),
        )

        assert results[0] == results[1] == processed(number)
        assert [outcome.kind for outcome in results[2]] in (["created"], ["no_op"])
        assert await evidence_rows(world, number) == (1, 1, 1)
        assert await delivery(world, scope) == DeliveryStatus.IN_PROGRESS.value

    async def test_polling_committed_during_the_scan_makes_the_wake_up_a_no_op(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The periodic owner commits the same evidence after the wake-up's
        observation and before its unit locks the Ticket."""
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)
        polled: list[list[IBSRequestOutcome]] = []

        async def poll(_: IBSRequestScope) -> None:
            if not polled:
                polled.append([])
                polled[0] = await reconcile(fake, [scope])

        before_lock(monkeypatch, poll)

        result = await wake(fake, number)

        assert result == processed(number)
        assert [outcome.kind for outcome in polled[0]] == ["created"]
        assert await evidence_rows(world, number) == (1, 1, 1)

    async def test_late_wake_up_never_replaces_newer_committed_truth(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A newer request state commits during the wake-up's scan: the
        wake-up's older observation fails as stale and changes nothing."""
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number, _ = open_submission(fake, world, scope)
        seed = RequestSeed(world)
        await seed.evidence(
            number,
            REVIEW,
            submission(scope.package_name, number),
            tracks=[scope],
        )
        await seed.commit()
        done = False

        async def newer(_: IBSRequestScope) -> None:
            nonlocal done
            if not done:
                done = True
                session = await world.open_session()
                await session.execute(
                    update(IBSRequest)
                    .where(IBSRequest.request_number == number)
                    .values(state=DECLINED.value, upstream_updated_at=LATER_AT)
                )
                await session.commit()

        before_lock(monkeypatch, newer)

        with capture_logs() as logs:
            result = await wake(fake, number)

        assert result == failed(
            number, "track_failed", track_count=1, failed_track_count=1
        )
        assert [entry["reason_category"] for entry in logged(logs, SCOPE_FAILED)] == [
            "stale_request_observation"
        ]
        [row] = await evidence_of(await world.probe(), scope.track_id)
        assert row.state == DECLINED.value


# ---------------------------------------------------------------------------
# 5. No Ticket event, publication, or convergence effect (Delivery
#    Derivation; ticket-audit-log.md no-event boundaries; Non-Goals)
# ---------------------------------------------------------------------------


class TestNoEventOrPublication:
    @pytest.mark.parametrize(
        "path", ["created", "no-op", "irrelevant", "lookup-failed", "scope-failed"]
    )
    async def test_no_ticket_event_or_publication_for_any_outcome(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        publication: Publish,
        path: str,
    ) -> None:
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()
        match path:
            case "created" | "no-op":
                number, _ = open_submission(fake, world, scope)
                if path == "no-op":
                    await wake(fake, number)
            case "irrelevant":
                fake.request(number, REVIEW, submission(unique_package(), number))
            case "lookup-failed":
                fake.respond("GET", f"/request/{number}", [], 404)
            case _:
                fake.request(number, REVIEW, submission(scope.package_name, number))

        result = await wake(fake, number)

        assert result.outcome in {
            DeliveryOutcome.PROCESSED,
            DeliveryOutcome.IRRELEVANT,
            DeliveryOutcome.FAILED,
        }
        assert await events_of(world, scope.ticket_id) == []
        assert publication.calls == []


# ---------------------------------------------------------------------------
# 6. Privacy (Security; ibs-submission-tracking.md Security and Privacy)
# ---------------------------------------------------------------------------


class TestPrivacy:
    async def test_event_actor_text_and_projects_reach_no_log_row_or_url(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The event carries actor fields, free text, and a personal project;
        the current detail names a personal source project too. Logs, rows,
        and request URLs carry none of them."""
        (scope,) = await scopes_of(world, (unique_package(), CODESTREAM))
        number = world.number()
        action = submission(
            scope.package_name,
            number,
            source_project=HOME_PROJECT,
            source_package=scope.package_name,
        )
        fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name, open_submissions=[number])

        with capture_logs() as logs:
            result = await wake(
                fake,
                number,
                routing_key=STATE_CHANGE,
                body=event_body(number, routing_key=STATE_CHANGE),
            )

        # The diff of an SR from a personal project is never requested, so
        # the scope is incomplete (ibs-integration.md, Request Action Diff).
        assert result == failed(
            number, "track_failed", track_count=1, failed_track_count=1
        )
        rendered = repr(logs) + repr(fake.served) + repr(result)
        for forbidden in (MARKER, "example-user", "home:", "jdoe"):
            assert forbidden not in rendered
        assert all(
            "home:" not in path and "example-user" not in path for path in fake.paths()
        )
        assert await evidence_rows(world, number) == (0, 0, 0)
