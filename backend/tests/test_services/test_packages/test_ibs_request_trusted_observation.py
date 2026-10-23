"""Integration tests for the trusted observation application
`apply_ibs_request_observation()`
(backend/app/services/packages/ibs_request_reconciliation.py).

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Shared Authoritative
  Reconciliation > Trusted Observation Application and Algorithm steps
  4-9; Delivery Derivation; Testing Requirements: every guard, the
  `created`, `updated`, and `no_op` outcomes, a `RELEASED` observation
  applied from `PENDING`, each rejection category, no IBS, Redis, or Celery
  I/O and no Ticket event).
- docs/features/packages/package-model.md (Automatic Transitions: the
  delivery table, the atomic `PENDING -> IN_PROGRESS -> RELEASED`
  application).

The function never commits, so every test runs on the rolled back
`db_session`. A scope is an `ANALYSIS`/`PENDING` IBS track of `CODESTREAM`
below an `Analysis` Ticket with its own CVE and a fresh logical package.
The structural test that only the example dataset loader references the
function is in
`tests/test_architecture/test_ibs_request_reconciliation_boundaries.py`.

All data is fictional: CVE identifiers `CVE-2099-NNNNNNNN`, packages
`example-*`, request numbers from `next_number()`, incidents from
`next_incident()`, checksums derived from fictional labels.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta
from typing import Any, Final

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    PackageStatus,
    TicketStatus,
    WorkflowType,
)
from app.core.exceptions import ServiceError, TicketNotMutableError
from app.database import detach_post_commit_callbacks
from app.models.cve import CVE
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.services.packages import ibs_request_reconciliation
from app.services.packages.ibs_request_identity import action_key
from app.services.packages.ibs_request_observation import (
    ActionWrite,
    IBSRequestScope,
    Observation,
    RequestWrite,
    ScopeSnapshot,
)
from app.services.packages.ibs_request_reconciliation import (
    IBSObservationRejectedError,
    apply_ibs_request_observation,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.ibs_request_reconciliation import (
    CODESTREAM,
    CREATED_AT,
    OTHER_CODESTREAM,
    WHEN_AT,
    checksum,
    next_incident,
    next_number,
    origin,
    unique_package,
)
from tests.support.no_outbound import OutboundGuard
from tests.support.post_ingest_resolution import record_publications

pytestmark = pytest.mark.integration

pytest_plugins = ["tests.support.no_outbound_fixtures"]
"""Provides the `no_outbound` guard."""

MI: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
MR: Final = IBSRequestActionType.MAINTENANCE_RELEASE
LATER_AT: Final = WHEN_AT + timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class Seeded:
    ticket_id: uuid.UUID
    track_id: uuid.UUID
    package: str


async def _seed(
    db: AsyncSession,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    workflow: WorkflowType = WorkflowType.IBS,
) -> Seeded:
    cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
    db.add(cve)
    await db.flush()
    ticket = Ticket(status=status.value, cve_id=cve.id)
    db.add(ticket)
    await db.flush()
    package = unique_package()
    ticket_package = TicketPackage(ticket_id=ticket.id, package_name=package)
    db.add(ticket_package)
    await db.flush()
    track = TicketPackageTrack(
        ticket_package_id=ticket_package.id,
        workflow_type=workflow.value,
        reference=CODESTREAM,
        status=PackageStatus.ANALYSIS.value,
        delivery_status=DeliveryStatus.PENDING.value,
    )
    db.add(track)
    await db.flush()
    return Seeded(ticket_id=ticket.id, track_id=track.id, package=package)


def _request(
    number: int,
    state: IBSRequestState,
    *,
    updated: datetime = WHEN_AT,
) -> RequestWrite:
    return RequestWrite(
        request_number=number,
        state=state,
        superseded_by_request_number=None,
        upstream_created_at=CREATED_AT,
        upstream_updated_at=updated,
    )


def _keyed(**values: Any) -> ActionWrite:
    """An `ActionWrite` whose key is the identity of its own fields."""
    key = action_key(
        values["request_number"],
        values["action_type"],
        source_project=values["source_project"],
        source_package=values["source_package"],
        target_project=values["target_project"],
        target_package=values["target_package"],
        target_release_project=values["target_release_project"],
    )
    return ActionWrite(key=key, **values)


def _fields(action: ActionWrite) -> dict[str, Any]:
    """The fields of `action` except its key."""
    return {
        field.name: getattr(action, field.name)
        for field in fields(action)
        if field.name != "key"
    }


def _submission(
    package: str,
    number: int,
    *,
    incident: int | None = None,
    srcmd5: str | None = None,
) -> ActionWrite:
    """A `maintenance_incident` action of `package` in `CODESTREAM`; with
    `incident`, its accepted form."""
    physical = f"{package}.{origin(CODESTREAM)}"
    accepted = incident is not None
    return _keyed(
        request_number=number,
        action_type=MI,
        source_project="SUSE:SLE-15-SP6:Branches",
        source_package=physical,
        target_project=f"SUSE:Maintenance:{incident}" if accepted else None,
        target_package=physical if accepted else None,
        target_release_project=CODESTREAM,
        logical_package=package,
        codestream_name=CODESTREAM,
        incident_number=incident,
        accepted_revision="1" if accepted else None,
        accepted_srcmd5=(srcmd5 or checksum(f"sr-accepted-{number}"))
        if accepted
        else None,
    )


def _release(package: str, number: int, incident: int) -> ActionWrite:
    """An accepted `maintenance_release` action of `package` from
    `incident` to `CODESTREAM`, with acceptinfo."""
    return _keyed(
        request_number=number,
        action_type=MR,
        source_project=f"SUSE:Maintenance:{incident}",
        source_package=f"{package}.{origin(CODESTREAM)}",
        target_project=CODESTREAM,
        target_package=f"{package}.{incident}",
        target_release_project=None,
        logical_package=package,
        codestream_name=CODESTREAM,
        incident_number=incident,
        accepted_revision="1",
        accepted_srcmd5=checksum(f"rr-accepted-{number}"),
    )


def _open_submission(package: str) -> tuple[int, Observation]:
    number = next_number()
    return number, Observation(
        DeliveryStatus.IN_PROGRESS,
        (_request(number, IBSRequestState.REVIEW),),
        (_submission(package, number),),
    )


async def _evidence_count(db: AsyncSession) -> tuple[int, int, int]:
    """The number of request, action, and correlation rows."""
    counts = []
    for model in (IBSRequest, IBSRequestAction, IBSRequestActionTrack):
        counts.append(await db.scalar(select(func.count()).select_from(model)) or 0)
    return counts[0], counts[1], counts[2]


async def _delivery(db: AsyncSession, track_id: uuid.UUID) -> str | None:
    return await db.scalar(
        select(TicketPackageTrack.delivery_status).where(
            TicketPackageTrack.id == track_id
        )
    )


async def _evidence(db: AsyncSession, track_id: uuid.UUID) -> list[tuple[Any, ...]]:
    """`(request number, state, action type, logical package, codestream,
    incident, target project, accepted checksum)` of every action correlated
    to `track_id`, by request number."""
    rows = await db.execute(
        select(
            IBSRequest.request_number,
            IBSRequest.state,
            IBSRequestAction.action_type,
            IBSRequestAction.logical_package,
            IBSRequestAction.codestream_name,
            IBSRequestAction.incident_number,
            IBSRequestAction.target_project,
            IBSRequestAction.accepted_srcmd5,
        )
        .select_from(IBSRequestActionTrack)
        .join(
            IBSRequestAction,
            IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
        )
        .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
        .where(IBSRequestActionTrack.ticket_package_track_id == track_id)
        .order_by(IBSRequest.request_number)
    )
    return [tuple(row) for row in rows]


class TestGuards:
    async def test_missing_track_is_rejected_without_write(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        _, observation = _open_submission(seeded.package)
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="does not exist"):
            await apply_ibs_request_observation(
                db_session, track_id=uuid.uuid7(), observation=observation
            )

        assert await _evidence_count(db_session) == before

    async def test_git_track_is_rejected_without_write(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session, workflow=WorkflowType.GIT)
        _, observation = _open_submission(seeded.package)
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="not an IBS track"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before

    @pytest.mark.parametrize("status", [TicketStatus.RESOLVED, TicketStatus.IGNORED])
    async def test_inactive_ticket_is_rejected_without_write(
        self, db_session: AsyncSession, status: TicketStatus
    ) -> None:
        seeded = await _seed(db_session, status=status)
        _, observation = _open_submission(seeded.package)
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="not active"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before

    async def test_action_without_its_request_is_rejected_without_write(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        observation = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(next_number(), IBSRequestState.REVIEW),),
            (_submission(seeded.package, next_number()),),
        )
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="request the observation lacks"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before

    @pytest.mark.parametrize(
        "changes",
        [
            {"target_release_project": None},
            {"codestream_name": OTHER_CODESTREAM},
            {"incident_number": 0},
            {"accepted_srcmd5": "A" * 32},
            {"accepted_srcmd5": "a" * 31},
        ],
        ids=[
            "no-release-project",
            "codestream-not-release-project",
            "non-positive-incident",
            "uppercase-checksum",
            "short-checksum",
        ],
    )
    async def test_submission_violating_the_action_structure_is_rejected(
        self, db_session: AsyncSession, changes: dict[str, Any]
    ) -> None:
        seeded = await _seed(db_session)
        number = next_number()
        action = _submission(seeded.package, number, incident=next_incident())
        observation = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(number, IBSRequestState.ACCEPTED),),
            (_keyed(**_fields(action) | changes),),
        )
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="action structure"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before

    @pytest.mark.parametrize(
        "changes",
        [
            {"incident_number": None},
            {"target_package": None},
            {"codestream_name": OTHER_CODESTREAM},
        ],
        ids=["no-incident", "no-target-package", "codestream-not-target"],
    )
    async def test_release_violating_the_action_structure_is_rejected(
        self, db_session: AsyncSession, changes: dict[str, Any]
    ) -> None:
        seeded = await _seed(db_session)
        number = next_number()
        action = _release(seeded.package, number, next_incident())
        observation = Observation(
            DeliveryStatus.RELEASED,
            (_request(number, IBSRequestState.ACCEPTED),),
            (_keyed(**_fields(action) | changes),),
        )
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="action structure"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before

    async def test_identity_that_differs_from_the_fields_is_rejected(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number = next_number()
        action = _submission(seeded.package, number)
        observation = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(number, IBSRequestState.REVIEW),),
            (
                replace(
                    action,
                    key=(number, MI, "SUSE:SLE-15-SP6:Branches", "other", CODESTREAM),
                ),
            ),
        )
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="identity differs"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before

    @pytest.mark.parametrize(
        "changes",
        [
            {"source_package": f"example-other.{origin(CODESTREAM)}"},
            {
                "target_release_project": OTHER_CODESTREAM,
                "codestream_name": OTHER_CODESTREAM,
            },
            {"logical_package": "example-other"},
        ],
        ids=["other-physical-package", "other-codestream", "other-stored-package"],
    )
    async def test_action_of_another_package_or_codestream_is_rejected(
        self, db_session: AsyncSession, changes: dict[str, Any]
    ) -> None:
        seeded = await _seed(db_session)
        number = next_number()
        action = _submission(seeded.package, number)
        observation = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(number, IBSRequestState.REVIEW),),
            (_keyed(**_fields(action) | changes),),
        )
        before = await _evidence_count(db_session)

        with pytest.raises(ValueError, match="scope's package"):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert await _evidence_count(db_session) == before


class TestOutcomes:
    async def test_first_observation_creates_correlated_evidence_and_progress(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number, observation = _open_submission(seeded.package)

        result = await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=observation
        )

        assert result == "created"
        assert await _delivery(db_session, seeded.track_id) == "IN_PROGRESS"
        assert await _evidence(db_session, seeded.track_id) == [
            (number, "review", MI.value, seeded.package, CODESTREAM, None, None, None)
        ]

    async def test_the_same_observation_again_is_a_no_op(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        _, observation = _open_submission(seeded.package)
        await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=observation
        )
        before = await _evidence_count(db_session)

        result = await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=observation
        )

        assert result == "no_op"
        assert await _evidence_count(db_session) == before
        assert await _delivery(db_session, seeded.track_id) == "IN_PROGRESS"

    async def test_a_later_observation_updates_the_request_and_action(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number, first = _open_submission(seeded.package)
        await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=first
        )
        incident = next_incident()
        later = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(number, IBSRequestState.ACCEPTED, updated=LATER_AT),),
            (_submission(seeded.package, number, incident=incident),),
        )

        result = await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=later
        )

        assert result == "updated"
        assert await _evidence(db_session, seeded.track_id) == [
            (
                number,
                "accepted",
                MI.value,
                seeded.package,
                CODESTREAM,
                incident,
                f"SUSE:Maintenance:{incident}",
                checksum(f"sr-accepted-{number}"),
            )
        ]

    async def test_a_released_observation_applies_from_pending(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number, incident = next_number(), next_incident()
        observation = Observation(
            DeliveryStatus.RELEASED,
            (_request(number, IBSRequestState.ACCEPTED),),
            (_release(seeded.package, number, incident),),
        )

        result = await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=observation
        )

        assert result == "created"
        assert await _delivery(db_session, seeded.track_id) == "RELEASED"
        assert await _evidence(db_session, seeded.track_id) == [
            (
                number,
                "accepted",
                MR.value,
                seeded.package,
                CODESTREAM,
                incident,
                CODESTREAM,
                checksum(f"rr-accepted-{number}"),
            )
        ]

    async def test_performs_no_io_registers_no_effect_and_creates_no_event(
        self,
        db_session: AsyncSession,
        no_outbound: OutboundGuard,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        publications = record_publications(monkeypatch)
        seeded = await _seed(db_session)
        _, observation = _open_submission(seeded.package)

        await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=observation
        )

        assert no_outbound.attempts == []
        assert publications.calls == []
        assert pending_ticket_convergence_effects(db_session) == ()
        assert detach_post_commit_callbacks(db_session) == []
        events = await db_session.scalar(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id == seeded.ticket_id)
        )
        assert events == 0
        track_status = await db_session.scalar(
            select(TicketPackageTrack.status).where(
                TicketPackageTrack.id == seeded.track_id
            )
        )
        assert track_status == PackageStatus.ANALYSIS.value


def _before_lock(monkeypatch: pytest.MonkeyPatch, status: TicketStatus) -> None:
    """Set the scope's Ticket to `status` after the guards and the step-1
    snapshot, before the Ticket lock: a change the locked revalidation
    observes."""
    original = ibs_request_reconciliation._reconcile_scope

    async def wrapped(
        db: AsyncSession,
        scope: IBSRequestScope,
        snapshot: ScopeSnapshot,
        observation: Observation,
    ) -> Any:
        await db.execute(
            update(Ticket)
            .where(Ticket.id == scope.ticket_id)
            .values(status=status.value)
        )
        return await original(db, scope, snapshot, observation)

    monkeypatch.setattr(ibs_request_reconciliation, "_reconcile_scope", wrapped)


class TestRejections:
    async def test_a_scope_changed_before_the_lock_is_rejected(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seeded = await _seed(db_session)
        _, observation = _open_submission(seeded.package)
        _before_lock(monkeypatch, TicketStatus.RESOLVED)
        before = await _evidence_count(db_session)

        with pytest.raises(IBSObservationRejectedError) as raised:
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

        assert raised.value.category == "scope_changed"
        assert str(raised.value) == "IBS request observation rejected: scope_changed"
        assert await _evidence_count(db_session) == before
        assert await _delivery(db_session, seeded.track_id) == "PENDING"

    async def test_a_ticket_that_became_not_mutable_raises(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seeded = await _seed(db_session)
        _, observation = _open_submission(seeded.package)
        _before_lock(monkeypatch, TicketStatus.IGNORED)

        with pytest.raises(TicketNotMutableError):
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=observation
            )

    async def test_an_older_request_observation_is_rejected_as_stale(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number = next_number()
        newer = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(number, IBSRequestState.REVIEW, updated=LATER_AT),),
            (_submission(seeded.package, number),),
        )
        await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=newer
        )
        older = replace(newer, requests=(_request(number, IBSRequestState.NEW),))

        with pytest.raises(IBSObservationRejectedError) as raised:
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=older
            )

        assert raised.value.category == "stale_request_observation"

    async def test_conflicting_equal_time_content_is_rejected(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number, first = _open_submission(seeded.package)
        await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=first
        )
        conflicting = replace(
            first, requests=(_request(number, IBSRequestState.DECLINED),)
        )

        with pytest.raises(IBSObservationRejectedError) as raised:
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=conflicting
            )

        assert raised.value.category == "conflicting_observation"

    async def test_conflicting_provenance_is_rejected(
        self, db_session: AsyncSession
    ) -> None:
        seeded = await _seed(db_session)
        number, incident = next_number(), next_incident()
        first = Observation(
            DeliveryStatus.IN_PROGRESS,
            (_request(number, IBSRequestState.ACCEPTED),),
            (_submission(seeded.package, number, incident=incident),),
        )
        await apply_ibs_request_observation(
            db_session, track_id=seeded.track_id, observation=first
        )
        conflicting = replace(
            first,
            actions=(
                _submission(
                    seeded.package,
                    number,
                    incident=incident,
                    srcmd5=checksum("another-acceptance"),
                ),
            ),
        )

        with pytest.raises(IBSObservationRejectedError) as raised:
            await apply_ibs_request_observation(
                db_session, track_id=seeded.track_id, observation=conflicting
            )

        assert raised.value.category == "conflicting_provenance"

    def test_the_rejection_inherits_directly_from_service_error(self) -> None:
        assert IBSObservationRejectedError.__bases__ == (ServiceError,)
