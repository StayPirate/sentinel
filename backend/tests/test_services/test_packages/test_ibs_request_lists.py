"""Tests for the Ticket-scoped IBS request lists
(backend/app/services/packages/ibs_request_lists.py).

See docs/features/packages/ibs-submission-tracking.md for the contract
under test: Public API, Common Query Rules, List Submission Requests,
List Release Requests (exposed fields, no endpoint-specific errors, and
the fixed `https://build.suse.de` links), Testing Requirements (the API
bullet and the log/API/persistence privacy bullet), Security and Privacy
bullet 1, and Data Model (IBSRequest, IBSRequestAction,
IBSRequestActionTrack, Retention and Deletion).

Visibility follows docs/features/identity/rbac.md (Scope and
Confidential Ticket Visibility) and is exercised against the Ticket
Accessibility matrix in docs/features/platform/testing-strategy.md.
Pagination, enum-filter, sorting, and Ticket identifier rules come from
docs/api-spec.md (Pagination, Enum Filter Validation, Deterministic
Pagination Ordering, Ticket Identifier Resolution).

The independent-session races live in `test_ibs_request_lists_races.py`.
"""

from __future__ import annotations

import dataclasses
import re
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestSortField,
    IBSRequestState,
    PackageStatus,
    Scope,
    SortOrder,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.packages.ibs_request_lists import (
    IBSRequestActionItem,
    IBSRequestActionPage,
    list_release_requests,
    list_submission_requests,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.no_outbound import OutboundGuard

pytest_plugins = ["tests.support.no_outbound_fixtures"]
"""Provides the `no_outbound` guard."""

# No module-level `pytestmark`: pytest marks accumulate rather than
# override, so every class below carries its own explicit marker
# (mirrors tests/test_services/test_ticket_audit_log.py).

_Factory = Callable[..., Awaitable[Any]]
_Lister = Callable[..., Awaitable[IBSRequestActionPage]]

_SR = IBSRequestActionType.MAINTENANCE_INCIDENT
_RR = IBSRequestActionType.MAINTENANCE_RELEASE
_CODESTREAM = "SUSE:SLE-15-SP6:Update"
_OTHER_CODESTREAM = "SUSE:SLE-15-SP7:Update"
_INT_MAX = 2_147_483_647


@dataclass(frozen=True, slots=True)
class _Kind:
    """One of the two list operations and the action type it returns."""

    lister: _Lister
    action_type: IBSRequestActionType

    @property
    def other_type(self) -> IBSRequestActionType:
        return _RR if self.action_type is _SR else _SR


_SUBMISSION = _Kind(list_submission_requests, _SR)
_RELEASE = _Kind(list_release_requests, _RR)
_KINDS = [
    pytest.param(_SUBMISSION, id="submission"),
    pytest.param(_RELEASE, id="release"),
]


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


async def _list(
    kind: _Kind,
    db: AsyncSession,
    ticket: Ticket,
    caller: TicketCaller = ANONYMOUS_CALLER,
    **kwargs: Any,
) -> IBSRequestActionPage:
    return await kind.lister(db, ticket_id=_sntl(ticket), caller=caller, **kwargs)


async def _ids(
    kind: _Kind,
    db: AsyncSession,
    ticket: Ticket,
    caller: TicketCaller = ANONYMOUS_CALLER,
    **kwargs: Any,
) -> list[uuid.UUID]:
    page = await _list(kind, db, ticket, caller, **kwargs)
    return [item.id for item in page.items]


@dataclass(frozen=True, slots=True)
class _Evidence:
    """Builds Ticket tracks and correlated IBS request actions from the
    shared model factories."""

    package_factory: _Factory
    track_factory: _Factory
    request_factory: _Factory
    action_factory: _Factory
    correlation_factory: _Factory

    async def track(
        self,
        ticket: Ticket,
        *,
        package: TicketPackage | None = None,
        **overrides: Any,
    ) -> TicketPackageTrack:
        """A track under `package`, or under a fresh package of `ticket`."""
        if package is None:
            package = await self.package_factory(ticket_id=ticket.id)
        track: TicketPackageTrack = await self.track_factory(
            ticket_package_id=package.id, **overrides
        )
        return track

    async def action(
        self,
        action_type: IBSRequestActionType,
        *tracks: TicketPackageTrack,
        request: IBSRequest | None = None,
        request_fields: dict[str, Any] | None = None,
        codestream: str | None = None,
        **overrides: Any,
    ) -> IBSRequestAction:
        """An action of `action_type` correlated to every given track.

        `codestream` sets the type-specific anchor (SR target release
        project or RR target project) from which the action factory derives
        `codestream_name`."""
        if request is None:
            request = await self.request_factory(**(request_fields or {}))
        fields = dict(overrides)
        if codestream is not None:
            anchor = (
                "target_project" if action_type is _RR else "target_release_project"
            )
            fields[anchor] = codestream
        action: IBSRequestAction = await self.action_factory(
            ibs_request_id=request.id, action_type=action_type.value, **fields
        )
        for track in tracks:
            await self.correlation_factory(
                ibs_request_action_id=action.id, ticket_package_track_id=track.id
            )
        return action


@pytest.fixture
def evidence(
    ticket_package_factory: _Factory,
    ticket_package_track_factory: _Factory,
    ibs_request_factory: _Factory,
    ibs_request_action_factory: _Factory,
    ibs_request_action_track_factory: _Factory,
) -> _Evidence:
    return _Evidence(
        package_factory=ticket_package_factory,
        track_factory=ticket_package_track_factory,
        request_factory=ibs_request_factory,
        action_factory=ibs_request_action_factory,
        correlation_factory=ibs_request_action_track_factory,
    )


# ---------------------------------------------------------------------------
# Input guards
# ---------------------------------------------------------------------------


def _session_without_queries() -> AsyncMock:
    """A session whose every statement fails, so a guard that ran a query
    would not raise the expected exception."""
    db = AsyncMock(spec=AsyncSession)
    db.execute.side_effect = AssertionError("a statement was executed")
    return db


@pytest.mark.unit
class TestInputGuards:
    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        ("page", "per_page"),
        [(0, 20), (-1, 20), (1, 0), (1, 101)],
        ids=["page-0", "page-negative", "per-page-0", "per-page-101"],
    )
    async def test_out_of_range_pagination_raises_before_query(
        self, kind: _Kind, page: int, per_page: int
    ) -> None:
        db = _session_without_queries()

        with pytest.raises(ValueError, match="page"):
            await kind.lister(
                db,
                ticket_id="SNTL-1",
                caller=ANONYMOUS_CALLER,
                page=page,
                per_page=per_page,
            )

        db.execute.assert_not_awaited()

    @pytest.mark.parametrize("incident_number", [0, -1, _INT_MAX + 1])
    async def test_out_of_range_incident_number_raises_before_query(
        self, incident_number: int
    ) -> None:
        db = _session_without_queries()

        with pytest.raises(ValueError, match="incident_number"):
            await list_release_requests(
                db,
                ticket_id="SNTL-1",
                caller=ANONYMOUS_CALLER,
                incident_number=incident_number,
            )

        db.execute.assert_not_awaited()

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        "locator",
        [
            "SNTL-0",
            "sntl-1",
            "SNTL-01",
            " SNTL-1",
            "SNTL-1 ",
            "SNTL-2147483648",
            # Fixed rather than random: pytest-xdist workers must collect
            # identical test ids.
            "8d0a6f1e-3c2b-4f5a-9e7d-1b2c3d4e5f60",
            "",
        ],
    )
    async def test_malformed_locator_raises_before_query(
        self, kind: _Kind, locator: str
    ) -> None:
        db = _session_without_queries()

        with pytest.raises(TicketNotFoundError):
            await kind.lister(db, ticket_id=locator, caller=ANONYMOUS_CALLER)

        db.execute.assert_not_awaited()

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_database_error_propagates(self, kind: _Kind) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await kind.lister(db, ticket_id="SNTL-1", caller=ANONYMOUS_CALLER)

        assert excinfo.value is failure


@pytest.mark.integration
class TestInputBoundaries:
    async def test_maximum_incident_number_is_accepted(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        await evidence.action(_RR, track, incident_number=45001)

        result = await list_release_requests(
            db_session,
            ticket_id=_sntl(ticket),
            caller=ANONYMOUS_CALLER,
            incident_number=_INT_MAX,
        )

        assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_maximum_page_is_accepted(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        await evidence.action(kind.action_type, track)

        result = await _list(kind, db_session, ticket, page=_INT_MAX, per_page=100)

        assert result.items == ()
        assert (result.total, result.page, result.per_page) == (1, _INT_MAX, 100)


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestItemShape:
    def test_item_exposes_exactly_the_documented_fields(self) -> None:
        """No author, actor, comment, description, raw source/target,
        acceptinfo, or local row timestamp (List Release Requests)."""
        assert {field.name for field in dataclasses.fields(IBSRequestActionItem)} == {
            "id",
            "action_type",
            "request_number",
            "state",
            "superseded_by_request_number",
            "package_name",
            "codestream_name",
            "incident_number",
            "ibs_url",
            "incident_url",
            "upstream_created_at",
            "upstream_updated_at",
        }

    def test_page_exposes_items_and_pagination_metadata(self) -> None:
        assert {field.name for field in dataclasses.fields(IBSRequestActionPage)} == {
            "items",
            "total",
            "page",
            "per_page",
        }


_CEST = timezone(timedelta(hours=2))


@pytest.mark.integration
class TestProjection:
    async def test_accepted_submission_with_incident(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ibs_request_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """The List Submission Requests example item. The timestamps are
        stored with a +02:00 offset and returned as the same UTC
        instants."""
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket, reference=_CODESTREAM)
        request: IBSRequest = await ibs_request_factory(
            request_number=410001,
            state="accepted",
            upstream_created_at=datetime(2026, 8, 10, 11, 15, tzinfo=_CEST),
            upstream_updated_at=datetime(2026, 8, 10, 13, 30, tzinfo=_CEST),
        )
        action = await evidence.action(
            _SR,
            track,
            request=request,
            codestream=_CODESTREAM,
            source_package="example-package",
            target_project="SUSE:Maintenance:45001",
            target_package="example-package.SUSE_SLE-15-SP6_Update",
            logical_package="example-package",
            incident_number=45001,
            accepted_revision="3",
            accepted_srcmd5="0123456789abcdef0123456789abcdef",
        )

        result = await _list(_SUBMISSION, db_session, ticket)

        assert (result.total, result.page, result.per_page) == (1, 1, 20)
        assert result.items == (
            IBSRequestActionItem(
                id=action.id,
                action_type=IBSRequestActionType.MAINTENANCE_INCIDENT,
                request_number=410001,
                state=IBSRequestState.ACCEPTED,
                superseded_by_request_number=None,
                package_name="example-package",
                codestream_name="SUSE:SLE-15-SP6:Update",
                incident_number=45001,
                ibs_url="https://build.suse.de/request/show/410001",
                incident_url=(
                    "https://build.suse.de/project/show/SUSE:Maintenance:45001"
                ),
                upstream_created_at=datetime(2026, 8, 10, 9, 15, tzinfo=UTC),
                upstream_updated_at=datetime(2026, 8, 10, 11, 30, tzinfo=UTC),
            ),
        )
        (item,) = result.items
        assert item.action_type == "maintenance_incident"
        assert item.state == "accepted"
        for value in (item.upstream_created_at, item.upstream_updated_at):
            assert value.tzinfo is not None
            assert value.utcoffset() == timedelta(0)

    async def test_submission_without_incident_has_no_incident_link(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        await evidence.action(
            _SR, track, request_fields={"request_number": 410002, "state": "review"}
        )

        (item,) = (await _list(_SUBMISSION, db_session, ticket)).items

        assert item.incident_number is None
        assert item.incident_url is None
        assert item.ibs_url == "https://build.suse.de/request/show/410002"

    async def test_release_item(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ibs_request_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """The List Release Requests example item."""
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket, reference=_CODESTREAM)
        request: IBSRequest = await ibs_request_factory(
            request_number=410101,
            state="review",
            upstream_created_at=datetime(2026, 8, 11, 8, 0, tzinfo=UTC),
            upstream_updated_at=datetime(2026, 8, 11, 8, 20, tzinfo=UTC),
        )
        action = await evidence.action(
            _RR,
            track,
            request=request,
            codestream=_CODESTREAM,
            source_project="SUSE:Maintenance:45001",
            source_package="example-package.SUSE_SLE-15-SP6_Update",
            target_package="example-package",
            logical_package="example-package",
            incident_number=45001,
        )

        result = await _list(_RELEASE, db_session, ticket)

        assert (result.total, result.page, result.per_page) == (1, 1, 20)
        assert result.items == (
            IBSRequestActionItem(
                id=action.id,
                action_type=IBSRequestActionType.MAINTENANCE_RELEASE,
                request_number=410101,
                state=IBSRequestState.REVIEW,
                superseded_by_request_number=None,
                package_name="example-package",
                codestream_name="SUSE:SLE-15-SP6:Update",
                incident_number=45001,
                ibs_url="https://build.suse.de/request/show/410101",
                incident_url=(
                    "https://build.suse.de/project/show/SUSE:Maintenance:45001"
                ),
                upstream_created_at=datetime(2026, 8, 11, 8, 0, tzinfo=UTC),
                upstream_updated_at=datetime(2026, 8, 11, 8, 20, tzinfo=UTC),
            ),
        )
        assert result.items[0].action_type == "maintenance_release"

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("state", list(IBSRequestState))
    async def test_successor_is_projected_only_for_superseded(
        self,
        kind: _Kind,
        state: IBSRequestState,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        request_fields: dict[str, Any] = {
            "request_number": 410003,
            "state": state.value,
        }
        if state is IBSRequestState.SUPERSEDED:
            request_fields["superseded_by_request_number"] = 410099
        await evidence.action(kind.action_type, track, request_fields=request_fields)

        (item,) = (await _list(kind, db_session, ticket)).items

        assert item.state is state
        expected = 410099 if state is IBSRequestState.SUPERSEDED else None
        assert item.superseded_by_request_number == expected

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_links_ignore_the_configured_ibs_api_url(
        self,
        kind: _Kind,
        monkeypatch: pytest.MonkeyPatch,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        monkeypatch.setattr(settings, "ibs_api_url", "https://ibs-api.example.com")
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        await evidence.action(
            kind.action_type,
            track,
            request_fields={"request_number": 410004},
            incident_number=45004,
        )

        (item,) = (await _list(kind, db_session, ticket)).items

        assert item.ibs_url == "https://build.suse.de/request/show/410004"
        assert (
            item.incident_url
            == "https://build.suse.de/project/show/SUSE:Maintenance:45004"
        )


# ---------------------------------------------------------------------------
# Candidate set: type separation, deduplication, and history scope
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTypeSeparation:
    async def test_each_list_returns_only_its_action_type(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        submission = await evidence.action(_SR, track, incident_number=45010)
        release = await evidence.action(_RR, track, incident_number=45010)

        submissions = await _list(_SUBMISSION, db_session, ticket)
        releases = await _list(_RELEASE, db_session, ticket)

        assert [item.id for item in submissions.items] == [submission.id]
        assert submissions.total == 1
        assert {item.action_type for item in submissions.items} == {_SR}
        assert [item.id for item in releases.items] == [release.id]
        assert releases.total == 1
        assert {item.action_type for item in releases.items} == {_RR}

    async def test_release_is_never_inferred_from_incident_equality(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """A release action of the same incident as a correlated SR, but
        correlated only to another Ticket or to nothing, is absent."""
        ticket: Ticket = await ticket_factory()
        other: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        other_track = await evidence.track(other)
        await evidence.action(_SR, track, incident_number=45011)
        await evidence.action(_RR, incident_number=45011)
        foreign = await evidence.action(_RR, other_track, incident_number=45011)

        for incident_number in (None, 45011):
            result = await _list(
                _RELEASE, db_session, ticket, incident_number=incident_number
            )
            assert (result.items, result.total) == ((), 0)
        assert await _ids(_RELEASE, db_session, other) == [foreign.id]


@pytest.mark.integration
class TestDeduplication:
    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("layout", ["one-package", "two-packages"])
    async def test_action_correlated_to_several_tracks_appears_once(
        self,
        kind: _Kind,
        layout: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_package_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        first = await evidence.track(ticket, package=package)
        second = await evidence.track(
            ticket, package=package if layout == "one-package" else None
        )
        action = await evidence.action(kind.action_type, first, second)

        result = await _list(kind, db_session, ticket)

        assert [item.id for item in result.items] == [action.id]
        assert result.total == 1

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_action_shared_by_two_visible_tickets_appears_in_each(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        first: Ticket = await ticket_factory()
        second: Ticket = await ticket_factory()
        shared = await evidence.action(
            kind.action_type,
            await evidence.track(first),
            await evidence.track(second),
        )

        for ticket in (first, second):
            result = await _list(kind, db_session, ticket)
            assert [item.id for item in result.items] == [shared.id]
            assert result.total == 1

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_action_of_another_ticket_never_appears(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        other: Ticket = await ticket_factory()
        own = await evidence.action(kind.action_type, await evidence.track(ticket))
        await evidence.action(kind.action_type, await evidence.track(other))
        # Uncorrelated to any track at all.
        await evidence.action(kind.action_type)

        result = await _list(kind, db_session, ticket)

        assert [item.id for item in result.items] == [own.id]
        assert result.total == 1

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_shared_action_follows_each_ticket_visibility(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        public: Ticket = await ticket_factory()
        confidential: Ticket = await ticket_factory(is_confidential=True)
        shared = await evidence.action(
            kind.action_type,
            await evidence.track(public),
            await evidence.track(confidential),
        )

        assert await _ids(kind, db_session, public) == [shared.id]
        with pytest.raises(TicketNotFoundError):
            await _list(kind, db_session, confidential)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_total_counts_distinct_visible_actions_under_fan_out(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_package_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """Several tracks per action, actions shared with an invisible
        Ticket, and the invisible Ticket's own actions never inflate the
        total or move visible actions between pages."""
        public: Ticket = await ticket_factory()
        hidden: Ticket = await ticket_factory(is_confidential=True)
        packages = [await ticket_package_factory(ticket_id=public.id) for _ in range(2)]
        tracks = [
            await evidence.track(public, package=package)
            for package in packages
            for _ in range(2)
        ]
        hidden_tracks = [await evidence.track(hidden) for _ in range(2)]
        visible = {
            (await evidence.action(kind.action_type, *tracks, *hidden_tracks)).id,
            (await evidence.action(kind.action_type, *tracks[1:])).id,
        }
        await evidence.action(kind.action_type, *hidden_tracks)
        callers = [ANONYMOUS_CALLER, _restricted(await user_factory())]

        for caller in callers:
            result = await _list(kind, db_session, public, caller)
            assert result.total == 2
            assert {item.id for item in result.items} == visible
            pages = [
                await _list(kind, db_session, public, caller, page=page, per_page=1)
                for page in (1, 2, 3)
            ]
            assert [page.total for page in pages] == [2, 2, 2]
            assert [len(page.items) for page in pages] == [1, 1, 0]
            assert {item.id for page in pages for item in page.items} == visible


@pytest.mark.integration
class TestHistoryScope:
    """Persisted history is returned regardless of current Ticket status,
    track affectedness, exclusion, or actionability (Public API)."""

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("excluded", ["package", "track"])
    async def test_correlation_under_an_excluded_record_is_returned(
        self,
        kind: _Kind,
        excluded: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_package_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        track = await evidence.track(ticket, package=package)
        action = await evidence.action(kind.action_type, track)
        target: TicketPackage | TicketPackageTrack = (
            package if excluded == "package" else track
        )
        target.deleted_at = datetime.now(UTC)
        await db_session.flush()

        result = await _list(kind, db_session, ticket)

        assert [item.id for item in result.items] == [action.id]
        assert result.total == 1

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        "status",
        [TicketStatus.RESOLVED, TicketStatus.IGNORED, TicketStatus.DUPLICATED],
    )
    async def test_closed_ticket_status_is_returned(
        self,
        kind: _Kind,
        status: TicketStatus,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        # The factory links a Duplicated Ticket to a fresh target Ticket.
        ticket: Ticket = await ticket_factory(status=status.value)
        action = await evidence.action(kind.action_type, await evidence.track(ticket))

        assert ticket.status == status.value
        assert await _ids(kind, db_session, ticket) == [action.id]

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        ("status", "delivery_status"),
        [
            (PackageStatus.FIXED, DeliveryStatus.PENDING),
            (PackageStatus.NOT_AFFECTED, DeliveryStatus.PENDING),
            (PackageStatus.ANALYSIS, DeliveryStatus.PENDING),
            (PackageStatus.FIXED, DeliveryStatus.RELEASED),
        ],
        ids=["fixed", "not-affected", "analysis", "released"],
    )
    async def test_track_affectedness_and_delivery_are_ignored(
        self,
        kind: _Kind,
        status: PackageStatus,
        delivery_status: DeliveryStatus,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(
            ticket, status=status.value, delivery_status=delivery_status.value
        )
        action = await evidence.action(kind.action_type, track)

        assert await _ids(kind, db_session, ticket) == [action.id]


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFilters:
    @pytest.mark.parametrize("kind", _KINDS)
    async def test_package_name_is_exact_and_case_sensitive(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        match = await evidence.action(
            kind.action_type, track, logical_package="example-package"
        )
        await evidence.action(kind.action_type, track, logical_package="example-pkg")

        assert await _ids(kind, db_session, ticket, package_name="example-package") == [
            match.id
        ]
        for near_miss in ("Example-Package", "example", "example-package "):
            result = await _list(kind, db_session, ticket, package_name=near_miss)
            assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_codestream_name_is_exact_and_case_sensitive(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        match = await evidence.action(kind.action_type, track, codestream=_CODESTREAM)
        await evidence.action(kind.action_type, track, codestream=_OTHER_CODESTREAM)

        assert await _ids(kind, db_session, ticket, codestream_name=_CODESTREAM) == [
            match.id
        ]
        for near_miss in ("suse:sle-15-sp6:update", "SUSE:SLE-15-SP6", "SUSE:"):
            result = await _list(kind, db_session, ticket, codestream_name=near_miss)
            assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("state", list(IBSRequestState))
    async def test_state_filter_returns_only_that_state(
        self,
        kind: _Kind,
        state: IBSRequestState,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        by_state = {
            each: await evidence.action(
                kind.action_type, track, request_fields={"state": each.value}
            )
            for each in IBSRequestState
        }

        result = await _list(kind, db_session, ticket, state=state)

        assert [item.id for item in result.items] == [by_state[state].id]
        assert result.total == 1
        assert result.items[0].state is state

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_invalid_state_returns_empty_page_for_accessible_ticket(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await evidence.action(kind.action_type, await evidence.track(ticket))

        result = await _list(
            kind, db_session, ticket, state=None, state_was_supplied=True
        )

        assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_invalid_state_on_inaccessible_ticket_is_not_found(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await evidence.action(kind.action_type, await evidence.track(ticket))

        with pytest.raises(TicketNotFoundError):
            await _list(kind, db_session, ticket, state=None, state_was_supplied=True)

    async def test_incident_number_is_exact(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        match = await evidence.action(_RR, track, incident_number=45001)
        await evidence.action(_RR, track, incident_number=45002)
        await evidence.action(_RR, track, incident_number=4500)

        assert await _ids(_RELEASE, db_session, ticket, incident_number=45001) == [
            match.id
        ]
        result = await _list(_RELEASE, db_session, ticket, incident_number=450)
        assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_filters_combine_with_and(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        wanted: dict[str, Any] = {
            "logical_package": "example-package",
            "codestream": _CODESTREAM,
            "state": IBSRequestState.ACCEPTED.value,
            "incident_number": 45001,
        }
        mismatches: list[dict[str, Any]] = [
            {"logical_package": "example-pkg"},
            {"codestream": _OTHER_CODESTREAM},
            {"state": IBSRequestState.REVIEW.value},
        ]
        if kind is _RELEASE:
            mismatches.append({"incident_number": 45002})

        async def _create(values: dict[str, Any]) -> IBSRequestAction:
            fields = dict(values)
            state = fields.pop("state")
            return await evidence.action(
                kind.action_type, track, request_fields={"state": state}, **fields
            )

        target = await _create(wanted)
        for mismatch in mismatches:
            await _create({**wanted, **mismatch})
        filters: dict[str, Any] = {
            "package_name": "example-package",
            "codestream_name": _CODESTREAM,
            "state": IBSRequestState.ACCEPTED,
        }
        if kind is _RELEASE:
            filters["incident_number"] = 45001

        result = await _list(kind, db_session, ticket, **filters)

        assert [item.id for item in result.items] == [target.id]
        assert result.total == 1
        unfiltered = await _list(kind, db_session, ticket)
        assert unfiltered.total == 1 + len(mismatches)


# ---------------------------------------------------------------------------
# Sorting and pagination
# ---------------------------------------------------------------------------

# Three requests whose creation order differs from their update order.
_TIMESTAMPS: dict[str, tuple[datetime, datetime]] = {
    "a": (datetime(2026, 8, 1, tzinfo=UTC), datetime(2026, 8, 20, tzinfo=UTC)),
    "b": (datetime(2026, 8, 2, tzinfo=UTC), datetime(2026, 8, 10, tzinfo=UTC)),
    "c": (datetime(2026, 8, 3, tzinfo=UTC), datetime(2026, 8, 15, tzinfo=UTC)),
}
_SAME_TIME = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


@pytest.mark.integration
class TestSortingAndPagination:
    async def _timeline(
        self, kind: _Kind, ticket: Ticket, evidence: _Evidence
    ) -> dict[str, uuid.UUID]:
        track = await evidence.track(ticket)
        actions: dict[str, uuid.UUID] = {}
        # Created in an order matching neither sort key.
        for name in ("c", "a", "b"):
            created, updated = _TIMESTAMPS[name]
            action = await evidence.action(
                kind.action_type,
                track,
                request_fields={
                    "upstream_created_at": created,
                    "upstream_updated_at": updated,
                },
            )
            actions[name] = action.id
        return actions

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_default_is_upstream_updated_at_descending(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actions = await self._timeline(kind, ticket, evidence)

        assert await _ids(kind, db_session, ticket) == [
            actions["a"],
            actions["c"],
            actions["b"],
        ]

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        ("sort_by", "sort_order", "expected"),
        [
            (IBSRequestSortField.UPSTREAM_CREATED_AT, SortOrder.ASC, "abc"),
            (IBSRequestSortField.UPSTREAM_CREATED_AT, SortOrder.DESC, "cba"),
            (IBSRequestSortField.UPSTREAM_UPDATED_AT, SortOrder.ASC, "bca"),
            (IBSRequestSortField.UPSTREAM_UPDATED_AT, SortOrder.DESC, "acb"),
        ],
        ids=["created-asc", "created-desc", "updated-asc", "updated-desc"],
    )
    async def test_selected_field_and_direction(
        self,
        kind: _Kind,
        sort_by: IBSRequestSortField,
        sort_order: SortOrder,
        expected: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actions = await self._timeline(kind, ticket, evidence)

        ids = await _ids(
            kind, db_session, ticket, sort_by=sort_by, sort_order=sort_order
        )

        assert ids == [actions[name] for name in expected]

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("sort_by", list(IBSRequestSortField))
    @pytest.mark.parametrize("sort_order", list(SortOrder))
    async def test_equal_timestamps_are_ordered_by_action_id_across_pages(
        self,
        kind: _Kind,
        sort_by: IBSRequestSortField,
        sort_order: SortOrder,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ibs_request_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """Requests are created first and their actions in reverse, so
        the action-ID order differs from the request-ID order; two actions
        share one request."""
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        requests: list[IBSRequest] = [
            await ibs_request_factory(
                upstream_created_at=_SAME_TIME, upstream_updated_at=_SAME_TIME
            )
            for _ in range(3)
        ]
        actions = [
            await evidence.action(kind.action_type, track, request=request)
            for request in [*reversed(requests), requests[0]]
        ]
        expected = sorted(
            (action.id for action in actions),
            reverse=sort_order is SortOrder.DESC,
        )
        by_request = sorted(
            actions,
            key=lambda action: (action.ibs_request_id, action.id),
            reverse=sort_order is SortOrder.DESC,
        )
        assert expected != [action.id for action in by_request]

        pages = [
            await _list(
                kind,
                db_session,
                ticket,
                sort_by=sort_by,
                sort_order=sort_order,
                page=page,
                per_page=1,
            )
            for page in range(1, 6)
        ]

        assert [len(page.items) for page in pages] == [1, 1, 1, 1, 0]
        assert {page.total for page in pages} == {4}
        assert [item.id for page in pages for item in page.items] == expected

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_page_beyond_the_last_is_empty_with_the_total(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        for _ in range(3):
            await evidence.action(kind.action_type, track)

        result = await _list(kind, db_session, ticket, page=3, per_page=2)

        assert result.items == ()
        assert (result.total, result.page, result.per_page) == (3, 3, 2)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_total_counts_the_filtered_set_not_the_page(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        for state in ("accepted", "accepted", "accepted", "review", "review"):
            await evidence.action(
                kind.action_type, track, request_fields={"state": state}
            )

        whole = await _list(kind, db_session, ticket, page=2, per_page=2)
        filtered = await _list(
            kind,
            db_session,
            ticket,
            state=IBSRequestState.ACCEPTED,
            page=1,
            per_page=2,
        )

        assert (len(whole.items), whole.total) == (2, 5)
        assert (whole.page, whole.per_page) == (2, 2)
        assert (len(filtered.items), filtered.total) == (2, 3)
        assert (filtered.page, filtered.per_page) == (1, 2)


# ---------------------------------------------------------------------------
# Accessibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("caller_kind", ["anonymous", "non_confidential"])
    async def test_non_confidential_ticket_is_visible(
        self,
        kind: _Kind,
        caller_kind: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        action = await evidence.action(kind.action_type, await evidence.track(ticket))
        caller = (
            ANONYMOUS_CALLER
            if caller_kind == "anonymous"
            else _restricted(await user_factory())
        )

        assert await _ids(kind, db_session, ticket, caller) == [action.id]

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        ("branch", "visible"),
        [
            ("anonymous", False),
            ("non_entitled", False),
            ("scope_all", True),
            ("grant", True),
            ("maintainer", True),
        ],
        ids=["anonymous", "non-entitled", "scope-all", "grant", "maintainer"],
    )
    async def test_confidential_ticket_visibility_branches(
        self,
        kind: _Kind,
        branch: str,
        visible: bool,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        action = await evidence.action(
            kind.action_type, await evidence.track(ticket, package=package)
        )
        caller = _restricted(user)
        if branch == "anonymous":
            caller = ANONYMOUS_CALLER
        elif branch == "scope_all":
            caller = TicketCaller.authenticated(user.id, Scope.ALL)
        elif branch == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        elif branch == "maintainer":
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )

        if visible:
            result = await _list(kind, db_session, ticket, caller)
            assert [item.id for item in result.items] == [action.id]
            assert result.total == 1
        else:
            with pytest.raises(TicketNotFoundError):
                await _list(kind, db_session, ticket, caller)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_excluded_maintained_package_denies_and_restore_reveals(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        action = await evidence.action(
            kind.action_type, await evidence.track(ticket, package=package)
        )
        package.deleted_at = datetime.now(UTC)
        await db_session.flush()

        with pytest.raises(TicketNotFoundError):
            await _list(kind, db_session, ticket, _restricted(user))

        package.deleted_at = None
        await db_session.flush()

        assert await _ids(kind, db_session, ticket, _restricted(user)) == [action.id]

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_track_and_product_exclusion_keep_maintainer_visibility(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_package_product_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        excluded_track = await evidence.track(
            ticket, package=package, deleted_at=datetime.now(UTC)
        )
        product_track = await evidence.track(ticket, package=package)
        await ticket_package_product_factory(
            ticket_package_track_id=product_track.id, deleted_at=datetime.now(UTC)
        )
        actions = {
            (await evidence.action(kind.action_type, excluded_track)).id,
            (await evidence.action(kind.action_type, product_track)).id,
        }

        result = await _list(kind, db_session, ticket, _restricted(user))

        assert {item.id for item in result.items} == actions
        assert result.total == 2

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_access_is_lost_only_after_the_last_maintained_package(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        packages: list[TicketPackage] = [
            await ticket_package_factory(ticket_id=ticket.id) for _ in range(2)
        ]
        for package in packages:
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )
        action = await evidence.action(
            kind.action_type, await evidence.track(ticket, package=packages[0])
        )

        packages[0].deleted_at = datetime.now(UTC)
        await db_session.flush()
        assert await _ids(kind, db_session, ticket, _restricted(user)) == [action.id]

        packages[1].deleted_at = datetime.now(UTC)
        await db_session.flush()
        with pytest.raises(TicketNotFoundError):
            await _list(kind, db_session, ticket, _restricted(user))

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize("locator_kind", ["missing", "uuid"])
    async def test_missing_ticket_and_uuid_locator_are_not_found(
        self,
        kind: _Kind,
        locator_kind: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await evidence.action(kind.action_type, await evidence.track(ticket))
        locator = "SNTL-2147483647" if locator_kind == "missing" else str(ticket.id)

        with pytest.raises(TicketNotFoundError):
            await kind.lister(db_session, ticket_id=locator, caller=ANONYMOUS_CALLER)

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_visible_ticket_without_correlations_returns_empty_page(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await evidence.track(ticket)
        # Correlated only with the other action type.
        await evidence.action(kind.other_type, await evidence.track(ticket))

        result = await _list(kind, db_session, ticket)

        assert (result.items, result.total) == ((), 0)
        assert (result.page, result.per_page) == (1, 20)

    @pytest.mark.parametrize("kind", _KINDS)
    @pytest.mark.parametrize(
        "filters",
        [
            {},
            {"state": None, "state_was_supplied": True},
            {"state": IBSRequestState.DELETED},
            {"package_name": "no-such-package"},
            {"codestream_name": "SUSE:No:Such:Update"},
            {"page": 99},
        ],
        ids=[
            "no-filter",
            "invalid-state",
            "state",
            "package",
            "codestream",
            "beyond-last-page",
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_filter(
        self,
        kind: _Kind,
        filters: dict[str, Any],
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await evidence.action(kind.action_type, await evidence.track(ticket))
        caller = _restricted(await user_factory())

        with pytest.raises(TicketNotFoundError):
            await _list(kind, db_session, ticket, caller, **filters)


# ---------------------------------------------------------------------------
# No side effects
# ---------------------------------------------------------------------------

_LOCKING_CLAUSE = re.compile(
    r"\bFOR\s+(NO\s+KEY\s+)?(UPDATE|SHARE|KEY\s+SHARE)\b", re.I
)


class _StatementRecorder:
    """Records every SQL statement sent through the session's engine."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc_info: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


async def _audit_event_count(db: AsyncSession) -> int:
    return (
        await db.execute(select(func.count()).select_from(TicketAuditEvent))
    ).scalar_one()


@pytest.mark.integration
class TestNoSideEffects:
    @pytest.mark.parametrize("kind", _KINDS)
    async def test_read_is_one_statement_without_a_lock(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """Parent accessibility, candidate set, total, and page come from
        one statement, hence one PostgreSQL snapshot (Public API; Security
        and Privacy bullet 1), with every filter supplied."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        track = await evidence.track(ticket)
        for _ in range(3):
            await evidence.action(kind.action_type, track, incident_number=45001)
        filters: dict[str, Any] = {
            "package_name": "example-pkg",
            "codestream_name": _CODESTREAM,
            "state": IBSRequestState.NEW,
        }
        if kind is _RELEASE:
            filters["incident_number"] = 45001

        with _StatementRecorder(db_session) as recorder:
            await _list(kind, db_session, ticket, _restricted(user), **filters)

        assert len(recorder.statements) == 1
        (statement,) = recorder.statements
        assert statement.lstrip().upper().startswith(("SELECT", "WITH"))
        assert _LOCKING_CLAUSE.search(statement) is None

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_read_leaves_the_session_clean_and_creates_no_event(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await evidence.action(kind.action_type, await evidence.track(ticket))
        events_before = await _audit_event_count(db_session)

        result = await _list(kind, db_session, ticket)

        assert result.total == 1
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert await _audit_event_count(db_session) == events_before

    @pytest.mark.parametrize("kind", _KINDS)
    async def test_read_does_not_flush_pending_caller_state(
        self,
        kind: _Kind,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
    ) -> None:
        """A pending correlation added by the caller is neither flushed nor
        observed: autoflush is suspended for the read."""
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        flushed = await evidence.action(kind.action_type, track)
        unrelated = await evidence.action(kind.action_type)
        pending = IBSRequestActionTrack(
            ibs_request_action_id=unrelated.id, ticket_package_track_id=track.id
        )
        db_session.add(pending)

        with _StatementRecorder(db_session) as recorder:
            result = await _list(kind, db_session, ticket)

        assert pending in db_session.new
        assert len(recorder.statements) == 1
        assert [item.id for item in result.items] == [flushed.id]
        assert result.total == 1

    async def test_reads_perform_no_outbound_call(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        evidence: _Evidence,
        no_outbound: OutboundGuard,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await evidence.track(ticket)
        await evidence.action(_SR, track, incident_number=45001)
        await evidence.action(_RR, track, incident_number=45001)

        submissions = await _list(_SUBMISSION, db_session, ticket)
        releases = await _list(_RELEASE, db_session, ticket)

        assert (submissions.total, releases.total) == (1, 1)
        assert no_outbound.attempts == []
