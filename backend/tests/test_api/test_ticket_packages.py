"""End-to-end tests for the Ticket package-tree endpoint
(`backend/app/api/v1/ticket_packages.py`).

See docs/features/packages/package-model.md (API Endpoints > List Ticket
Packages) for the endpoint contract, docs/features/tickets/tickets.md
(Response Schemas > ProductDetail, TrackDetail, TrackMilestones,
PackageDetail), docs/features/tickets/ticket-deadlines.md (Evaluation
Instant, API Surface), and docs/api-spec.md (Optional Authentication on
Public Endpoints, Ticket Accessibility Check, Ticket Identifier Resolution,
Response Format). Tree projection, milestone, ordering, N+1, and
independent-session race coverage lives in
tests/test_services/test_package_service.py; these tests cover the HTTP
contract.
"""

from __future__ import annotations

import typing
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import ticket_packages as route
from app.core.enums import (
    CurrentPhase,
    DeliveryStatus,
    LifecyclePhase,
    MilestoneStatus,
    NonActionableReason,
    PackageStatus,
    Role,
    Severity,
    WorkflowType,
)
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.schemas import package as schemas
from app.services import package_service

Factory = Callable[..., Awaitable[Any]]

_NOT_FOUND = {"code": "TICKET_NOT_FOUND", "detail": "Ticket not found."}
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_PATH = "/api/v1/tickets/{ticket_id}/packages"
_CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, tzinfo=UTC)
_NOW = datetime(2026, 3, 11, 12, 0, tzinfo=UTC)
_EXCLUDED_AT = datetime(2026, 3, 10, 18, 0, tzinfo=UTC)


def _url(ticket: Ticket | str) -> str:
    locator = (
        ticket if isinstance(ticket, str) else format_ticket_id(ticket.sequence_id)
    )
    return _PATH.format(ticket_id=locator)


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


class Clock:
    """Controlled evaluation-instant source: each capture pops the next
    queued instant (or reuses `_NOW`) and is recorded in `calls`."""

    def __init__(self) -> None:
        self.queue: list[datetime] = []
        self.calls: list[datetime] = []

    def now(self) -> datetime:
        instant = self.queue.pop(0) if self.queue else _NOW
        self.calls.append(instant)
        return instant


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Replaces the endpoint's single evaluation-instant capture."""
    clock = Clock()
    monkeypatch.setattr(route, "_utc_now", clock.now)
    return clock


@pytest.mark.e2e
class TestAuthentication:
    async def test_anonymous_caller_reads_a_non_confidential_tree(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)

        response = await client.get(_url(ticket))

        assert response.status_code == 200
        assert [p["id"] for p in response.json()["data"]] == [str(package.id)]

    async def test_invalid_credential_returns_401_before_lookup(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "get_ticket_packages", spy)

        for locator in ("SNTL-1", "not-a-ticket"):
            response = await client.get(
                _url(locator), headers={"Authorization": "Bearer invalid-token"}
            )
            assert response.status_code == 401
            assert response.json() == _UNAUTHENTICATED

        spy.assert_not_awaited()


@pytest.mark.e2e
class TestListTicketPackagesEndpoint:
    async def test_returns_the_complete_tree_in_the_wire_format(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        cve = await cve_factory(severity=Severity.CRITICAL.value)
        ticket: Ticket = await ticket_factory(cve_id=cve.id, created_at=_CREATED_AT)
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-lib"
        )
        excluded = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-tool", deleted_at=_EXCLUDED_AT
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Codestream:1:Update",
            status=PackageStatus.NOT_AFFECTED.value,
        )
        eol_product = await product_factory(
            cpe="cpe:/o:example:beta:1",
            display_name="Example Beta 1",
            general_support_end_date=date(2020, 1, 1),
        )
        supported = await product_factory(
            cpe="cpe:/o:example:alpha:1",
            display_name="Example Alpha 1",
            general_support_end_date=date(2030, 1, 1),
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=supported.id
        )
        eol_occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=eol_product.id,
            eligible=False,
            is_eligible_override=True,
        )

        response = await client.get(_url(ticket))

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        assert body["data"] == [
            {
                "id": str(package.id),
                "package_name": "example-lib",
                "deleted_at": None,
                "actionable": True,
                "non_actionable_reason": None,
                "tracks": [
                    {
                        "id": str(track.id),
                        "workflow_type": "ibs",
                        "reference": "Example:Codestream:1:Update",
                        "status": "not_affected",
                        "delivery_status": "pending",
                        "delivery_relevant": False,
                        "deleted_at": None,
                        "actionable": True,
                        "non_actionable_reason": None,
                        "triage_due_at": "2026-03-13T14:37:21Z",
                        "submission_due_at": "2026-03-28T14:37:21Z",
                        "um_due_at": "2026-03-31T14:37:21Z",
                        "qa_due_at": "2026-04-09T14:37:21Z",
                        "release_due_at": "2026-04-09T14:37:21Z",
                        "milestones": {
                            "triage": "done",
                            "submission": "not_applicable",
                            "um": "not_applicable",
                            "qa": "not_applicable",
                        },
                        "current_phase": "done",
                        "products": [
                            {
                                "id": str(occurrence.id),
                                "product_cpe": "cpe:/o:example:alpha:1",
                                "product_name": "Example Alpha 1",
                                "eligible": True,
                                "is_eligible_override": False,
                                "released_at": None,
                                "lifecycle_phase": "general_support",
                                "deleted_at": None,
                                "actionable": True,
                                "non_actionable_reason": None,
                            },
                            {
                                "id": str(eol_occurrence.id),
                                "product_cpe": "cpe:/o:example:beta:1",
                                "product_name": "Example Beta 1",
                                "eligible": False,
                                "is_eligible_override": True,
                                "released_at": None,
                                "lifecycle_phase": "eol",
                                "deleted_at": None,
                                "actionable": False,
                                "non_actionable_reason": "eol",
                            },
                        ],
                    }
                ],
            },
            {
                "id": str(excluded.id),
                "package_name": "example-tool",
                "deleted_at": "2026-03-10T18:00:00Z",
                "actionable": False,
                "non_actionable_reason": "package_excluded",
                "tracks": [],
            },
        ]

    async def test_null_sla_and_unobservable_phases_serialize_as_null(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        ignored: Ticket = await ticket_factory(status="Ignored")
        cve_less: Ticket = await ticket_factory(severity_manual=Severity.LOW.value)
        for ticket in (ignored, cve_less):
            package = await ticket_package_factory(ticket_id=ticket.id)
            track = await ticket_package_track_factory(
                ticket_package_id=package.id,
                workflow_type=WorkflowType.GIT.value,
                delivery_status=DeliveryStatus.IN_PROGRESS.value,
            )
            await ticket_package_product_factory(ticket_package_track_id=track.id)

        ignored_track = (await client.get(_url(ignored))).json()["data"][0]["tracks"][0]
        cve_less_track = (await client.get(_url(cve_less))).json()["data"][0]["tracks"][
            0
        ]

        assert {
            key: ignored_track[key]
            for key in (
                "triage_due_at",
                "submission_due_at",
                "um_due_at",
                "qa_due_at",
                "release_due_at",
                "current_phase",
            )
        } == dict.fromkeys(
            (
                "triage_due_at",
                "submission_due_at",
                "um_due_at",
                "qa_due_at",
                "release_due_at",
                "current_phase",
            )
        )
        assert ignored_track["milestones"] == dict.fromkeys(
            ("triage", "submission", "um", "qa")
        )
        assert cve_less_track["workflow_type"] == "git"
        assert cve_less_track["delivery_status"] == "in_progress"
        assert cve_less_track["delivery_relevant"] is True
        assert cve_less_track["milestones"] == {
            "triage": "pending",
            "submission": None,
            "um": None,
            "qa": None,
        }
        assert cve_less_track["current_phase"] == "triage"

    async def test_ticket_without_packages_returns_an_empty_list(
        self, client: AsyncClient, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        response = await client.get(_url(ticket))

        assert response.status_code == 200
        assert response.json() == {"data": []}

    async def test_undeclared_query_parameters_are_ignored(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for name in ("b", "a"):
            await ticket_package_factory(ticket_id=ticket.id, package_name=name)

        response = await client.get(
            _url(ticket),
            params={"sort_by": "package_name", "sort_order": "desc", "page": 2},
        )

        assert response.status_code == 200
        assert [p["package_name"] for p in response.json()["data"]] == ["a", "b"]


@pytest.mark.e2e
class TestEvaluationInstant:
    async def test_one_instant_and_its_utc_date_across_midnight(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two requests either side of UTC midnight: each captures exactly
        one instant and passes that instant's UTC date as the evaluation
        date, so a Product whose General Support ends on the first day is
        `general_support` before midnight and `eol` after it."""
        gs_end = date(2026, 3, 11)
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.HIGH.value, created_at=_CREATED_AT
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        product = await product_factory(general_support_end_date=gs_end)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        before_midnight = datetime(2026, 3, 11, 23, 59, 59, 999999, tzinfo=UTC)
        after_midnight = before_midnight + timedelta(microseconds=1)
        fixed_clock.queue.extend([before_midnight, after_midnight])
        original = package_service.get_ticket_packages
        received: list[tuple[date, datetime]] = []

        async def _spy(db: AsyncSession, **kwargs: Any) -> Any:
            received.append((kwargs["evaluation_date"], kwargs["evaluation_instant"]))
            return await original(db, **kwargs)

        monkeypatch.setattr(package_service, "get_ticket_packages", _spy)

        first = (await client.get(_url(ticket))).json()["data"][0]["tracks"][0]
        second = (await client.get(_url(ticket))).json()["data"][0]["tracks"][0]

        assert fixed_clock.calls == [before_midnight, after_midnight]
        assert received == [
            (date(2026, 3, 11), before_midnight),
            (date(2026, 3, 12), after_midnight),
        ]
        assert first["products"][0]["lifecycle_phase"] == "general_support"
        assert (first["actionable"], first["milestones"]["triage"]) == (True, "pending")
        assert second["products"][0]["lifecycle_phase"] == "eol"
        assert (second["actionable"], second["non_actionable_reason"]) == (
            False,
            "no_actionable_products",
        )
        assert second["milestones"]["triage"] == "not_applicable"


@pytest.mark.e2e
class TestTicketAccessibility:
    async def test_every_not_found_cause_returns_the_identical_response(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        visible: Ticket = await ticket_factory()
        confidential: Ticket = await ticket_factory(is_confidential=True)
        await ticket_package_factory(ticket_id=confidential.id)
        visible_id = format_ticket_id(visible.sequence_id)
        locators = [
            visible_id.lower(),
            "Sntl-" + visible_id.removeprefix("SNTL-"),
            f"%20{visible_id}",
            f"{visible_id}%20",
            f"SNTL-0{visible.sequence_id}",
            "SNTL-0",
            "SNTL-2147483648",
            "SNTL-99999999999999999999",
            "SNTL-",
            str(visible.id),
            "SNTL-2147483647",
            format_ticket_id(confidential.sequence_id),
        ]

        responses = [await client.get(_url(loc)) for loc in locators]

        for locator, response in zip(locators, responses, strict=True):
            assert response.status_code == 404, locator
            assert response.json() == _NOT_FOUND, locator
            assert response.headers["content-type"] == "application/json"
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(
        "branch", ["va_scope", "admin_scope", "grant", "maintainer"]
    )
    async def test_each_visibility_branch_allows_the_read(
        self,
        branch: str,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=ticket.id)
        if branch == "va_scope":
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
            )
        elif branch == "admin_scope":
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.ADMIN.value
            )
        elif branch == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        else:
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        assert [p["id"] for p in response.json()["data"]] == [str(package.id)]

    async def test_authenticated_caller_without_a_path_gets_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
        )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_mixed_visibility_exposes_only_visible_trees(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        public: Ticket = await ticket_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        for ticket in (public, granted, hidden):
            await ticket_package_factory(ticket_id=ticket.id)
        await ticket_access_grant_factory(
            ticket_id=granted.id, user_id=authenticated_user.id
        )

        statuses = [
            (await authenticated_client.get(_url(t))).status_code
            for t in (public, granted, hidden)
        ]

        assert statuses == [200, 200, 404]

    async def test_access_lost_before_the_protected_selection_is_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Caller resolution happened before the grant is revoked; the
        protected selection alone decides the response."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_package_factory(ticket_id=ticket.id)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        original = package_service.get_ticket_packages

        async def _revoke_then_read(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(package_service, "get_ticket_packages", _revoke_then_read)

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_package_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_package_factory(ticket_id=ticket.id)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = package_service.get_ticket_packages

        async def _remove_role_then_read(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            package_service, "get_ticket_packages", _remove_role_then_read
        )
        in_flight = await authenticated_client.get(_url(ticket))
        monkeypatch.setattr(package_service, "get_ticket_packages", original)
        next_request = await authenticated_client.get(_url(ticket))

        assert in_flight.status_code == 200
        assert len(in_flight.json()["data"]) == 1
        assert next_request.status_code == 404


# ---------------------------------------------------------------------------
# OpenAPI and schema contract
# ---------------------------------------------------------------------------


def _literal_values(alias: Any) -> set[str]:
    """The values of a `type X = Literal[...]` alias."""
    return set(typing.get_args(alias.__value__))


@pytest.mark.unit
class TestSchemaEnumerations:
    @pytest.mark.parametrize(
        ("alias", "expected"),
        [
            (schemas.PackageStatusValue, {s.value.lower() for s in PackageStatus}),
            (schemas.DeliveryStatusValue, {s.value.lower() for s in DeliveryStatus}),
            (schemas.WorkflowTypeValue, {w.value for w in WorkflowType}),
            (schemas.LifecyclePhaseValue, {p.value for p in LifecyclePhase}),
            (schemas.MilestoneStatusValue, {s.value for s in MilestoneStatus}),
            (schemas.CurrentPhaseValue, {p.value for p in CurrentPhase}),
            (
                schemas.ProductReasonValue,
                {"package_excluded", "track_excluded", "product_excluded", "eol"},
            ),
            (
                schemas.TrackReasonValue,
                {"package_excluded", "track_excluded", "no_actionable_products"},
            ),
            (
                schemas.PackageReasonValue,
                {"package_excluded", "no_actionable_tracks"},
            ),
        ],
    )
    def test_wire_values_are_the_lowercase_domain_values(
        self, alias: Any, expected: set[str]
    ) -> None:
        assert _literal_values(alias) == expected

    def test_level_reasons_partition_the_reason_enum(self) -> None:
        assert _literal_values(schemas.ProductReasonValue) | _literal_values(
            schemas.TrackReasonValue
        ) | _literal_values(schemas.PackageReasonValue) == {
            r.value for r in NonActionableReason
        }


@pytest.mark.unit
class TestOpenApiContract:
    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
        return operation

    def test_ticket_id_is_a_string_sntl_identity_and_no_query_is_declared(
        self,
    ) -> None:
        parameters = self._operation()["parameters"]
        (path_param,) = [p for p in parameters if p["in"] == "path"]

        assert path_param["name"] == "ticket_id"
        assert path_param["schema"]["type"] == "string"
        assert "pattern" not in path_param["schema"]
        assert "format" not in path_param["schema"]
        assert [p for p in parameters if p["in"] == "query"] == []

    def test_declares_the_unpaginated_envelope_and_404(self) -> None:
        operation = self._operation()
        schemas_ = app.openapi()["components"]["schemas"]

        assert "404" in operation["responses"]
        assert set(schemas_["TicketPackageListResponse"]["properties"]) == {"data"}

    def test_tree_schemas_expose_occurrence_uuids_and_no_ticket_uuid(self) -> None:
        schemas_ = app.openapi()["components"]["schemas"]

        for name in ("PackageDetail", "TrackDetail", "ProductDetail"):
            properties = schemas_[name]["properties"]
            assert properties["id"]["format"] == "uuid", name
            assert not {
                "ticket_id",
                "ticket_uuid",
                "product_id",
                "identifier",
                "ticket_sequence_id",
                "maintainers",
            } & set(properties), name

    def test_required_consumer_guidance_is_documented(self) -> None:
        schemas_ = app.openapi()["components"]["schemas"]
        track = schemas_["TrackDetail"]["properties"]
        milestones = schemas_["TrackMilestones"]["properties"]

        assert "delivery_relevant" in track["delivery_status"]["description"]
        assert "should not display" in track["delivery_relevant"]["description"]
        assert "qa_due_at" in track["release_due_at"]["description"]
        assert "release_due_at" in track["qa_due_at"]["description"]
        for phase, actor in (
            ("triage", "VA (Vulnerability Analyst)"),
            ("submission", "maintainer"),
            ("um", "UM (SUSE maintenance update team)"),
            ("qa", "QA (quality assurance)"),
        ):
            description = milestones[phase]["description"]
            assert actor in description, phase
            assert "unrelated to `delivery_status = pending`" in description, phase
        assert "never phases" in track["current_phase"]["description"]
