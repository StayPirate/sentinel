"""End-to-end tests for the Ticket list endpoint (`GET /api/v1/tickets`).

See docs/features/tickets/tickets.md (List Tickets, Response Schemas >
TicketSummary, CVESummary, UserSummary), docs/features/tickets/
ticket-priority.md (API Surface; Testing Requirement 9),
docs/features/tickets/ticket-deadlines.md (Ticket-Level Overdue Filter,
Sorting, API Surface), docs/api-spec.md (Optional Authentication on
Public Endpoints, Query Parameter Length Limit, Undeclared Query
Parameters, Pagination, Enum Filter Validation, Sort Parameter
Validation, Response Format), and docs/features/platform/
testing-strategy.md (API Endpoints; Ticket Accessibility). Search,
filter, sort, fan-out, N+1, evaluation-instant, and independent-session
race coverage lives in tests/test_services/test_ticket_list.py; these
tests cover the HTTP contract.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import tickets as route
from app.core.enums import (
    MilestonePhase,
    Role,
    Severity,
    SortOrder,
    TicketPriority,
    TicketSortField,
    TicketStatus,
)
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_service
from app.services.ticket_deadlines import DueDates
from app.services.ticket_service import (
    CVESummaryProjection,
    TicketPage,
    TicketSummaryProjection,
    TicketUserProjection,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets"
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, tzinfo=UTC)
_UPDATED_AT = datetime(2026, 3, 10, 16, 0, tzinfo=UTC)
_NOW = datetime(2026, 3, 11, 12, 0, tzinfo=UTC)
_DUE_FIELDS = (
    "triage_due_at",
    "submission_due_at",
    "um_due_at",
    "qa_due_at",
    "release_due_at",
)
_TICKET_SUMMARY_FIELDS = {
    "ticket_id",
    "status",
    "severity",
    "priority",
    "assignee",
    "cve",
    "duplicate_of_ticket_id",
    "is_confidential",
    "coordinated_release_at",
    *_DUE_FIELDS,
    "package_names",
    "created_at",
    "updated_at",
}


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> list[datetime]:
    calls: list[datetime] = []

    def now() -> datetime:
        calls.append(_NOW)
        return _NOW

    monkeypatch.setattr(ticket_service, "_utc_now", now)
    return calls


async def _ids(client: AsyncClient, **params: Any) -> list[str]:
    response = await client.get(_PATH, params={"per_page": 100, **params})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["meta"]["total"] == len(body["data"])
    return [item["ticket_id"] for item in body["data"]]


@pytest.mark.e2e
class TestListEndpoint:
    async def test_returns_the_paginated_summary_envelope_in_the_wire_format(
        self,
        client: AsyncClient,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
        cve_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        assignee: User = await user_factory(
            username="fictional.analyst", full_name="Fictional Analyst"
        )
        cve = await cve_factory(
            cve_id="CVE-2099-50001",
            title="Fictional title",
            description=None,
            severity=Severity.CRITICAL.value,
        )
        ticket: Ticket = await ticket_factory(
            cve_id=cve.id,
            assignee_id=assignee.id,
            status=TicketStatus.ANALYSIS.value,
            priority_auto=TicketPriority.P2.value,
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )
        await ticket_package_factory(ticket_id=ticket.id, package_name="openssl-3")
        await ticket_package_factory(ticket_id=ticket.id, package_name="curl")

        response = await client.get(_PATH)

        assert response.status_code == 200
        body = response.json()
        assert body["meta"] == {"total": 1, "page": 1, "per_page": 20}
        (item,) = body["data"]
        assert set(item) == _TICKET_SUMMARY_FIELDS
        assert item == {
            "ticket_id": _sntl(ticket),
            "status": "analysis",
            "severity": "critical",
            "priority": "p2",
            "assignee": {
                "id": str(assignee.id),
                "username": "fictional.analyst",
                "full_name": "Fictional Analyst",
                "active": True,
            },
            "cve": {
                "cve_id": "CVE-2099-50001",
                "title": "Fictional title",
                "description": None,
            },
            "duplicate_of_ticket_id": None,
            "is_confidential": False,
            "coordinated_release_at": None,
            # 30-day tier: +3/+18/+21/+30/+30 days (ticket-deadlines.md).
            "triage_due_at": _iso(_CREATED_AT + timedelta(days=3)),
            "submission_due_at": _iso(_CREATED_AT + timedelta(days=18)),
            "um_due_at": _iso(_CREATED_AT + timedelta(days=21)),
            "qa_due_at": _iso(_CREATED_AT + timedelta(days=30)),
            "release_due_at": _iso(_CREATED_AT + timedelta(days=30)),
            "package_names": ["curl", "openssl-3"],
            "created_at": _iso(_CREATED_AT),
            "updated_at": _iso(_UPDATED_AT),
        }
        assert len(fixed_clock) == 1

    async def test_null_severity_priority_and_due_dates_serialize_as_null(
        self, client: AsyncClient, fixed_clock: list[datetime], ticket_factory: Factory
    ) -> None:
        target = await ticket_factory()
        await ticket_factory(
            duplicate_of_id=target.id, severity_manual=Severity.NONE.value
        )

        response = await client.get(
            _PATH, params={"status": "duplicated", "severity": "none"}
        )

        (item,) = response.json()["data"]
        assert item["status"] == "duplicated"
        assert item["severity"] == "none"
        assert item["priority"] is None
        assert item["duplicate_of_ticket_id"] == _sntl(target)
        assert {field: item[field] for field in _DUE_FIELDS} == dict.fromkeys(
            _DUE_FIELDS
        )

    async def test_repeatable_filters_parse_wire_values_and_ignore_invalid_ones(
        self, client: AsyncClient, fixed_clock: list[datetime], ticket_factory: Factory
    ) -> None:
        new = await ticket_factory(
            status=TicketStatus.NEW.value,
            severity_manual=Severity.HIGH.value,
            priority_auto=TicketPriority.P1.value,
        )
        analysis = await ticket_factory(status=TicketStatus.ANALYSIS.value)

        assert set(await _ids(client, status=["new", "analysis", "bogus"])) == {
            _sntl(new),
            _sntl(analysis),
        }
        assert await _ids(client, severity=["high", "HIGH"]) == [_sntl(new)]
        assert await _ids(client, severity=["unresolved"]) == [_sntl(analysis)]
        assert await _ids(client, priority=["p1"]) == [_sntl(new)]
        assert await _ids(client, priority=["unresolved"]) == [_sntl(analysis)]

    @pytest.mark.parametrize(
        "params",
        [
            {"status": "bogus"},
            {"status": "new,analysis"},
            {"status": "New"},
            {"severity": ["unknown", "CRITICAL"]},
            {"priority": "P1"},
            {"overdue": ["release", "late"]},
        ],
    )
    async def test_all_invalid_supplied_filter_returns_an_empty_page(
        self,
        client: AsyncClient,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
        params: dict[str, Any],
    ) -> None:
        await ticket_factory(
            status=TicketStatus.NEW.value,
            severity_manual=Severity.CRITICAL.value,
            priority_auto=TicketPriority.P1.value,
        )

        response = await client.get(_PATH, params=params)

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_overdue_filter_parses_phases(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        late = datetime(2026, 3, 20, tzinfo=UTC)
        monkeypatch.setattr(ticket_service, "_utc_now", lambda: late)
        overdue = await ticket_factory(created_at=_CREATED_AT)
        await ticket_factory(created_at=late - timedelta(hours=1))

        assert await _ids(client, overdue=["triage", "bogus"]) == [_sntl(overdue)]

    async def test_assignee_and_maintainer_accept_uuid_username_and_unknown(
        self,
        client: AsyncClient,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        analyst: User = await user_factory(username="fictional.va")
        assigned = await ticket_factory(assignee_id=analyst.id)
        unassigned = await ticket_factory()
        package = await ticket_package_factory(ticket_id=unassigned.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=analyst.id
        )

        assert await _ids(client, assignee=str(analyst.id)) == [_sntl(assigned)]
        assert await _ids(client, assignee="fictional.va") == [_sntl(assigned)]
        assert await _ids(client, assignee="none") == [_sntl(unassigned)]
        assert await _ids(client, maintainer=str(analyst.id)) == [_sntl(unassigned)]
        assert await _ids(client, maintainer="fictional.va") == [_sntl(unassigned)]
        for params in (
            {"assignee": "unknown.user"},
            {"maintainer": "unknown.user"},
            {"maintainer": "none"},
        ):
            response = await client.get(_PATH, params=params)
            assert response.status_code == 200, params
            assert response.json()["meta"]["total"] == 0, params

    async def test_search_and_sort_reach_the_service(
        self, client: AsyncClient, fixed_clock: list[datetime], ticket_factory: Factory
    ) -> None:
        first = await ticket_factory(sequence_id=42, created_at=_CREATED_AT)
        second = await ticket_factory(
            sequence_id=420, created_at=_CREATED_AT + timedelta(hours=1)
        )
        await ticket_factory(sequence_id=1042)

        assert await _ids(client, search=" sntl-42 ", sort_by="created_at") == [
            _sntl(second),
            _sntl(first),
        ]
        assert await _ids(
            client, search="42", sort_by="ticket_id", sort_order="asc"
        ) == [_sntl(first), _sntl(second)]

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, client: AsyncClient, fixed_clock: list[datetime], ticket_factory: Factory
    ) -> None:
        for _ in range(3):
            await ticket_factory()

        response = await client.get(_PATH, params={"page": 3, "per_page": 2})

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 3, "page": 3, "per_page": 2},
        }

    @pytest.mark.parametrize(
        ("params", "field"),
        [
            ({"page": 0}, "page"),
            ({"page": "x"}, "page"),
            ({"per_page": 0}, "per_page"),
            ({"per_page": 101}, "per_page"),
            ({"sort_by": "title"}, "sort_by"),
            ({"sort_by": "Created_At"}, "sort_by"),
            ({"sort_order": "up"}, "sort_order"),
            ({"search": "x" * 501}, "search"),
            ({"assignee": "x" * 501}, "assignee"),
            ({"maintainer": "x" * 501}, "maintainer"),
            ({"status": ["new", "x" * 501]}, "status"),
        ],
    )
    async def test_invalid_pagination_sort_and_length_return_422(
        self,
        client: AsyncClient,
        params: dict[str, Any],
        field: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(ticket_service, "list_tickets", spy)

        response = await client.get(_PATH, params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", field]]
        spy.assert_not_awaited()

    async def test_limits_accept_boundary_values(
        self, client: AsyncClient, fixed_clock: list[datetime], ticket_factory: Factory
    ) -> None:
        await ticket_factory()

        response = await client.get(
            _PATH, params={"per_page": 100, "search": "x" * 500, "page": 1}
        )

        assert response.status_code == 200
        assert response.json()["meta"] == {"total": 0, "page": 1, "per_page": 100}

    async def test_undeclared_query_parameters_are_ignored(
        self, client: AsyncClient, fixed_clock: list[datetime], ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory()

        response = await client.get(
            _PATH,
            params={"evaluation_date": "2020-01-01", "caller": "x", "q": "y" * 600},
        )

        assert response.status_code == 200
        assert [item["ticket_id"] for item in response.json()["data"]] == [
            _sntl(ticket)
        ]

    async def test_every_sort_field_and_order_is_accepted(
        self,
        client: AsyncClient,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
    ) -> None:
        await ticket_factory()

        for sort_by in TicketSortField:
            for sort_order in SortOrder:
                response = await client.get(
                    _PATH,
                    params={"sort_by": sort_by.value, "sort_order": sort_order.value},
                )
                assert response.status_code == 200, (sort_by, sort_order)
                assert response.json()["meta"]["total"] == 1


@pytest.mark.e2e
class TestAuthenticationAndVisibility:
    async def test_invalid_credential_returns_401_before_the_query(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(ticket_service, "list_tickets", spy)

        response = await client.get(
            _PATH, headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_mixed_visibility_rows_and_total(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        public = await ticket_factory()
        granted = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=granted.id, user_id=authenticated_user.id
        )
        maintained = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=maintained.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=authenticated_user.id
        )
        excluded_maintained = await ticket_factory(is_confidential=True)
        excluded = await ticket_package_factory(
            ticket_id=excluded_maintained.id, deleted_at=_NOW
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=authenticated_user.id
        )
        hidden = await ticket_factory(is_confidential=True)

        # `authenticated_client` is the shared client with a session cookie;
        # drop it for one anonymous request.
        token = authenticated_client.cookies[SESSION_COOKIE_NAME]
        authenticated_client.cookies.delete(SESSION_COOKIE_NAME)
        assert await _ids(authenticated_client) == [_sntl(public)]
        authenticated_client.cookies.set(SESSION_COOKIE_NAME, token)
        assert set(await _ids(authenticated_client)) == {
            _sntl(public),
            _sntl(granted),
            _sntl(maintained),
        }
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        assert set(await _ids(authenticated_client)) == {
            _sntl(t) for t in (public, granted, maintained, excluded_maintained, hidden)
        }

    async def test_access_lost_before_the_protected_selection_is_not_listed(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Caller resolution happened before the grant is revoked; the one
        protected selection alone decides rows and total."""
        target = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=target.id, user_id=authenticated_user.id
        )
        original = ticket_service.list_tickets

        async def _revoke_then_list(db: AsyncSession, **kwargs: Any) -> TicketPage:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == target.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "list_tickets", _revoke_then_list)

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 0

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        fixed_clock: list[datetime],
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await ticket_factory(is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = ticket_service.list_tickets

        async def _remove_role_then_list(db: AsyncSession, **kwargs: Any) -> TicketPage:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "list_tickets", _remove_role_then_list)
        in_flight = await _ids(authenticated_client)
        monkeypatch.setattr(ticket_service, "list_tickets", original)
        next_request = await _ids(authenticated_client)

        assert in_flight == [_sntl(target)]
        assert next_request == []


@pytest.mark.unit
class TestSerializer:
    def test_summary_serializes_lowercase_values_and_expanded_due_dates(
        self,
    ) -> None:
        due = DueDates(
            triage=_CREATED_AT,
            submission=_CREATED_AT + timedelta(days=1),
            um=_CREATED_AT + timedelta(days=2),
            qa=_CREATED_AT + timedelta(days=3),
            release=_CREATED_AT + timedelta(days=3),
        )
        serialized = route.serialize_ticket_summary(
            TicketSummaryProjection(
                ticket_id="SNTL-1",
                status=TicketStatus.ANALYZED,
                severity=Severity.LOW,
                priority=TicketPriority.P4,
                assignee=TicketUserProjection(
                    id=uuid.UUID(int=1),
                    username="fictional.user",
                    full_name=None,
                    active=False,
                ),
                cve=CVESummaryProjection(
                    cve_id="CVE-2099-1", title=None, description="d"
                ),
                duplicate_of_ticket_id=None,
                is_confidential=True,
                coordinated_release_at=_NOW,
                due_dates=due,
                package_names=("a", "b"),
                created_at=_CREATED_AT,
                updated_at=_UPDATED_AT,
            )
        )

        assert (serialized.status, serialized.severity, serialized.priority) == (
            "analyzed",
            "low",
            "p4",
        )
        assert serialized.um_due_at == due.um
        assert serialized.release_due_at == due.release
        assert serialized.package_names == ["a", "b"]
        assert serialized.assignee is not None
        assert serialized.assignee.active is False
        assert serialized.cve is not None
        assert serialized.cve.cve_id == "CVE-2099-1"

    def test_wire_filter_maps_cover_every_domain_member(self) -> None:
        assert set(route._STATUS_FILTER.values()) == set(TicketStatus)
        assert set(route._SEVERITY_FILTER) == {
            "critical",
            "high",
            "medium",
            "low",
            "none",
            "unresolved",
        }
        assert route._SEVERITY_FILTER["unresolved"] is None
        assert set(route._PRIORITY_FILTER) == {"p1", "p2", "p3", "p4", "unresolved"}
        assert route._PRIORITY_FILTER["unresolved"] is None
        assert set(route._OVERDUE_FILTER) == {"triage", "submission", "um", "qa"}
        assert set(route._OVERDUE_FILTER.values()) == set(MilestonePhase)


@pytest.mark.unit
class TestOpenApiContract:
    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
        return operation

    def _schemas(self) -> dict[str, Any]:
        schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
        return schemas

    def test_declares_exactly_the_specified_query_parameters(self) -> None:
        parameters = self._operation()["parameters"]

        assert {p["name"] for p in parameters if p["in"] == "query"} == {
            "search",
            "status",
            "assignee",
            "severity",
            "priority",
            "overdue",
            "maintainer",
            "page",
            "per_page",
            "sort_by",
            "sort_order",
        }
        assert [p for p in parameters if p["in"] == "path"] == []

    def test_repeatable_filters_are_arrays(self) -> None:
        parameters = {p["name"]: p for p in self._operation()["parameters"]}

        for name in ("status", "severity", "priority", "overdue"):
            assert parameters[name]["schema"]["type"] == "array", name

    def test_sort_by_enumerates_the_specified_fields(self) -> None:
        parameters = {p["name"]: p for p in self._operation()["parameters"]}
        sort_by = parameters["sort_by"]["schema"]
        enum_schema = (
            self._schemas()[sort_by["$ref"].rsplit("/", 1)[1]]
            if "$ref" in sort_by
            else sort_by
        )

        assert set(enum_schema["enum"]) == {field.value for field in TicketSortField}
        assert sort_by.get("default") == "created_at"

    def test_paginated_envelope_and_summary_fields(self) -> None:
        schemas = self._schemas()
        operation = self._operation()

        assert operation["tags"] == ["Tickets"]
        assert set(schemas["TicketListResponse"]["properties"]) == {"data", "meta"}
        properties = schemas["TicketSummary"]["properties"]
        assert set(properties) == _TICKET_SUMMARY_FIELDS
        assert not {
            "id",
            "identifier",
            "ticket_sequence_id",
            "duplicate_of_id",
            "packages",
            "priority_automatic",
            "priority_override",
        } & set(properties)
        assert set(schemas["CVESummary"]["properties"]) == {
            "cve_id",
            "title",
            "description",
        }

    def test_summary_and_detail_share_the_consumer_guidance(self) -> None:
        schemas = self._schemas()
        summary = schemas["TicketSummary"]["properties"]
        detail = schemas["TicketDetail"]["properties"]

        for field in (*_DUE_FIELDS, "severity", "priority", "ticket_id", "status"):
            assert summary[field]["description"] == detail[field]["description"]
        assert "VA (Vulnerability Analyst)" in summary["triage_due_at"]["description"]
        assert "qa_due_at" in summary["release_due_at"]["description"]
