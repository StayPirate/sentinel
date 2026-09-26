"""End-to-end tests for the Ticket audit log endpoint
(`backend/app/api/v1/ticket_audit.py`).

See docs/features/tickets/ticket-audit-log.md (API > List Ticket Events)
for the endpoint contract, docs/api-spec.md (Ticket Accessibility Check,
Ticket Identifier Resolution, Pagination, Enum Filter Validation, Date
Range Interpretation) for the shared responses, and
docs/features/platform/testing-strategy.md (Ticket Accessibility) for
the matrix split: filter, ordering, and independent-session race
coverage lives in tests/test_services/test_ticket_audit_log.py, while
these tests cover the HTTP contract.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ticket_audit import parse_event_types
from app.core.enums import Role, TicketAuditEventType
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_audit_log, ticket_service

Factory = Callable[..., Awaitable[Any]]

_NOT_FOUND = {"code": "TICKET_NOT_FOUND", "detail": "Ticket not found."}
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_BASE_TIME = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)


def _url(ticket: Ticket | str) -> str:
    locator = (
        ticket if isinstance(ticket, str) else format_ticket_id(ticket.sequence_id)
    )
    return f"/api/v1/tickets/{locator}/audit-log"


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


def _spy_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace both Ticket lookups reachable from the route with spies."""
    resolver, lister = AsyncMock(), AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_audit_log, "list_ticket_events", lister)
    return resolver, lister


@pytest.mark.unit
class TestParseEventTypes:
    def test_omitted_filter_is_none(self) -> None:
        assert parse_event_types([]) is None

    def test_invalid_values_are_dropped(self) -> None:
        assert parse_event_types(
            ["assignment", "bogus", "status_change,assignment"]
        ) == [TicketAuditEventType.ASSIGNMENT]

    def test_all_invalid_values_yield_an_empty_filter(self) -> None:
        assert parse_event_types(["bogus"]) == []


@pytest.mark.e2e
class TestAuthentication:
    async def test_anonymous_request_returns_401_before_lookup(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver, lister = _spy_lookups(monkeypatch)

        for locator in ("SNTL-1", "not-a-ticket"):
            response = await client.get(_url(locator))
            assert response.status_code == 401
            assert response.json() == _UNAUTHENTICATED

        resolver.assert_not_awaited()
        lister.assert_not_awaited()

    async def test_invalid_credential_returns_401_before_lookup(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver, lister = _spy_lookups(monkeypatch)

        response = await client.get(
            _url("SNTL-1"), headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        resolver.assert_not_awaited()
        lister.assert_not_awaited()


@pytest.mark.e2e
class TestListTicketEventsEndpoint:
    async def test_returns_paginated_events_for_a_visible_ticket(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actor: User = await user_factory(
            username="fictional.analyst", full_name="Fictional Analyst"
        )
        system_event = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="status_change",
            old_value="New",
            new_value="Analysis",
            created_at=_BASE_TIME,
        )
        user_event = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="priority_changed",
            user_id=actor.id,
            old_value="P3",
            new_value="P1",
            detail={"override_action": "set"},
            created_at=_BASE_TIME + timedelta(minutes=1),
        )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        body = response.json()
        assert body["meta"] == {"total": 2, "page": 1, "per_page": 20}
        assert body["data"] == [
            {
                "id": str(user_event.id),
                "ticket_id": format_ticket_id(ticket.sequence_id),
                "event_type": "priority_changed",
                "old_value": "P3",
                "new_value": "P1",
                "comment": None,
                "detail": {"override_action": "set"},
                "created_at": "2026-03-15T10:31:00Z",
                "actor": {
                    "id": str(actor.id),
                    "username": "fictional.analyst",
                    "full_name": "Fictional Analyst",
                    "active": True,
                },
            },
            {
                "id": str(system_event.id),
                "ticket_id": format_ticket_id(ticket.sequence_id),
                "event_type": "status_change",
                "old_value": "New",
                "new_value": "Analysis",
                "comment": None,
                "detail": None,
                "created_at": "2026-03-15T10:30:00Z",
                "actor": None,
            },
        ]
        assert str(ticket.id) not in response.text

    async def test_filters_are_forwarded(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actor: User = await user_factory(username="fictional.filter")
        match = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="status_change",
            user_id=actor.id,
            new_value="Fixed 100%",
            created_at=_BASE_TIME,
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="assignment", created_at=_BASE_TIME
        )

        response = await authenticated_client.get(
            _url(ticket),
            params={
                "event_type": ["status_change", "bogus"],
                "actor": "fictional.filter",
                "search": " 100% ",
                "from_date": "2026-03-15",
                "to_date": "2026-03-15",
            },
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["data"]] == [str(match.id)]
        assert response.json()["meta"]["total"] == 1

    async def test_all_invalid_event_types_return_an_empty_page(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)

        response = await authenticated_client.get(
            _url(ticket), params={"event_type": ["bogus", "status_change,assignment"]}
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_page_beyond_the_last_is_empty_with_the_total(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for _ in range(3):
            await ticket_audit_event_factory(ticket_id=ticket.id, created_at=_BASE_TIME)

        first = await authenticated_client.get(
            _url(ticket), params={"page": 1, "per_page": 2}
        )
        second = await authenticated_client.get(
            _url(ticket), params={"page": 2, "per_page": 2}
        )
        beyond = await authenticated_client.get(
            _url(ticket), params={"page": 3, "per_page": 2}
        )

        ids = [item["id"] for page in (first, second) for item in page.json()["data"]]
        assert ids == sorted(ids, reverse=True)
        assert len(set(ids)) == 3
        assert beyond.json() == {
            "data": [],
            "meta": {"total": 3, "page": 3, "per_page": 2},
        }

    @pytest.mark.parametrize(
        "params",
        [
            {"page": 0},
            {"page": -1},
            {"page": 2_147_483_648},
            {"per_page": 0},
            {"per_page": 101},
            {"page": "abc"},
            {"from_date": "15/03/2026"},
            {"to_date": "1710498600"},
            {"search": "x" * 501},
            {"actor": "x" * 501},
            {"event_type": "x" * 501},
        ],
    )
    async def test_invalid_query_returns_422(
        self,
        params: dict[str, Any],
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()

        response = await authenticated_client.get(_url(ticket), params=params)

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_boundary_query_values_are_accepted(
        self, authenticated_client: AsyncClient, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        response = await authenticated_client.get(
            _url(ticket),
            params={"page": 2_147_483_647, "per_page": 100, "search": "x" * 500},
        )

        assert response.status_code == 200
        assert response.json()["meta"] == {
            "total": 0,
            "page": 2_147_483_647,
            "per_page": 100,
        }

    async def test_inverted_date_range_returns_400(
        self, authenticated_client: AsyncClient, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        response = await authenticated_client.get(
            _url(ticket), params={"from_date": "2026-03-16", "to_date": "2026-03-15"}
        )

        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_undeclared_sort_parameters_are_ignored(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        older = await ticket_audit_event_factory(
            ticket_id=ticket.id, created_at=_BASE_TIME
        )
        newer = await ticket_audit_event_factory(
            ticket_id=ticket.id, created_at=_BASE_TIME + timedelta(hours=1)
        )

        response = await authenticated_client.get(
            _url(ticket), params={"sort_by": "created_at", "sort_order": "asc"}
        )

        assert [item["id"] for item in response.json()["data"]] == [
            str(newer.id),
            str(older.id),
        ]


@pytest.mark.e2e
class TestTicketAccessibility:
    async def test_every_not_found_cause_returns_the_identical_response(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        visible: Ticket = await ticket_factory()
        confidential: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(ticket_id=confidential.id)
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

        responses = [await authenticated_client.get(_url(loc)) for loc in locators]

        for locator, response in zip(locators, responses, strict=True):
            assert response.status_code == 404, locator
            assert response.json() == _NOT_FOUND, locator
            assert response.headers["content-type"] == "application/json"
        assert len({response.content for response in responses}) == 1

    async def test_inaccessible_ticket_is_404_even_with_empty_filters(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)

        for params in (
            {"event_type": "bogus"},
            {"actor": "fictional.nobody"},
            {"page": 99},
            {"from_date": "2026-03-16", "to_date": "2026-03-15"},
        ):
            response = await authenticated_client.get(_url(ticket), params=params)
            assert response.status_code == 404
            assert response.json() == _NOT_FOUND

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
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(ticket_id=ticket.id)
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
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 1

    async def test_restricted_analyst_without_path_gets_404(
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

    async def test_access_lost_after_the_preliminary_boundary_is_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_audit_event_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The route relies on the service's own protected selection, not
        on the preliminary `require_accessible_ticket` decision."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        await ticket_audit_event_factory(ticket_id=ticket.id)
        original = ticket_audit_log.list_ticket_events

        async def _revoke_then_list(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_audit_log, "list_ticket_events", _revoke_then_list)

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_audit_event_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(ticket_id=ticket.id)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = ticket_audit_log.list_ticket_events

        async def _remove_role_then_list(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_audit_log, "list_ticket_events", _remove_role_then_list
        )
        in_flight = await authenticated_client.get(_url(ticket))
        monkeypatch.setattr(ticket_audit_log, "list_ticket_events", original)
        next_request = await authenticated_client.get(_url(ticket))

        assert in_flight.status_code == 200
        assert in_flight.json()["meta"]["total"] == 1
        assert next_request.status_code == 404


@pytest.mark.unit
class TestOpenApiContract:
    def test_ticket_id_is_a_string_sntl_identity(self) -> None:
        schema = app.openapi()
        operation = schema["paths"]["/api/v1/tickets/{ticket_id}/audit-log"]["get"]
        (path_param,) = [p for p in operation["parameters"] if p["in"] == "path"]

        assert path_param["name"] == "ticket_id"
        assert path_param["schema"]["type"] == "string"
        assert "format" not in path_param["schema"]
        assert "pattern" not in path_param["schema"]
        assert "SNTL-" in path_param["description"]

    def test_event_projection_exposes_no_ticket_uuid(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        event = schemas["TicketAuditEventData"]["properties"]

        assert event["ticket_id"]["type"] == "string"
        assert "format" not in event["ticket_id"]
        assert event["id"]["format"] == "uuid"
        assert not {"identifier", "ticket_sequence_id", "ticket_uuid"} & set(event)

    def test_declares_the_404_response(self) -> None:
        operation = app.openapi()["paths"]["/api/v1/tickets/{ticket_id}/audit-log"][
            "get"
        ]

        assert "404" in operation["responses"]
        assert {p["name"] for p in operation["parameters"] if p["in"] == "query"} == {
            "event_type",
            "actor",
            "search",
            "from_date",
            "to_date",
            "page",
            "per_page",
        }
