"""End-to-end tests for the Set Priority Override endpoint
(`PATCH /api/v1/tickets/{ticket_id}/priority`, `backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Set Priority Override, Response
Schemas > TicketDetail, Endpoint -> Schema Mapping),
docs/features/tickets/ticket-priority.md (`set_priority_override()`),
docs/features/tickets/ticket-service.md (`get_ticket_detail()` mutation
assembly), docs/api-spec.md (Authorization Chain Evaluation Order flow 3,
Global Responses, Ticket Accessibility Check, Manual-Zone Mutability Guard,
Partial Update Semantics), docs/features/identity/rbac.md (Endpoint
Permission Map: `triage_ticket`), and docs/features/platform/testing-strategy.md
(Tier Responsibility and Proportionality; API Endpoints; Ticket
Accessibility; Ticket Priority).

These tests cover only the HTTP boundary: authentication, capability before
lookup, request validation, the status and complete body of each error
mapping, the response shape, OpenAPI, and the handler-owned steps (the one
captured date and the final `TicketDetail` assembly with its rollback). The
service matrix (every action, effective value, auto-assignment and event
combination, guard order, lock order, races) is proven once in
`tests/test_services/test_set_priority_override.py` and
`tests/test_services/test_set_priority_override_atomicity.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import tickets as route
from app.core.enums import Role, TicketPriority, TicketStatus
from app.main import app
from app.models.ticket import Ticket
from app.models.user import User
from app.services import ticket_mutations, ticket_service, user_service
from app.services.ticket_service import TicketDetailProjection
from tests.support.ticket_api import (
    FORBIDDEN,
    INVALID_LOCATORS,
    MAX_SEQUENCE,
    NOT_FOUND,
    NOT_MUTABLE,
    TICKET_DETAIL_FIELDS,
    UNAUTHENTICATED,
    Clock,
    CommittedApp,
    committed_app_client,
    event_count,
    locator,
    ticket_row,
    validation_error,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/priority"
_LITERAL_MESSAGE = "Input should be 'p1', 'p2', 'p3' or 'p4'"


def _url(target: Ticket | str) -> str:
    return _PATH.format(
        ticket_id=target if isinstance(target, str) else locator(target)
    )


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, "set_priority_override", mutation)
    return resolver, mutation


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest_asyncio.fixture
async def va_user(authenticated_user: User, user_role_factory: Factory) -> User:
    """`authenticated_client`'s user holding only `vulnerability_analyst`."""
    await user_role_factory(
        user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
    )
    return authenticated_user


@pytest_asyncio.fixture
async def ra_user(authenticated_user: User, user_role_factory: Factory) -> User:
    """`authenticated_client`'s user holding only `restricted_analyst`."""
    await user_role_factory(
        user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
    )
    return authenticated_user


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient]]:
    async with committed_app_client(db_session_factory) as pair:
        yield pair


# ---------------------------------------------------------------------------
# Authentication and capability (flow 3, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndCapability:
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_credential_failure_returns_401_before_any_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
    ) -> None:
        target: Ticket = await ticket_factory()
        resolver, mutation = _forbid_lookups(monkeypatch)

        for path in (_url(target), _url(f"SNTL-{MAX_SEQUENCE}")):
            response = await client.patch(
                path, json={"priority": "p1"}, headers=headers
            )
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()

    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_triage_ticket_gets_the_generic_403_before_lookup(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
    ) -> None:
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        visible: Ticket = await ticket_factory()
        resolver, mutation = _forbid_lookups(monkeypatch)

        existing = await authenticated_client.patch(
            _url(visible), json={"priority": "p1"}
        )
        missing = await authenticated_client.patch(
            _url(f"SNTL-{MAX_SEQUENCE}"), json={"priority": "p1"}
        )

        assert existing.status_code == missing.status_code == 403
        assert existing.content == missing.content
        assert existing.json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert (await ticket_row(db_session, visible.id))["priority_override"] is None

    async def test_roles_are_loaded_once_for_capability_and_scope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.patch(
            _url(target), json={"priority": "p1"}
        )

        assert response.status_code == 200
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize(
        "build_locator",
        [pytest.param(build, id=name) for name, build in INVALID_LOCATORS],
    )
    async def test_invalid_or_missing_locator_returns_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        build_locator: Callable[[Ticket], str],
    ) -> None:
        target: Ticket = await ticket_factory()
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.patch(
            _url(build_locator(target)), json={"priority": "p1"}
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        hidden: Ticket = await ticket_factory(is_confidential=True)
        before = await ticket_row(db_session, hidden.id)

        inaccessible = await authenticated_client.patch(
            _url(hidden), json={"priority": "p1"}
        )
        missing = await authenticated_client.patch(
            _url(f"SNTL-{MAX_SEQUENCE}"), json={"priority": "p1"}
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await ticket_row(db_session, hidden.id) == before
        assert await event_count(db_session, hidden.id) == 0


# ---------------------------------------------------------------------------
# Request validation (global 422)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        ("body", "error"),
        [
            pytest.param(
                {},
                {
                    "loc": ["body", "priority"],
                    "msg": "Field required",
                    "type": "missing",
                },
                id="omitted",
            ),
            *[
                pytest.param(
                    {"priority": value},
                    {
                        "loc": ["body", "priority"],
                        "msg": _LITERAL_MESSAGE,
                        "type": "literal_error",
                    },
                    id=f"invalid-{value!r}",
                )
                for value in ("P1", "p5", "unresolved", 1)
            ],
        ],
    )
    async def test_invalid_body_returns_the_validation_envelope_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        body: dict[str, Any],
        error: dict[str, Any],
    ) -> None:
        target: Ticket = await ticket_factory()
        before = await ticket_row(db_session, target.id)
        mutation = AsyncMock()
        monkeypatch.setattr(ticket_service, "set_priority_override", mutation)

        response = await authenticated_client.patch(_url(target), json=body)

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        mutation.assert_not_awaited()
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    async def test_absent_body_is_a_validation_error(
        self, authenticated_client: AsyncClient, va_user: User, ticket_factory: Factory
    ) -> None:
        target: Ticket = await ticket_factory()

        response = await authenticated_client.patch(_url(target))

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["body"], "msg": "Field required", "type": "missing"}
        )


# ---------------------------------------------------------------------------
# Successful requests (200 TicketDetail) and the one error mapping (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSetPriority:
    async def test_set_then_clear_returns_the_effective_and_both_stored_values(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=va_user.id,
            severity_manual="High",
            priority_auto=TicketPriority.P3.value,
        )

        set_response = await authenticated_client.patch(
            _url(target), json={"priority": "p2"}
        )
        after_set = await authenticated_client.get(f"/api/v1/tickets/{locator(target)}")
        clear_response = await authenticated_client.patch(
            _url(target), json={"priority": None}
        )

        assert set_response.status_code == clear_response.status_code == 200
        assert set(set_response.json()) == {"data"}
        data = set_response.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == after_set.json()["data"]
        assert (
            data["priority"],
            data["priority_automatic"],
            data["priority_override"],
        ) == (
            "p2",
            "p3",
            "p2",
        )
        cleared = clear_response.json()["data"]
        assert (
            cleared["priority"],
            cleared["priority_automatic"],
            cleared["priority_override"],
        ) == ("p3", "p3", None)
        state = await ticket_row(db_session, target.id)
        assert (state["priority_auto"], state["priority_override"]) == ("P3", None)
        assert await event_count(db_session, target.id) == 2

    async def test_same_value_returns_the_unchanged_detail_without_event(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(priority_override=TicketPriority.P2.value)
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"priority": "p2"}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["status"], data["assignee"], data["priority_override"]) == (
            "new",
            None,
            "p2",
        )
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    async def test_manual_zone_ticket_is_not_mutable(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(status=TicketStatus.IGNORED.value)
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"priority": "p1"}
        )

        assert response.status_code == 409
        assert response.json() == NOT_MUTABLE
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0


# ---------------------------------------------------------------------------
# Handler-owned final assembly in the real request transaction
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMutationAssembly:
    async def test_detail_is_assembled_from_the_uncommitted_post_state(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket()
        observed: list[tuple[str | None, str | None]] = []
        original = ticket_service.assemble_ticket_detail

        async def _observe(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            independent = await world.session()
            observed.append(
                (
                    (await ticket_row(db, target.id))["priority_override"],
                    (await ticket_row(independent, target.id))["priority_override"],
                )
            )
            await independent.rollback()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _observe)

        response = await committed_client.patch(
            _url(target), json={"priority": "p1"}, headers=headers
        )

        assert response.status_code == 200
        assert response.json()["data"]["priority_override"] == "p1"
        # The request's own session sees the override; the commit follows.
        assert observed == [("P1", None)]
        fresh = await world.session()
        assert (await ticket_row(fresh, target.id))["priority_override"] == "P1"

    async def test_failed_assembly_rolls_back_the_real_transaction(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket()
        before = await ticket_row(await world.session(), target.id)
        reached: list[int] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            reached.append(await event_count(db, target.id))
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)

        response = await committed_client.patch(
            _url(target), json={"priority": "p1"}, headers=headers
        )

        assert response.status_code == 500
        # Assignment, promotion, and the override event existed before the
        # failure; none of them survives.
        assert reached == [3]
        fresh = await world.session()
        assert await ticket_row(fresh, target.id) == before
        assert await event_count(fresh, target.id) == 0


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured date across UTC midnight
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEvaluationDate:
    async def test_one_date_captured_before_midnight_is_reused_after_it(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handler_clock = Clock(datetime(2026, 9, 27, 23, 59, 59, 999000, tzinfo=UTC))
        service_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        mutation_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", service_clock.now)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        seen: dict[str, list[date | None]] = {
            "mutation": [],
            "reconcile": [],
            "assembly": [],
        }
        original_mutation = ticket_service.set_priority_override
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_assembly = ticket_service.assemble_ticket_detail

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Ticket:
            seen["mutation"].append(kwargs.get("evaluation_date"))
            return await original_mutation(db, **kwargs)

        async def _reconcile(ticket: Ticket, db: AsyncSession, **kwargs: Any) -> None:
            seen["reconcile"].append(kwargs.get("evaluation_date"))
            await original_reconcile(ticket, db, **kwargs)

        async def _assembly(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            seen["assembly"].append(kwargs.get("evaluation_date"))
            return await original_assembly(db, **kwargs)

        monkeypatch.setattr(ticket_service, "set_priority_override", _mutation)
        monkeypatch.setattr(ticket_service, "reconcile_ticket_status", _reconcile)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        target: Ticket = await ticket_factory()

        response = await authenticated_client.patch(
            _url(target), json={"priority": "p1"}
        )

        assert response.status_code == 200
        captured = date(2026, 9, 27)
        assert seen == {
            "mutation": [captured],
            "reconcile": [captured],
            "assembly": [captured],
        }
        assert handler_clock.calls == 1
        # The service clock is read only for the assembly's own milestone
        # instant (ticket-deadlines.md, Evaluation Instant), never for the
        # workflow date; the mutation clock is never read.
        assert (service_clock.calls, mutation_clock.calls) == (1, 0)


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_PATH]["patch"]
        return operation

    def _resolve(self, schema: dict[str, Any]) -> dict[str, Any]:
        ref = schema.get("$ref")
        if ref is None:
            return schema
        resolved: dict[str, Any] = self._spec()["components"]["schemas"][
            ref.rsplit("/", 1)[-1]
        ]
        return resolved

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_request_body_requires_a_nullable_lowercase_priority(self) -> None:
        operation = self._operation()
        assert operation["tags"] == ["Tickets"]
        request_body = operation["requestBody"]
        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketPriorityUpdateRequest"

        schema = self._resolve(request_body["content"]["application/json"]["schema"])
        assert schema["required"] == ["priority"]
        assert set(schema["properties"]) == {"priority"}
        variants = [self._resolve(v) for v in schema["properties"]["priority"]["anyOf"]]
        assert {"type": "null"} in variants
        (enum_variant,) = [v for v in variants if "enum" in v]
        assert enum_variant["type"] == "string"
        assert enum_variant["enum"] == ["p1", "p2", "p3", "p4"]

    def test_responses_declare_detail_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "422" in responses
        assert "400" not in responses
        assert not any(
            "TICKET_ASSIGNEE" in response.get("description", "")
            for response in responses.values()
        )
