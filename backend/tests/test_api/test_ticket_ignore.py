"""End-to-end tests for the Ignore Ticket endpoint
(`POST /api/v1/tickets/{ticket_id}/ignore`, `backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Ignore Ticket, Auto-Assignment on
Unassigned Tickets, Response Schemas > TicketDetail, Endpoint -> Schema
Mapping), docs/features/tickets/ticket-service.md (`ignore_ticket`;
`get_ticket_detail()` mutation assembly), docs/api-spec.md (Authorization
Chain Evaluation Order flow 3, Global Responses, Ticket Accessibility Check,
Anti-Enumeration Boundary, Manual-Zone Mutability Guard),
docs/features/identity/rbac.md (Endpoint Permission Map: `triage_ticket`),
and docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; API Endpoints; Ticket Accessibility).

These tests cover only the HTTP boundary: authentication, capability before
lookup, the status and complete body of each error mapping (one
representative request each), the absent request body, the response shape,
OpenAPI, and the handler-owned steps (the one captured date and the final
`TicketDetail` assembly with its rollback). The service matrix (every source
status, VA/non-VA actor, event sequence, guard order, lock order, races) is
proven once in `tests/test_services/test_ignore_ticket.py` and
`tests/test_services/test_manual_zone_entry_atomicity.py`.
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
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import tickets as route
from app.core.enums import Role, TicketStatus
from app.main import app
from app.models.ticket import Ticket
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.ticket_service import TicketDetailProjection
from tests.support.ticket_api import (
    FORBIDDEN,
    INTERNAL_ERROR,
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
    force_production_error_page,
    locator,
    ticket_row,
    user_reference,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/ignore"
_INVALID_TRANSITION = {
    "code": "TICKET_INVALID_TRANSITION",
    "detail": "Ticket status transition is not allowed.",
}


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
    monkeypatch.setattr(ticket_service, "ignore_ticket", mutation)
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
# Successful request (200 TicketDetail)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIgnoreTicket:
    async def test_bodiless_request_returns_the_committed_ignored_detail(
        self, committed_app: tuple[CommittedApp, AsyncClient]
    ) -> None:
        """A VA caller ignores an unassigned `New` Ticket with no request
        body: the response is the complete post-mutation `TicketDetail`
        (auto-assigned to the caller), equal to a subsequent GET, and the
        state is committed."""
        world, committed_client = committed_app
        caller, headers = await world.va_headers()
        target = await world.ticket()

        response = await committed_client.post(_url(target), headers=headers)
        detail = await committed_client.get(
            f"/api/v1/tickets/{locator(target)}", headers=headers
        )

        assert response.status_code == 200
        assert set(response.json()) == {"data"}
        data = response.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == detail.json()["data"]
        assert (data["ticket_id"], data["status"], data["duplicate_of_ticket_id"]) == (
            locator(target),
            "ignored",
            None,
        )
        assert data["assignee"] == user_reference(caller)
        fresh = await world.session()
        state = await ticket_row(fresh, target.id)
        assert (state["status"], state["assignee_id"]) == (
            TicketStatus.IGNORED.value,
            caller.id,
        )


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
            response = await client.post(path, headers=headers)
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

        existing = await authenticated_client.post(_url(visible))
        missing = await authenticated_client.post(_url(f"SNTL-{MAX_SEQUENCE}"))

        assert existing.status_code == missing.status_code == 403
        assert existing.content == missing.content
        assert existing.json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert (await ticket_row(db_session, visible.id))["status"] == (
            TicketStatus.NEW.value
        )


# ---------------------------------------------------------------------------
# Ticket accessibility and anti-enumeration (identical 404)
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

        response = await authenticated_client.post(_url(build_locator(target)))

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

        inaccessible = await authenticated_client.post(_url(hidden))
        missing = await authenticated_client.post(_url(f"SNTL-{MAX_SEQUENCE}"))

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await ticket_row(db_session, hidden.id) == before
        assert await event_count(db_session, hidden.id) == 0


# ---------------------------------------------------------------------------
# Error mappings (one representative request each)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestErrorMappings:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            pytest.param(
                TicketStatus.ANALYZED, _INVALID_TRANSITION, id="invalid-transition"
            ),
            pytest.param(TicketStatus.IGNORED, NOT_MUTABLE, id="not-mutable"),
        ],
    )
    async def test_rejection_returns_its_complete_409_body_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        status: TicketStatus,
        expected: dict[str, str],
    ) -> None:
        target: Ticket = await ticket_factory(status=status.value)
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.post(_url(target))

        assert response.status_code == 409
        assert response.json() == expected
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0


# ---------------------------------------------------------------------------
# Handler-owned final assembly in the real request transaction
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMutationAssembly:
    async def test_failed_assembly_rolls_back_the_mutation_and_its_audit(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket()
        before = await ticket_row(await world.session(), target.id)
        reached: list[tuple[str, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            reached.append(
                (
                    (await ticket_row(db, target.id))["status"],
                    await event_count(db, target.id),
                )
            )
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)
        force_production_error_page(monkeypatch)

        response = await committed_client.post(_url(target), headers=headers)

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        # The auto-assignment, promotion, and entry transition existed in the
        # request transaction before the failure; none of them survives.
        assert reached == [(TicketStatus.IGNORED.value, 3)]
        fresh = await world.session()
        assert await ticket_row(fresh, target.id) == before
        assert await event_count(fresh, target.id) == 0


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured date across UTC midnight
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEvaluationDate:
    async def test_one_date_captured_before_midnight_is_used_for_the_projection(
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
        mutation_kwargs: list[set[str]] = []
        assembly_dates: list[date] = []
        original_mutation = ticket_service.ignore_ticket
        original_assembly = ticket_service.assemble_ticket_detail

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Ticket:
            mutation_kwargs.append(set(kwargs))
            return await original_mutation(db, **kwargs)

        async def _assembly(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            assembly_dates.append(kwargs["evaluation_date"])
            return await original_assembly(db, **kwargs)

        monkeypatch.setattr(ticket_service, "ignore_ticket", _mutation)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        target: Ticket = await ticket_factory()

        response = await authenticated_client.post(_url(target))

        assert response.status_code == 200
        # The mutation neither receives nor captures a workflow date.
        assert mutation_kwargs == [{"ticket_id", "acting_user_id", "caller"}]
        assert assembly_dates == [date(2026, 9, 27)]
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
    def _operation(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        operation: dict[str, Any] = spec["paths"][_PATH]["post"]
        return operation

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_operation_declares_no_request_body(self) -> None:
        operation = self._operation()

        assert operation["tags"] == ["Tickets"]
        assert operation["summary"] == "Ignore Ticket"
        assert "requestBody" not in operation

    def test_responses_declare_detail_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_INVALID_TRANSITION" in responses["409"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "400" not in responses


# ---------------------------------------------------------------------------
# Locked-current accessibility through HTTP (handler mapping of the
# service's authoritative denial; api-spec.md, flow 3)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIndependentRaces:
    async def test_visibility_lost_to_a_committed_change_after_the_preliminary_check(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another session commits the confidentiality flag after the
        preliminary dependency check but before the service locks the
        Ticket. The service's locked-current denial maps to the identical
        `404 TICKET_NOT_FOUND` with no effect. The service tier owns the
        race matrix; this proves only the handler's mapping of that denial."""
        world, committed_client = committed_app
        _, headers = await world.va_headers(role=Role.RESTRICTED_ANALYST)
        target = await world.ticket()
        ticket_id: uuid.UUID = target.id
        before = await ticket_row(await world.session(), ticket_id)
        original = ticket_service.ignore_ticket
        reached: list[bool] = []

        async def _lose_then_call(db: AsyncSession, **kwargs: Any) -> Ticket:
            reached.append(True)
            racer = await world.session()
            await racer.execute(
                update(Ticket)
                .where(Ticket.id == ticket_id)
                .values(is_confidential=True)
            )
            await racer.commit()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "ignore_ticket", _lose_then_call)

        response = await committed_client.post(_url(target), headers=headers)
        monkeypatch.undo()

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert reached == [True]
        fresh = await world.session()
        after = await ticket_row(fresh, ticket_id)
        # Only the racer's own write (and its `updated_at`) is committed.
        assert {k: v for k, v in after.items() if k != "updated_at"} == {
            k: v for k, v in before.items() if k != "updated_at"
        }
        assert await event_count(fresh, ticket_id) == 0
