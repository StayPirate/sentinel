"""End-to-end tests for the Assign Ticket endpoint
(`PATCH /api/v1/tickets/{ticket_id}/assignee`, `backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Assign Ticket, Reassignment, Response
Schemas > TicketDetail, Endpoint -> Schema Mapping),
docs/features/tickets/ticket-service.md (`assign_ticket`; `get_ticket_detail()`
mutation assembly), docs/api-spec.md (Authorization Chain Evaluation Order
flow 3, Global Responses, Ticket Accessibility Check, Manual-Zone Mutability
Guard, User Identifier Resolution, Partial Update Semantics),
docs/features/identity/rbac.md (Endpoint Permission Map: `triage_ticket`),
and docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; API Endpoints; User Identifier Resolution; Ticket
Accessibility).

These tests cover only the HTTP boundary: authentication, capability before
lookup, request validation, the status and complete body of each error
mapping (one representative request each), the response shape, OpenAPI, and
the handler-owned steps (the one captured date and the final `TicketDetail`
assembly with its rollback). The service matrix (reassignment, idempotency,
guard order permutations, lock order, races) is proven once in
`tests/test_services/test_assign_ticket.py` and
`tests/test_services/test_assign_ticket_atomicity.py`.
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
    user_reference,
    validation_error,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/assignee"
_USER_NOT_FOUND = {"code": "USER_NOT_FOUND", "detail": "User not found."}
_ASSIGNEE_INACTIVE = {
    "code": "TICKET_ASSIGNEE_INACTIVE",
    "detail": "Assignee is inactive.",
}
_ASSIGNEE_NOT_VA = {
    "code": "TICKET_ASSIGNEE_NOT_VA",
    "detail": "Assignee must hold the vulnerability_analyst role.",
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
    monkeypatch.setattr(ticket_service, "assign_ticket", mutation)
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


@pytest.fixture
def target_user(
    user_factory: Factory, user_role_factory: Factory
) -> Callable[..., Awaitable[User]]:
    """Create a prospective assignee with the given role and activity."""

    async def _create(
        *, role: Role | None = Role.VULNERABILITY_ANALYST, active: bool = True
    ) -> User:
        suffix = uuid.uuid4().hex[:8]
        user: User = await user_factory(
            username=f"dave.va.{suffix}",
            email=f"dave.va.{suffix}@example.com",
            full_name="Dave Analyst",
            active=active,
        )
        if role is not None:
            await user_role_factory(user_id=user.id, role=role.value)
        return user

    return _create


TargetUser = Callable[..., Awaitable[User]]


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
                path, json={"user_id": "nobody.va"}, headers=headers
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
        target_user: TargetUser,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
    ) -> None:
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        visible: Ticket = await ticket_factory()
        assignee = await target_user()
        resolver, mutation = _forbid_lookups(monkeypatch)

        existing = await authenticated_client.patch(
            _url(visible), json={"user_id": str(assignee.id)}
        )
        missing = await authenticated_client.patch(
            _url(f"SNTL-{MAX_SEQUENCE}"), json={"user_id": str(assignee.id)}
        )

        assert existing.status_code == missing.status_code == 403
        assert existing.content == missing.content
        assert existing.json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert (await ticket_row(db_session, visible.id))["assignee_id"] is None


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
        target_user: TargetUser,
        build_locator: Callable[[Ticket], str],
    ) -> None:
        target: Ticket = await ticket_factory()
        assignee = await target_user()
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.patch(
            _url(build_locator(target)), json={"user_id": str(assignee.id)}
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    @pytest.mark.parametrize(
        "target_kind",
        [
            pytest.param("eligible", id="eligible-target"),
            # The target's absence is never disclosed for an inaccessible
            # Ticket (ticket-service.md, Concurrency control).
            pytest.param("absent", id="absent-target"),
        ],
    )
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        target_user: TargetUser,
        target_kind: str,
    ) -> None:
        hidden: Ticket = await ticket_factory(is_confidential=True)
        identifier = (
            str((await target_user()).id)
            if target_kind == "eligible"
            else str(uuid.uuid7())
        )
        before = await ticket_row(db_session, hidden.id)

        inaccessible = await authenticated_client.patch(
            _url(hidden), json={"user_id": identifier}
        )
        missing = await authenticated_client.patch(
            _url(f"SNTL-{MAX_SEQUENCE}"), json={"user_id": identifier}
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
                    "loc": ["body", "user_id"],
                    "msg": "Field required",
                    "type": "missing",
                },
                id="omitted",
            ),
            *[
                pytest.param(
                    {"user_id": value},
                    {
                        "loc": ["body", "user_id"],
                        "msg": "Input should be a valid string",
                        "type": "string_type",
                    },
                    id=f"invalid-{value!r}",
                )
                for value in (None, 42)
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
        monkeypatch.setattr(ticket_service, "assign_ticket", mutation)

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
# User Identifier Resolution (testing-strategy.md; api-spec.md)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUserIdentifierResolution:
    async def test_uuid_and_username_assign_the_same_user(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        target_user: TargetUser,
    ) -> None:
        """A `New` unassigned Ticket moves to `analysis` with the target as
        assignee; the full detail equals a subsequent GET."""
        assignee = await target_user()
        by_uuid: Ticket = await ticket_factory()
        by_username: Ticket = await ticket_factory()

        uuid_response = await authenticated_client.patch(
            _url(by_uuid), json={"user_id": str(assignee.id)}
        )
        username_response = await authenticated_client.patch(
            _url(by_username), json={"user_id": assignee.username}
        )
        detail = await authenticated_client.get(f"/api/v1/tickets/{locator(by_uuid)}")

        assert uuid_response.status_code == username_response.status_code == 200
        assert set(uuid_response.json()) == {"data"}
        data = uuid_response.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == detail.json()["data"]
        for response in (uuid_response, username_response):
            body = response.json()["data"]
            assert body["status"] == "analysis"
            assert body["assignee"] == user_reference(assignee)
        for ticket in (by_uuid, by_username):
            state = await ticket_row(db_session, ticket.id)
            assert (state["status"], state["assignee_id"]) == (
                TicketStatus.ANALYSIS.value,
                assignee.id,
            )

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_nonexistent_user_returns_user_not_found_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        form: str,
    ) -> None:
        target: Ticket = await ticket_factory()
        identifier = (
            str(uuid.uuid7()) if form == "uuid" else f"nobody.va.{uuid.uuid4().hex[:8]}"
        )
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"user_id": identifier}
        )

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert await ticket_row(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0


# ---------------------------------------------------------------------------
# Error mappings (one representative request each)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestErrorMappings:
    @pytest.mark.parametrize(
        ("status", "target_kind", "expected_status", "expected"),
        [
            pytest.param(
                TicketStatus.IGNORED,
                "absent",
                409,
                NOT_MUTABLE,
                id="not-mutable-before-user-not-found",
            ),
            pytest.param(
                TicketStatus.NEW, "inactive", 409, _ASSIGNEE_INACTIVE, id="inactive"
            ),
            pytest.param(
                TicketStatus.NEW, "non-va", 400, _ASSIGNEE_NOT_VA, id="not-va"
            ),
        ],
    )
    async def test_rejection_returns_its_complete_body_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        target_user: TargetUser,
        status: TicketStatus,
        target_kind: str,
        expected_status: int,
        expected: dict[str, str],
    ) -> None:
        target: Ticket = await ticket_factory(status=status.value)
        if target_kind == "absent":
            identifier = str(uuid.uuid7())
        elif target_kind == "inactive":
            identifier = str((await target_user(active=False)).id)
        else:
            identifier = str((await target_user(role=Role.RESTRICTED_ANALYST)).id)
        before = await ticket_row(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"user_id": identifier}
        )

        assert response.status_code == expected_status
        assert response.json() == expected
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
        assignee = await world.user(role=Role.VULNERABILITY_ANALYST)
        target = await world.ticket()
        observed: list[tuple[uuid.UUID | None, uuid.UUID | None]] = []
        original = ticket_service.assemble_ticket_detail

        async def _observe(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            independent = await world.session()
            observed.append(
                (
                    (await ticket_row(db, target.id))["assignee_id"],
                    (await ticket_row(independent, target.id))["assignee_id"],
                )
            )
            await independent.rollback()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _observe)

        response = await committed_client.patch(
            _url(target), json={"user_id": assignee.username}, headers=headers
        )

        assert response.status_code == 200
        assert response.json()["data"]["assignee"] == user_reference(assignee)
        # The request's own session sees the assignment; the commit follows.
        assert observed == [(assignee.id, None)]
        fresh = await world.session()
        assert (await ticket_row(fresh, target.id))["assignee_id"] == assignee.id

    async def test_failed_assembly_rolls_back_the_real_transaction(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        assignee = await world.user(role=Role.VULNERABILITY_ANALYST)
        target = await world.ticket()
        before = await ticket_row(await world.session(), target.id)
        reached: list[int] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            reached.append(await event_count(db, target.id))
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)

        response = await committed_client.patch(
            _url(target), json={"user_id": str(assignee.id)}, headers=headers
        )

        assert response.status_code == 500
        # The assignment and its promotion existed before the failure; none
        # of them survives.
        assert reached == [2]
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
        target_user: TargetUser,
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
        original_mutation = ticket_service.assign_ticket
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

        monkeypatch.setattr(ticket_service, "assign_ticket", _mutation)
        monkeypatch.setattr(ticket_service, "reconcile_ticket_status", _reconcile)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        target: Ticket = await ticket_factory()
        assignee = await target_user()

        response = await authenticated_client.patch(
            _url(target), json={"user_id": str(assignee.id)}
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

    def test_request_body_requires_a_non_nullable_string_user_id(self) -> None:
        operation = self._operation()
        assert operation["tags"] == ["Tickets"]
        request_body = operation["requestBody"]
        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketAssigneeUpdateRequest"

        schema = self._resolve(request_body["content"]["application/json"]["schema"])
        assert schema["required"] == ["user_id"]
        assert set(schema["properties"]) == {"user_id"}
        user_id = schema["properties"]["user_id"]
        assert user_id["type"] == "string"
        assert "anyOf" not in user_id
        assert "format" not in user_id

    def test_responses_declare_detail_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        for code in ("400", "404", "409"):
            assert self._ref_name(responses[code]["content"]) == "ErrorResponse"
        assert "TICKET_ASSIGNEE_NOT_VA" in responses["400"]["description"]
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "USER_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_ASSIGNEE_INACTIVE" in responses["409"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "422" in responses


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
        assignee = await world.user(role=Role.VULNERABILITY_ANALYST)
        target = await world.ticket()
        ticket_id = target.id
        before = await ticket_row(await world.session(), ticket_id)
        original = ticket_service.assign_ticket
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

        monkeypatch.setattr(ticket_service, "assign_ticket", _lose_then_call)

        response = await committed_client.patch(
            _url(target), json={"user_id": str(assignee.id)}, headers=headers
        )
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
