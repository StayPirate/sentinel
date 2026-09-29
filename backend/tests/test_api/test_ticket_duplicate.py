"""End-to-end tests for the Mark Ticket as Duplicate endpoint
(`POST /api/v1/tickets/{ticket_id}/duplicate`, `backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Mark Ticket as Duplicate, Duplicate
Handling, Response Schemas > TicketDetail, Endpoint -> Schema Mapping,
Identifier Disclosure Boundary), docs/features/tickets/ticket-service.md
(`mark_as_duplicate`; `get_ticket_detail()` mutation assembly),
docs/api-spec.md (Authorization Chain Evaluation Order flow 3, Global
Responses, Ticket Accessibility Check, Anti-Enumeration Boundary,
Manual-Zone Mutability Guard, Ticket Identifier Resolution),
docs/features/identity/rbac.md (Endpoint Permission Map: `triage_ticket`),
and docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; API Endpoints; Ticket Accessibility).

These tests cover only the HTTP boundary: authentication, capability before
lookup, request-body validation of `duplicate_of_ticket_id` (this module is
its proving tier), the path and body-target 404 families, the status and
complete body of each error mapping (one representative request each), the
response shape, OpenAPI, and the handler-owned steps (target resolution, the
one captured date, and the final `TicketDetail` assembly with its rollback).
The service matrix (every source status, VA/non-VA actor, event sequence,
dependent order, guard order, lock order, races, and the identifier
disclosure after a target becomes confidential) is proven once in
`tests/test_services/test_mark_as_duplicate.py` and
`tests/test_services/test_manual_zone_entry_atomicity.py`; the read-side
projection of an inaccessible target is proven in
`tests/test_api/test_tickets.py`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select, update
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
    validation_error,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/duplicate"
_FIELD = "duplicate_of_ticket_id"
_SELF_DUPLICATE = {
    "code": "TICKET_SELF_DUPLICATE",
    "detail": "Ticket cannot be marked as a duplicate of itself.",
}
_TARGET_DUPLICATED = {
    "code": "TICKET_DUPLICATE_TARGET_DUPLICATED",
    "detail": "Duplicate target is itself a duplicate.",
}
_CONCURRENT_MODIFICATION = {
    "code": "TICKET_DUPLICATE_CONCURRENT_MODIFICATION",
    "detail": "A duplicate dependent is being modified concurrently.",
}
_MALFORMED_MESSAGE = (
    "Value error, duplicate_of_ticket_id must be a canonical SNTL-{n} identifier."
)
_MALFORMED_BODY = {_FIELD: "sntl-1"}


def _url(target: Ticket | str) -> str:
    return _PATH.format(
        ticket_id=target if isinstance(target, str) else locator(target)
    )


def _body(target: Ticket | str) -> dict[str, str]:
    return {_FIELD: target if isinstance(target, str) else locator(target)}


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, "mark_as_duplicate", mutation)
    return resolver, mutation


async def _dependent_link(db: AsyncSession, ticket_id: uuid.UUID) -> uuid.UUID | None:
    link: uuid.UUID | None = (await ticket_row(db, ticket_id))["duplicate_of_id"]
    return link


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


async def _duplicate_group(
    world: CommittedApp,
) -> tuple[Ticket, Ticket, Ticket]:
    """A committed unassigned `New` source, an `Analysis` target, and one
    dependent currently marked as a duplicate of the source."""
    source = await world.ticket()
    target = await world.ticket(status=TicketStatus.ANALYSIS.value)
    dependent = await world.ticket(
        status=TicketStatus.DUPLICATED.value, duplicate_of_id=source.id
    )
    return source, target, dependent


# ---------------------------------------------------------------------------
# Successful request (200 TicketDetail)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMarkAsDuplicate:
    async def test_source_is_marked_and_its_dependent_repointed_on_commit(
        self, committed_app: tuple[CommittedApp, AsyncClient]
    ) -> None:
        """The response is the complete post-mutation `TicketDetail` of the
        source, equal to a subsequent GET; the link and the dependent's
        repoint are committed."""
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        source, target, dependent = await _duplicate_group(world)

        response = await committed_client.post(
            _url(source), json=_body(target), headers=headers
        )
        detail = await committed_client.get(
            f"/api/v1/tickets/{locator(source)}", headers=headers
        )

        assert response.status_code == 200
        assert set(response.json()) == {"data"}
        data = response.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == detail.json()["data"]
        assert (data["ticket_id"], data["status"], data[_FIELD]) == (
            locator(source),
            "duplicated",
            locator(target),
        )
        fresh = await world.session()
        state = await ticket_row(fresh, source.id)
        assert (state["status"], state["duplicate_of_id"]) == (
            TicketStatus.DUPLICATED.value,
            target.id,
        )
        assert await _dependent_link(fresh, dependent.id) == target.id


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
    async def test_credential_failure_returns_401_before_validation_or_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
    ) -> None:
        source: Ticket = await ticket_factory()
        target: Ticket = await ticket_factory()
        resolver, mutation = _forbid_lookups(monkeypatch)

        for path in (_url(source), _url(f"SNTL-{MAX_SEQUENCE}")):
            for body in (_body(target), _MALFORMED_BODY):
                response = await client.post(path, json=body, headers=headers)
                assert response.status_code == 401
                assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()

    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_triage_ticket_gets_the_generic_403_first(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
    ) -> None:
        """Existing and missing paths, with a valid or a malformed body, all
        return the identical 403 without any Ticket lookup."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        source: Ticket = await ticket_factory()
        target: Ticket = await ticket_factory()
        before = await ticket_row(db_session, source.id)
        resolver, mutation = _forbid_lookups(monkeypatch)

        bodies = set()
        for path in (_url(source), _url(f"SNTL-{MAX_SEQUENCE}")):
            for body in (_body(target), _MALFORMED_BODY):
                response = await authenticated_client.post(path, json=body)
                assert response.status_code == 403
                assert response.json() == FORBIDDEN
                bodies.add(response.content)

        assert len(bodies) == 1
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await ticket_row(db_session, source.id) == before


# ---------------------------------------------------------------------------
# Path Ticket accessibility and anti-enumeration (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestPathTicketNotFound:
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
        source: Ticket = await ticket_factory()
        target: Ticket = await ticket_factory()
        before = await ticket_row(db_session, source.id)

        response = await authenticated_client.post(
            _url(build_locator(source)), json=_body(target)
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await ticket_row(db_session, source.id) == before
        assert await event_count(db_session, source.id) == 0
        assert await event_count(db_session, target.id) == 0

    async def test_inaccessible_source_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        hidden: Ticket = await ticket_factory(is_confidential=True)
        target: Ticket = await ticket_factory()
        before = await ticket_row(db_session, hidden.id)

        inaccessible = await authenticated_client.post(_url(hidden), json=_body(target))
        missing = await authenticated_client.post(
            _url(f"SNTL-{MAX_SEQUENCE}"), json=_body(target)
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await ticket_row(db_session, hidden.id) == before
        assert await event_count(db_session, hidden.id) == 0


# ---------------------------------------------------------------------------
# Request-body validation of `duplicate_of_ticket_id` (global 422)
# ---------------------------------------------------------------------------


_MALFORMED_ERROR = {
    "loc": ["body", _FIELD],
    "msg": _MALFORMED_MESSAGE,
    "type": "value_error",
}
_MALFORMED_TARGETS: list[tuple[str, Callable[[Ticket], str]]] = [
    ("lowercase-prefix", lambda t: f"sntl-{t.sequence_id}"),
    ("zero-padded", lambda t: f"SNTL-0{t.sequence_id}"),
    ("ticket-uuid", lambda t: str(t.id)),
    ("leading-whitespace", lambda t: f" {locator(t)}"),
    ("trailing-whitespace", lambda t: f"{locator(t)} "),
    ("overflow", lambda t: f"SNTL-{MAX_SEQUENCE + 1}"),
]
"""Malformed spellings of an existing, accessible target: a normalizing
implementation would resolve them and succeed instead of returning 422."""


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        ("build_body", "error"),
        [
            *[
                pytest.param(
                    lambda t, build=build: {_FIELD: build(t)},
                    _MALFORMED_ERROR,
                    id=name,
                )
                for name, build in _MALFORMED_TARGETS
            ],
            pytest.param(
                lambda t: {},
                {"loc": ["body", _FIELD], "msg": "Field required", "type": "missing"},
                id="omitted",
            ),
            *[
                pytest.param(
                    lambda t, value=value: {_FIELD: value},
                    {
                        "loc": ["body", _FIELD],
                        "msg": "Input should be a valid string",
                        "type": "string_type",
                    },
                    id=f"invalid-{value!r}",
                )
                for value in (None, 1)
            ],
        ],
    )
    async def test_invalid_target_returns_the_validation_envelope_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        build_body: Callable[[Ticket], dict[str, Any]],
        error: dict[str, Any],
    ) -> None:
        """api-spec.md, Ticket Identifier Resolution: a request-body Ticket
        field uses the canonical grammar with ordinary Pydantic semantics
        and no trimming or normalization, so every shape other than a
        canonical `SNTL-{n}` string is the global `422 VALIDATION_ERROR`,
        never `TICKET_NOT_FOUND` or a resolved target."""
        source: Ticket = await ticket_factory()
        target: Ticket = await ticket_factory()
        before = await ticket_row(db_session, source.id)
        mutation = AsyncMock()
        monkeypatch.setattr(ticket_service, "mark_as_duplicate", mutation)

        response = await authenticated_client.post(
            _url(source), json=build_body(target)
        )

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        mutation.assert_not_awaited()
        assert await ticket_row(db_session, source.id) == before
        assert await event_count(db_session, source.id) == 0

    async def test_absent_body_is_a_validation_error(
        self, authenticated_client: AsyncClient, va_user: User, ticket_factory: Factory
    ) -> None:
        source: Ticket = await ticket_factory()

        response = await authenticated_client.post(_url(source))

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["body"], "msg": "Field required", "type": "missing"}
        )


# ---------------------------------------------------------------------------
# Body target resolution (identical 404 for a well-formed target)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTargetNotFound:
    async def test_missing_target_returns_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        source: Ticket = await ticket_factory()
        before = await ticket_row(db_session, source.id)

        response = await authenticated_client.post(
            _url(source), json=_body(f"SNTL-{MAX_SEQUENCE}")
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await ticket_row(db_session, source.id) == before
        assert await event_count(db_session, source.id) == 0

    async def test_inaccessible_target_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """The `non_confidential` caller can see the source but not the
        confidential target."""
        source: Ticket = await ticket_factory()
        hidden: Ticket = await ticket_factory(is_confidential=True)
        before = {t.id: await ticket_row(db_session, t.id) for t in (source, hidden)}

        inaccessible = await authenticated_client.post(_url(source), json=_body(hidden))
        missing = await authenticated_client.post(
            _url(source), json=_body(f"SNTL-{MAX_SEQUENCE}")
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        for ticket_id, state in before.items():
            assert await ticket_row(db_session, ticket_id) == state
            assert await event_count(db_session, ticket_id) == 0


# ---------------------------------------------------------------------------
# Error mappings (one representative request each)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestErrorMappings:
    @pytest.mark.parametrize(
        ("case", "expected_status", "expected"),
        [
            pytest.param("self", 400, _SELF_DUPLICATE, id="self-duplicate"),
            pytest.param(
                "target-duplicated", 409, _TARGET_DUPLICATED, id="target-duplicated"
            ),
            pytest.param("source-ignored", 409, NOT_MUTABLE, id="not-mutable"),
        ],
    )
    async def test_rejection_returns_its_complete_body_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        case: str,
        expected_status: int,
        expected: dict[str, str],
    ) -> None:
        source: Ticket = await ticket_factory(
            status=(
                TicketStatus.IGNORED.value
                if case == "source-ignored"
                else TicketStatus.NEW.value
            )
        )
        if case == "self":
            target = source
        elif case == "target-duplicated":
            original: Ticket = await ticket_factory()
            target = await ticket_factory(
                status=TicketStatus.DUPLICATED.value, duplicate_of_id=original.id
            )
        else:
            target = await ticket_factory()
        before = {t.id: await ticket_row(db_session, t.id) for t in (source, target)}

        response = await authenticated_client.post(_url(source), json=_body(target))

        assert response.status_code == expected_status
        assert response.json() == expected
        for ticket_id, state in before.items():
            assert await ticket_row(db_session, ticket_id) == state
            assert await event_count(db_session, ticket_id) == 0

    async def test_locked_dependent_maps_to_concurrent_modification_and_rolls_back(
        self, committed_app: tuple[CommittedApp, AsyncClient]
    ) -> None:
        """An independent transaction holds a dependent's row lock; the
        request returns promptly with the complete 409 body and its
        transaction is rolled back. The service tier owns the lock-phase
        matrix and the retry; this proves only the HTTP mapping and the
        request-transaction rollback."""
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        source, target, dependent = await _duplicate_group(world)
        before = await ticket_row(await world.session(), source.id)
        holder = await world.session()
        await holder.execute(
            select(Ticket.id).where(Ticket.id == dependent.id).with_for_update()
        )

        try:
            response = await asyncio.wait_for(
                committed_client.post(
                    _url(source), json=_body(target), headers=headers
                ),
                timeout=10,
            )
        finally:
            await holder.rollback()

        assert response.status_code == 409
        assert response.json() == _CONCURRENT_MODIFICATION
        fresh = await world.session()
        assert await ticket_row(fresh, source.id) == before
        assert await _dependent_link(fresh, dependent.id) == source.id
        for ticket in (source, target, dependent):
            assert await event_count(fresh, ticket.id) == 0


# ---------------------------------------------------------------------------
# Handler-owned final assembly in the real request transaction
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMutationAssembly:
    async def test_failed_assembly_rolls_back_the_link_repoint_and_audit(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        source, target, dependent = await _duplicate_group(world)
        before_session = await world.session()
        before = await ticket_row(before_session, source.id)
        reached: list[tuple[uuid.UUID | None, uuid.UUID | None, int, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            reached.append(
                (
                    (await ticket_row(db, source.id))["duplicate_of_id"],
                    await _dependent_link(db, dependent.id),
                    await event_count(db, source.id),
                    await event_count(db, dependent.id),
                )
            )
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)
        force_production_error_page(monkeypatch)

        response = await committed_client.post(
            _url(source), json=_body(target), headers=headers
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        # The link, the repoint, and every event (assignment, promotion,
        # entry transition, `duplicate_set`; `duplicate_target_changed`)
        # existed in the request transaction before the failure.
        assert reached == [(target.id, target.id, 4, 1)]
        fresh = await world.session()
        assert await ticket_row(fresh, source.id) == before
        assert await _dependent_link(fresh, dependent.id) == source.id
        for ticket in (source, target, dependent):
            assert await event_count(fresh, ticket.id) == 0


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
        original_mutation = ticket_service.mark_as_duplicate
        original_assembly = ticket_service.assemble_ticket_detail

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Ticket:
            mutation_kwargs.append(set(kwargs))
            return await original_mutation(db, **kwargs)

        async def _assembly(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            assembly_dates.append(kwargs["evaluation_date"])
            return await original_assembly(db, **kwargs)

        monkeypatch.setattr(ticket_service, "mark_as_duplicate", _mutation)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        source: Ticket = await ticket_factory()
        target: Ticket = await ticket_factory()

        response = await authenticated_client.post(_url(source), json=_body(target))

        assert response.status_code == 200
        # The mutation neither receives nor captures a workflow date.
        assert mutation_kwargs == [
            {"ticket_id", "duplicate_of_id", "acting_user_id", "caller"}
        ]
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
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_PATH]["post"]
        return operation

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_request_body_requires_a_string_target_identifier(self) -> None:
        operation = self._operation()
        assert operation["tags"] == ["Tickets"]
        assert operation["summary"] == "Mark Ticket as Duplicate"
        request_body = operation["requestBody"]
        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketDuplicateRequest"

        schema = self._spec()["components"]["schemas"]["TicketDuplicateRequest"]
        assert schema["required"] == [_FIELD]
        assert set(schema["properties"]) == {_FIELD}
        field = schema["properties"][_FIELD]
        assert field["type"] == "string"
        assert "anyOf" not in field
        assert "format" not in field

    def test_responses_declare_detail_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        for code in ("400", "404", "409", "422"):
            assert self._ref_name(responses[code]["content"]) == "ErrorResponse"
        assert "TICKET_SELF_DUPLICATE" in responses["400"]["description"]
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        for code in (
            "TICKET_DUPLICATE_TARGET_DUPLICATED",
            "TICKET_DUPLICATE_CONCURRENT_MODIFICATION",
            "TICKET_NOT_MUTABLE",
        ):
            assert code in responses["409"]["description"]
        assert "VALIDATION_ERROR" in responses["422"]["description"]


# ---------------------------------------------------------------------------
# Locked-current accessibility through HTTP (handler mapping of the
# service's authoritative denial; api-spec.md, flow 3)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIndependentRaces:
    async def test_target_visibility_lost_after_the_preliminary_resolution(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another session commits the target's confidentiality flag after
        the handler's preliminary resolutions of both roots but before the
        service locks them. The service's locked-current denial maps to the
        identical `404 TICKET_NOT_FOUND` with no effect. The service tier
        owns the per-root race matrix; this proves only the handler's
        mapping of that denial."""
        world, committed_client = committed_app
        _, headers = await world.va_headers(role=Role.RESTRICTED_ANALYST)
        source = await world.ticket()
        target = await world.ticket()
        target_id: uuid.UUID = target.id
        before = await ticket_row(await world.session(), source.id)
        original = ticket_service.mark_as_duplicate
        reached: list[bool] = []

        async def _lose_then_call(db: AsyncSession, **kwargs: Any) -> Ticket:
            reached.append(True)
            racer = await world.session()
            await racer.execute(
                update(Ticket)
                .where(Ticket.id == target_id)
                .values(is_confidential=True)
            )
            await racer.commit()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "mark_as_duplicate", _lose_then_call)

        response = await committed_client.post(
            _url(source), json=_body(target), headers=headers
        )
        monkeypatch.undo()

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert reached == [True]
        fresh = await world.session()
        assert await ticket_row(fresh, source.id) == before
        for ticket_id in (source.id, target_id):
            assert await event_count(fresh, ticket_id) == 0
