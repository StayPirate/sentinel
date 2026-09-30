"""End-to-end tests for the Access Grant Management endpoints in
`backend/app/api/v1/tickets.py`: List Access Grants
(`GET /api/v1/tickets/{ticket_id}/access`), Grant Access
(`POST /api/v1/tickets/{ticket_id}/access`), and Revoke Access
(`DELETE /api/v1/tickets/{ticket_id}/access/{user}`).

See docs/features/tickets/tickets.md (Access Grant Management > List Access
Grants, Grant Access, Revoke Access; Response Schemas >
TicketAccessGrantResponse; Endpoint -> Schema Mapping; Confidential
Tickets > Audit Trail), docs/api-spec.md (Authorization Chain Evaluation
Order flows 2 and 3, Response Format, Global Responses, Ticket
Accessibility Check, Manual-Zone Mutability Guard exceptions, Response
Applicability Derivation, User Identifier Resolution and User References in
Responses, JSON Request Body Scalar Types, Undeclared Query Parameters),
docs/features/identity/rbac.md (Predefined Roles; Endpoint Permission Map:
`manage_confidentiality` on all three `/access` rows), and
docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; Ticket Accessibility > Authentication, authorization, and
anti-enumeration, Ticket identifier and read-contract coverage, and
Confidentiality and explicit access grants).

These tests cover only the HTTP boundary, parametrized over the three
endpoints where the contract is shared: authentication, capability before
any Ticket lookup, the identical 404 family (which discloses nothing about
the target user), the confidentiality-before-target precedence as seen
through HTTP, request validation, the complete body of each error mapping,
the success status codes and response shapes (201/200/204, the unpaginated
list), the manual-zone opt-out, one role resolution per request, the
handler mapping of the locked-current denial, and OpenAPI. The service
matrix (every Ticket status, exact event values and no-op classification,
precedence permutations, lock order, rollback, listing statement count and
visibility paths, the grant/revoke, confidentiality, lifecycle, and rename
races, and ATR 15 locked-current accessibility races) is proven once in
`tests/test_services/test_access_grants.py` and
`tests/test_services/test_access_grants_atomicity.py`.

Under the predefined roles `manage_confidentiality` implies scope `all`
(rbac.md, Predefined Roles), so an inaccessible Ticket cannot be produced
for a capability holder through role assignment alone. The accessibility
tests below narrow the request-resolved caller scope to `non_confidential`
(a synthetic caller context standing in for any capability holder without
scope `all`). The converse self-loss case (revoking the caller's own last
visibility path) is reachable only through that synthetic scope as well and
is proven at the service tier only
(`tests/test_services/test_access_grants.py::TestSelfLoss`).

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.core.enums import Role, Scope, TicketStatus
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services import ticket_service, user_service
from tests.support.ticket_api import (
    FORBIDDEN,
    INVALID_LOCATORS,
    MAX_SEQUENCE,
    NOT_FOUND,
    UNAUTHENTICATED,
    CommittedApp,
    committed_app_client,
    event_count,
    locator,
    validation_error,
)
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

Factory = Callable[..., Awaitable[Any]]

GrantRow = tuple[uuid.UUID, uuid.UUID, datetime]
"""A persisted grant as `(user_id, granted_by_id, granted_at)`."""

_NOT_CONFIDENTIAL = {
    "code": "TICKET_NOT_CONFIDENTIAL",
    "detail": "Operation requires a confidential Ticket.",
}
_USER_NOT_FOUND = {"code": "USER_NOT_FOUND", "detail": "User not found."}
_USER_INACTIVE = {"code": "USER_INACTIVE", "detail": "User is inactive."}
"""docs/api-spec.md, error registry; ticket-service.md, Service
Exceptions."""

_PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
_PAST_WIRE = "2026-03-15T10:30:00Z"
_EARLIER = datetime(2026, 2, 1, 9, 0, tzinfo=UTC)
_EARLIER_WIRE = "2026-02-01T09:00:00Z"

_ABSENT_USERNAME = "nobody.qa"
_ANY_USERNAME = "frank.qa"
"""A target for requests that must be rejected before resolution."""


@dataclass(frozen=True, slots=True)
class _Endpoint:
    """One access-grant endpoint."""

    method: str
    service: str
    """The `ticket_service` function the handler delegates to."""
    path: str
    """The OpenAPI path template."""

    @property
    def takes_user(self) -> bool:
        return self.method != "GET"

    def url(self, target: Ticket | str, user: str = _ANY_USERNAME) -> str:
        ticket_id = target if isinstance(target, str) else locator(target)
        return self.path.format(ticket_id=ticket_id, user=user)

    async def send(
        self,
        client: AsyncClient,
        target: Ticket | str,
        user: str = _ANY_USERNAME,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        body = {"user": user} if self.method == "POST" else None
        return await client.request(
            self.method, self.url(target, user), json=body, headers=headers
        )


LIST = _Endpoint("GET", "list_access_grants", "/api/v1/tickets/{ticket_id}/access")
GRANT = _Endpoint("POST", "grant_access", "/api/v1/tickets/{ticket_id}/access")
REVOKE = _Endpoint(
    "DELETE", "revoke_access", "/api/v1/tickets/{ticket_id}/access/{user}"
)
ENDPOINTS = [
    pytest.param(LIST, id="list"),
    pytest.param(GRANT, id="grant"),
    pytest.param(REVOKE, id="revoke"),
]
MUTATIONS = [pytest.param(GRANT, id="grant"), pytest.param(REVOKE, id="revoke")]
_SUCCESS = {"GET": 200, "POST": 201, "DELETE": 204}
"""The ordinary success status of each endpoint (tickets.md)."""


@dataclass(frozen=True, slots=True)
class _World:
    """A confidential Ticket with one existing grant (`grantee`) and one
    active user without a grant (`candidate`)."""

    ticket: Ticket
    grantee: User
    candidate: User

    def target(self, endpoint: _Endpoint) -> str:
        """The username whose effect a successful request would have: a
        revoke deletes `grantee`'s grant, a grant creates `candidate`'s."""
        return self.grantee.username if endpoint is REVOKE else self.candidate.username


async def _person(
    user_factory: Factory,
    username: str,
    *,
    active: bool = True,
    full_name: str | None = None,
) -> User:
    user: User = await user_factory(
        username=username,
        email=f"{username}@example.com",
        active=active,
        full_name=full_name,
    )
    return user


async def _world(
    ticket_factory: Factory,
    user_factory: Factory,
    grant_factory: Factory,
    **ticket_columns: Any,
) -> _World:
    ticket_columns.setdefault("is_confidential", True)
    ticket: Ticket = await ticket_factory(**ticket_columns)
    grantor = await _person(user_factory, "heidi.va", full_name="Heidi Grantor")
    grantee = await _person(user_factory, "ivan.qa", full_name="Ivan Reviewer")
    candidate = await _person(user_factory, "grace.qa", full_name="Grace Tester")
    await grant_factory(
        ticket_id=ticket.id,
        user_id=grantee.id,
        granted_by_id=grantor.id,
        granted_at=_PAST,
    )
    return _World(ticket, grantee, candidate)


async def _grants(db: AsyncSession, ticket_id: uuid.UUID) -> set[GrantRow]:
    """Every persisted grant of the Ticket."""
    rows = await db.execute(
        select(
            TicketAccessGrant.user_id,
            TicketAccessGrant.granted_by_id,
            TicketAccessGrant.granted_at,
        ).where(TicketAccessGrant.ticket_id == ticket_id)
    )
    return {(r.user_id, r.granted_by_id, r.granted_at) for r in rows}


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted Ticket columns these endpoints must never change."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.duplicate_of_id,
                Ticket.is_confidential,
                Ticket.coordinated_release_at,
                Ticket.updated_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return dict(row._mapping)


def _forbid_lookups(
    monkeypatch: pytest.MonkeyPatch, endpoint: _Endpoint
) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the service operation with spies that
    must stay unused."""
    resolver = AsyncMock()
    operation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, endpoint.service, operation)
    return resolver, operation


def _narrow_caller_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every request's caller with scope `non_confidential` while
    keeping its real roles and capabilities (see the module docstring)."""

    def _non_confidential(roles: Iterable[Role]) -> Scope:
        return Scope.NON_CONFIDENTIAL

    monkeypatch.setattr(dependencies, "get_effective_scope", _non_confidential)


def _profile(
    user: User, *, username: str, full_name: str | None, active: bool
) -> dict[str, Any]:
    """The expected `UserSummary` wire object, with the literal values the
    test assigned (docs/api-spec.md, User References in Responses)."""
    return {
        "id": str(user.id),
        "username": username,
        "full_name": full_name,
        "active": active,
    }


def _added(actor: User, username: str) -> EventRow:
    """tickets.md, Confidential Tickets > Audit Trail: `access_grant_added`."""
    return EventRow("access_grant_added", actor.id, None, username, None, None)


def _removed(actor: User, username: str) -> EventRow:
    """tickets.md, Confidential Tickets > Audit Trail: `access_grant_removed`."""
    return EventRow("access_grant_removed", actor.id, username, None, None, None)


def _assert_empty_204(response: httpx.Response) -> None:
    assert response.status_code == 204
    assert response.content == b""
    assert "content-type" not in response.headers


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest_asyncio.fixture
async def va_user(authenticated_user: User, user_role_factory: Factory) -> User:
    """`authenticated_client`'s user holding only `vulnerability_analyst`
    (the predefined holder of `manage_confidentiality`)."""
    await user_role_factory(
        user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
    )
    return authenticated_user


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient]]:
    """`committed_app_client()` plus explicit deletion of committed grants
    before the world's own cleanup (their FKs are `ON DELETE RESTRICT`)."""
    async with committed_app_client(db_session_factory) as (world, committed_client):
        try:
            yield world, committed_client
        finally:
            db = await world.session()
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id.in_(world.ticket_ids)
                )
            )
            await db.commit()


# ---------------------------------------------------------------------------
# Authentication and capability (flow 2 / flow 3, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndCapability:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
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
        endpoint: _Endpoint,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        resolver, operation = _forbid_lookups(monkeypatch, endpoint)

        for path in (target, f"SNTL-{MAX_SEQUENCE}"):
            response = await endpoint.send(client, path, headers=headers)
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        operation.assert_not_awaited()

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param([], id="no-roles"),
            pytest.param([Role.RESTRICTED_ANALYST], id="restricted-analyst"),
            pytest.param([Role.ADMIN], id="admin"),
        ],
    )
    async def test_caller_without_manage_confidentiality_gets_403_before_lookup(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
        endpoint: _Endpoint,
    ) -> None:
        """The same generic 403 for an existing confidential Ticket (whose
        request would otherwise succeed), a missing one, and a malformed
        locator; no lookup, service call, grant write, or event happens."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        before = await _grants(db_session, world.ticket.id)
        resolver, operation = _forbid_lookups(monkeypatch, endpoint)

        responses = [
            await endpoint.send(authenticated_client, path, world.target(endpoint))
            for path in (world.ticket, f"SNTL-{MAX_SEQUENCE}", "not-a-ticket")
        ]

        assert [r.status_code for r in responses] == [403, 403, 403]
        assert len({r.content for r in responses}) == 1
        assert responses[0].json() == FORBIDDEN
        resolver.assert_not_awaited()
        operation.assert_not_awaited()
        assert await _grants(db_session, world.ticket.id) == before
        assert await event_count(db_session, world.ticket.id) == 0

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_roles_are_loaded_once_for_capability_and_scope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await endpoint.send(
            authenticated_client, world.ticket, world.target(endpoint)
        )

        assert response.status_code == _SUCCESS[endpoint.method]
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


_ENDPOINT_TARGETS = [
    pytest.param(LIST, True, id="list"),
    pytest.param(GRANT, True, id="grant-existing-target"),
    pytest.param(GRANT, False, id="grant-absent-target"),
    pytest.param(REVOKE, True, id="revoke-existing-target"),
    pytest.param(REVOKE, False, id="revoke-absent-target"),
]
"""Every endpoint, and for the two mutations both an existing and an absent
target user (List Access Grants has no target)."""


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize(("endpoint", "existing_target"), _ENDPOINT_TARGETS)
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
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        build_locator: Callable[[Ticket], str],
        existing_target: bool,
        endpoint: _Endpoint,
    ) -> None:
        """The Ticket is confidential and the target would be affected by a
        canonical locator; the 404 discloses nothing about the target."""
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        user = world.target(endpoint) if existing_target else _ABSENT_USERNAME
        before = await _state(db_session, world.ticket.id)
        grants = await _grants(db_session, world.ticket.id)

        response = await endpoint.send(
            authenticated_client, build_locator(world.ticket), user
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await _state(db_session, world.ticket.id) == before
        assert await _grants(db_session, world.ticket.id) == grants
        assert await event_count(db_session, world.ticket.id) == 0

    @pytest.mark.parametrize(("endpoint", "existing_target"), _ENDPOINT_TARGETS)
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        existing_target: bool,
        endpoint: _Endpoint,
    ) -> None:
        """A `manage_confidentiality` holder without scope `all` and
        without a visibility path gets the identical 404, whether the
        target user exists or not; the same caller with an explicit grant
        is served, so the denial is the visibility predicate's."""
        _narrow_caller_scope(monkeypatch)
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        user = world.target(endpoint) if existing_target else _ABSENT_USERNAME
        before = await _state(db_session, world.ticket.id)
        grants = await _grants(db_session, world.ticket.id)

        inaccessible = await endpoint.send(authenticated_client, world.ticket, user)
        missing = await endpoint.send(
            authenticated_client, f"SNTL-{MAX_SEQUENCE}", user
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await _state(db_session, world.ticket.id) == before
        assert await _grants(db_session, world.ticket.id) == grants
        assert await event_count(db_session, world.ticket.id) == 0

        await ticket_access_grant_factory(
            ticket_id=world.ticket.id, user_id=va_user.id, granted_by_id=va_user.id
        )
        granted = await endpoint.send(authenticated_client, world.ticket, user)
        if existing_target:
            assert granted.status_code == _SUCCESS[endpoint.method]
        else:
            assert granted.status_code == 404
            assert granted.json() == _USER_NOT_FOUND


# ---------------------------------------------------------------------------
# Confidentiality guard and deferred target resolution (precedence)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestPrecedence:
    @pytest.mark.parametrize(("endpoint", "existing_target"), _ENDPOINT_TARGETS)
    async def test_non_confidential_ticket_is_rejected_whatever_the_target(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        existing_target: bool,
        endpoint: _Endpoint,
    ) -> None:
        """An accessible non-confidential Ticket returns the complete
        `409 TICKET_NOT_CONFIDENTIAL` (never an empty list, a grant, or a
        `USER_NOT_FOUND`) with no effect."""
        ticket: Ticket = await ticket_factory()
        target = await _person(user_factory, "grace.qa", full_name="Grace Tester")
        user = target.username if existing_target else _ABSENT_USERNAME
        before = await _state(db_session, ticket.id)

        response = await endpoint.send(authenticated_client, ticket, user)

        assert response.status_code == 409
        assert response.json() == _NOT_CONFIDENTIAL
        assert await _state(db_session, ticket.id) == before
        assert await _grants(db_session, ticket.id) == set()
        assert await event_count(db_session, ticket.id) == 0

    @pytest.mark.parametrize("endpoint", MUTATIONS)
    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_absent_target_of_an_accessible_confidential_ticket(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        form: str,
        endpoint: _Endpoint,
    ) -> None:
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        user = str(uuid.uuid7()) if form == "uuid" else _ABSENT_USERNAME
        before = await _state(db_session, world.ticket.id)
        grants = await _grants(db_session, world.ticket.id)

        response = await endpoint.send(authenticated_client, world.ticket, user)

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert await _state(db_session, world.ticket.id) == before
        assert await _grants(db_session, world.ticket.id) == grants
        assert await event_count(db_session, world.ticket.id) == 0


# ---------------------------------------------------------------------------
# Request validation (global 422) and the unconstrained `{user}` path
# ---------------------------------------------------------------------------


def _string_type() -> dict[str, Any]:
    return {
        "loc": ["body", "user"],
        "msg": "Input should be a valid string",
        "type": "string_type",
    }


_VALIDATION_CASES = [
    pytest.param(
        {},
        {"loc": ["body", "user"], "msg": "Field required", "type": "missing"},
        id="omitted",
    ),
    pytest.param({"user": None}, _string_type(), id="null"),
    pytest.param({"user": 42}, _string_type(), id="number"),
    pytest.param({"user": True}, _string_type(), id="boolean"),
    pytest.param({"user": {"username": "grace.qa"}}, _string_type(), id="object"),
    pytest.param({"user": ["grace.qa"]}, _string_type(), id="list"),
    pytest.param(
        ["grace.qa"],
        {
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract "
            "fields from",
            "type": "model_attributes_type",
        },
        id="non-object-body",
    ),
]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("body", "error"), _VALIDATION_CASES)
    async def test_invalid_grant_body_returns_the_validation_envelope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        body: Any,
        error: dict[str, Any],
    ) -> None:
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        grants = await _grants(db_session, world.ticket.id)
        operation = AsyncMock()
        monkeypatch.setattr(ticket_service, "grant_access", operation)

        response = await authenticated_client.post(GRANT.url(world.ticket), json=body)

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        operation.assert_not_awaited()
        assert await _grants(db_session, world.ticket.id) == grants
        assert await event_count(db_session, world.ticket.id) == 0

    async def test_absent_grant_body_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)

        response = await authenticated_client.post(GRANT.url(target))

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["body"], "msg": "Field required", "type": "missing"}
        )

    async def test_revoke_path_user_is_any_string_never_a_422(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        """A non-UUID username with `-`, `.`, and `_` is resolved by exact
        username (204, grant removed); a UUID-like but invalid value is
        just an unknown username (`404 USER_NOT_FOUND`), never 422."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        target = await _person(user_factory, "erin-va.qa_2")
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=target.id, granted_by_id=va_user.id
        )

        revoked = await authenticated_client.delete(REVOKE.url(ticket, "erin-va.qa_2"))
        unknown = [
            await authenticated_client.delete(REVOKE.url(ticket, value))
            for value in ("not-a-uuid", "0000-zzzz-1111", "123")
        ]

        _assert_empty_204(revoked)
        assert await _grants(db_session, ticket.id) == set()
        assert [r.status_code for r in unknown] == [404, 404, 404]
        assert all(r.json() == _USER_NOT_FOUND for r in unknown)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _removed(va_user, "erin-va.qa_2")
        ]


# ---------------------------------------------------------------------------
# Grant Access (201 / 200 / 409 USER_INACTIVE)
# ---------------------------------------------------------------------------


def _identifier(user: User, form: str) -> str:
    return str(user.id) if form == "uuid" else user.username


@pytest.mark.e2e
class TestGrantAccess:
    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_new_grant_returns_201_with_the_complete_grant(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        form: str,
    ) -> None:
        """The exact `{"data": grant}` envelope: the target (set
        `full_name`) and the acting grantor (`full_name` `null`) as complete
        current `UserSummary` objects, `granted_at` the UTC creation time;
        one row and one exact `access_grant_added` event."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        target = await _person(user_factory, "grace.qa", full_name="Grace Tester")
        now = (await db_session.execute(select(func.now()))).scalar_one()

        response = await authenticated_client.post(
            GRANT.url(ticket), json={"user": _identifier(target, form)}
        )

        assert response.status_code == 201
        body = response.json()
        assert set(body) == {"data"}
        granted_at = body["data"]["granted_at"]
        assert body == {
            "data": {
                "user": _profile(
                    target, username="grace.qa", full_name="Grace Tester", active=True
                ),
                "granted_at": granted_at,
                "granted_by": _profile(
                    va_user, username=va_user.username, full_name=None, active=True
                ),
            }
        }
        assert va_user.full_name is None
        assert granted_at.endswith("Z")
        assert datetime.fromisoformat(granted_at) == now
        assert await _grants(db_session, ticket.id) == {(target.id, va_user.id, now)}
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _added(va_user, "grace.qa")
        ]

    @pytest.mark.parametrize("form", ["uuid", "username"])
    @pytest.mark.parametrize(
        "active", [pytest.param(True, id="active"), pytest.param(False, id="inactive")]
    )
    async def test_existing_grant_returns_200_with_original_provenance(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        form: str,
        active: bool,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        grantor = await _person(user_factory, "heidi.va", full_name="Heidi Grantor")
        target = await _person(
            user_factory, "ivan.qa", active=active, full_name="Ivan Reviewer"
        )
        await ticket_access_grant_factory(
            ticket_id=ticket.id,
            user_id=target.id,
            granted_by_id=grantor.id,
            granted_at=_PAST,
        )

        response = await authenticated_client.post(
            GRANT.url(ticket), json={"user": _identifier(target, form)}
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "user": _profile(
                    target, username="ivan.qa", full_name="Ivan Reviewer", active=active
                ),
                "granted_at": _PAST_WIRE,
                "granted_by": _profile(
                    grantor,
                    username="heidi.va",
                    full_name="Heidi Grantor",
                    active=True,
                ),
            }
        }
        assert await _grants(db_session, ticket.id) == {(target.id, grantor.id, _PAST)}
        assert await event_count(db_session, ticket.id) == 0

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_inactive_target_without_grant_is_rejected_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        form: str,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        target = await _person(user_factory, "judy.qa", active=False)
        before = await _state(db_session, ticket.id)

        response = await authenticated_client.post(
            GRANT.url(ticket), json={"user": _identifier(target, form)}
        )

        assert response.status_code == 409
        assert response.json() == _USER_INACTIVE
        assert await _state(db_session, ticket.id) == before
        assert await _grants(db_session, ticket.id) == set()
        assert await event_count(db_session, ticket.id) == 0


# ---------------------------------------------------------------------------
# Revoke Access (204, empty body)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRevokeAccess:
    @pytest.mark.parametrize("form", ["uuid", "username"])
    @pytest.mark.parametrize(
        "active", [pytest.param(True, id="active"), pytest.param(False, id="inactive")]
    )
    async def test_effective_revoke_returns_an_empty_204(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        form: str,
        active: bool,
    ) -> None:
        """The row is removed, another user's grant is retained, and one
        exact `access_grant_removed` event exists."""
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        target = await _person(user_factory, "karl.qa", active=active)
        await ticket_access_grant_factory(
            ticket_id=world.ticket.id, user_id=target.id, granted_by_id=va_user.id
        )
        retained = {
            row
            for row in await _grants(db_session, world.ticket.id)
            if row[0] == world.grantee.id
        }

        response = await authenticated_client.delete(
            REVOKE.url(world.ticket, _identifier(target, form))
        )

        _assert_empty_204(response)
        assert await _grants(db_session, world.ticket.id) == retained
        assert await ticket_events_by_id(db_session, world.ticket.id) == [
            _removed(va_user, "karl.qa")
        ]

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_absent_grant_is_an_empty_204_without_event(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        form: str,
    ) -> None:
        world = await _world(ticket_factory, user_factory, ticket_access_grant_factory)
        grants = await _grants(db_session, world.ticket.id)

        response = await authenticated_client.delete(
            REVOKE.url(world.ticket, _identifier(world.candidate, form))
        )

        _assert_empty_204(response)
        assert await _grants(db_session, world.ticket.id) == grants
        assert await event_count(db_session, world.ticket.id) == 0


# ---------------------------------------------------------------------------
# List Access Grants (200, unpaginated, fixed order)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListAccessGrants:
    async def test_complete_current_profiles_in_fixed_order_without_meta(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        """`granted_at ASC, user.id ASC`: two grants share one `granted_at`
        and are inserted in descending UUID order, and the earliest grant is
        inserted last. Deactivated target and grantor are complete with
        `active = false`; another Ticket's grant is not listed; supplied
        `sort_by`/`sort_order`/`page`/`per_page` are ignored."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        other: Ticket = await ticket_factory(is_confidential=True)
        grantee_a = await _person(user_factory, "grantee-a", full_name="Grantee A")
        grantee_b = await _person(user_factory, "grantee-b")
        grantee_c = await _person(
            user_factory, "grantee-c", active=False, full_name="Grantee C"
        )
        granter_x = await _person(user_factory, "granter-x", full_name="Granter X")
        granter_y = await _person(user_factory, "granter-y", active=False)
        low, high = sorted((grantee_a, grantee_b), key=lambda u: u.id)
        for grantee in (high, low):
            await ticket_access_grant_factory(
                ticket_id=ticket.id,
                user_id=grantee.id,
                granted_by_id=granter_y.id,
                granted_at=_PAST,
            )
        await ticket_access_grant_factory(
            ticket_id=ticket.id,
            user_id=grantee_c.id,
            granted_by_id=granter_x.id,
            granted_at=_EARLIER,
        )
        await ticket_access_grant_factory(ticket_id=other.id, user_id=grantee_a.id)

        response = await authenticated_client.get(LIST.url(ticket))
        reordered = await authenticated_client.get(
            LIST.url(ticket),
            params={
                "sort_by": "granted_at",
                "sort_order": "desc",
                "page": "2",
                "per_page": "1",
            },
        )

        profiles = {
            grantee_a.id: _profile(
                grantee_a, username="grantee-a", full_name="Grantee A", active=True
            ),
            grantee_b.id: _profile(
                grantee_b, username="grantee-b", full_name=None, active=True
            ),
        }
        by_y = _profile(granter_y, username="granter-y", full_name=None, active=False)
        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "user": _profile(
                        grantee_c,
                        username="grantee-c",
                        full_name="Grantee C",
                        active=False,
                    ),
                    "granted_at": _EARLIER_WIRE,
                    "granted_by": _profile(
                        granter_x,
                        username="granter-x",
                        full_name="Granter X",
                        active=True,
                    ),
                },
                {
                    "user": profiles[low.id],
                    "granted_at": _PAST_WIRE,
                    "granted_by": by_y,
                },
                {
                    "user": profiles[high.id],
                    "granted_at": _PAST_WIRE,
                    "granted_by": by_y,
                },
            ]
        }
        assert reordered.status_code == 200
        assert reordered.content == response.content
        assert await event_count(db_session, ticket.id) == 0

    async def test_accessible_confidential_ticket_without_grants_is_empty(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory()

        response = await authenticated_client.get(LIST.url(ticket))

        assert response.status_code == 200
        assert response.json() == {"data": []}


# ---------------------------------------------------------------------------
# Manual-zone opt-out (api-spec.md, Manual-Zone Mutability Guard exceptions)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestManualZone:
    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_every_endpoint_succeeds_without_changing_the_ticket(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        status: TicketStatus,
    ) -> None:
        """List, grant, and revoke succeed on a confidential manual-zone
        Ticket, never `409 TICKET_NOT_MUTABLE`; the Ticket stays in its
        status, unassigned, with its duplicate link and flag."""
        world = await _world(
            ticket_factory,
            user_factory,
            ticket_access_grant_factory,
            status=status.value,
        )
        before = await _state(db_session, world.ticket.id)

        listed = await authenticated_client.get(LIST.url(world.ticket))
        granted = await authenticated_client.post(
            GRANT.url(world.ticket), json={"user": world.candidate.username}
        )
        revoked = await authenticated_client.delete(
            REVOKE.url(world.ticket, world.grantee.username)
        )

        assert listed.status_code == 200
        assert [item["user"]["username"] for item in listed.json()["data"]] == [
            "ivan.qa"
        ]
        assert granted.status_code == 201
        _assert_empty_204(revoked)
        after = await _state(db_session, world.ticket.id)
        keys = ("status", "assignee_id", "duplicate_of_id", "is_confidential")
        assert {k: after[k] for k in keys} == {k: before[k] for k in keys}
        assert after["status"] == status.value
        assert after["assignee_id"] is None
        assert await ticket_events_by_id(db_session, world.ticket.id) == [
            _added(va_user, "grace.qa"),
            _removed(va_user, "ivan.qa"),
        ]


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    @staticmethod
    def _spec() -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self, endpoint: _Endpoint) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][endpoint.path][
            endpoint.method.lower()
        ]
        return operation

    def _schema(self, name: str) -> dict[str, Any]:
        schema: dict[str, Any] = self._spec()["components"]["schemas"][name]
        return schema

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_operations_exist_with_their_methods_and_paths(self) -> None:
        paths = self._spec()["paths"]

        assert set(paths[LIST.path]) >= {"get", "post"}
        assert "delete" not in paths[LIST.path]
        assert set(paths[REVOKE.path]) == {"delete"}
        for endpoint, summary in (
            (LIST, "List Access Grants"),
            (GRANT, "Grant Access"),
            (REVOKE, "Revoke Access"),
        ):
            operation = self._operation(endpoint)
            assert operation["tags"] == ["Tickets"]
            assert operation["summary"] == summary

    @pytest.mark.parametrize(
        ("endpoint", "codes"),
        [
            pytest.param(LIST, {"200", "404", "409", "422"}, id="list"),
            pytest.param(GRANT, {"200", "201", "404", "409", "422"}, id="grant"),
            pytest.param(REVOKE, {"204", "404", "409", "422"}, id="revoke"),
        ],
    )
    def test_documented_responses(self, endpoint: _Endpoint, codes: set[str]) -> None:
        responses = self._operation(endpoint)["responses"]

        assert set(responses) == codes
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_CONFIDENTIAL" in responses["409"]["description"]
        assert ("USER_NOT_FOUND" in responses["404"]["description"]) is (
            endpoint.takes_user
        )
        assert ("USER_INACTIVE" in responses["409"]["description"]) is (
            endpoint is GRANT
        )
        assert not any(
            "TICKET_NOT_MUTABLE" in response.get("description", "")
            for response in responses.values()
        )

    def test_success_bodies_expose_the_grant_without_a_ticket_identity(self) -> None:
        grant_responses = self._operation(GRANT)["responses"]
        for code in ("200", "201"):
            assert (
                self._ref_name(grant_responses[code]["content"])
                == "TicketAccessGrantDataResponse"
            )
        list_ok = self._operation(LIST)["responses"]["200"]
        assert self._ref_name(list_ok["content"]) == "TicketAccessGrantListResponse"
        assert "content" not in self._operation(REVOKE)["responses"]["204"]

        data_envelope = self._schema("TicketAccessGrantDataResponse")
        assert set(data_envelope["properties"]) == {"data"}
        list_envelope = self._schema("TicketAccessGrantListResponse")
        assert set(list_envelope["properties"]) == {"data"}
        items = list_envelope["properties"]["data"]
        assert items["type"] == "array"
        assert items["items"]["$ref"].endswith("/TicketAccessGrantResponse")

        grant = self._schema("TicketAccessGrantResponse")
        assert set(grant["properties"]) == {"user", "granted_at", "granted_by"}
        assert set(grant["required"]) == {"user", "granted_at", "granted_by"}
        assert grant["properties"]["granted_at"]["format"] == "date-time"
        for field in ("user", "granted_by"):
            assert grant["properties"][field]["$ref"].endswith("/UserReference")
        user_reference = self._schema("UserReference")
        assert set(user_reference["properties"]) == {
            "id",
            "username",
            "full_name",
            "active",
        }

    def test_grant_request_requires_a_non_nullable_string_user(self) -> None:
        request_body = self._operation(GRANT)["requestBody"]

        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketAccessGrantRequest"
        schema = self._schema("TicketAccessGrantRequest")
        assert schema["required"] == ["user"]
        assert set(schema["properties"]) == {"user"}
        user = schema["properties"]["user"]
        assert user["type"] == "string"
        assert "anyOf" not in user
        assert "format" not in user

    def test_list_declares_fixed_order_and_no_pagination_or_sort_parameters(
        self,
    ) -> None:
        operation = self._operation(LIST)

        assert "requestBody" not in operation
        assert [p["name"] for p in operation["parameters"]] == ["ticket_id"]
        description = operation["description"]
        assert "Unpaginated" in description
        assert "`meta`" in description
        assert "`granted_at` ascending then user UUID ascending" in description

    def test_revoke_user_path_parameter_is_an_unconstrained_string(self) -> None:
        operation = self._operation(REVOKE)

        assert "requestBody" not in operation
        parameters = {p["name"]: p for p in operation["parameters"]}
        assert set(parameters) == {"ticket_id", "user"}
        user = parameters["user"]
        assert (user["in"], user["required"]) == ("path", True)
        schema = user["schema"]
        assert schema["type"] == "string"
        for constraint in ("format", "pattern", "minLength", "maxLength", "anyOf"):
            assert constraint not in schema


# ---------------------------------------------------------------------------
# Locked-current accessibility through HTTP (handler mapping of the
# service's authoritative denial; api-spec.md, flows 2 and 3)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIndependentRaces:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_visibility_lost_to_a_committed_revoke_after_the_preliminary_check(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        """A capability holder without scope `all` (see the module
        docstring) passes the preliminary check through its explicit grant;
        another session then commits the deletion of that grant before the
        service's authoritative selection or lock. The denial maps to the
        identical `404 TICKET_NOT_FOUND` with no effect: the list is not
        returned, `candidate` is not granted, and `grantee`'s grant is not
        revoked. The service tier owns the race matrix (ATR 15, ATR 16);
        this proves only the handler's mapping of that denial."""
        _narrow_caller_scope(monkeypatch)
        world, committed_client = committed_app
        caller, headers = await world.va_headers()
        grantee = await world.user(role=None)
        candidate = await world.user(role=None)
        target = await world.ticket(is_confidential=True)
        ticket_id = target.id
        db = await world.session()
        db.add_all(
            TicketAccessGrant(
                ticket_id=ticket_id, user_id=user.id, granted_by_id=caller.id
            )
            for user in (caller, grantee)
        )
        await db.commit()
        setup = await world.session()
        before = await _state(setup, ticket_id)
        retained = {
            row for row in await _grants(setup, ticket_id) if row[0] == grantee.id
        }
        await setup.rollback()
        original = getattr(ticket_service, endpoint.service)
        reached: list[bool] = []

        async def _lose_then_call(db: AsyncSession, **kwargs: Any) -> Any:
            reached.append(True)
            racer = await world.session()
            await racer.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket_id,
                    TicketAccessGrant.user_id == caller.id,
                )
            )
            await racer.commit()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, endpoint.service, _lose_then_call)
        user = grantee.username if endpoint is REVOKE else candidate.username

        response = await endpoint.send(committed_client, target, user, headers=headers)

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert reached == [True]
        fresh = await world.session()
        assert await _state(fresh, ticket_id) == before
        # Only the racer's own deletion is committed.
        assert await _grants(fresh, ticket_id) == retained
        assert await event_count(fresh, ticket_id) == 0
