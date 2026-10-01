"""End-to-end tests for the Ticket reference endpoints in
`backend/app/api/v1/ticket_references.py`: List References
(`GET /api/v1/tickets/{ticket_id}/references`), Add Reference
(`POST /api/v1/tickets/{ticket_id}/references`), Update Reference
(`PATCH /api/v1/tickets/{ticket_id}/references/{reference_id}`), and Delete
Reference (`DELETE /api/v1/tickets/{ticket_id}/references/{reference_id}`).

See docs/features/tickets/ticket-references.md (API Schemas, API Endpoints,
Manual-Zone Exception, Service Exceptions, Security and Privacy),
docs/api-spec.md (Optional Authentication on Public Endpoints,
Authorization Chain Evaluation Order flows 1 and 3, Undeclared Query
Parameters, Query Parameter Length Limit, JSON Request Body Scalar Types,
Enum Filter Validation, Response Format, Global Responses, Ticket
Accessibility Check, Manual-Zone Mutability Guard exceptions, Response
Applicability Derivation, Ticket Identifier Resolution, Partial Update
Semantics), docs/features/identity/rbac.md (Predefined Roles; Endpoint
Permission Map > Ticket References), and
docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; Ticket References; Ticket Accessibility > Authentication,
authorization, and anti-enumeration and Ticket identifier and
read-contract coverage).

These tests cover only the HTTP boundary: authentication (optional on the
read, mandatory on the mutations), `manage_references` before any lookup
and before request validation, the identical `TICKET_NOT_FOUND` family and
the identical nested `RESOURCE_NOT_FOUND`, each error mapping with its
complete body, the global `422 VALIDATION_ERROR` bodies of the transport
schemas (which never echo the submitted URL), the handler's mapping of
omitted versus `null` fields, the success envelopes (201/200/204 and the
unpaginated fixed-order list), the read filters and ignored undeclared
parameters, accessibility as observed through HTTP, the manual-zone
opt-out, one role resolution per request, the acting user of the audit
events, an equivalent PATCH across independently committed requests, and
OpenAPI. The service matrix (every field state and Ticket status, exact
audit payloads and event order, guard precedence permutations, lock order,
rollback, and the manual/manual and manual/automatic races) is proven once
in `tests/test_services/test_reference_service.py` and
`tests/test_services/test_reference_service_atomicity.py`; the URL boundary
itself in `tests/test_core/test_reference_urls.py`.

`restricted_analyst` holds `manage_references` with scope
`non_confidential` (rbac.md, Predefined Roles), so it is a real capability
holder without visibility of a confidential Ticket: no synthetic caller
scope is needed.

Expected values are transcribed from the specifications, never computed
with the module under test. Error `detail` strings, which the
specification leaves to the implementation, are transcribed from the
handler.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.models.user import User
from app.services import reference_service, user_service
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
    ticket_row,
    validation_error,
)
from tests.support.ticket_mutations import ticket_events_by_id

Factory = Callable[..., Awaitable[Any]]

_REFERENCE_NOT_FOUND: Final = (
    b'{"code":"RESOURCE_NOT_FOUND","detail":"Resource not found."}'
)
_NOT_EDITABLE: Final = {
    "code": "RESOURCE_NOT_EDITABLE",
    "detail": "Reference is not editable.",
}
_CONFLICT: Final = {
    "code": "RESOURCE_CONFLICT",
    "detail": "Another reference already uses this URL on the Ticket.",
}
"""ticket-references.md, Service Exceptions; `detail` from the handler."""

_AUTOMATIC_SOURCE: Final = "sync_nvd_cves"
"""A stable fetcher name owning an automatic reference (data-sources.md)."""

_MALFORMED_UUID_ERROR: Final = {
    "loc": ["path", "reference_id"],
    "msg": "Input should be a valid UUID, invalid character: found `n` at 1",
    "type": "uuid_parsing",
}

ReferenceRow = tuple[Any, ...]
"""A persisted reference as `(id, url, title, description, type, source,
created_at, updated_at)`."""


@dataclass(frozen=True, slots=True)
class _Endpoint:
    """One Ticket reference endpoint."""

    method: str
    service: str
    """The `reference_service` function the handler delegates to."""
    path: str
    """The OpenAPI path template."""
    default_body: dict[str, Any] | None
    """A valid request body whose effect a canonical request would have."""

    @property
    def takes_reference(self) -> bool:
        return "{reference_id}" in self.path

    def url(self, target: Ticket | str, reference: uuid.UUID | str = "") -> str:
        ticket_id = target if isinstance(target, str) else locator(target)
        return self.path.format(ticket_id=ticket_id, reference_id=reference)

    async def send(
        self,
        client: AsyncClient,
        target: Ticket | str,
        reference: uuid.UUID | str = "",
        *,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await client.request(
            self.method,
            self.url(target, reference),
            json=self.default_body if body is None else body,
            headers=headers,
        )


_COLLECTION = "/api/v1/tickets/{ticket_id}/references"
_ITEM = "/api/v1/tickets/{ticket_id}/references/{reference_id}"
LIST = _Endpoint("GET", "list_references", _COLLECTION, None)
ADD = _Endpoint(
    "POST",
    "create_reference",
    _COLLECTION,
    {"url": "https://advisories.example.test/entries/77"},
)
UPDATE = _Endpoint(
    "PATCH", "update_reference", _ITEM, {"title": "Fictional updated title"}
)
DELETE = _Endpoint("DELETE", "delete_reference", _ITEM, None)
ENDPOINTS = [
    pytest.param(LIST, id="list"),
    pytest.param(ADD, id="add"),
    pytest.param(UPDATE, id="update"),
    pytest.param(DELETE, id="delete"),
]
MUTATIONS = [
    pytest.param(ADD, id="add"),
    pytest.param(UPDATE, id="update"),
    pytest.param(DELETE, id="delete"),
]
NESTED = [pytest.param(UPDATE, id="update"), pytest.param(DELETE, id="delete")]
_SUCCESS = {"GET": 200, "POST": 201, "PATCH": 200, "DELETE": 204}
"""The success status of each endpoint (ticket-references.md)."""


async def _references(db: AsyncSession, ticket_id: uuid.UUID) -> set[ReferenceRow]:
    """Every persisted reference of the Ticket."""
    rows = await db.execute(
        select(
            TicketReference.id,
            TicketReference.url,
            TicketReference.title,
            TicketReference.description,
            TicketReference.type,
            TicketReference.source,
            TicketReference.created_at,
            TicketReference.updated_at,
        ).where(TicketReference.ticket_id == ticket_id)
    )
    return {tuple(row) for row in rows}


def _forbid_service(monkeypatch: pytest.MonkeyPatch) -> list[AsyncMock]:
    """Replace every reference service operation with a spy that must stay
    unused."""
    spies = []
    for name in (
        "list_references",
        "create_reference",
        "update_reference",
        "delete_reference",
    ):
        spy = AsyncMock()
        monkeypatch.setattr(reference_service, name, spy)
        spies.append(spy)
    return spies


def _assert_unused(spies: list[AsyncMock]) -> None:
    for spy in spies:
        spy.assert_not_awaited()


def _assert_empty_204(response: httpx.Response) -> None:
    assert response.status_code == 204
    assert response.content == b""
    assert "content-type" not in response.headers


def _wire(instant: datetime) -> str:
    """The UTC `Z` wire form of a whole-second instant."""
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.fixture
def assign(
    authenticated_user: User, user_role_factory: Factory
) -> Callable[..., Awaitable[User]]:
    """Give `authenticated_client`'s user the listed roles."""

    async def _assign(*roles: Role) -> User:
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        return authenticated_user

    return _assign


@pytest_asyncio.fixture
async def va_user(assign: Callable[..., Awaitable[User]]) -> User:
    """`authenticated_client`'s user holding only `vulnerability_analyst`
    (`manage_references`, scope `all`)."""
    return await assign(Role.VULNERABILITY_ANALYST)


@pytest_asyncio.fixture
async def ra_user(assign: Callable[..., Awaitable[User]]) -> User:
    """`authenticated_client`'s user holding only `restricted_analyst`
    (`manage_references`, scope `non_confidential`)."""
    return await assign(Role.RESTRICTED_ANALYST)


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient]]:
    """`committed_app_client()`; committed references are removed with
    their Tickets (`ON DELETE CASCADE`)."""
    async with committed_app_client(db_session_factory) as (world, committed_client):
        yield world, committed_client


# ---------------------------------------------------------------------------
# Authentication (flow 1 step 1, flow 3 step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthentication:
    @pytest.mark.parametrize("endpoint", MUTATIONS)
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="anonymous"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_mutation_without_valid_credential_returns_401_before_lookup(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
        endpoint: _Endpoint,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        before = await _references(db_session, ticket.id)
        spies = _forbid_service(monkeypatch)

        for path in (ticket, f"SNTL-{MAX_SEQUENCE}"):
            response = await endpoint.send(client, path, reference.id, headers=headers)
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        _assert_unused(spies)
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

    async def test_list_with_invalid_credential_returns_401_before_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A selected invalid optional credential never falls back to
        anonymous access, even for a non-confidential Ticket."""
        ticket: Ticket = await ticket_factory()
        spies = _forbid_service(monkeypatch)

        for path in (locator(ticket), "not-a-ticket"):
            response = await LIST.send(
                client, path, headers={"Authorization": "Bearer invalid-token"}
            )
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        _assert_unused(spies)

    async def test_anonymous_list_of_a_non_confidential_ticket(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)

        response = await LIST.send(client, ticket)

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["data"]] == [str(reference.id)]


# ---------------------------------------------------------------------------
# Capability before lookup and before request validation (flow 3 step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCapability:
    @pytest.mark.parametrize("endpoint", MUTATIONS)
    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_manage_references_gets_the_generic_403(
        self,
        authenticated_client: AsyncClient,
        assign: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
        endpoint: _Endpoint,
    ) -> None:
        """The same generic 403 for an existing accessible Ticket (whose
        request would otherwise succeed), a missing Ticket, a malformed
        locator, an invalid request body, and a malformed reference UUID;
        no service call, row write, or event happens. Admin's scope `all`
        makes the Ticket visible without granting the capability."""
        await assign(*roles)
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        before = await _references(db_session, ticket.id)
        spies = _forbid_service(monkeypatch)
        invalid_body = {"POST": {"url": 5}, "PATCH": {}}.get(endpoint.method)

        responses = [
            await endpoint.send(authenticated_client, path, reference.id)
            for path in (ticket, f"SNTL-{MAX_SEQUENCE}", "not-a-ticket")
        ]
        if invalid_body is not None:
            responses.append(
                await endpoint.send(
                    authenticated_client, ticket, reference.id, body=invalid_body
                )
            )
        if endpoint.takes_reference:
            responses.append(
                await endpoint.send(authenticated_client, ticket, "not-a-uuid")
            )

        assert {r.status_code for r in responses} == {403}
        assert len({r.content for r in responses}) == 1
        assert responses[0].json() == FORBIDDEN
        _assert_unused(spies)
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

    async def test_visibility_without_capability_reads_but_cannot_write(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        """A role-less user with an explicit grant reads the confidential
        Ticket's references but receives the generic 403 for a write."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )

        listed = await LIST.send(authenticated_client, ticket)
        added = await ADD.send(authenticated_client, ticket)

        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()["data"]] == [str(reference.id)]
        assert added.status_code == 403
        assert added.json() == FORBIDDEN
        assert await event_count(db_session, ticket.id) == 0


@pytest.mark.e2e
class TestRolesResolvedOnce:
    @pytest.mark.parametrize(
        "endpoint", [pytest.param(LIST, id="list"), pytest.param(ADD, id="add")]
    )
    async def test_roles_are_loaded_once_for_capability_and_scope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await endpoint.send(authenticated_client, ticket)

        assert response.status_code == _SUCCESS[endpoint.method]
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# Ticket identifier resolution and accessibility (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
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
        ticket_reference_factory: Factory,
        build_locator: Callable[[Ticket], str],
        endpoint: _Endpoint,
    ) -> None:
        """The reference exists under the Ticket, so a canonical locator
        would succeed; every other form returns the same complete 404."""
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        before = await _references(db_session, ticket.id)

        response = await endpoint.send(
            authenticated_client, build_locator(ticket), reference.id
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        ticket_access_grant_factory: Factory,
        endpoint: _Endpoint,
    ) -> None:
        """A `manage_references` holder without a visibility path gets the
        identical 404 with no effect; the capability does not make the
        Ticket visible. The same caller with an explicit grant is served,
        so the denial is the visibility predicate's."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        before = await _references(db_session, ticket.id)

        inaccessible = await endpoint.send(authenticated_client, ticket, reference.id)
        missing = await endpoint.send(
            authenticated_client, f"SNTL-{MAX_SEQUENCE}", reference.id
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=ra_user.id)
        granted = await endpoint.send(authenticated_client, ticket, reference.id)
        assert granted.status_code == _SUCCESS[endpoint.method]

    async def test_anonymous_list_of_a_confidential_ticket_is_the_identical_404(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_reference_factory(ticket_id=ticket.id)

        inaccessible = await LIST.send(client, ticket)
        missing = await LIST.send(client, f"SNTL-{MAX_SEQUENCE}")

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND


# ---------------------------------------------------------------------------
# Nested reference resolution (RESOURCE_NOT_FOUND after parent accessibility)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestReferenceNotFound:
    @pytest.mark.parametrize("endpoint", NESTED)
    async def test_unknown_and_wrong_parent_references_share_one_404(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        endpoint: _Endpoint,
    ) -> None:
        """A reference of another accessible Ticket is not found under the
        path Ticket, exactly like an unknown UUID; neither leaks the actual
        parent, and neither Ticket changes."""
        ticket: Ticket = await ticket_factory()
        other: Ticket = await ticket_factory()
        await ticket_reference_factory(ticket_id=ticket.id)
        foreign = await ticket_reference_factory(ticket_id=other.id)
        before = await _references(db_session, ticket.id)
        before_other = await _references(db_session, other.id)

        wrong_parent = await endpoint.send(authenticated_client, ticket, foreign.id)
        unknown = await endpoint.send(authenticated_client, ticket, uuid.uuid7())

        assert wrong_parent.status_code == unknown.status_code == 404
        assert wrong_parent.content == unknown.content == _REFERENCE_NOT_FOUND
        assert await _references(db_session, ticket.id) == before
        assert await _references(db_session, other.id) == before_other
        assert await event_count(db_session, ticket.id) == 0
        assert await event_count(db_session, other.id) == 0

    @pytest.mark.parametrize("endpoint", NESTED)
    async def test_inaccessible_parent_precedes_the_nested_lookup(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        endpoint: _Endpoint,
    ) -> None:
        """Under an inaccessible parent, a wrong-parent and an unknown
        reference both return `TICKET_NOT_FOUND`, never
        `RESOURCE_NOT_FOUND`."""
        hidden: Ticket = await ticket_factory(is_confidential=True)
        visible: Ticket = await ticket_factory()
        foreign = await ticket_reference_factory(ticket_id=visible.id)
        before = await _references(db_session, visible.id)

        responses = [
            await endpoint.send(authenticated_client, hidden, reference_id)
            for reference_id in (foreign.id, uuid.uuid7())
        ]

        assert [r.status_code for r in responses] == [404, 404]
        assert {r.content for r in responses} == {NOT_FOUND}
        assert await _references(db_session, visible.id) == before
        assert await event_count(db_session, visible.id) == 0

    @pytest.mark.parametrize("endpoint", NESTED)
    async def test_malformed_reference_uuid_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        spies = _forbid_service(monkeypatch)

        response = await endpoint.send(authenticated_client, ticket, "not-a-uuid")

        assert response.status_code == 422
        assert response.json() == validation_error(_MALFORMED_UUID_ERROR)
        _assert_unused(spies)


# ---------------------------------------------------------------------------
# Domain error mappings (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestErrorMappings:
    @pytest.mark.parametrize("endpoint", NESTED)
    async def test_automatic_reference_is_not_editable(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        endpoint: _Endpoint,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        automatic = await ticket_reference_factory(
            ticket_id=ticket.id,
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-3317",
            title="NVD",
            type="advisory",
            source=_AUTOMATIC_SOURCE,
        )
        before = await _references(db_session, ticket.id)

        response = await endpoint.send(authenticated_client, ticket, automatic.id)

        assert response.status_code == 409
        assert response.json() == _NOT_EDITABLE
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

    @pytest.mark.parametrize("owner", ["manual", _AUTOMATIC_SOURCE])
    async def test_add_of_a_normalized_duplicate_conflicts(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        owner: str,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_reference_factory(
            ticket_id=ticket.id, url="https://example.com", source=owner
        )
        before = await _references(db_session, ticket.id)

        response = await ADD.send(
            authenticated_client, ticket, body={"url": "HTTP://Example.COM/"}
        )

        assert response.status_code == 409
        assert response.json() == _CONFLICT
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

    async def test_update_to_another_references_normalized_url_conflicts(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_reference_factory(
            ticket_id=ticket.id, url="https://example.com/advisory"
        )
        moved = await ticket_reference_factory(
            ticket_id=ticket.id, url="https://example.com/other"
        )
        before = await _references(db_session, ticket.id)

        response = await UPDATE.send(
            authenticated_client,
            ticket,
            moved.id,
            body={"url": "http://EXAMPLE.com/advisory", "title": "Moved"},
        )

        assert response.status_code == 409
        assert response.json() == _CONFLICT
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0


# ---------------------------------------------------------------------------
# Request validation (global 422)
# ---------------------------------------------------------------------------

_HOST = "https://example.com"
_TOO_LONG_RAW = "https://example.com/" + "a" * 2029
"""2049 characters before normalization."""
_TOO_LONG_NORMALIZED = "http://example.com/" + "a" * 2029
"""Exactly 2048 characters, 2049 after the `https` upgrade."""


def _error(field: str | None, msg: str, type_: str) -> dict[str, Any]:
    loc: list[str] = ["body"] if field is None else ["body", field]
    return {"loc": loc, "msg": msg, "type": type_}


def _string_type(field: str) -> dict[str, Any]:
    return _error(field, "Input should be a valid string", "string_type")


def _url_error(message: str) -> dict[str, Any]:
    return _error("url", f"Value error, {message}", "value_error")


_TYPE_ERROR = _error(
    "type", "Input should be 'advisory', 'patch', 'issue' or 'article'", "literal_error"
)
_WHITESPACE = "Value error, Value must not be whitespace-only."

_COMMON_FIELD_CASES = [
    pytest.param(
        {"url": "ftp://example.com/file"},
        _url_error("URL scheme must be http or https."),
        id="url-scheme",
    ),
    pytest.param(
        {"url": "https://fictional-user:fictional-secret@example.com/"},
        _url_error("URL must not contain user information."),
        id="url-userinfo-password",
    ),
    pytest.param(
        {"url": "https://fictional-user@example.com/"},
        _url_error("URL must not contain user information."),
        id="url-userinfo-username",
    ),
    pytest.param(
        {"url": "https://example.com/\x07path"},
        _url_error("URL must not contain control characters."),
        id="url-control-character",
    ),
    pytest.param(
        {"url": "https:///path"},
        _url_error("URL must have a valid host."),
        id="url-no-host",
    ),
    pytest.param(
        {"url": "example.com/path"},
        _url_error("URL must be a well-formed absolute URL."),
        id="url-relative",
    ),
    pytest.param(
        {"url": _TOO_LONG_RAW},
        _error("url", "String should have at most 2048 characters", "string_too_long"),
        id="url-2049",
    ),
    pytest.param(
        {"url": _TOO_LONG_NORMALIZED},
        _url_error("URL must be at most 2048 characters."),
        id="url-2049-after-normalization",
    ),
    pytest.param({"url": 2048}, _string_type("url"), id="url-number"),
    pytest.param({"url": True}, _string_type("url"), id="url-boolean"),
    pytest.param({"url": {"href": _HOST}}, _string_type("url"), id="url-object"),
    pytest.param(
        {"title": ""},
        _error("title", "String should have at least 1 character", "string_too_short"),
        id="title-empty",
    ),
    pytest.param(
        {"title": "   "}, _error("title", _WHITESPACE, "value_error"), id="title-blank"
    ),
    pytest.param(
        {"title": "t" * 501},
        _error("title", "String should have at most 500 characters", "string_too_long"),
        id="title-501",
    ),
    pytest.param({"title": 7}, _string_type("title"), id="title-number"),
    pytest.param(
        {"description": ""},
        _error(
            "description", "String should have at least 1 character", "string_too_short"
        ),
        id="description-empty",
    ),
    pytest.param(
        {"description": "\t \n"},
        _error("description", _WHITESPACE, "value_error"),
        id="description-blank",
    ),
    pytest.param(
        {"description": "d" * 2001},
        _error(
            "description",
            "String should have at most 2000 characters",
            "string_too_long",
        ),
        id="description-2001",
    ),
    pytest.param(
        {"description": ["text"]}, _string_type("description"), id="description-list"
    ),
    pytest.param({"type": "Patch"}, _TYPE_ERROR, id="type-wrong-case"),
    pytest.param({"type": "blog"}, _TYPE_ERROR, id="type-unknown"),
    pytest.param({"type": 1}, _TYPE_ERROR, id="type-number"),
]
"""Invalid field values shared by both schemas; each POST case adds a valid
`url` unless it tests `url` itself."""


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("fields", "error"), _COMMON_FIELD_CASES)
    async def test_invalid_add_field_returns_the_validation_envelope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        fields: dict[str, Any],
        error: dict[str, Any],
    ) -> None:
        ticket: Ticket = await ticket_factory()
        spies = _forbid_service(monkeypatch)

        response = await ADD.send(
            authenticated_client, ticket, body={"url": _HOST} | fields
        )

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        _assert_unused(spies)
        assert await _references(db_session, ticket.id) == set()
        assert await event_count(db_session, ticket.id) == 0

    @pytest.mark.parametrize(
        ("body", "error"),
        [
            pytest.param(
                {"title": "Fictional title"},
                _error("url", "Field required", "missing"),
                id="url-omitted",
            ),
            pytest.param({"url": None}, _string_type("url"), id="url-null"),
            pytest.param(
                [_HOST],
                _error(
                    None,
                    "Input should be a valid dictionary or object to extract fields "
                    "from",
                    "model_attributes_type",
                ),
                id="non-object-body",
            ),
        ],
    )
    async def test_add_requires_a_non_null_url_in_an_object_body(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        body: Any,
        error: dict[str, Any],
    ) -> None:
        ticket: Ticket = await ticket_factory()
        spies = _forbid_service(monkeypatch)

        response = await ADD.send(authenticated_client, ticket, body=body)

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        _assert_unused(spies)
        assert await _references(db_session, ticket.id) == set()

    async def test_absent_add_body_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()

        response = await authenticated_client.post(ADD.url(ticket))

        assert response.status_code == 422
        assert response.json() == validation_error(
            _error(None, "Field required", "missing")
        )

    @pytest.mark.parametrize(("fields", "error"), _COMMON_FIELD_CASES)
    async def test_invalid_update_field_returns_the_validation_envelope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        fields: dict[str, Any],
        error: dict[str, Any],
    ) -> None:
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        before = await _references(db_session, ticket.id)
        spies = _forbid_service(monkeypatch)

        response = await UPDATE.send(
            authenticated_client, ticket, reference.id, body=fields
        )

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        _assert_unused(spies)
        assert await _references(db_session, ticket.id) == before
        assert await event_count(db_session, ticket.id) == 0

    @pytest.mark.parametrize(
        ("body", "error"),
        [
            pytest.param(
                {},
                _error(
                    None,
                    "Value error, At least one field must be provided.",
                    "value_error",
                ),
                id="empty-object",
            ),
            pytest.param(
                {"url": None},
                _url_error("url cannot be null."),
                id="url-null",
            ),
        ],
    )
    async def test_update_rejects_an_empty_object_and_a_null_url(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        body: dict[str, Any],
        error: dict[str, Any],
    ) -> None:
        """ticket-references.md, TicketReferenceUpdate; api-spec.md,
        Partial Update Semantics (the empty-object message)."""
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        before = await _references(db_session, ticket.id)
        spies = _forbid_service(monkeypatch)

        response = await UPDATE.send(
            authenticated_client, ticket, reference.id, body=body
        )

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        if not body:
            (only,) = response.json()["errors"]
            assert "At least one field must be provided." in only["msg"]
        _assert_unused(spies)
        assert await _references(db_session, ticket.id) == before

    @pytest.mark.parametrize(
        "endpoint", [pytest.param(ADD, id="add"), pytest.param(UPDATE, id="update")]
    )
    async def test_rejected_url_is_never_echoed(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        endpoint: _Endpoint,
    ) -> None:
        """ticket-references.md, Security and Privacy: the 422 body carries
        no part of a credential-bearing or overlength submitted URL."""
        ticket: Ticket = await ticket_factory()
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        submitted = [
            "https://fictional-user:fictional-secret@example.com/private?token=zz9",
            "https://example.com/\x07fictional-secret",
            "http://example.com/fictional-secret-" + "s" * 2012,
        ]

        for url in submitted:
            response = await endpoint.send(
                authenticated_client, ticket, reference.id, body={"url": url}
            )
            assert response.status_code == 422
            assert "fictional-secret" not in response.text
            assert "fictional-user" not in response.text
            assert "token=zz9" not in response.text
            assert "example.com" not in response.text

    async def test_list_source_over_500_characters_is_a_validation_error(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """api-spec.md, Query Parameter Length Limit; exactly 500 is
        accepted."""
        ticket: Ticket = await ticket_factory()

        accepted = await client.get(LIST.url(ticket), params={"source": "s" * 500})
        spies = _forbid_service(monkeypatch)
        rejected = await client.get(LIST.url(ticket), params={"source": "s" * 501})

        assert accepted.status_code == 200
        assert accepted.json() == {"data": []}
        assert rejected.status_code == 422
        assert rejected.json() == validation_error(
            {
                "loc": ["query", "source"],
                "msg": "String should have at most 500 characters",
                "type": "string_too_long",
            }
        )
        _assert_unused(spies)


# ---------------------------------------------------------------------------
# Add Reference (201)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAddReference:
    async def test_created_reference_is_the_persisted_normalized_projection(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """The exact `{"data": reference}` envelope: the normalized URL
        (scheme and host lowercased, `http` upgraded, the non-root path and
        its trailing slash preserved), `source = manual`, the canonical
        `SNTL-{n}` Ticket identity, and equal UTC creation timestamps."""
        ticket: Ticket = await ticket_factory()
        now = (await db_session.execute(select(func.now()))).scalar_one()

        response = await ADD.send(
            authenticated_client,
            ticket,
            body={
                "url": "http://Issues.Example.TEST/Tickets/12345/",
                "title": "Fictional packaging issue",
                "description": "Tracks the downstream packaging review",
                "type": "issue",
            },
        )

        assert response.status_code == 201
        body = response.json()
        assert set(body) == {"data"}
        data = body["data"]
        assert data == {
            "id": data["id"],
            "ticket_id": f"SNTL-{ticket.sequence_id}",
            "url": "https://issues.example.test/Tickets/12345/",
            "title": "Fictional packaging issue",
            "description": "Tracks the downstream packaging review",
            "type": "issue",
            "source": "manual",
            "created_at": data["created_at"],
            "updated_at": data["created_at"],
        }
        assert data["created_at"].endswith("Z")
        assert datetime.fromisoformat(data["created_at"]) == now
        assert await _references(db_session, ticket.id) == {
            (
                uuid.UUID(data["id"]),
                "https://issues.example.test/Tickets/12345/",
                "Fictional packaging issue",
                "Tracks the downstream packaging review",
                "issue",
                "manual",
                now,
                now,
            )
        }

    @pytest.mark.parametrize(
        ("fields", "expected_type"),
        [
            pytest.param({}, "patch", id="type-omitted-is-classified"),
            pytest.param({"type": None}, None, id="type-null-is-uncategorized"),
            pytest.param({"type": "article"}, "article", id="type-explicit"),
        ],
    )
    async def test_omitted_type_is_classified_and_null_is_kept(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        fields: dict[str, Any],
        expected_type: str | None,
    ) -> None:
        """The handler distinguishes an omitted `type` (URL classification)
        from an explicit `null`; omitted `title` and `description` are
        `null`."""
        ticket: Ticket = await ticket_factory()
        url = "https://github.com/example-org/example-repo/pull/7"

        response = await ADD.send(
            authenticated_client, ticket, body={"url": url} | fields
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert (data["url"], data["title"], data["description"], data["type"]) == (
            url,
            None,
            None,
            expected_type,
        )

    async def test_url_of_exactly_2048_characters_is_accepted(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        url = "https://example.com/" + "a" * 2028

        response = await ADD.send(authenticated_client, ticket, body={"url": url})

        assert len(url) == 2048
        assert response.status_code == 201
        assert response.json()["data"]["url"] == url


# ---------------------------------------------------------------------------
# Update Reference (200)
# ---------------------------------------------------------------------------

_SEED_URL = "https://issues.example.test/tickets/12345"


async def _seed(
    ticket_reference_factory: Factory, ticket: Ticket, **columns: Any
) -> TicketReference:
    """A manual reference with every nullable field set."""
    reference: TicketReference = await ticket_reference_factory(
        ticket_id=ticket.id,
        **(
            {
                "url": _SEED_URL,
                "title": "Fictional packaging issue",
                "description": "Tracks the downstream packaging review",
                "type": "issue",
                "created_at": datetime(2026, 4, 21, 14, 30, tzinfo=UTC),
                "updated_at": datetime(2026, 4, 21, 14, 30, tzinfo=UTC),
            }
            | columns
        ),
    )
    return reference


_SEEDED = {
    "url": _SEED_URL,
    "title": "Fictional packaging issue",
    "description": "Tracks the downstream packaging review",
    "type": "issue",
}


@pytest.mark.e2e
class TestUpdateReference:
    @pytest.mark.parametrize(
        ("body", "changed"),
        [
            pytest.param(
                {"title": "Updated fictional issue title", "description": None},
                {"title": "Updated fictional issue title", "description": None},
                id="title-value-description-null",
            ),
            pytest.param({"title": None}, {"title": None}, id="title-null"),
            pytest.param({"type": None}, {"type": None}, id="type-null"),
            pytest.param(
                {"url": "HTTP://Mirror.Example.TEST/Tickets/12345"},
                {"url": "https://mirror.example.test/Tickets/12345"},
                id="url-without-type-keeps-type",
            ),
            pytest.param(
                {
                    "url": "https://mirror.example.test/tickets/12345",
                    "type": "patch",
                    "title": "Replacement title",
                    "description": "Replacement description",
                },
                {
                    "url": "https://mirror.example.test/tickets/12345",
                    "type": "patch",
                    "title": "Replacement title",
                    "description": "Replacement description",
                },
                id="all-fields",
            ),
        ],
    )
    async def test_partial_update_returns_the_persisted_projection(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        body: dict[str, Any],
        changed: dict[str, Any],
    ) -> None:
        """The handler maps omitted fields to "preserve" and `null` to
        "clear"; the response is the complete persisted projection."""
        ticket: Ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)

        response = await UPDATE.send(
            authenticated_client, ticket, reference.id, body=body
        )

        assert response.status_code == 200
        body_json = response.json()
        assert set(body_json) == {"data"}
        data = body_json["data"]
        assert data == {
            "id": str(reference.id),
            "ticket_id": f"SNTL-{ticket.sequence_id}",
            **(_SEEDED | changed),
            "source": "manual",
            "created_at": "2026-04-21T14:30:00Z",
            "updated_at": data["updated_at"],
        }
        assert data["updated_at"].endswith("Z")
        persisted = await _references(db_session, ticket.id)
        assert {row[1:5] for row in persisted} == {
            tuple(
                (_SEEDED | changed)[k] for k in ("url", "title", "description", "type")
            )
        }


# ---------------------------------------------------------------------------
# Delete Reference (204)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDeleteReference:
    async def test_effective_delete_returns_an_empty_204(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        """Only the addressed manual row is removed; an automatic sibling
        remains."""
        ticket: Ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        sibling = await ticket_reference_factory(
            ticket_id=ticket.id, source=_AUTOMATIC_SOURCE
        )

        response = await DELETE.send(authenticated_client, ticket, reference.id)

        _assert_empty_204(response)
        assert {row[0] for row in await _references(db_session, ticket.id)} == {
            sibling.id
        }


# ---------------------------------------------------------------------------
# Audit through HTTP (acting user; exact payloads at the service tier)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuditThroughHttp:
    async def test_add_records_one_reference_added_by_the_caller(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()

        response = await ADD.send(authenticated_client, ticket)

        assert response.status_code == 201
        events = await ticket_events_by_id(db_session, ticket.id)
        assert [(e.event_type, e.user_id, e.new_value) for e in events] == [
            (
                "reference_added",
                va_user.id,
                "https://advisories.example.test/entries/77",
            )
        ]

    async def test_update_records_one_event_per_changed_field_by_the_caller(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)

        response = await UPDATE.send(
            authenticated_client,
            ticket,
            reference.id,
            body={"title": "Updated fictional issue title", "description": None},
        )

        assert response.status_code == 200
        events = await ticket_events_by_id(db_session, ticket.id)
        assert [(e.event_type, e.user_id) for e in events] == [
            ("reference_title_changed", va_user.id),
            ("reference_description_changed", va_user.id),
        ]

    async def test_delete_records_one_reference_deleted_by_the_caller(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)

        response = await DELETE.send(authenticated_client, ticket, reference.id)

        _assert_empty_204(response)
        events = await ticket_events_by_id(db_session, ticket.id)
        assert [(e.event_type, e.user_id, e.old_value) for e in events] == [
            ("reference_deleted", va_user.id, _SEED_URL)
        ]


# ---------------------------------------------------------------------------
# Equivalent PATCH across independently committed requests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCommittedRequests:
    async def test_equivalent_update_keeps_updated_at_and_records_nothing(
        self, committed_app: tuple[CommittedApp, AsyncClient]
    ) -> None:
        """Each request commits in its own transaction: the effective
        PATCH advances `updated_at`; a later equivalent PATCH (an
        equivalent URL form and the same title) returns 200 with the
        identical projection and adds no event."""
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        ticket = await world.ticket()
        ticket_id = ticket.id

        added = await ADD.send(
            committed_client,
            ticket,
            body={"url": "https://example.com", "title": "Original title"},
            headers=headers,
        )
        assert added.status_code == 201
        created = added.json()["data"]

        updated = await UPDATE.send(
            committed_client,
            ticket,
            created["id"],
            body={"title": "Revised title"},
            headers=headers,
        )
        assert updated.status_code == 200
        effective = updated.json()["data"]
        assert effective["title"] == "Revised title"
        assert datetime.fromisoformat(effective["updated_at"]) > datetime.fromisoformat(
            created["updated_at"]
        )
        observer = await world.session()
        events_after_update = await event_count(observer, ticket_id)
        await observer.rollback()

        equivalent = await UPDATE.send(
            committed_client,
            ticket,
            created["id"],
            body={"url": "HTTP://Example.COM/", "title": "Revised title"},
            headers=headers,
        )

        assert equivalent.status_code == 200
        assert equivalent.json() == {"data": effective}
        fresh = await world.session()
        assert events_after_update == 2
        assert await event_count(fresh, ticket_id) == events_after_update


# ---------------------------------------------------------------------------
# List References (200, unpaginated, fixed order, filters)
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 4, 21, 7, 0, tzinfo=UTC)
_T1 = datetime(2026, 4, 21, 8, 0, tzinfo=UTC)
_T2 = datetime(2026, 4, 21, 9, 0, tzinfo=UTC)
_T3 = datetime(2026, 4, 21, 10, 0, tzinfo=UTC)
_T4 = datetime(2026, 4, 21, 11, 0, tzinfo=UTC)
_T5 = datetime(2026, 4, 21, 12, 0, tzinfo=UTC)
_EDITED = datetime(2026, 4, 22, 9, 15, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _Listed:
    ticket: Ticket
    expected: list[dict[str, Any]]
    """Every item of the Ticket in the documented order."""

    def subset(self, **match: Any) -> list[dict[str, Any]]:
        return [
            item
            for item in self.expected
            if all(item[key] == value for key, value in match.items())
        ]


@pytest_asyncio.fixture
async def listed(ticket_factory: Factory, ticket_reference_factory: Factory) -> _Listed:
    """A non-confidential Ticket with automatic and manual references of
    every type, inserted out of order, two of them sharing type and
    `created_at` (the higher UUID inserted first); another Ticket's
    reference is never listed."""
    ticket: Ticket = await ticket_factory()
    other: Ticket = await ticket_factory()
    await ticket_reference_factory(ticket_id=other.id, type="advisory")
    low_id, high_id = sorted((uuid.uuid7(), uuid.uuid7()))
    rows: list[dict[str, Any]] = [
        {
            "url": "https://lists.example.test/thread/1",
            "title": None,
            "description": None,
            "type": None,
            "source": "manual",
            "created_at": _T3,
            "updated_at": _EDITED,
        },
        {
            "url": "https://seclists.org/oss-sec/2026/q2/1",
            "title": None,
            "description": None,
            "type": "article",
            "source": "sync_mitre_cves",
            "created_at": _T2,
            "updated_at": _T2,
        },
        {
            "id": high_id,
            "url": "https://issues.example.test/b",
            "title": "Second issue",
            "description": "Same instant, higher identifier",
            "type": "issue",
            "source": "manual",
            "created_at": _T0,
            "updated_at": _T0,
        },
        {
            "url": "https://github.com/example-org/example-repo/commit/abc123",
            "title": "Fix",
            "description": "Fictional upstream fix",
            "type": "patch",
            "source": "manual",
            "created_at": _T4,
            "updated_at": _T4,
        },
        {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-3317",
            "title": "NVD",
            "description": None,
            "type": "advisory",
            "source": _AUTOMATIC_SOURCE,
            "created_at": _T5,
            "updated_at": _T5,
        },
        {
            "url": "https://gitlab.com/example-group/example-project/-/merge_requests/9",
            "title": None,
            "description": None,
            "type": "patch",
            "source": "sync_mitre_cves",
            "created_at": _T1,
            "updated_at": _T1,
        },
        {
            "id": low_id,
            "url": "https://issues.example.test/a",
            "title": "First issue",
            "description": None,
            "type": "issue",
            "source": "manual",
            "created_at": _T0,
            "updated_at": _T0,
        },
    ]
    created = [
        await ticket_reference_factory(ticket_id=ticket.id, **row) for row in rows
    ]

    def item(index: int) -> dict[str, Any]:
        row = rows[index]
        return {
            "id": str(created[index].id),
            "ticket_id": f"SNTL-{ticket.sequence_id}",
            "url": row["url"],
            "title": row["title"],
            "description": row["description"],
            "type": row["type"],
            "source": row["source"],
            "created_at": _wire(row["created_at"]),
            "updated_at": _wire(row["updated_at"]),
        }

    # advisory; patch (T1, T4); issue (T0 low id, T0 high id); article; null.
    return _Listed(ticket, [item(i) for i in (4, 5, 3, 6, 2, 1, 0)])


@pytest.mark.e2e
class TestListReferences:
    async def test_complete_unpaginated_list_in_fixed_order(
        self, client: AsyncClient, listed: _Listed
    ) -> None:
        """`{"data": [...]}` without `meta`; type priority `advisory`,
        `patch`, `issue`, `article`, uncategorized, then `created_at`, then
        `id`; automatic and manual rows together."""
        response = await LIST.send(client, listed.ticket)

        assert response.status_code == 200
        assert response.json() == {"data": listed.expected}

    async def test_undeclared_sort_and_pagination_parameters_are_ignored(
        self, client: AsyncClient, listed: _Listed
    ) -> None:
        plain = await LIST.send(client, listed.ticket)
        decorated = await client.get(
            LIST.url(listed.ticket),
            params={
                "sort_by": "url",
                "sort_order": "desc",
                "page": "2",
                "per_page": "1",
            },
        )

        assert decorated.status_code == 200
        assert decorated.content == plain.content

    @pytest.mark.parametrize(
        ("params", "match"),
        [
            pytest.param({"source": "manual"}, {"source": "manual"}, id="source"),
            pytest.param(
                {"source": _AUTOMATIC_SOURCE},
                {"source": _AUTOMATIC_SOURCE},
                id="source-automatic",
            ),
            pytest.param({"type": "patch"}, {"type": "patch"}, id="type"),
            pytest.param(
                {"type": "issue", "source": "manual"},
                {"type": "issue", "source": "manual"},
                id="type-and-source",
            ),
        ],
    )
    async def test_filters_are_exact_and_combine_with_and(
        self,
        client: AsyncClient,
        listed: _Listed,
        params: dict[str, str],
        match: dict[str, str],
    ) -> None:
        response = await client.get(LIST.url(listed.ticket), params=params)

        expected = listed.subset(**match)
        assert expected
        assert response.status_code == 200
        assert response.json() == {"data": expected}

    @pytest.mark.parametrize(
        "params",
        [
            pytest.param({"source": "Manual"}, id="source-is-case-sensitive"),
            pytest.param({"source": "sync_nvd"}, id="source-is-not-a-prefix"),
            pytest.param({"type": "Patch"}, id="type-wrong-case"),
            pytest.param({"type": "blog"}, id="type-unknown"),
            pytest.param({"type": "patch,issue"}, id="type-comma-separated"),
            pytest.param({"type": "patch", "source": "sync_nvd_cves"}, id="and-empty"),
        ],
    )
    async def test_non_matching_or_invalid_filter_is_an_empty_list(
        self, client: AsyncClient, listed: _Listed, params: dict[str, str]
    ) -> None:
        response = await client.get(LIST.url(listed.ticket), params=params)

        assert response.status_code == 200
        assert response.json() == {"data": []}

    async def test_invalid_type_on_an_inaccessible_ticket_is_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        """Parent accessibility precedes filter emptiness."""
        hidden: Ticket = await ticket_factory(is_confidential=True)
        await ticket_reference_factory(ticket_id=hidden.id)

        responses = [
            await authenticated_client.get(LIST.url(target), params={"type": "blog"})
            for target in (locator(hidden), f"SNTL-{MAX_SEQUENCE}", "not-a-ticket")
        ]

        assert [r.status_code for r in responses] == [404, 404, 404]
        assert {r.content for r in responses} == {NOT_FOUND}

    async def test_accessible_ticket_without_references_is_an_empty_list(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_reference_factory()

        response = await LIST.send(client, ticket)

        assert response.status_code == 200
        assert response.json() == {"data": []}


# ---------------------------------------------------------------------------
# Accessibility of the read through HTTP (canonical predicate branches)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListAccessibility:
    @pytest.mark.parametrize(
        ("branch", "visible"),
        [
            pytest.param("restricted", False, id="restricted-analyst-denied"),
            pytest.param("no-roles", False, id="no-roles-denied"),
            pytest.param("va-scope-all", True, id="vulnerability-analyst"),
            pytest.param("grant", True, id="restricted-analyst-with-grant"),
            pytest.param("maintainer", True, id="restricted-analyst-maintainer"),
            pytest.param(
                "excluded-maintainer", False, id="maintainer-of-excluded-package"
            ),
        ],
    )
    async def test_confidential_ticket_visibility_branches(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        assign: Callable[..., Awaitable[User]],
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        branch: str,
        visible: bool,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        reference = await ticket_reference_factory(ticket_id=ticket.id)
        if branch == "va-scope-all":
            await assign(Role.VULNERABILITY_ANALYST)
        elif branch != "no-roles":
            await assign(Role.RESTRICTED_ANALYST)
        if branch == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        elif branch in ("maintainer", "excluded-maintainer"):
            package = await ticket_package_factory(
                ticket_id=ticket.id,
                deleted_at=(
                    datetime(2026, 4, 20, tzinfo=UTC)
                    if branch == "excluded-maintainer"
                    else None
                ),
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await LIST.send(authenticated_client, ticket)

        if visible:
            assert response.status_code == 200
            assert [item["id"] for item in response.json()["data"]] == [
                str(reference.id)
            ]
        else:
            assert response.status_code == 404
            assert response.content == NOT_FOUND


# ---------------------------------------------------------------------------
# Manual-zone opt-out (api-spec.md, Manual-Zone Mutability Guard exceptions)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestManualZone:
    @pytest.mark.parametrize(
        "status",
        [TicketStatus.IGNORED, TicketStatus.DUPLICATED, TicketStatus.RESOLVED],
    )
    async def test_every_mutation_succeeds_without_changing_the_ticket(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_reference_factory: Factory,
        status: TicketStatus,
    ) -> None:
        """Add, update, and delete succeed, never `409 TICKET_NOT_MUTABLE`;
        the Ticket keeps its status, assignment, priority, duplicate link,
        and `updated_at`."""
        ticket: Ticket = await ticket_factory(status=status.value)
        seeded = await _seed(ticket_reference_factory, ticket)
        before = await ticket_row(db_session, ticket.id)

        added = await ADD.send(authenticated_client, ticket)
        updated = await UPDATE.send(authenticated_client, ticket, seeded.id)
        deleted = await DELETE.send(authenticated_client, ticket, seeded.id)

        assert added.status_code == 201
        assert updated.status_code == 200
        _assert_empty_204(deleted)
        assert await ticket_row(db_session, ticket.id) == before
        assert before["status"] == status.value
        assert before["assignee_id"] is None
        events = await ticket_events_by_id(db_session, ticket.id)
        assert [e.event_type for e in events] == [
            "reference_added",
            "reference_title_changed",
            "reference_deleted",
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

    def _resolve(self, schema: dict[str, Any]) -> dict[str, Any]:
        if "$ref" in schema:
            return self._schema(schema["$ref"].rsplit("/", 1)[-1])
        return schema

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def _nullable_branches(self, field: dict[str, Any]) -> list[dict[str, Any]]:
        """The non-null branches of a nullable field; fails if not
        nullable."""
        branches: list[dict[str, Any]] = field["anyOf"]
        assert {"type": "null"} in branches
        return [self._resolve(b) for b in branches if b != {"type": "null"}]

    def test_operations_exist_with_their_methods_and_summaries(self) -> None:
        paths = self._spec()["paths"]

        assert set(paths[_COLLECTION]) == {"get", "post"}
        assert set(paths[_ITEM]) == {"patch", "delete"}
        for endpoint, summary in (
            (LIST, "List References"),
            (ADD, "Add Reference"),
            (UPDATE, "Update Reference"),
            (DELETE, "Delete Reference"),
        ):
            assert self._operation(endpoint)["summary"] == summary

    @pytest.mark.parametrize(
        ("endpoint", "codes"),
        [
            pytest.param(LIST, {"200", "404", "422"}, id="list"),
            pytest.param(ADD, {"201", "404", "409", "422"}, id="add"),
            pytest.param(UPDATE, {"200", "404", "409", "422"}, id="update"),
            pytest.param(DELETE, {"204", "404", "409", "422"}, id="delete"),
        ],
    )
    def test_documented_responses(self, endpoint: _Endpoint, codes: set[str]) -> None:
        responses = self._operation(endpoint)["responses"]

        assert set(responses) == codes
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert ("RESOURCE_NOT_FOUND" in responses["404"]["description"]) is (
            endpoint.takes_reference
        )
        if "409" in responses:
            description = responses["409"]["description"]
            assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
            assert ("RESOURCE_CONFLICT" in description) is (endpoint in (ADD, UPDATE))
            assert ("RESOURCE_NOT_EDITABLE" in description) is (
                endpoint in (UPDATE, DELETE)
            )
        assert not any(
            "TICKET_NOT_MUTABLE" in response.get("description", "")
            for response in responses.values()
        )

    def test_success_bodies_use_the_data_envelope(self) -> None:
        for endpoint, code in ((ADD, "201"), (UPDATE, "200")):
            success = self._operation(endpoint)["responses"][code]
            assert self._ref_name(success["content"]) == "TicketReferenceDataResponse"
        list_ok = self._operation(LIST)["responses"]["200"]
        assert self._ref_name(list_ok["content"]) == "TicketReferenceListResponse"
        assert "content" not in self._operation(DELETE)["responses"]["204"]

        data_envelope = self._schema("TicketReferenceDataResponse")
        assert set(data_envelope["properties"]) == {"data"}
        assert data_envelope["properties"]["data"]["$ref"].endswith(
            "/TicketReferenceResponse"
        )
        list_envelope = self._schema("TicketReferenceListResponse")
        assert set(list_envelope["properties"]) == {"data"}
        items = list_envelope["properties"]["data"]
        assert items["type"] == "array"
        assert items["items"]["$ref"].endswith("/TicketReferenceResponse")

    def test_response_schema_has_exactly_the_documented_fields(self) -> None:
        schema = self._schema("TicketReferenceResponse")
        fields = {
            "id",
            "ticket_id",
            "url",
            "title",
            "description",
            "type",
            "source",
            "created_at",
            "updated_at",
        }
        properties = schema["properties"]

        assert set(properties) == fields
        assert set(schema["required"]) == fields
        assert properties["id"]["format"] == "uuid"
        for name in ("ticket_id", "url", "source"):
            assert properties[name]["type"] == "string"
            assert "anyOf" not in properties[name]
        for name in ("created_at", "updated_at"):
            assert properties[name]["format"] == "date-time"
        for name in ("title", "description"):
            assert self._nullable_branches(properties[name]) == [{"type": "string"}]
        (type_branch,) = self._nullable_branches(properties["type"])
        assert type_branch["enum"] == ["advisory", "patch", "issue", "article"]

    def test_create_request_requires_only_a_non_nullable_url(self) -> None:
        request_body = self._operation(ADD)["requestBody"]

        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketReferenceCreate"
        schema = self._schema("TicketReferenceCreate")
        assert schema["required"] == ["url"]
        properties = schema["properties"]
        assert set(properties) == {"url", "title", "description", "type"}
        url = properties["url"]
        assert (url["type"], url["maxLength"]) == ("string", 2048)
        assert "anyOf" not in url
        self._assert_nullable_text_and_type(properties)

    def test_update_request_has_only_optional_fields(self) -> None:
        request_body = self._operation(UPDATE)["requestBody"]

        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketReferenceUpdate"
        schema = self._schema("TicketReferenceUpdate")
        assert "required" not in schema
        properties = schema["properties"]
        assert set(properties) == {"url", "title", "description", "type"}
        # `url` is optional but never nullable (TicketReferenceUpdate:
        # "explicit null is invalid").
        url = properties["url"]
        assert (url["type"], url["maxLength"]) == ("string", 2048)
        assert "anyOf" not in url
        self._assert_nullable_text_and_type(properties)

    def _assert_nullable_text_and_type(self, properties: dict[str, Any]) -> None:
        for name, max_length in (("title", 500), ("description", 2000)):
            (branch,) = self._nullable_branches(properties[name])
            assert branch == {"type": "string", "minLength": 1, "maxLength": max_length}
        (type_branch,) = self._nullable_branches(properties["type"])
        assert type_branch == {
            "type": "string",
            "enum": ["advisory", "patch", "issue", "article"],
        }

    def test_parameters_of_each_operation(self) -> None:
        list_parameters = {p["name"]: p for p in self._operation(LIST)["parameters"]}
        assert list(list_parameters) == ["ticket_id", "source", "type"]
        for name in ("source", "type"):
            assert list_parameters[name]["in"] == "query"
            assert list_parameters[name]["required"] is False
        assert "requestBody" not in self._operation(LIST)
        assert "requestBody" not in self._operation(DELETE)

        for endpoint in (UPDATE, DELETE):
            parameters = {p["name"]: p for p in self._operation(endpoint)["parameters"]}
            assert set(parameters) == {"ticket_id", "reference_id"}
            reference_id = parameters["reference_id"]
            assert (reference_id["in"], reference_id["required"]) == ("path", True)
            assert reference_id["schema"]["format"] == "uuid"
        for endpoint in (LIST, ADD, UPDATE, DELETE):
            ticket_id = {p["name"]: p for p in self._operation(endpoint)["parameters"]}[
                "ticket_id"
            ]
            assert ticket_id["schema"]["type"] == "string"
            for constraint in ("format", "pattern"):
                assert constraint not in ticket_id["schema"]
