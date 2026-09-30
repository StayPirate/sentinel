"""End-to-end tests for the Set Confidentiality
(`PATCH /api/v1/tickets/{ticket_id}/confidentiality`) and Set Coordinated
Release Date (`PATCH /api/v1/tickets/{ticket_id}/coordinated-release-date`)
endpoints in `backend/app/api/v1/tickets.py`.

See docs/features/tickets/tickets.md (Set Confidentiality, Set Coordinated
Release Date, Confidential Tickets > Coordinated Release Date and Audit
Trail, Response Schemas > TicketDetail, Endpoint -> Schema Mapping),
docs/api-spec.md (Authorization Chain Evaluation Order flow 3, Global
Responses, Ticket Accessibility Check, Manual-Zone Mutability Guard
exceptions, Response Applicability Derivation, Partial Update Semantics),
docs/features/identity/rbac.md (Endpoint Permission Map:
`manage_confidentiality`; Predefined Roles), and
docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; Ticket Accessibility > Confidentiality and explicit access
grants).

These tests cover only the HTTP boundary, parametrized over both endpoints
where the contract is shared: authentication, capability before lookup, the
identical 404 family (before the confidentiality guard), request
validation (including the shared Coordinated Release Date parser, so both
CRD-accepting endpoints are proven to accept the same inputs), the complete
body of the one error mapping, the response shape, OpenAPI, and the
handler-owned steps (the one captured date and the final `TicketDetail`
assembly with its rollback). The service matrix (every status, exact event
values, no-op classification, guard and lock order, grant deletion scope,
maintainer retention, injected service failures, and the races) is proven
once in `tests/test_services/test_confidentiality.py`,
`tests/test_services/test_coordinated_release_date.py`, and
`tests/test_services/test_confidentiality_atomicity.py`.

Under the predefined roles `manage_confidentiality` implies scope `all`
(rbac.md, Predefined Roles), so an inaccessible Ticket cannot be produced
for a capability holder through role assignment alone. The accessibility
tests below narrow the request-resolved caller scope to `non_confidential`
(a synthetic caller context standing in for any capability holder without
scope `all`) to prove the handler maps both the preliminary and the
locked-current denial to the identical 404.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.v1 import tickets as route
from app.core.enums import Role, Scope, TicketStatus
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services import ticket_mutations, ticket_service, user_service
from app.services.ticket_service import TicketDetailProjection
from tests.support.ticket_api import (
    FORBIDDEN,
    INTERNAL_ERROR,
    INVALID_LOCATORS,
    MAX_SEQUENCE,
    NOT_FOUND,
    TICKET_DETAIL_FIELDS,
    UNAUTHENTICATED,
    Clock,
    CommittedApp,
    committed_app_client,
    event_count,
    force_production_error_page,
    locator,
    validation_error,
)
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

Factory = Callable[..., Awaitable[Any]]

_NOT_CONFIDENTIAL = {
    "code": "TICKET_NOT_CONFIDENTIAL",
    "detail": "Operation requires a confidential Ticket.",
}
"""docs/api-spec.md, error registry; tickets.md, Set Coordinated Release
Date error responses."""

_CRD = "2026-10-06T14:00:00Z"
_CRD_INSTANT = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
_LATER = "2026-11-20T09:30:00Z"


@dataclass(frozen=True, slots=True)
class _Endpoint:
    """One confidentiality-management endpoint."""

    path: str
    summary: str
    service: str
    """The `ticket_service` function the handler delegates to."""
    field: str
    """The single required request field."""
    body: dict[str, Any]
    """A valid request body used where the value is irrelevant."""
    request_schema: str

    def url(self, target: Ticket | str) -> str:
        return self.path.format(
            ticket_id=target if isinstance(target, str) else locator(target)
        )


CONFIDENTIALITY = _Endpoint(
    "/api/v1/tickets/{ticket_id}/confidentiality",
    "Set Confidentiality",
    "set_confidentiality",
    "is_confidential",
    {"is_confidential": False},
    "TicketConfidentialityUpdateRequest",
)
CRD_ENDPOINT = _Endpoint(
    "/api/v1/tickets/{ticket_id}/coordinated-release-date",
    "Set Coordinated Release Date",
    "set_coordinated_release_date",
    "coordinated_release_at",
    {"coordinated_release_at": _LATER},
    "TicketCoordinatedReleaseDateUpdateRequest",
)
ENDPOINTS = [
    pytest.param(CONFIDENTIALITY, id="confidentiality"),
    pytest.param(CRD_ENDPOINT, id="crd"),
]


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted Ticket columns these endpoints may (or must not)
    change."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.duplicate_of_id,
                Ticket.is_confidential,
                Ticket.coordinated_release_at,
                Ticket.created_at,
                Ticket.updated_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return dict(row._mapping)


async def _grant_count(db: AsyncSession, ticket_id: uuid.UUID) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(TicketAccessGrant)
            .where(TicketAccessGrant.ticket_id == ticket_id)
        )
    ).scalar_one()


def _forbid_lookups(
    monkeypatch: pytest.MonkeyPatch, endpoint: _Endpoint
) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, endpoint.service, mutation)
    return resolver, mutation


def _narrow_caller_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every request's caller with scope `non_confidential` while
    keeping its real roles and capabilities (see the module docstring)."""

    def _non_confidential(roles: Iterable[Role]) -> Scope:
        return Scope.NON_CONFIDENTIAL

    monkeypatch.setattr(dependencies, "get_effective_scope", _non_confidential)


def _crd_event(user: User, old: str | None, new: str | None) -> EventRow:
    return EventRow("coordinated_release_changed", user.id, old, new, None, None)


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


async def _committed_grants(
    world: CommittedApp, ticket: Ticket, granted_by: User, count: int
) -> None:
    grantees = [await world.user(role=None) for _ in range(count)]
    db = await world.session()
    db.add_all(
        TicketAccessGrant(
            ticket_id=ticket.id, user_id=grantee.id, granted_by_id=granted_by.id
        )
        for grantee in grantees
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Authentication and capability (flow 3, step 1)
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
        resolver, mutation = _forbid_lookups(monkeypatch, endpoint)

        for path in (endpoint.url(target), endpoint.url(f"SNTL-{MAX_SEQUENCE}")):
            response = await client.patch(path, json=endpoint.body, headers=headers)
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()

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
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
        endpoint: _Endpoint,
    ) -> None:
        """The same generic 403 for an existing (non-confidential, hence
        visible to every role) Ticket, a missing one, and a malformed
        locator; no lookup, mutation, write, or event happens."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        visible: Ticket = await ticket_factory()
        before = await _state(db_session, visible.id)
        resolver, mutation = _forbid_lookups(monkeypatch, endpoint)

        responses = [
            await authenticated_client.patch(endpoint.url(path), json=endpoint.body)
            for path in (visible, f"SNTL-{MAX_SEQUENCE}", "not-a-ticket")
        ]

        assert [r.status_code for r in responses] == [403, 403, 403]
        assert len({r.content for r in responses}) == 1
        assert responses[0].json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _state(db_session, visible.id) == before
        assert await event_count(db_session, visible.id) == 0

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_roles_are_loaded_once_for_capability_and_scope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.patch(
            endpoint.url(target), json=endpoint.body
        )

        assert response.status_code == 200
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
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
        build_locator: Callable[[Ticket], str],
        endpoint: _Endpoint,
    ) -> None:
        """The target is non-confidential, so its canonical locator would
        reach the CRD endpoint's confidentiality guard: a missing Ticket
        returns 404, never `409 TICKET_NOT_CONFIDENTIAL`."""
        target: Ticket = await ticket_factory()
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            endpoint.url(build_locator(target)), json=endpoint.body
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await _state(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        """A `manage_confidentiality` holder without scope `all` and
        without a visibility path gets the identical 404; the same caller
        with an explicit grant is served, so the denial is the visibility
        predicate's."""
        _narrow_caller_scope(monkeypatch)
        hidden: Ticket = await ticket_factory(
            is_confidential=True, coordinated_release_at=_CRD_INSTANT
        )
        before = await _state(db_session, hidden.id)

        inaccessible = await authenticated_client.patch(
            endpoint.url(hidden), json=endpoint.body
        )
        missing = await authenticated_client.patch(
            endpoint.url(f"SNTL-{MAX_SEQUENCE}"), json=endpoint.body
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await _state(db_session, hidden.id) == before
        assert await event_count(db_session, hidden.id) == 0

        await ticket_access_grant_factory(ticket_id=hidden.id, user_id=va_user.id)
        granted = await authenticated_client.patch(
            endpoint.url(hidden), json=endpoint.body
        )
        assert granted.status_code == 200


# ---------------------------------------------------------------------------
# Request validation (global 422)
# ---------------------------------------------------------------------------


def _field_error(field: str, msg: str, type_: str) -> dict[str, Any]:
    return {"loc": ["body", field], "msg": msg, "type": type_}


_BOOL_TYPE = _field_error(
    "is_confidential", "Input should be a valid boolean", "bool_type"
)
_CRD_NOT_A_STRING = _field_error(
    "coordinated_release_at",
    "Value error, coordinated_release_at must be an ISO 8601 datetime string.",
    "value_error",
)
_CRD_NO_TIME = _field_error(
    "coordinated_release_at",
    "Value error, coordinated_release_at must include a time component.",
    "value_error",
)
_CRD_INVALID = _field_error(
    "coordinated_release_at",
    "Value error, coordinated_release_at must be a valid ISO 8601 datetime.",
    "value_error",
)
_CRD_OUT_OF_RANGE = _field_error(
    "coordinated_release_at",
    "Value error, coordinated_release_at is out of the representable datetime range.",
    "value_error",
)
_NON_OBJECT_BODY = {
    "loc": ["body"],
    "msg": "Input should be a valid dictionary or object to extract fields from",
    "type": "model_attributes_type",
}


def _crd(value: Any) -> dict[str, Any]:
    return {"coordinated_release_at": value}


_VALIDATION_CASES = [
    *[
        pytest.param(
            endpoint,
            {},
            _field_error(endpoint.field, "Field required", "missing"),
            id=f"{name}-omitted",
        )
        for name, endpoint in (
            ("confidentiality", CONFIDENTIALITY),
            ("crd", CRD_ENDPOINT),
        )
    ],
    *[
        pytest.param(endpoint, [], _NON_OBJECT_BODY, id=f"{name}-non-object-body")
        for name, endpoint in (
            ("confidentiality", CONFIDENTIALITY),
            ("crd", CRD_ENDPOINT),
        )
    ],
    pytest.param(
        CONFIDENTIALITY, {"is_confidential": None}, _BOOL_TYPE, id="confidential-null"
    ),
    pytest.param(
        CONFIDENTIALITY,
        {"is_confidential": "maybe"},
        _field_error(
            "is_confidential",
            "Input should be a valid boolean, unable to interpret input",
            "bool_parsing",
        ),
        id="confidential-unparsable-string",
    ),
    pytest.param(
        CONFIDENTIALITY, {"is_confidential": {}}, _BOOL_TYPE, id="confidential-object"
    ),
    pytest.param(
        CONFIDENTIALITY, {"is_confidential": []}, _BOOL_TYPE, id="confidential-list"
    ),
    pytest.param(CRD_ENDPOINT, _crd(1791295200), _CRD_NOT_A_STRING, id="crd-number"),
    pytest.param(CRD_ENDPOINT, _crd(True), _CRD_NOT_A_STRING, id="crd-bool"),
    pytest.param(CRD_ENDPOINT, _crd({"at": _CRD}), _CRD_NOT_A_STRING, id="crd-object"),
    pytest.param(CRD_ENDPOINT, _crd([_CRD]), _CRD_NOT_A_STRING, id="crd-list"),
    pytest.param(CRD_ENDPOINT, _crd("2026-10-06"), _CRD_NO_TIME, id="crd-date-only"),
    pytest.param(CRD_ENDPOINT, _crd("20261006"), _CRD_NO_TIME, id="crd-basic-date"),
    pytest.param(CRD_ENDPOINT, _crd("not-a-date"), _CRD_INVALID, id="crd-invalid"),
    pytest.param(CRD_ENDPOINT, _crd(""), _CRD_INVALID, id="crd-empty-string"),
    pytest.param(
        CRD_ENDPOINT, _crd("2026-13-01T00:00:00Z"), _CRD_INVALID, id="crd-bad-month"
    ),
    pytest.param(
        CRD_ENDPOINT,
        _crd("0001-01-01T00:00:00+01:00"),
        _CRD_OUT_OF_RANGE,
        id="crd-underflow",
    ),
    pytest.param(
        CRD_ENDPOINT,
        _crd("9999-12-31T23:59:59-01:00"),
        _CRD_OUT_OF_RANGE,
        id="crd-overflow",
    ),
]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("endpoint", "body", "error"), _VALIDATION_CASES)
    async def test_invalid_body_returns_the_validation_envelope_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
        body: Any,
        error: dict[str, Any],
    ) -> None:
        target: Ticket = await ticket_factory(
            is_confidential=True, coordinated_release_at=_CRD_INSTANT
        )
        before = await _state(db_session, target.id)
        mutation = AsyncMock()
        monkeypatch.setattr(ticket_service, endpoint.service, mutation)

        response = await authenticated_client.patch(endpoint.url(target), json=body)

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        mutation.assert_not_awaited()
        assert await _state(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_absent_body_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        endpoint: _Endpoint,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)

        response = await authenticated_client.patch(endpoint.url(target))

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["body"], "msg": "Field required", "type": "missing"}
        )


# ---------------------------------------------------------------------------
# Set Confidentiality (200 TicketDetail)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSetConfidentiality:
    async def test_declassification_returns_the_detail_and_deletes_every_grant(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        """The complete `TicketDetail` equals a subsequent GET, the flag is
        `false`, the retained CRD is unchanged, every grant is deleted, and
        exactly one `confidentiality_changed` exists (no
        `access_grant_removed`, no `coordinated_release_changed`)."""
        target: Ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=va_user.id,
            is_confidential=True,
            coordinated_release_at=_CRD_INSTANT,
        )
        for _ in range(2):
            await ticket_access_grant_factory(ticket_id=target.id)
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            CONFIDENTIALITY.url(target), json={"is_confidential": False}
        )
        detail = await authenticated_client.get(f"/api/v1/tickets/{locator(target)}")

        assert response.status_code == 200
        assert set(response.json()) == {"data"}
        data = response.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == detail.json()["data"]
        assert (data["ticket_id"], data["status"], data["is_confidential"]) == (
            locator(target),
            "analysis",
            False,
        )
        assert data["coordinated_release_at"] == _CRD
        state = await _state(db_session, target.id)
        assert state["is_confidential"] is False
        assert {k: v for k, v in state.items() if k != "is_confidential"} == {
            k: v for k, v in before.items() if k != "is_confidential"
        }
        assert await _grant_count(db_session, target.id) == 0
        assert await ticket_events_by_id(db_session, target.id) == [
            EventRow("confidentiality_changed", va_user.id, "true", "false", None, None)
        ]

    async def test_classification_returns_the_confidential_detail(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory()

        response = await authenticated_client.patch(
            CONFIDENTIALITY.url(target), json={"is_confidential": True}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["is_confidential"], data["coordinated_release_at"]) == (True, None)
        assert (await _state(db_session, target.id))["is_confidential"] is True
        assert await _grant_count(db_session, target.id) == 0
        assert await ticket_events_by_id(db_session, target.id) == [
            EventRow("confidentiality_changed", va_user.id, "false", "true", None, None)
        ]

    @pytest.mark.parametrize("value", [True, False])
    async def test_same_value_returns_the_unchanged_detail_without_event(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        value: bool,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=value)
        if value:
            await ticket_access_grant_factory(ticket_id=target.id)
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            CONFIDENTIALITY.url(target), json={"is_confidential": value}
        )

        assert response.status_code == 200
        assert response.json()["data"]["is_confidential"] is value
        assert await _state(db_session, target.id) == before
        assert await _grant_count(db_session, target.id) == (1 if value else 0)
        assert await event_count(db_session, target.id) == 0

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize("value", [True, False])
    async def test_manual_zone_ticket_is_not_subject_to_the_mutability_guard(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        status: TicketStatus,
        value: bool,
    ) -> None:
        """A visibility-only opt-out (api-spec.md, Manual-Zone Mutability
        Guard exceptions): the flag changes and the Ticket stays in the
        manual zone, unassigned, never `409 TICKET_NOT_MUTABLE`."""
        target: Ticket = await ticket_factory(
            status=status.value, is_confidential=not value
        )
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            CONFIDENTIALITY.url(target), json={"is_confidential": value}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["status"], data["assignee"], data["is_confidential"]) == (
            status.value.lower(),
            None,
            value,
        )
        state = await _state(db_session, target.id)
        assert (state["status"], state["duplicate_of_id"], state["assignee_id"]) == (
            before["status"],
            before["duplicate_of_id"],
            None,
        )
        assert await event_count(db_session, target.id) == 1


# ---------------------------------------------------------------------------
# Set Coordinated Release Date (200 TicketDetail, 409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSetCoordinatedReleaseDate:
    @pytest.mark.parametrize(
        ("supplied", "expected"),
        [
            pytest.param(_CRD, _CRD, id="utc-z"),
            pytest.param("2026-10-06T14:00:00", _CRD, id="naive-is-utc"),
            pytest.param("2026-10-06T16:00:00+02:00", _CRD, id="offset"),
            pytest.param("2026-10-06T14:00:00+00:00", _CRD, id="explicit-zero-offset"),
            pytest.param(
                "2026-12-31T23:30:00-05:00",
                "2027-01-01T04:30:00Z",
                id="offset-crossing-midnight",
            ),
            pytest.param(
                "2026-10-06T14:00:00.5Z",
                "2026-10-06T14:00:00.500000Z",
                id="sub-second",
            ),
            pytest.param("2020-01-02T03:04:05Z", "2020-01-02T03:04:05Z", id="past"),
        ],
    )
    async def test_crd_is_stored_returned_and_audited_as_the_utc_instant(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        supplied: str,
        expected: str,
    ) -> None:
        """The same input matrix as `POST /api/v1/tickets` (the shared
        parser): the response and the event carry the UTC instant with a
        `Z` suffix, and the stored value is that aware UTC instant."""
        target: Ticket = await ticket_factory(is_confidential=True)

        response = await authenticated_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(supplied)
        )

        assert response.status_code == 200
        assert response.json()["data"]["coordinated_release_at"] == expected
        stored = (await _state(db_session, target.id))["coordinated_release_at"]
        assert stored == datetime.fromisoformat(expected)
        assert await ticket_events_by_id(db_session, target.id) == [
            _crd_event(va_user, None, expected)
        ]

    async def test_change_then_clear_returns_the_complete_detail(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=va_user.id,
            is_confidential=True,
            coordinated_release_at=_CRD_INSTANT,
        )
        before = await _state(db_session, target.id)

        changed = await authenticated_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(_LATER)
        )
        after_change = await authenticated_client.get(
            f"/api/v1/tickets/{locator(target)}"
        )
        cleared = await authenticated_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(None)
        )

        assert changed.status_code == cleared.status_code == 200
        assert set(changed.json()) == {"data"}
        data = changed.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == after_change.json()["data"]
        assert (data["status"], data["is_confidential"]) == ("analysis", True)
        assert data["coordinated_release_at"] == _LATER
        assert cleared.json()["data"]["coordinated_release_at"] is None
        state = await _state(db_session, target.id)
        assert state["coordinated_release_at"] is None
        assert (state["status"], state["assignee_id"], state["created_at"]) == (
            before["status"],
            before["assignee_id"],
            before["created_at"],
        )
        assert await ticket_events_by_id(db_session, target.id) == [
            _crd_event(va_user, _CRD, _LATER),
            _crd_event(va_user, _LATER, None),
        ]

    @pytest.mark.parametrize(
        ("stored", "supplied"),
        [
            pytest.param(_CRD_INSTANT, "2026-10-06T16:00:00+02:00", id="same-instant"),
            pytest.param(_CRD_INSTANT, "2026-10-06T14:00:00", id="same-naive"),
            pytest.param(None, None, id="null-when-absent"),
        ],
    )
    async def test_unchanged_request_returns_the_detail_without_event(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        stored: datetime | None,
        supplied: str | None,
    ) -> None:
        target: Ticket = await ticket_factory(
            is_confidential=True, coordinated_release_at=stored
        )
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(supplied)
        )

        assert response.status_code == 200
        assert response.json()["data"]["coordinated_release_at"] == (
            None if stored is None else _CRD
        )
        assert await _state(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_confidential_ticket_accepts_the_change(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        status: TicketStatus,
    ) -> None:
        """An embargo-metadata opt-out (api-spec.md, Manual-Zone Mutability
        Guard exceptions): never `409 TICKET_NOT_MUTABLE`."""
        target: Ticket = await ticket_factory(status=status.value, is_confidential=True)
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(_CRD)
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["status"], data["assignee"], data["coordinated_release_at"]) == (
            status.value.lower(),
            None,
            _CRD,
        )
        state = await _state(db_session, target.id)
        assert (state["status"], state["duplicate_of_id"], state["assignee_id"]) == (
            before["status"],
            before["duplicate_of_id"],
            None,
        )
        assert await event_count(db_session, target.id) == 1

    @pytest.mark.parametrize(
        "stored",
        [
            pytest.param(None, id="never-confidential"),
            pytest.param(_CRD_INSTANT, id="declassified-with-retained-crd"),
        ],
    )
    @pytest.mark.parametrize(
        "supplied",
        [
            pytest.param(_LATER, id="set"),
            pytest.param(_CRD, id="retained-value"),
            pytest.param(None, id="clear"),
        ],
    )
    async def test_non_confidential_ticket_is_rejected_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        stored: datetime | None,
        supplied: str | None,
    ) -> None:
        """The complete `409 TICKET_NOT_CONFIDENTIAL` body, whatever the
        requested value (including one that would otherwise be a no-op);
        the retained value stays read-only."""
        target: Ticket = await ticket_factory(coordinated_release_at=stored)
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(supplied)
        )

        assert response.status_code == 409
        assert response.json() == _NOT_CONFIDENTIAL
        assert await _state(db_session, target.id) == before
        assert await event_count(db_session, target.id) == 0


# ---------------------------------------------------------------------------
# Handler-owned final assembly in the real request transaction
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMutationAssembly:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_detail_is_assembled_from_the_uncommitted_post_state(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket(is_confidential=True)
        column = endpoint.field
        observed: list[tuple[Any, Any]] = []
        original = ticket_service.assemble_ticket_detail

        async def _observe(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            independent = await world.session()
            observed.append(
                (
                    (await _state(db, target.id))[column],
                    (await _state(independent, target.id))[column],
                )
            )
            await independent.rollback()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _observe)

        response = await committed_client.patch(
            endpoint.url(target), json=endpoint.body, headers=headers
        )

        assert response.status_code == 200
        pre, post = (
            (True, False)
            if endpoint is CONFIDENTIALITY
            else (None, datetime(2026, 11, 20, 9, 30, tzinfo=UTC))
        )
        # The request's own session sees the change; the commit follows.
        assert observed == [(post, pre)]
        fresh = await world.session()
        assert (await _state(fresh, target.id))[column] == post

    async def test_failed_assembly_rolls_back_the_declassification_and_its_grants(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        caller, headers = await world.va_headers()
        target = await world.ticket(
            is_confidential=True, coordinated_release_at=_CRD_INSTANT
        )
        await _committed_grants(world, target, caller, 2)
        before = await _state(await world.session(), target.id)
        reached: list[tuple[bool, int, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            reached.append(
                (
                    (await _state(db, target.id))["is_confidential"],
                    await _grant_count(db, target.id),
                    await event_count(db, target.id),
                )
            )
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)
        force_production_error_page(monkeypatch)

        response = await committed_client.patch(
            CONFIDENTIALITY.url(target),
            json={"is_confidential": False},
            headers=headers,
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        # The flag, both grant deletions, and the event existed in the
        # request transaction; none of them survives.
        assert reached == [(False, 0, 1)]
        fresh = await world.session()
        assert await _state(fresh, target.id) == before
        assert await _grant_count(fresh, target.id) == 2
        assert await event_count(fresh, target.id) == 0

    async def test_failed_assembly_rolls_back_the_crd_change(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket(is_confidential=True)
        before = await _state(await world.session(), target.id)
        reached: list[tuple[datetime | None, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            reached.append(
                (
                    (await _state(db, target.id))["coordinated_release_at"],
                    await event_count(db, target.id),
                )
            )
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)
        force_production_error_page(monkeypatch)

        response = await committed_client.patch(
            CRD_ENDPOINT.url(target), json=_crd(_CRD), headers=headers
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        assert reached == [(_CRD_INSTANT, 1)]
        fresh = await world.session()
        assert await _state(fresh, target.id) == before
        assert await event_count(fresh, target.id) == 0


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured date across UTC midnight
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEvaluationDate:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_one_date_captured_before_midnight_reaches_the_assembly(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        """The handler captures one UTC date just before midnight; every
        later clock reads just after midnight. The mutation receives no
        date at all, and the final assembly receives the handler's date:
        no second workflow date is captured."""
        handler_clock = Clock(datetime(2026, 9, 27, 23, 59, 59, 999000, tzinfo=UTC))
        service_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        mutation_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", service_clock.now)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        mutation_kwargs: list[set[str]] = []
        assembly_dates: list[date] = []
        original_mutation = getattr(ticket_service, endpoint.service)
        original_assembly = ticket_service.assemble_ticket_detail

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Ticket:
            mutation_kwargs.append(set(kwargs))
            result: Ticket = await original_mutation(db, **kwargs)
            return result

        async def _assembly(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            assembly_dates.append(kwargs["evaluation_date"])
            return await original_assembly(db, **kwargs)

        monkeypatch.setattr(ticket_service, endpoint.service, _mutation)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        target: Ticket = await ticket_factory(is_confidential=True)

        response = await authenticated_client.patch(
            endpoint.url(target), json=endpoint.body
        )

        assert response.status_code == 200
        assert mutation_kwargs == [
            {"ticket_id", endpoint.field, "acting_user_id", "caller"}
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
    @staticmethod
    def _spec() -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self, endpoint: _Endpoint) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][endpoint.path]["patch"]
        return operation

    def _schema(self, name: str) -> dict[str, Any]:
        schema: dict[str, Any] = self._spec()["components"]["schemas"][name]
        return schema

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_operation_requires_its_single_field_body(
        self, endpoint: _Endpoint
    ) -> None:
        operation = self._operation(endpoint)

        assert operation["tags"] == ["Tickets"]
        assert operation["summary"] == endpoint.summary
        assert "`manage_confidentiality`" in operation["description"]
        request_body = operation["requestBody"]
        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == endpoint.request_schema
        schema = self._schema(endpoint.request_schema)
        assert schema["required"] == [endpoint.field]
        assert set(schema["properties"]) == {endpoint.field}

    def test_confidentiality_field_is_a_non_nullable_boolean(self) -> None:
        schema = self._schema(CONFIDENTIALITY.request_schema)

        assert schema["properties"]["is_confidential"]["type"] == "boolean"
        assert "anyOf" not in schema["properties"]["is_confidential"]

    def test_crd_field_is_a_nullable_date_time(self) -> None:
        schema = self._schema(CRD_ENDPOINT.request_schema)

        variants = schema["properties"]["coordinated_release_at"]["anyOf"]
        assert {"type": "null"} in variants
        assert {"type": "string", "format": "date-time"} in variants

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_responses_declare_detail_and_error_envelopes(
        self, endpoint: _Endpoint
    ) -> None:
        responses = self._operation(endpoint)["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "422" in responses
        assert "400" not in responses
        assert not any(
            "TICKET_NOT_MUTABLE" in response.get("description", "")
            for response in responses.values()
        )
        if endpoint is CRD_ENDPOINT:
            assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
            assert "TICKET_NOT_CONFIDENTIAL" in responses["409"]["description"]
        else:
            assert "409" not in responses


# ---------------------------------------------------------------------------
# Locked-current accessibility through HTTP (handler mapping of the
# service's authoritative denial; api-spec.md, flow 3)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIndependentRaces:
    @pytest.mark.parametrize(
        ("endpoint", "body"),
        [
            pytest.param(
                CONFIDENTIALITY, {"is_confidential": True}, id="confidentiality"
            ),
            pytest.param(CRD_ENDPOINT, _crd(_CRD), id="crd"),
        ],
    )
    async def test_visibility_lost_to_a_committed_change_after_the_preliminary_check(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
        body: dict[str, Any],
    ) -> None:
        """A capability holder without scope `all` (see the module
        docstring) passes the preliminary check on a non-confidential
        Ticket; another session then commits the confidentiality flag
        before the service locks the Ticket. The locked-current denial
        maps to the identical `404 TICKET_NOT_FOUND` with no effect: the
        confidentiality request is not classified as a no-op and the CRD
        request is neither accepted nor rejected as non-confidential. The
        service tier owns the race matrix; this proves only the handler's
        mapping of that denial."""
        _narrow_caller_scope(monkeypatch)
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket()
        ticket_id = target.id
        before = await _state(await world.session(), ticket_id)
        original = getattr(ticket_service, endpoint.service)
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
            result: Ticket = await original(db, **kwargs)
            return result

        monkeypatch.setattr(ticket_service, endpoint.service, _lose_then_call)

        response = await committed_client.patch(
            endpoint.url(target), json=body, headers=headers
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert reached == [True]
        fresh = await world.session()
        after = await _state(fresh, ticket_id)
        # Only the racer's own write (and its `updated_at`) is committed.
        assert after["is_confidential"] is True
        assert {
            k: v for k, v in after.items() if k not in {"is_confidential", "updated_at"}
        } == {
            k: v
            for k, v in before.items()
            if k not in {"is_confidential", "updated_at"}
        }
        assert await event_count(fresh, ticket_id) == 0
