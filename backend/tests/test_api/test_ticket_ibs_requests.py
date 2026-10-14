"""End-to-end tests for the Ticket IBS request list endpoints in
`backend/app/api/v1/ticket_ibs_requests.py`: List Submission Requests
(`GET /api/v1/tickets/{ticket_id}/submission-requests`) and List Release
Requests (`GET /api/v1/tickets/{ticket_id}/release-requests`).

See docs/features/packages/ibs-submission-tracking.md (Public API, Common
Query Rules, List Submission Requests, List Release Requests, Testing
Requirements, Security and Privacy), docs/api-spec.md (Optional
Authentication on Public Endpoints, Authorization Chain Evaluation Order
flow 1, Query Parameter Length Limit, Undeclared Query Parameters,
Inadmissible Characters in Request Input, Pagination, Enum Filter
Validation, Sort Parameter Validation, Response Format, Global Responses,
Ticket Accessibility Check, Response Applicability Derivation, Ticket
Identifier Resolution), docs/conventions.md (Timestamps & Timezones), and
docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; Mandatory Test Scenarios > API Endpoints; Ticket
Accessibility > Authentication, authorization, and anti-enumeration and
Ticket identifier and read-contract coverage).

These tests cover only the HTTP boundary: optional authentication and its
operational effects, one role resolution per request, the identical
`TICKET_NOT_FOUND` family, accessibility as observed through HTTP, the
global `422 VALIDATION_ERROR` bodies (which precede the scoped 404 and
never echo the offending value), the invalid `state` empty page, ignored
undeclared parameters, the exact success envelopes, one wiring proof per
path for filters, sorting, and pagination, and OpenAPI. The service
matrix (deduplication, every filter and state, ordering ties, package and
track exclusion, visibility branches, and the independent-session races)
is proven once in
`tests/test_services/test_packages/test_ibs_request_lists.py` and
`tests/test_services/test_packages/test_ibs_request_lists_races.py`.

Expected values are transcribed from the specifications, never computed
with the module under test. Pydantic validation messages are transcribed
from the framework's documented output.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
import redis.asyncio as redis_asyncio
from httpx import AsyncClient

from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.config import settings
from app.core.enums import Role
from app.core.jwt import issue_token
from app.main import app
from app.models.ibs_request_action import IBSRequestAction
from app.models.session import Session
from app.models.ticket import Ticket
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import user_service
from app.services.packages import ibs_request_lists
from tests.support.inadmissible import REQUEST_INPUT_ERROR
from tests.support.ticket_api import (
    MAX_SEQUENCE,
    NOT_FOUND,
    UNAUTHENTICATED,
    locator,
    validation_error,
)

Factory = Callable[..., Awaitable[Any]]

_CODESTREAM: Final = "SUSE:SLE-15-SP6:Update"
_OTHER_CODESTREAM: Final = "SUSE:SLE-15-SP7:Update"
_CEST: Final = timezone(timedelta(hours=2))
_EMPTY_PAGE: Final = {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}
"""An empty first page with the default `per_page` (api-spec.md, Response
Format, Pagination)."""

_ITEM_FIELDS: Final = {
    "id",
    "action_type",
    "request_number",
    "state",
    "superseded_by_request_number",
    "package_name",
    "codestream_name",
    "incident_number",
    "ibs_url",
    "incident_url",
    "upstream_created_at",
    "upstream_updated_at",
}
"""ibs-submission-tracking.md, List Submission/Release Requests > Item
schema."""

_STATES: Final = [
    "new",
    "review",
    "accepted",
    "declined",
    "revoked",
    "superseded",
    "deleted",
]
"""ibs-submission-tracking.md, Common Query Rules (`state`)."""


@dataclass(frozen=True, slots=True)
class _Endpoint:
    """One of the two request list endpoints."""

    path: str
    """The OpenAPI path template."""
    service: str
    """The `ibs_request_lists` function the handler delegates to."""
    action_type: str
    anchor: str
    """The action column from which the factory derives `codestream_name`."""
    default_incident: int | None
    """The incident of a seeded action unless overridden."""
    item_schema: str
    list_schema: str

    def url(self, target: Ticket | str) -> str:
        ticket_id = target if isinstance(target, str) else locator(target)
        return self.path.format(ticket_id=ticket_id)


SUBMISSION = _Endpoint(
    "/api/v1/tickets/{ticket_id}/submission-requests",
    "list_submission_requests",
    "maintenance_incident",
    "target_release_project",
    None,
    "SubmissionRequestItem",
    "SubmissionRequestListResponse",
)
RELEASE = _Endpoint(
    "/api/v1/tickets/{ticket_id}/release-requests",
    "list_release_requests",
    "maintenance_release",
    "target_project",
    45001,
    "ReleaseRequestItem",
    "ReleaseRequestListResponse",
)
ENDPOINTS = [
    pytest.param(SUBMISSION, id="submission"),
    pytest.param(RELEASE, id="release"),
]
_OTHER = {SUBMISSION.path: RELEASE, RELEASE.path: SUBMISSION}


def _spy(monkeypatch: pytest.MonkeyPatch, endpoint: _Endpoint) -> AsyncMock:
    """Replace the endpoint's service function with a spy that must stay
    unused."""
    spy = AsyncMock()
    monkeypatch.setattr(ibs_request_lists, endpoint.service, spy)
    return spy


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


def _ids(response: httpx.Response) -> list[str]:
    return [item["id"] for item in response.json()["data"]]


@dataclass(frozen=True, slots=True)
class _Seed:
    """Builds Ticket tracks and correlated IBS request actions from the
    shared model factories."""

    package_factory: Factory
    track_factory: Factory
    request_factory: Factory
    action_factory: Factory
    correlation_factory: Factory

    async def track(
        self, ticket: Ticket, reference: str = _CODESTREAM
    ) -> TicketPackageTrack:
        """A track of `reference` under a fresh package of `ticket`."""
        package = await self.package_factory(ticket_id=ticket.id)
        track: TicketPackageTrack = await self.track_factory(
            ticket_package_id=package.id, reference=reference
        )
        return track

    async def action(
        self,
        endpoint: _Endpoint,
        *tracks: TicketPackageTrack,
        codestream: str = _CODESTREAM,
        request: dict[str, Any] | None = None,
        **fields: Any,
    ) -> IBSRequestAction:
        """An action of the endpoint's type, in its own request, correlated
        to every given track."""
        parent = await self.request_factory(**(request or {}))
        fields.setdefault("logical_package", "example-package")
        fields.setdefault("incident_number", endpoint.default_incident)
        action: IBSRequestAction = await self.action_factory(
            ibs_request_id=parent.id,
            action_type=endpoint.action_type,
            **{endpoint.anchor: codestream},
            **fields,
        )
        for track in tracks:
            await self.correlation_factory(
                ibs_request_action_id=action.id, ticket_package_track_id=track.id
            )
        return action


@pytest.fixture
def seed(
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ibs_request_factory: Factory,
    ibs_request_action_factory: Factory,
    ibs_request_action_track_factory: Factory,
) -> _Seed:
    return _Seed(
        ticket_package_factory,
        ticket_package_track_factory,
        ibs_request_factory,
        ibs_request_action_factory,
        ibs_request_action_track_factory,
    )


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The `User` behind `authenticated_client` and `admin_client`."""
    return _authenticated_user_and_client[0]


async def _correlated_ticket(
    ticket_factory: Factory, seed: _Seed, endpoint: _Endpoint, **columns: Any
) -> tuple[Ticket, IBSRequestAction]:
    """A Ticket with one correlated action of the endpoint's type."""
    ticket: Ticket = await ticket_factory(**columns)
    track = await seed.track(ticket)
    action = await seed.action(endpoint, track)
    return ticket, action


# ---------------------------------------------------------------------------
# Optional authentication (flow 1 step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestOptionalAuthentication:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_anonymous_request_on_a_non_confidential_ticket(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        ticket, action = await _correlated_ticket(ticket_factory, seed, endpoint)

        response = await client.get(endpoint.url(ticket))

        assert response.status_code == 200
        assert _ids(response) == [str(action.id)]
        assert "set-cookie" not in response.headers

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_valid_session_cookie_is_accepted(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        ticket, action = await _correlated_ticket(ticket_factory, seed, endpoint)

        response = await authenticated_client.get(endpoint.url(ticket))

        assert response.status_code == 200
        assert _ids(response) == [str(action.id)]

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_valid_api_key_is_accepted_and_processed(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        user_factory: Factory,
        api_key_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        """A valid selected API key authenticates the caller and runs the
        API-key operational effect (`last_used_at` debouncing)."""
        ticket, action = await _correlated_ticket(ticket_factory, seed, endpoint)
        user: User = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch)

        response = await client.get(
            endpoint.url(ticket), headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert _ids(response) == [str(action.id)]
        touch.assert_awaited_once()
        assert touch.await_args is not None
        assert touch.await_args.args[0] == key.id

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_eligible_jwt_triggers_sliding_refresh(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
        endpoint: _Endpoint,
    ) -> None:
        """Optional authentication is wired end-to-end, not accepted as a
        no-op (api-spec.md, Optional Authentication on Public Endpoints:
        "so browser activity on those endpoints participates in sliding
        session refresh")."""
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await client.get(
            endpoint.url(ticket), headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"headers": {"Authorization": "Bearer stl_ak_" + "0" * 32}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "unknown-api-key", "cookie"],
    )
    async def test_invalid_selected_credential_returns_401_before_the_service(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
        endpoint: _Endpoint,
    ) -> None:
        """Never a fallback to anonymous access, even for a non-confidential
        Ticket, a missing Ticket, or a malformed locator."""
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        spy = _spy(monkeypatch, endpoint)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        for target in (locator(ticket), f"SNTL-{MAX_SEQUENCE}", "not-a-ticket"):
            response = await client.get(
                endpoint.url(target), headers=credential.get("headers", {})
            )
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        spy.assert_not_awaited()

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_invalid_bearer_never_falls_back_to_a_valid_cookie(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        spy = _spy(monkeypatch, endpoint)

        response = await authenticated_client.get(
            endpoint.url(ticket), headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()


@pytest.mark.e2e
class TestRolesResolvedOnce:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_roles_are_loaded_once_per_request(
        self,
        admin_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        ticket, action = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy_roles(db: Any, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy_roles)

        response = await admin_client.get(endpoint.url(ticket))

        assert response.status_code == 200
        assert _ids(response) == [str(action.id)]
        assert calls == [authenticated_user.id]


# ---------------------------------------------------------------------------
# Ticket identifier resolution and accessibility (identical 404)
# ---------------------------------------------------------------------------

_LOCATOR_SHAPES = [
    pytest.param(lambda t: "SNTL-0", id="zero"),
    pytest.param(lambda t: "sntl-1", id="lowercase-literal"),
    pytest.param(lambda t: "SNTL-01", id="zero-padded-literal"),
    pytest.param(lambda t: "not-a-ticket", id="free-text"),
    pytest.param(lambda t: f"sntl-{t.sequence_id}", id="lowercase-of-existing"),
    pytest.param(lambda t: f"SNTL-0{t.sequence_id}", id="zero-padded-of-existing"),
    pytest.param(lambda t: f"SNTL-{MAX_SEQUENCE + 1}", id="overflow"),
    pytest.param(lambda t: str(t.id), id="ticket-uuid"),
    pytest.param(lambda t: f"SNTL-{MAX_SEQUENCE}", id="well-formed-missing"),
]
"""Every non-canonical or missing locator; the Ticket's canonical locator
would succeed (testing-strategy.md, Ticket identifier and read-contract
coverage)."""


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize("build_locator", _LOCATOR_SHAPES)
    async def test_invalid_or_missing_locator_returns_the_identical_404(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        build_locator: Callable[[Ticket], str],
        endpoint: _Endpoint,
    ) -> None:
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        assert (await client.get(endpoint.url(ticket))).status_code == 200

        response = await client.get(endpoint.url(build_locator(ticket)))

        assert response.status_code == 404
        assert response.content == NOT_FOUND

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_anonymous_read_of_a_confidential_ticket_is_the_identical_404(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        hidden, _ = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )

        inaccessible = await client.get(endpoint.url(hidden))
        missing = await client.get(endpoint.url(f"SNTL-{MAX_SEQUENCE}"))

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_non_entitled_authenticated_read_is_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """A role-less caller (effective scope `non_confidential`) without
        a grant or maintainership."""
        hidden, _ = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )

        inaccessible = await authenticated_client.get(endpoint.url(hidden))
        missing = await authenticated_client.get(endpoint.url(f"SNTL-{MAX_SEQUENCE}"))

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_invalid_state_on_an_inaccessible_ticket_is_the_identical_404(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """Parent accessibility precedes the invalid-filter empty page."""
        hidden, _ = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )

        responses = [
            await client.get(endpoint.url(target), params={"state": "bogus"})
            for target in (locator(hidden), f"SNTL-{MAX_SEQUENCE}", "not-a-ticket")
        ]

        assert [r.status_code for r in responses] == [404, 404, 404]
        assert {r.content for r in responses} == {NOT_FOUND}


# ---------------------------------------------------------------------------
# Accessibility of the reads through HTTP (canonical predicate branches)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAccessibility:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize(
        ("branch", "visible"),
        [
            pytest.param("grant", True, id="explicit-grant"),
            pytest.param("maintainer", True, id="included-package-maintainer"),
            pytest.param("restricted", False, id="restricted-analyst-denied"),
            pytest.param("excluded-maintainer", False, id="excluded-package"),
        ],
    )
    async def test_confidential_ticket_visibility_branches(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        user_role_factory: Factory,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        seed: _Seed,
        branch: str,
        visible: bool,
        endpoint: _Endpoint,
    ) -> None:
        ticket, action = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
        )
        if branch == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        elif branch in ("maintainer", "excluded-maintainer"):
            package = await ticket_package_factory(
                ticket_id=ticket.id,
                deleted_at=(
                    datetime(2026, 8, 20, tzinfo=UTC)
                    if branch == "excluded-maintainer"
                    else None
                ),
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.get(endpoint.url(ticket))

        if visible:
            assert response.status_code == 200
            assert _ids(response) == [str(action.id)]
        else:
            assert response.status_code == 404
            assert response.content == NOT_FOUND

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_scope_all_caller_reads_a_confidential_ticket(
        self,
        admin_client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """`admin` has scope `all`: no grant or maintainership needed."""
        ticket, action = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )

        response = await admin_client.get(endpoint.url(ticket))

        assert response.status_code == 200
        assert _ids(response) == [str(action.id)]


# ---------------------------------------------------------------------------
# Request validation (global 422)
# ---------------------------------------------------------------------------


def _query_error(name: str, msg: str, type_: str) -> dict[str, Any]:
    return {"loc": ["query", name], "msg": msg, "type": type_}


_GE_1 = ("Input should be greater than or equal to 1", "greater_than_equal")
_LE_INT_MAX = ("Input should be less than or equal to 2147483647", "less_than_equal")
_INT_PARSING = (
    "Input should be a valid integer, unable to parse string as an integer",
    "int_parsing",
)

_SHARED_INVALID = [
    pytest.param(
        "sort_by",
        "fictional_sort_field",
        "Input should be 'upstream_created_at' or 'upstream_updated_at'",
        "enum",
        id="sort-by-unknown",
    ),
    pytest.param(
        "sort_by",
        "created_at",
        "Input should be 'upstream_created_at' or 'upstream_updated_at'",
        "enum",
        id="sort-by-local-chronology",
    ),
    pytest.param(
        "sort_order",
        "sideways",
        "Input should be 'asc' or 'desc'",
        "enum",
        id="sort-order-unknown",
    ),
    pytest.param(
        "sort_order",
        "ASC",
        "Input should be 'asc' or 'desc'",
        "enum",
        id="sort-order-uppercase",
    ),
    pytest.param("page", "0", *_GE_1, id="page-0"),
    pytest.param("page", "2147483648", *_LE_INT_MAX, id="page-int-max-plus-1"),
    pytest.param("per_page", "0", *_GE_1, id="per-page-0"),
    pytest.param(
        "per_page",
        "101",
        "Input should be less than or equal to 100",
        "less_than_equal",
        id="per-page-101",
    ),
]

_INCIDENT_INVALID = [
    pytest.param("0", *_GE_1, id="zero"),
    pytest.param("-1", *_GE_1, id="negative"),
    pytest.param("abc", *_INT_PARSING, id="not-a-number"),
    pytest.param("1.5", *_INT_PARSING, id="fraction"),
    pytest.param("2147483648", *_LE_INT_MAX, id="int-max-plus-1"),
]

_LENGTH_LIMITED = ["package_name", "codestream_name", "state"]
_TOO_LONG = (
    "String should have at most 500 characters",
    "string_too_long",
)


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize(("name", "value", "msg", "type_"), _SHARED_INVALID)
    async def test_invalid_shared_parameter_returns_the_validation_envelope(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        value: str,
        msg: str,
        type_: str,
        endpoint: _Endpoint,
    ) -> None:
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        spy = _spy(monkeypatch, endpoint)

        response = await client.get(endpoint.url(ticket), params={name: value})

        assert response.status_code == 422
        assert response.json() == validation_error(_query_error(name, msg, type_))
        spy.assert_not_awaited()

    @pytest.mark.parametrize(("value", "msg", "type_"), _INCIDENT_INVALID)
    async def test_invalid_release_incident_number_returns_the_validation_envelope(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        value: str,
        msg: str,
        type_: str,
    ) -> None:
        """ibs-submission-tracking.md, List Release Requests: a positive
        integer of at most 2147483647."""
        ticket, _ = await _correlated_ticket(ticket_factory, seed, RELEASE)
        spy = _spy(monkeypatch, RELEASE)

        response = await client.get(
            RELEASE.url(ticket), params={"incident_number": value}
        )

        assert response.status_code == 422
        assert response.json() == validation_error(
            _query_error("incident_number", msg, type_)
        )
        spy.assert_not_awaited()

    async def test_incident_number_bounds_are_accepted(
        self, client: AsyncClient, ticket_factory: Factory, seed: _Seed
    ) -> None:
        ticket, _ = await _correlated_ticket(ticket_factory, seed, RELEASE)

        for value in ("1", "2147483647"):
            response = await client.get(
                RELEASE.url(ticket), params={"incident_number": value}
            )
            assert response.status_code == 200
            assert response.json() == _EMPTY_PAGE

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize("name", _LENGTH_LIMITED)
    async def test_string_parameter_over_500_characters_is_a_validation_error(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        endpoint: _Endpoint,
    ) -> None:
        """api-spec.md, Query Parameter Length Limit; exactly 500 is
        accepted (and matches nothing)."""
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)

        accepted = await client.get(endpoint.url(ticket), params={name: "x" * 500})
        spy = _spy(monkeypatch, endpoint)
        rejected = await client.get(endpoint.url(ticket), params={name: "x" * 501})

        assert accepted.status_code == 200
        assert accepted.json() == _EMPTY_PAGE
        assert rejected.status_code == 422
        assert rejected.json() == validation_error(_query_error(name, *_TOO_LONG))
        spy.assert_not_awaited()

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_nul_in_a_string_parameter_is_a_validation_error(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        monkeypatch: pytest.MonkeyPatch,
        endpoint: _Endpoint,
    ) -> None:
        """One representative of the shared check (api-spec.md, Inadmissible
        Characters in Request Input), before the scoped 404."""
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        spy = _spy(monkeypatch, endpoint)

        for target in (locator(ticket), f"SNTL-{MAX_SEQUENCE}"):
            response = await client.get(
                f"{endpoint.url(target)}?package_name=fictional%00package"
            )
            assert response.status_code == 422
            assert response.json() == validation_error(
                {"loc": ["query", "package_name"], **REQUEST_INPUT_ERROR}
            )
            assert "fictional" not in response.text

        spy.assert_not_awaited()

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_validation_precedes_the_scoped_not_found(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """An invalid `sort_by` on a missing, malformed, or inaccessible
        Ticket is the 422, not `TICKET_NOT_FOUND`."""
        hidden, _ = await _correlated_ticket(
            ticket_factory, seed, endpoint, is_confidential=True
        )
        expected = validation_error(
            _query_error(
                "sort_by",
                "Input should be 'upstream_created_at' or 'upstream_updated_at'",
                "enum",
            )
        )

        for target in (f"SNTL-{MAX_SEQUENCE}", "not-a-ticket", locator(hidden)):
            response = await authenticated_client.get(
                endpoint.url(target), params={"sort_by": "fictional_sort_field"}
            )
            assert response.status_code == 422
            assert response.json() == expected

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_rejected_values_are_never_echoed(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        ticket, _ = await _correlated_ticket(ticket_factory, seed, endpoint)
        params: list[dict[str, str]] = [
            {"sort_by": "fictional-marker"},
            {"sort_order": "fictional-marker"},
            {"page": "fictional-marker"},
            {"per_page": "fictional-marker"},
            {"package_name": "fictional-marker" + "x" * 500},
        ]
        if endpoint is RELEASE:
            params.append({"incident_number": "fictional-marker"})

        for query in params:
            response = await client.get(endpoint.url(ticket), params=query)
            assert response.status_code == 422
            assert "fictional-marker" not in response.text


# ---------------------------------------------------------------------------
# Enum filter and undeclared parameters
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestQueryShape:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize(
        "state",
        [
            pytest.param("bogus", id="unknown"),
            pytest.param("accepted,review", id="comma-separated"),
            pytest.param("ACCEPTED", id="wrong-case"),
            pytest.param("", id="empty"),
        ],
    )
    async def test_invalid_state_is_an_empty_page(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        state: str,
        endpoint: _Endpoint,
    ) -> None:
        """api-spec.md, Enum Filter Validation: an all-invalid filter set
        returns an empty result, never an error; the Ticket has an action
        in each of the named states."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        for value in ("accepted", "review"):
            await seed.action(endpoint, track, request={"state": value})

        response = await client.get(endpoint.url(ticket), params={"state": state})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_undeclared_parameters_are_ignored(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """Unknown names (including a lookalike `sort`) are ignored, even
        with a value a declared parameter of that name would reject."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        for _ in range(2):
            await seed.action(endpoint, track)

        plain = await client.get(endpoint.url(ticket))
        decorated = await client.get(
            endpoint.url(ticket),
            params={"foo": "bar", "sort": "x", "order": "sideways", "limit": "abc"},
        )

        assert plain.status_code == 200
        assert plain.json()["meta"]["total"] == 2
        assert decorated.status_code == 200
        assert decorated.content == plain.content

    @pytest.mark.parametrize(
        "value", ["abc", "45001", "x" * 501], ids=["non-integer", "valid", "too-long"]
    )
    async def test_incident_number_is_undeclared_on_the_submission_list(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        value: str,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        await seed.action(SUBMISSION, track, incident_number=45001)
        await seed.action(SUBMISSION, track, incident_number=45002)

        plain = await client.get(SUBMISSION.url(ticket))
        decorated = await client.get(
            SUBMISSION.url(ticket), params={"incident_number": value}
        )

        assert plain.status_code == 200
        assert plain.json()["meta"]["total"] == 2
        assert decorated.status_code == 200
        assert decorated.content == plain.content


# ---------------------------------------------------------------------------
# Envelope and exact item JSON
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEnvelope:
    async def test_submission_example_item(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
    ) -> None:
        """The List Submission Requests response example. The timestamps
        are persisted with a +02:00 offset and serialized as the same UTC
        instants with `Z`; raw source and target fields are absent."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        action = await seed.action(
            SUBMISSION,
            track,
            request={
                "request_number": 410001,
                "state": "accepted",
                "upstream_created_at": datetime(2026, 8, 10, 11, 15, tzinfo=_CEST),
                "upstream_updated_at": datetime(2026, 8, 10, 13, 30, tzinfo=_CEST),
            },
            source_project="SUSE:Fictional:Devel:Origin",
            source_package="example-package-origin-source",
            target_project="SUSE:Maintenance:45001",
            target_package="example-package.fictional_target_suffix",
            incident_number=45001,
        )

        response = await client.get(SUBMISSION.url(ticket))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "id": str(action.id),
                    "action_type": "maintenance_incident",
                    "request_number": 410001,
                    "state": "accepted",
                    "superseded_by_request_number": None,
                    "package_name": "example-package",
                    "codestream_name": "SUSE:SLE-15-SP6:Update",
                    "incident_number": 45001,
                    "ibs_url": "https://build.suse.de/request/show/410001",
                    "incident_url": (
                        "https://build.suse.de/project/show/SUSE:Maintenance:45001"
                    ),
                    "upstream_created_at": "2026-08-10T09:15:00Z",
                    "upstream_updated_at": "2026-08-10T11:30:00Z",
                }
            ],
            "meta": {"total": 1, "page": 1, "per_page": 20},
        }
        for raw in (
            "SUSE:Fictional:Devel:Origin",
            "example-package-origin-source",
            "fictional_target_suffix",
        ):
            assert raw not in response.text

    async def test_superseded_submission_without_incident(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
    ) -> None:
        """No established incident serializes `incident_number` and
        `incident_url` as `null`; a superseded request carries its
        successor."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        action = await seed.action(
            SUBMISSION,
            track,
            request={
                "request_number": 410002,
                "state": "superseded",
                "superseded_by_request_number": 410003,
                "upstream_created_at": datetime(2026, 8, 9, 7, 0, tzinfo=UTC),
                "upstream_updated_at": datetime(2026, 8, 9, 7, 45, 30, tzinfo=UTC),
            },
        )

        response = await client.get(SUBMISSION.url(ticket))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "id": str(action.id),
                    "action_type": "maintenance_incident",
                    "request_number": 410002,
                    "state": "superseded",
                    "superseded_by_request_number": 410003,
                    "package_name": "example-package",
                    "codestream_name": "SUSE:SLE-15-SP6:Update",
                    "incident_number": None,
                    "ibs_url": "https://build.suse.de/request/show/410002",
                    "incident_url": None,
                    "upstream_created_at": "2026-08-09T07:00:00Z",
                    "upstream_updated_at": "2026-08-09T07:45:30Z",
                }
            ],
            "meta": {"total": 1, "page": 1, "per_page": 20},
        }

    async def test_release_example_item(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
    ) -> None:
        """The List Release Requests response example."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        action = await seed.action(
            RELEASE,
            track,
            request={
                "request_number": 410101,
                "state": "review",
                "upstream_created_at": datetime(2026, 8, 11, 8, 0, tzinfo=UTC),
                "upstream_updated_at": datetime(2026, 8, 11, 8, 20, tzinfo=UTC),
            },
            source_project="SUSE:Maintenance:45001",
            source_package="example-package.fictional_source_suffix",
            target_package="example-package",
            incident_number=45001,
        )

        response = await client.get(RELEASE.url(ticket))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "id": str(action.id),
                    "action_type": "maintenance_release",
                    "request_number": 410101,
                    "state": "review",
                    "superseded_by_request_number": None,
                    "package_name": "example-package",
                    "codestream_name": "SUSE:SLE-15-SP6:Update",
                    "incident_number": 45001,
                    "ibs_url": "https://build.suse.de/request/show/410101",
                    "incident_url": (
                        "https://build.suse.de/project/show/SUSE:Maintenance:45001"
                    ),
                    "upstream_created_at": "2026-08-11T08:00:00Z",
                    "upstream_updated_at": "2026-08-11T08:20:00Z",
                }
            ],
            "meta": {"total": 1, "page": 1, "per_page": 20},
        }
        assert "fictional_source_suffix" not in response.text

    async def test_superseded_release_with_a_non_utc_offset(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        action = await seed.action(
            RELEASE,
            track,
            request={
                "request_number": 410102,
                "state": "superseded",
                "superseded_by_request_number": 410103,
                "upstream_created_at": datetime(2026, 8, 12, 1, 0, tzinfo=_CEST),
                "upstream_updated_at": datetime(2026, 8, 12, 1, 30, tzinfo=_CEST),
            },
            incident_number=45002,
        )

        response = await client.get(RELEASE.url(ticket))

        assert response.status_code == 200
        (item,) = response.json()["data"]
        assert set(item) == _ITEM_FIELDS
        assert item == {
            "id": str(action.id),
            "action_type": "maintenance_release",
            "request_number": 410102,
            "state": "superseded",
            "superseded_by_request_number": 410103,
            "package_name": "example-package",
            "codestream_name": "SUSE:SLE-15-SP6:Update",
            "incident_number": 45002,
            "ibs_url": "https://build.suse.de/request/show/410102",
            "incident_url": "https://build.suse.de/project/show/SUSE:Maintenance:45002",
            "upstream_created_at": "2026-08-11T23:00:00Z",
            "upstream_updated_at": "2026-08-11T23:30:00Z",
        }

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_accessible_ticket_without_correlated_actions_is_empty(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """The Ticket has a track but no correlated action of this type;
        another Ticket's action is never listed."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        await seed.action(_OTHER[endpoint.path], track)
        other: Ticket = await ticket_factory()
        await seed.action(endpoint, await seed.track(other))

        response = await client.get(endpoint.url(ticket))

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE


# ---------------------------------------------------------------------------
# Filters, sorting, and pagination reach the service (wiring only)
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 8, 12, 8, 0, tzinfo=UTC)


@pytest.mark.e2e
class TestQueryWiring:
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    async def test_filters_sorting_and_pagination_through_http(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        seed: _Seed,
        endpoint: _Endpoint,
    ) -> None:
        """Two actions match every filter; each other action differs in
        exactly one filtered field. `first` was created earlier but updated
        later than `second`, so the two sort fields order them oppositely.
        `first` correlates to both tracks and is still counted once."""
        ticket: Ticket = await ticket_factory()
        track = await seed.track(ticket)
        other_track = await seed.track(ticket, _OTHER_CODESTREAM)
        accepted = "accepted"
        first = await seed.action(
            endpoint,
            track,
            other_track,
            request={
                "state": accepted,
                "upstream_created_at": _T0,
                "upstream_updated_at": _T0 + timedelta(hours=5),
            },
        )
        second = await seed.action(
            endpoint,
            track,
            request={
                "state": accepted,
                "upstream_created_at": _T0 + timedelta(hours=1),
                "upstream_updated_at": _T0 + timedelta(hours=4),
            },
        )
        non_matching = [
            await seed.action(
                endpoint,
                other_track,
                codestream=_OTHER_CODESTREAM,
                request={"state": accepted},
            ),
            await seed.action(
                endpoint,
                track,
                logical_package="other-example-package",
                request={"state": accepted},
            ),
            await seed.action(endpoint, track, request={"state": "review"}),
        ]
        filters = {
            "package_name": "example-package",
            "codestream_name": _CODESTREAM,
            "state": accepted,
        }
        if endpoint is RELEASE:
            non_matching.append(
                await seed.action(
                    endpoint, track, request={"state": accepted}, incident_number=45002
                )
            )
            filters["incident_number"] = "45001"
        await seed.action(_OTHER[endpoint.path], track, request={"state": accepted})

        async def _get(**params: str) -> httpx.Response:
            response = await client.get(endpoint.url(ticket), params=params)
            assert response.status_code == 200
            return response

        unfiltered = await _get()
        assert set(_ids(unfiltered)) == {
            str(a.id) for a in (first, second, *non_matching)
        }
        assert unfiltered.json()["meta"] == {
            "total": 2 + len(non_matching),
            "page": 1,
            "per_page": 20,
        }

        expected = {
            (): [first, second],
            (("sort_order", "asc"),): [second, first],
            (("sort_by", "upstream_created_at"),): [second, first],
            (("sort_by", "upstream_created_at"), ("sort_order", "asc")): [
                first,
                second,
            ],
        }
        for ordering, actions in expected.items():
            response = await _get(**filters, **dict(ordering))
            assert _ids(response) == [str(a.id) for a in actions], ordering
            assert response.json()["meta"] == {"total": 2, "page": 1, "per_page": 20}

        second_page = await _get(**filters, page="2", per_page="1")
        assert _ids(second_page) == [str(second.id)]
        assert second_page.json()["meta"] == {"total": 2, "page": 2, "per_page": 1}

        beyond = await _get(**filters, page="3", per_page="1")
        assert beyond.json() == {
            "data": [],
            "meta": {"total": 2, "page": 3, "per_page": 1},
        }


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
        operation: dict[str, Any] = self._spec()["paths"][endpoint.path]["get"]
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

    def _parameters(self, endpoint: _Endpoint) -> dict[str, dict[str, Any]]:
        return {p["name"]: p for p in self._operation(endpoint)["parameters"]}

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_get_operation_with_summary_description_and_tag(
        self, endpoint: _Endpoint
    ) -> None:
        assert set(self._spec()["paths"][endpoint.path]) == {"get"}
        operation = self._operation(endpoint)
        assert operation["tags"] == ["IBS Submission Tracking"]
        assert operation["summary"]
        assert endpoint.action_type in operation["description"]
        assert "requestBody" not in operation

    @pytest.mark.parametrize(
        ("endpoint", "query"),
        [
            pytest.param(
                SUBMISSION,
                {
                    "package_name",
                    "codestream_name",
                    "state",
                    "sort_by",
                    "sort_order",
                    "page",
                    "per_page",
                },
                id="submission",
            ),
            pytest.param(
                RELEASE,
                {
                    "package_name",
                    "codestream_name",
                    "state",
                    "sort_by",
                    "sort_order",
                    "page",
                    "per_page",
                    "incident_number",
                },
                id="release",
            ),
        ],
    )
    def test_declared_parameters(self, endpoint: _Endpoint, query: set[str]) -> None:
        parameters = self._parameters(endpoint)

        assert {n for n, p in parameters.items() if p["in"] == "query"} == query
        assert {n for n, p in parameters.items() if p["in"] == "path"} == {"ticket_id"}
        ticket_id = parameters["ticket_id"]
        assert ticket_id["required"] is True
        assert ticket_id["schema"]["type"] == "string"
        for constraint in ("format", "pattern"):
            assert constraint not in ticket_id["schema"]
        for name in query:
            assert parameters[name]["required"] is False

        sort_by = parameters["sort_by"]["schema"]
        assert self._resolve(sort_by)["enum"] == [
            "upstream_created_at",
            "upstream_updated_at",
        ]
        assert sort_by["default"] == "upstream_updated_at"
        sort_order = parameters["sort_order"]["schema"]
        assert self._resolve(sort_order)["enum"] == ["asc", "desc"]
        assert sort_order["default"] == "desc"
        page = parameters["page"]["schema"]
        assert (page["minimum"], page["maximum"], page["default"]) == (
            1,
            2147483647,
            1,
        )
        per_page = parameters["per_page"]["schema"]
        assert (per_page["minimum"], per_page["maximum"], per_page["default"]) == (
            1,
            100,
            20,
        )

    def test_release_incident_number_is_a_bounded_integer(self) -> None:
        schema = self._parameters(RELEASE)["incident_number"]["schema"]
        (branch,) = [b for b in schema["anyOf"] if b != {"type": "null"}]

        assert branch == {"type": "integer", "minimum": 1, "maximum": 2147483647}

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_documented_responses(self, endpoint: _Endpoint) -> None:
        """200, the scoped `TICKET_NOT_FOUND`, and FastAPI's 422; no
        endpoint-specific error (ibs-submission-tracking.md, List Release
        Requests)."""
        responses = self._operation(endpoint)["responses"]

        assert set(responses) == {"200", "404", "422"}
        assert self._ref_name(responses["200"]["content"]) == endpoint.list_schema
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_list_envelope(self, endpoint: _Endpoint) -> None:
        envelope = self._schema(endpoint.list_schema)

        assert set(envelope["properties"]) == {"data", "meta"}
        assert set(envelope["required"]) == {"data", "meta"}
        data = envelope["properties"]["data"]
        assert data["type"] == "array"
        assert data["items"]["$ref"].endswith(f"/{endpoint.item_schema}")
        meta = self._resolve(envelope["properties"]["meta"])
        assert set(meta["properties"]) == {"total", "page", "per_page"}
        assert set(meta["required"]) == {"total", "page", "per_page"}

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_item_schema_has_exactly_the_documented_fields(
        self, endpoint: _Endpoint
    ) -> None:
        schema = self._schema(endpoint.item_schema)
        properties = schema["properties"]

        assert set(properties) == _ITEM_FIELDS
        assert set(schema["required"]) == _ITEM_FIELDS
        assert properties["id"]["format"] == "uuid"
        action_type = properties["action_type"]
        assert action_type.get("const", action_type.get("enum", [None])[0]) == (
            endpoint.action_type
        )
        assert len(action_type.get("enum", [action_type.get("const")])) == 1
        assert self._resolve(properties["state"])["enum"] == _STATES
        for name in ("request_number",):
            assert properties[name]["type"] == "integer"
        for name in ("package_name", "codestream_name", "ibs_url"):
            assert properties[name]["type"] == "string"
            assert "anyOf" not in properties[name]
        for name in ("upstream_created_at", "upstream_updated_at"):
            assert properties[name]["format"] == "date-time"
        assert properties["superseded_by_request_number"]["anyOf"] == [
            {"type": "integer"},
            {"type": "null"},
        ]

    def test_incident_is_nullable_only_on_the_submission_item(self) -> None:
        submission = self._schema(SUBMISSION.item_schema)["properties"]
        release = self._schema(RELEASE.item_schema)["properties"]

        assert submission["incident_number"]["anyOf"] == [
            {"type": "integer"},
            {"type": "null"},
        ]
        assert submission["incident_url"]["anyOf"] == [
            {"type": "string"},
            {"type": "null"},
        ]
        assert release["incident_number"]["type"] == "integer"
        assert release["incident_url"]["type"] == "string"
        for name in ("incident_number", "incident_url"):
            assert "anyOf" not in release[name]
