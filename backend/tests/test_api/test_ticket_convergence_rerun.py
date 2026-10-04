"""End-to-end tests for Rerun Ticket Convergence
(`POST /api/v1/tickets/{ticket_id}/rerun-reactivation`,
`backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Rerun Ticket Convergence,
TicketConvergenceDispatchResponse, Endpoint -> Schema Mapping),
docs/features/tickets/ticket-service.md (`dispatch_ticket_convergence()`;
Publication failure logging), docs/features/identity/rbac.md (Endpoint
Permission Map; Authorization Chain Evaluation Order: alternative
capabilities before any lookup), docs/api-spec.md (Ticket Identifier
Resolution, Ticket Accessibility Check, Infrastructure Dependency Errors:
`CELERY_UNAVAILABLE`), docs/features/tickets/ticket-audit-log.md (the
rerun creates no event), and docs/features/platform/testing-strategy.md
(Ticket Convergence Publication Handoff > explicit operator rerun, Control
signals and security; Ticket Accessibility; API Endpoints).

The service owns one short session from the overridable
`get_ticket_convergence_session_factory`, so the accepted and
service-mapped cases commit their rows (`committed_app_client`, explicit
cleanup) and point that factory at the test engine. The broker call
(`task_publication.publish_task`) is substituted by a recorder. The
locked-current races, the commit/close/lock-release ordering, commit
failures, and non-operational publication exceptions are proven once by
`tests/test_services/test_dispatch_ticket_convergence.py`; these tests
cover the HTTP contract.

Capability premise (app/core/permissions.py, rbac.md Predefined Roles):
`vulnerability_analyst` and `restricted_analyst` hold `triage_ticket`
without `manage_fetchers`; `admin` holds `manage_fetchers` without
`triage_ticket`, so each alternative is exercised alone.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.api.v1 import tickets as route
from app.core.enums import Capability, Role, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.permissions import get_capabilities
from app.main import app
from app.models.ticket import Ticket
from app.models.user import User
from app.services import task_publication, ticket_service
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
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/rerun-reactivation"
_INVALID_TRANSITION = {
    "code": "TICKET_INVALID_TRANSITION",
    "detail": "Ticket status transition is not allowed.",
}
_CELERY_UNAVAILABLE = {
    "code": "CELERY_UNAVAILABLE",
    "detail": "Ticket convergence could not be dispatched to the task broker",
}
_BROKER_URL = "redis://sentinel-user:fictional-secret@broker.example.test:6379/0"
"""A fictional credential-bearing broker URL carried by the injected error."""

_ACCEPTED = [TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED]
_REJECTED = [TicketStatus.NEW, TicketStatus.IGNORED, TicketStatus.DUPLICATED]


def _url(target: Ticket | str) -> str:
    return _PATH.format(
        ticket_id=target if isinstance(target, str) else locator(target)
    )


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})
        if self.error is not None:
            raise self.error


@pytest.fixture
def publish(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient]]:
    """Committed rows, a per-request committing client, and the dispatch's
    session factory bound to the test engine. `redis_client` isolates the
    session liveness cache used by authentication."""
    app.dependency_overrides[route.get_ticket_convergence_session_factory] = lambda: (
        real_session_factory
    )
    try:
        async with committed_app_client(db_session_factory) as (world, client):
            yield world, client
    finally:
        app.dependency_overrides.pop(route.get_ticket_convergence_session_factory, None)


async def _ticket(world: CommittedApp, status: TicketStatus, **columns: Any) -> Ticket:
    """A committed CVE-less Ticket in `status` (a `Duplicated` one is linked
    to a committed `Analysis` target)."""
    if status is TicketStatus.DUPLICATED:
        target = await world.ticket(status=TicketStatus.ANALYSIS.value)
        columns["duplicate_of_id"] = target.id
    return await world.ticket(status=status.value, **columns)


async def _state(world: CommittedApp, ticket_id: uuid.UUID) -> dict[str, Any]:
    """Every persisted Ticket column, including `updated_at`."""
    db = await world.session()
    row = (
        await db.execute(select(Ticket.__table__).where(Ticket.id == ticket_id))
    ).one()
    await db.rollback()
    return dict(row._mapping)


async def _events(world: CommittedApp, ticket_id: uuid.UUID) -> int:
    db = await world.session()
    count = await event_count(db, ticket_id)
    await db.rollback()
    return count


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the dispatch with spies that must stay
    unused."""
    resolver = AsyncMock()
    dispatch = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, "dispatch_ticket_convergence", dispatch)
    return resolver, dispatch


# ---------------------------------------------------------------------------
# Authentication and alternative capabilities (before any lookup)
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
    async def test_credential_failure_returns_401_before_capability_or_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        publish: _Publish,
        headers: dict[str, str],
    ) -> None:
        ticket: Ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        resolver, dispatch = _forbid_lookups(monkeypatch)

        for path in (_url(ticket), _url(f"SNTL-{MAX_SEQUENCE}")):
            response = await client.post(path, headers=headers)
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        dispatch.assert_not_awaited()
        assert publish.calls == []

    async def test_caller_with_neither_capability_gets_the_generic_403_before_lookup(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        publish: _Publish,
    ) -> None:
        """A role-less caller holds neither `triage_ticket` nor
        `manage_fetchers`: the same 403 for an existing and a missing
        Ticket, without resolving either."""
        ticket: Ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value)
        resolver, dispatch = _forbid_lookups(monkeypatch)

        existing = await authenticated_client.post(_url(ticket))
        missing = await authenticated_client.post(_url(f"SNTL-{MAX_SEQUENCE}"))
        malformed = await authenticated_client.post(_url("not-a-ticket"))

        assert existing.status_code == missing.status_code == malformed.status_code
        assert existing.status_code == 403
        assert existing.content == missing.content == malformed.content
        assert existing.json() == FORBIDDEN
        resolver.assert_not_awaited()
        dispatch.assert_not_awaited()
        assert publish.calls == []

    @pytest.mark.parametrize(
        ("role", "capability"),
        [
            pytest.param(
                Role.VULNERABILITY_ANALYST, Capability.TRIAGE_TICKET, id="va-triage"
            ),
            pytest.param(
                Role.RESTRICTED_ANALYST, Capability.TRIAGE_TICKET, id="ra-triage"
            ),
            pytest.param(Role.ADMIN, Capability.MANAGE_FETCHERS, id="admin-fetchers"),
        ],
    )
    async def test_either_capability_alone_is_accepted(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        publish: _Publish,
        role: Role,
        capability: Capability,
    ) -> None:
        alternatives = {Capability.TRIAGE_TICKET, Capability.MANAGE_FETCHERS}
        assert alternatives & get_capabilities([role]) == {capability}
        world, client = committed_app
        _, headers = await world.va_headers(role=role)
        ticket = await _ticket(world, TicketStatus.ANALYSIS)

        response = await client.post(_url(ticket), headers=headers)

        assert response.status_code == 202
        assert response.json()["data"]["ticket_id"] == locator(ticket)
        [call] = publish.calls
        assert call["kwargs"] == {"ticket_id": str(ticket.id)}
        assert response.json()["data"]["task_id"] == call["task_id"]


# ---------------------------------------------------------------------------
# Accepted dispatch (202 TicketConvergenceDispatchResponse)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAcceptedDispatch:
    @pytest.mark.parametrize("status", _ACCEPTED, ids=lambda s: s.value)
    async def test_eligible_status_returns_202_with_the_published_task_id(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        publish: _Publish,
        status: TicketStatus,
    ) -> None:
        """The exact body: the canonical `SNTL-{n}` and the root task UUID
        that was published for the internal Ticket UUID. The Ticket row
        (including `updated_at`) is unchanged and no audit event exists;
        the request publishes nothing else."""
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, status, severity_manual="High")
        before = await _state(world, ticket.id)

        response = await client.post(_url(ticket), headers=headers)

        assert response.status_code == 202
        [call] = publish.calls
        assert (call["task_name"], call["kwargs"]) == (
            "run_ticket_convergence",
            {"ticket_id": str(ticket.id)},
        )
        assert response.json() == {
            "data": {"ticket_id": locator(ticket), "task_id": call["task_id"]}
        }
        assert uuid.UUID(call["task_id"]).version == 7
        assert str(ticket.id) not in response.text
        assert await _state(world, ticket.id) == before
        assert await _events(world, ticket.id) == 0

    async def test_request_body_is_ignored(
        self, committed_app: tuple[CommittedApp, AsyncClient], publish: _Publish
    ) -> None:
        """No request body is defined: a supplied one neither selects
        another Ticket nor changes the dispatch."""
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, TicketStatus.ANALYZED)
        other = await _ticket(world, TicketStatus.ANALYSIS)

        response = await client.post(
            _url(ticket),
            json={"ticket_id": locator(other), "status": "new", "task_id": "x"},
            headers=headers,
        )

        assert response.status_code == 202
        [call] = publish.calls
        assert call["kwargs"] == {"ticket_id": str(ticket.id)}
        assert response.json()["data"]["ticket_id"] == locator(ticket)

    async def test_repeated_requests_are_each_accepted_with_a_new_task(
        self, committed_app: tuple[CommittedApp, AsyncClient], publish: _Publish
    ) -> None:
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, TicketStatus.RESOLVED)

        first = await client.post(_url(ticket), headers=headers)
        second = await client.post(_url(ticket), headers=headers)

        assert first.status_code == second.status_code == 202
        task_ids = [first.json()["data"]["task_id"], second.json()["data"]["task_id"]]
        assert task_ids == [call["task_id"] for call in publish.calls]
        assert len(set(task_ids)) == 2
        assert await _events(world, ticket.id) == 0


# ---------------------------------------------------------------------------
# Ticket accessibility and anti-enumeration (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize(
        "build_locator",
        [
            pytest.param(lambda t: "not-a-ticket", id="malformed"),
            *[pytest.param(build, id=name) for name, build in INVALID_LOCATORS],
        ],
    )
    async def test_invalid_uuid_or_missing_locator_returns_the_identical_404(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        publish: _Publish,
        build_locator: Callable[[Ticket], str],
    ) -> None:
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, TicketStatus.ANALYSIS)

        response = await client.post(_url(build_locator(ticket)), headers=headers)

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert publish.calls == []

    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        publish: _Publish,
    ) -> None:
        """Holding `triage_ticket` grants no visibility: a confidential
        Ticket without a grant or maintained package is not found for a
        `restricted_analyst` (`non_confidential`) caller, exactly like a
        missing one."""
        world, client = committed_app
        _, headers = await world.va_headers(role=Role.RESTRICTED_ANALYST)
        hidden = await _ticket(world, TicketStatus.ANALYSIS, is_confidential=True)
        before = await _state(world, hidden.id)

        inaccessible = await client.post(_url(hidden), headers=headers)
        missing = await client.post(_url(f"SNTL-{MAX_SEQUENCE}"), headers=headers)

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert publish.calls == []
        assert await _state(world, hidden.id) == before
        assert await _events(world, hidden.id) == 0

    async def test_locked_denial_after_preliminary_access_is_the_identical_404(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        publish: _Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The preliminary SNTL resolution passes, then the service's
        locked-current check denies (the independent-session races are
        proven by the service tests): the handler maps that denial to the
        same `404 TICKET_NOT_FOUND` body."""
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, TicketStatus.ANALYSIS)
        dispatch = AsyncMock(side_effect=TicketNotFoundError())
        monkeypatch.setattr(ticket_service, "dispatch_ticket_convergence", dispatch)

        response = await client.post(_url(ticket), headers=headers)

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        dispatch.assert_awaited_once()
        assert dispatch.await_args is not None
        assert dispatch.await_args.kwargs["ticket_id"] == ticket.id
        assert publish.calls == []


# ---------------------------------------------------------------------------
# Service error mappings
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestErrorMappings:
    @pytest.mark.parametrize("status", _REJECTED, ids=lambda s: s.value)
    async def test_ineligible_status_is_an_invalid_transition_without_publication(
        self,
        committed_app: tuple[CommittedApp, AsyncClient],
        publish: _Publish,
        status: TicketStatus,
    ) -> None:
        """The manual-zone statuses map to `TICKET_INVALID_TRANSITION`,
        never `TICKET_NOT_MUTABLE` (no operability guard)."""
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, status)
        before = await _state(world, ticket.id)

        response = await client.post(_url(ticket), headers=headers)

        assert response.status_code == 409
        assert response.json() == _INVALID_TRANSITION
        assert publish.calls == []
        assert await _state(world, ticket.id) == before
        assert await _events(world, ticket.id) == 0

    async def test_broker_operational_error_returns_the_sanitized_503(
        self, committed_app: tuple[CommittedApp, AsyncClient], publish: _Publish
    ) -> None:
        """`acceptance_unconfirmed`: the fixed `CELERY_UNAVAILABLE` body with
        no exception text, URL, host, port, or credential; exactly one
        request-owned `ticket_convergence_dispatch_failed` ERROR, and
        neither the automatic publication-failure event nor the generic
        post-commit callback log."""
        world, client = committed_app
        _, headers = await world.va_headers()
        ticket = await _ticket(world, TicketStatus.ANALYZED)
        before = await _state(world, ticket.id)
        publish.error = BrokerOperationalError(f"{_BROKER_URL} timed out")

        with capture_logs() as logs:
            response = await client.post(_url(ticket), headers=headers)

        assert response.status_code == 503
        assert response.json() == _CELERY_UNAVAILABLE
        for fragment in (
            "fictional-secret",
            "sentinel-user",
            "broker.example.test",
            "6379",
            "redis://",
            "timed out",
            "Traceback",
        ):
            assert fragment not in response.text
        assert len(publish.calls) == 1
        failures = [
            log
            for log in logs
            if log["event"]
            in {
                "ticket_convergence_dispatch_failed",
                "ticket_convergence_publication_failed",
                "post_commit_callback_failed",
            }
        ]
        assert failures == [
            {
                "event": "ticket_convergence_dispatch_failed",
                "log_level": "error",
                "ticket_id": str(ticket.id),
                "cause": "broker_operational_error",
            }
        ]
        assert "fictional-secret" not in repr(logs)
        assert await _state(world, ticket.id) == before
        assert await _events(world, ticket.id) == 0


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    @staticmethod
    def _spec() -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_operation_declares_no_request_body_and_a_202_response(self) -> None:
        operation = self._spec()["paths"][_PATH]["post"]
        responses = operation["responses"]

        assert operation["tags"] == ["Tickets"]
        assert operation["summary"] == "Rerun Ticket Convergence"
        assert "requestBody" not in operation
        assert "200" not in responses
        assert (
            self._ref_name(responses["202"]["content"])
            == "TicketConvergenceDispatchDataResponse"
        )

    def test_error_responses_are_documented_with_the_error_envelope(self) -> None:
        responses = self._spec()["paths"][_PATH]["post"]["responses"]

        for code, error in (
            ("404", "TICKET_NOT_FOUND"),
            ("409", "TICKET_INVALID_TRANSITION"),
            ("503", "CELERY_UNAVAILABLE"),
        ):
            assert self._ref_name(responses[code]["content"]) == "ErrorResponse"
            assert error in responses[code]["description"]
        assert "TICKET_NOT_MUTABLE" not in responses["409"]["description"]

    def test_response_schema_has_exactly_the_ticket_and_task_ids(self) -> None:
        schemas = self._spec()["components"]["schemas"]
        envelope = schemas["TicketConvergenceDispatchDataResponse"]
        body = schemas["TicketConvergenceDispatchResponse"]

        assert envelope["required"] == ["data"]
        assert envelope["properties"]["data"]["$ref"].endswith(
            "/TicketConvergenceDispatchResponse"
        )
        assert set(body["properties"]) == {"ticket_id", "task_id"}
        assert sorted(body["required"]) == ["task_id", "ticket_id"]
        assert {p["type"] for p in body["properties"].values()} == {"string"}


@pytest.mark.unit
def test_session_factory_provider_returns_the_production_factory() -> None:
    """Without an override the dispatch uses the production session
    factory (no I/O at resolution)."""
    from app.database import async_session_factory

    assert route.get_ticket_convergence_session_factory() is async_session_factory
