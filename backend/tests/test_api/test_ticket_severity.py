"""End-to-end tests for the Set Severity Manual endpoint
(`PATCH /api/v1/tickets/{ticket_id}/severity`, `backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Set Severity Manual, Response Schemas >
TicketDetail, Endpoint -> Schema Mapping, Mutability Guard),
docs/features/tickets/ticket-mutations.md (`set_severity_manual()`),
docs/features/tickets/ticket-service.md (`get_ticket_detail()` mutation
assembly), docs/features/tickets/ticket-deadlines.md (SLA Tier, Due Dates),
docs/api-spec.md (Authorization Chain Evaluation Order flow 3, Global
Responses, Ticket Accessibility Check, Manual-Zone Mutability Guard, Ticket
Identifier Resolution, Partial Update Semantics), and
docs/features/platform/testing-strategy.md (Ticket Accessibility). The
service-level mutation matrix lives in tests/test_services; these tests cover
the HTTP boundary.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import tickets as route
from app.core.enums import (
    Role,
    SessionCreationReason,
    Severity,
    TicketAuditEventType,
    TicketPriority,
    TicketStatus,
)
from app.core.identifiers import format_ticket_id
from app.database import get_db
from app.main import app
from app.models.session import Session as SessionRow
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_mutations, ticket_service, user_service
from app.services.session_service import create_session
from app.services.ticket_service import TicketDetailProjection

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/severity"
_NOT_FOUND = b'{"code":"TICKET_NOT_FOUND","detail":"Ticket not found."}'
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_SEVERITY_DERIVED = {
    "code": "TICKET_SEVERITY_DERIVED",
    "detail": "Ticket severity is derived from CVSS assessments.",
}
_NOT_MUTABLE = {"code": "TICKET_NOT_MUTABLE", "detail": "Ticket is not mutable."}
_LITERAL_MESSAGE = "Input should be 'critical', 'high', 'medium', 'low' or 'none'"
_CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, tzinfo=UTC)
_UPDATED_AT = datetime(2026, 3, 10, 16, 0, tzinfo=UTC)
_MAX_SEQUENCE = 2_147_483_647
# ticket-deadlines.md (Due Dates): field -> cumulative milestone percent.
_DUE_MILESTONES = {
    "triage_due_at": 10,
    "submission_due_at": 60,
    "um_due_at": 70,
    "qa_due_at": 100,
    "release_due_at": 100,
}
_SECONDS_PER_DAY_PERCENT = 864


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _locator(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _url(target: Ticket | str) -> str:
    locator = target if isinstance(target, str) else _locator(target)
    return _PATH.format(ticket_id=locator)


def _iso(value: datetime) -> str:
    """The API's UTC wire format for a datetime."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _due_dates(created_at: datetime, sla_days: int | None) -> dict[str, str | None]:
    """The five Ticket due dates for an SLA tier (`None`: no SLA)."""
    if sla_days is None:
        return dict.fromkeys(_DUE_MILESTONES)
    return {
        field: _iso(
            created_at
            + timedelta(seconds=sla_days * _SECONDS_PER_DAY_PERCENT * milestone)
        )
        for field, milestone in _DUE_MILESTONES.items()
    }


type EventRow = tuple[str, uuid.UUID | None, str | None, str | None, str | None]


async def _events(db: AsyncSession, ticket_id: uuid.UUID) -> list[EventRow]:
    """The Ticket's audit events in creation order."""
    rows = (
        await db.execute(
            select(
                TicketAuditEvent.event_type,
                TicketAuditEvent.user_id,
                TicketAuditEvent.old_value,
                TicketAuditEvent.new_value,
                TicketAuditEvent.comment,
            )
            .where(TicketAuditEvent.ticket_id == ticket_id)
            .order_by(TicketAuditEvent.id)
        )
    ).all()
    return [tuple(row) for row in rows]


async def _event_count(db: AsyncSession, *ticket_ids: uuid.UUID) -> int:
    """The number of audit events of the given Tickets."""
    return (
        await db.execute(
            select(func.count(TicketAuditEvent.id)).where(
                TicketAuditEvent.ticket_id.in_(ticket_ids)
            )
        )
    ).scalar_one()


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted Ticket columns touched by the mutation."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.severity_manual,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.assignee_id,
                Ticket.created_at,
                Ticket.updated_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return dict(row._mapping)


async def _user_reference(db: AsyncSession, user_id: uuid.UUID) -> dict[str, Any]:
    row = (
        await db.execute(
            select(User.username, User.full_name, User.active).where(User.id == user_id)
        )
    ).one()
    return {
        "id": str(user_id),
        "username": row.username,
        "full_name": row.full_name,
        "active": row.active,
    }


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_mutations, "set_severity_manual", mutation)
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
async def va_commit_client(
    db_session: AsyncSession,
    user_factory: Factory,
    user_role_factory: Factory,
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[tuple[User, AsyncClient]]:
    """A vulnerability-analyst client whose `get_db` override commits after
    the handler and rolls back when an exception escapes, like production
    `app.database.get_db`.

    The shared `client` fixture never commits or rolls back, so it cannot
    prove the rollback of a failed mutation. Commits and rollbacks act on
    `db_session`'s savepoint; the outer test transaction still reverts
    everything at teardown. `raise_app_exceptions=False` returns the
    global 500 envelope instead of re-raising into the test.
    """
    user = await user_factory(username="alice.va", full_name="Alice Analyst")
    await user_role_factory(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
    created = await create_session(
        db_session,
        user,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as commit_client:
            commit_client.cookies.set(SESSION_COOKIE_NAME, created.token)
            yield user, commit_client
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Authentication and capability (flow 3, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthentication:
    async def test_missing_credential_returns_401_before_any_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public: Ticket = await ticket_factory()
        hidden: Ticket = await ticket_factory(is_confidential=True)
        resolver, mutation = _forbid_lookups(monkeypatch)
        role_loader = AsyncMock()
        monkeypatch.setattr(user_service, "get_user_roles", role_loader)

        bodies = []
        for locator in (
            _locator(public),
            _locator(hidden),
            f"SNTL-{_MAX_SEQUENCE}",
            "not-a-ticket",
        ):
            response = await client.patch(_url(locator), json={"severity": "high"})
            assert response.status_code == 401, locator
            bodies.append(response.content)

        assert len(set(bodies)) == 1
        assert response.json() == _UNAUTHENTICATED
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        role_loader.assert_not_awaited()

    async def test_invalid_credential_returns_401_before_any_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target: Ticket = await ticket_factory()
        resolver, mutation = _forbid_lookups(monkeypatch)

        for locator in (_locator(target), f"SNTL-{_MAX_SEQUENCE}"):
            response = await client.patch(
                _url(locator),
                json={"severity": "high"},
                headers={"Authorization": "Bearer invalid-token"},
            )
            assert response.status_code == 401
            assert response.json() == _UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()


@pytest.mark.e2e
class TestCapability:
    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_triage_ticket_gets_the_generic_403_before_lookup(
        self,
        roles: list[Role],
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The caller can see the public and the granted confidential Ticket,
        yet every locator (visible, missing, malformed, inaccessible)
        returns the identical 403 without a Ticket lookup."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        public: Ticket = await ticket_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=granted.id, user_id=authenticated_user.id
        )
        resolver, mutation = _forbid_lookups(monkeypatch)

        bodies = []
        for locator in (
            _locator(public),
            _locator(granted),
            _locator(hidden),
            f"SNTL-{_MAX_SEQUENCE}",
            "sntl-1",
        ):
            response = await authenticated_client.patch(
                _url(locator), json={"severity": "high"}
            )
            assert response.status_code == 403, locator
            assert response.json() == _FORBIDDEN, locator
            bodies.append(response.content)

        assert len(set(bodies)) == 1
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _event_count(db_session, public.id, granted.id, hidden.id) == 0

    async def test_visibility_without_capability_reads_but_cannot_mutate(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=target.id, user_id=authenticated_user.id
        )

        read = await authenticated_client.get(f"/api/v1/tickets/{_locator(target)}")
        mutate = await authenticated_client.patch(
            _url(target), json={"severity": "low"}
        )

        assert read.status_code == 200
        assert mutate.status_code == 403
        assert mutate.json() == _FORBIDDEN
        assert (await _state(db_session, target.id))["severity_manual"] is None


@pytest.mark.e2e
class TestCallerResolution:
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
            _url(target), json={"severity": "low"}
        )

        assert response.status_code == 200
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


_MALFORMED_LOCATORS: list[tuple[str, Callable[[Ticket], str]]] = [
    ("lowercase-prefix", lambda t: f"sntl-{t.sequence_id}"),
    ("zero", lambda t: "SNTL-0"),
    ("zero-padded", lambda t: f"SNTL-0{t.sequence_id}"),
    ("leading-whitespace", lambda t: f" SNTL-{t.sequence_id}"),
    ("trailing-whitespace", lambda t: f"SNTL-{t.sequence_id} "),
    ("signed", lambda t: f"SNTL-+{t.sequence_id}"),
    ("overflow", lambda t: f"SNTL-{_MAX_SEQUENCE + 1}"),
    ("missing-digits", lambda t: "SNTL-"),
    ("ticket-uuid", lambda t: str(t.id)),
    ("well-formed-missing", lambda t: f"SNTL-{_MAX_SEQUENCE}"),
]


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize(
        "build_locator",
        [pytest.param(build, id=name) for name, build in _MALFORMED_LOCATORS],
    )
    async def test_invalid_or_missing_locator_returns_the_identical_404(
        self,
        build_locator: Callable[[Ticket], str],
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory()
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            _url(build_locator(target)), json={"severity": "high"}
        )

        assert response.status_code == 404
        assert response.content == _NOT_FOUND
        assert await _state(db_session, target.id) == before
        assert await _event_count(db_session, target.id) == 0

    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """A restricted analyst holds `triage_ticket`, but the capability
        never makes a confidential Ticket without a grant visible."""
        hidden: Ticket = await ticket_factory(is_confidential=True)
        before = await _state(db_session, hidden.id)

        inaccessible = await authenticated_client.patch(
            _url(hidden), json={"severity": "high"}
        )
        missing = await authenticated_client.patch(
            _url(f"SNTL-{_MAX_SEQUENCE}"), json={"severity": "high"}
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == _NOT_FOUND
        assert inaccessible.headers.get("content-length") == missing.headers.get(
            "content-length"
        )
        assert await _state(db_session, hidden.id) == before
        assert await _event_count(db_session, hidden.id) == 0

    async def test_access_lost_after_the_preliminary_check_is_404_without_effect(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The grant disappears after the preliminary dependency check but
        before the mutation locks the Ticket; locked-current accessibility
        decides (api-spec.md, Authorization Chain Evaluation Order, flow 3)."""
        target: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=target.id, user_id=ra_user.id)
        before = await _state(db_session, target.id)
        original = ticket_mutations.set_severity_manual

        async def _revoke_then_mutate(db: AsyncSession, **kwargs: Any) -> Ticket:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == target.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_mutations, "set_severity_manual", _revoke_then_mutate
        )

        response = await authenticated_client.patch(
            _url(target), json={"severity": "high"}
        )

        assert response.status_code == 404
        assert response.content == _NOT_FOUND
        assert await _state(db_session, target.id) == before
        assert await _event_count(db_session, target.id) == 0


# ---------------------------------------------------------------------------
# Request validation (global 422)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        ("body", "errors"),
        [
            pytest.param(
                {},
                [
                    {
                        "loc": ["body", "severity"],
                        "msg": "Field required",
                        "type": "missing",
                    }
                ],
                id="missing-field",
            ),
            *[
                pytest.param(
                    {"severity": value},
                    [
                        {
                            "loc": ["body", "severity"],
                            "msg": _LITERAL_MESSAGE,
                            "type": "literal_error",
                        }
                    ],
                    id=f"invalid-{value!r}",
                )
                for value in ("High", "unresolved", "critical ", "", 1, True)
            ],
        ],
    )
    async def test_invalid_body_returns_the_validation_envelope_without_effect(
        self,
        body: dict[str, Any],
        errors: list[dict[str, Any]],
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target: Ticket = await ticket_factory()
        before = await _state(db_session, target.id)
        mutation = AsyncMock()
        monkeypatch.setattr(ticket_mutations, "set_severity_manual", mutation)

        response = await authenticated_client.patch(_url(target), json=body)

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": errors,
        }
        mutation.assert_not_awaited()
        assert await _state(db_session, target.id) == before
        assert await _event_count(db_session, target.id) == 0

    async def test_absent_body_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory()

        response = await authenticated_client.patch(_url(target))

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [{"loc": ["body"], "msg": "Field required", "type": "missing"}],
        }


# ---------------------------------------------------------------------------
# Successful mutation (200 TicketDetail)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSetSeverity:
    async def test_va_sets_severity_on_a_new_unassigned_ticket(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(
            created_at=_CREATED_AT, updated_at=_UPDATED_AT
        )
        assignee = await _user_reference(db_session, va_user.id)

        response = await authenticated_client.patch(
            _url(target), json={"severity": "high"}
        )

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        data = body["data"]
        assert isinstance(data.pop("updated_at"), str)
        assert data == {
            "ticket_id": format_ticket_id(target.sequence_id),
            "status": "analysis",
            "severity": "high",
            "priority": "p3",
            "priority_automatic": "p3",
            "priority_override": None,
            "assignee": assignee,
            "cve": None,
            "duplicate_of_ticket_id": None,
            "is_confidential": False,
            "coordinated_release_at": None,
            **_due_dates(_CREATED_AT, 30),
            "packages": [],
            "created_at": _iso(_CREATED_AT),
        }
        state = await _state(db_session, target.id)
        assert state["status"] == TicketStatus.ANALYSIS.value
        assert state["severity_manual"] == Severity.HIGH.value
        assert state["priority_auto"] == TicketPriority.P3.value
        assert state["priority_override"] is None
        assert state["assignee_id"] == va_user.id
        assert state["created_at"] == _CREATED_AT
        assert await _events(db_session, target.id) == [
            (
                TicketAuditEventType.ASSIGNMENT.value,
                va_user.id,
                None,
                assignee["username"],
                None,
            ),
            (
                TicketAuditEventType.STATUS_CHANGE.value,
                None,
                TicketStatus.NEW.value,
                TicketStatus.ANALYSIS.value,
                None,
            ),
            (
                TicketAuditEventType.SEVERITY_CHANGED.value,
                va_user.id,
                None,
                Severity.HIGH.value,
                None,
            ),
            (
                TicketAuditEventType.PRIORITY_CHANGED.value,
                None,
                None,
                TicketPriority.P3.value,
                None,
            ),
        ]

    async def test_none_label_and_json_null_are_distinct(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(created_at=_CREATED_AT)

        labelled = await authenticated_client.patch(
            _url(target), json={"severity": "none"}
        )
        labelled_state = await _state(db_session, target.id)
        cleared = await authenticated_client.patch(
            _url(target), json={"severity": None}
        )
        cleared_state = await _state(db_session, target.id)

        assert labelled.status_code == cleared.status_code == 200
        labelled_data = labelled.json()["data"]
        assert labelled_data["severity"] == "none"
        assert labelled_data["priority"] == labelled_data["priority_automatic"] == "p4"
        assert {f: labelled_data[f] for f in _DUE_MILESTONES} == _due_dates(
            _CREATED_AT, None
        )
        assert labelled_state["severity_manual"] == Severity.NONE.value
        assert labelled_state["priority_auto"] == TicketPriority.P4.value

        cleared_data = cleared.json()["data"]
        assert cleared_data["severity"] is None
        assert cleared_data["priority"] is None
        assert cleared_data["priority_automatic"] is None
        assert cleared_data["status"] == "analysis"
        assert {f: cleared_data[f] for f in _DUE_MILESTONES} == _due_dates(
            _CREATED_AT, 30
        )
        assert cleared_state["severity_manual"] is None
        assert cleared_state["priority_auto"] is None

        events = await _events(db_session, target.id)
        assert [e[0] for e in events[:2]] == [
            TicketAuditEventType.ASSIGNMENT.value,
            TicketAuditEventType.STATUS_CHANGE.value,
        ]
        assert events[2:] == [
            (
                TicketAuditEventType.SEVERITY_CHANGED.value,
                va_user.id,
                None,
                Severity.NONE.value,
                None,
            ),
            (
                TicketAuditEventType.PRIORITY_CHANGED.value,
                None,
                None,
                TicketPriority.P4.value,
                None,
            ),
            (
                TicketAuditEventType.SEVERITY_CHANGED.value,
                va_user.id,
                Severity.NONE.value,
                None,
                None,
            ),
            (
                TicketAuditEventType.PRIORITY_CHANGED.value,
                None,
                TicketPriority.P4.value,
                None,
                None,
            ),
        ]

    @pytest.mark.parametrize(
        ("stored", "priority", "requested"),
        [
            pytest.param(
                Severity.HIGH.value, TicketPriority.P3.value, "high", id="high"
            ),
        ],
    )
    async def test_same_value_is_a_no_op_with_unchanged_detail(
        self,
        stored: str | None,
        priority: str | None,
        requested: str | None,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """No assignment, status change, write, or event, even though the
        caller is an active VA and the Ticket is New and unassigned."""
        target: Ticket = await ticket_factory(
            severity_manual=stored,
            priority_auto=priority,
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"severity": requested}
        )
        detail = await authenticated_client.get(f"/api/v1/tickets/{_locator(target)}")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data == detail.json()["data"]
        assert data["status"] == "new"
        assert data["assignee"] is None
        assert data["severity"] == requested
        assert data["updated_at"] == _iso(_UPDATED_AT)
        assert await _state(db_session, target.id) == before
        assert await _event_count(db_session, target.id) == 0

    async def test_restricted_analyst_with_a_grant_sets_severity_without_assignment(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=target.id, user_id=ra_user.id)

        response = await authenticated_client.patch(
            _url(target), json={"severity": "medium"}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["ticket_id"] == format_ticket_id(target.sequence_id)
        assert data["is_confidential"] is True
        assert data["severity"] == "medium"
        assert data["priority"] == data["priority_automatic"] == "p4"
        assert data["assignee"] is None
        assert data["status"] == "new"
        state = await _state(db_session, target.id)
        assert state["assignee_id"] is None
        assert state["status"] == TicketStatus.NEW.value
        assert state["severity_manual"] == Severity.MEDIUM.value
        assert await _events(db_session, target.id) == [
            (
                TicketAuditEventType.SEVERITY_CHANGED.value,
                ra_user.id,
                None,
                Severity.MEDIUM.value,
                None,
            ),
            (
                TicketAuditEventType.PRIORITY_CHANGED.value,
                None,
                None,
                TicketPriority.P4.value,
                None,
            ),
        ]


# ---------------------------------------------------------------------------
# Domain conflicts (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestConflicts:
    @pytest.mark.parametrize("requested", ["high"])
    async def test_ticket_with_a_cve_is_severity_derived(
        self,
        requested: str | None,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        cve = await cve_factory(severity=Severity.MEDIUM.value)
        target: Ticket = await ticket_factory(cve_id=cve.id)
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"severity": requested}
        )

        assert response.status_code == 409
        assert response.json() == _SEVERITY_DERIVED
        assert await _state(db_session, target.id) == before
        assert await _event_count(db_session, target.id) == 0

    async def test_manual_zone_ticket_is_not_mutable(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """An `Ignored` CVE-less Ticket fails the operability precondition
        (ticket-mutations.md, `set_severity_manual()` step 3)."""
        target: Ticket = await ticket_factory(status=TicketStatus.IGNORED.value)
        before = await _state(db_session, target.id)

        response = await authenticated_client.patch(
            _url(target), json={"severity": "high"}
        )

        assert response.status_code == 409
        assert response.json() == _NOT_MUTABLE
        assert await _state(db_session, target.id) == before
        assert await _event_count(db_session, target.id) == 0


# ---------------------------------------------------------------------------
# Mutation assembly
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMutationAssembly:
    async def test_detail_is_assembled_from_the_uncommitted_post_state(
        self,
        va_commit_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user, commit_client = va_commit_client
        target: Ticket = await ticket_factory()
        ticket_id = target.id
        await db_session.commit()
        observed: list[tuple[str | None, int]] = []
        original = ticket_service.assemble_ticket_detail

        async def _observe(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            observed.append(
                (
                    (await _state(db, ticket_id))["severity_manual"],
                    await _event_count(db, ticket_id),
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _observe)

        response = await commit_client.patch(_url(target), json={"severity": "low"})

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["severity"] == "low"
        assert data["assignee"]["id"] == str(user.id)
        assert observed == [(Severity.LOW.value, 4)]
        assert (await _state(db_session, ticket_id))["severity_manual"] == (
            Severity.LOW.value
        )


# ---------------------------------------------------------------------------
# Controlled clock: one evaluation date across UTC midnight
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.instant


@pytest.mark.e2e
class TestEvaluationDate:
    async def test_one_date_captured_before_midnight_is_reused_after_it(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handler_clock = _Clock(datetime(2026, 9, 27, 23, 59, 59, 999000, tzinfo=UTC))
        later_clock = _Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        mutation_clock = _Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", later_clock.now)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        seen: dict[str, list[date | None]] = {
            "mutation": [],
            "reconcile": [],
            "assembly": [],
        }
        original_mutation = ticket_mutations.set_severity_manual
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_assembly = ticket_service.assemble_ticket_detail

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Ticket:
            seen["mutation"].append(kwargs.get("evaluation_date"))
            return await original_mutation(db, **kwargs)

        async def _reconcile(
            ticket: Ticket, db: AsyncSession, *args: Any, **kwargs: Any
        ) -> None:
            seen["reconcile"].append(kwargs.get("evaluation_date"))
            await original_reconcile(ticket, db, *args, **kwargs)

        async def _assembly(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            seen["assembly"].append(kwargs.get("evaluation_date"))
            return await original_assembly(db, **kwargs)

        monkeypatch.setattr(ticket_mutations, "set_severity_manual", _mutation)
        monkeypatch.setattr(ticket_mutations, "reconcile_ticket_status", _reconcile)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        target: Ticket = await ticket_factory()

        response = await authenticated_client.patch(
            _url(target), json={"severity": "critical"}
        )

        assert response.status_code == 200
        assert response.json()["data"]["status"] == "analysis"
        captured = date(2026, 9, 27)
        assert seen == {
            "mutation": [captured],
            "reconcile": [captured],
            "assembly": [captured],
        }
        assert handler_clock.calls == 1
        assert mutation_clock.calls == 0


# ---------------------------------------------------------------------------
# Due dates: the immutable created_at start
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDueDates:
    @pytest.mark.parametrize(
        ("requested", "sla_days"),
        [
            pytest.param("medium", 90, id="medium"),
        ],
    )
    async def test_severity_change_moves_due_dates_but_never_the_start(
        self,
        requested: str | None,
        sla_days: int | None,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(
            severity_manual=Severity.LOW.value,
            priority_auto=TicketPriority.P4.value,
            created_at=_CREATED_AT,
        )
        before = await authenticated_client.get(f"/api/v1/tickets/{_locator(target)}")
        assert {f: before.json()["data"][f] for f in _DUE_MILESTONES} == _due_dates(
            _CREATED_AT, 180
        )

        response = await authenticated_client.patch(
            _url(target), json={"severity": requested}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["created_at"] == before.json()["data"]["created_at"]
        assert data["created_at"] == _iso(_CREATED_AT)
        assert {f: data[f] for f in _DUE_MILESTONES} == _due_dates(
            _CREATED_AT, sla_days
        )
        assert (await _state(db_session, target.id))["created_at"] == _CREATED_AT


# ---------------------------------------------------------------------------
# Independent transactions: real commits and a concurrent role change
# ---------------------------------------------------------------------------


class _CommittedApp:
    """Committed setup rows plus an app client whose every request runs in
    its own independent session, committed or rolled back like production
    `app.database.get_db` (testing-strategy.md, Concurrency Testing,
    Ticket Accessibility).

    Every row created here or by a request is deleted explicitly by
    `cleanup()`, which runs at teardown even after a failed assertion.
    """

    def __init__(self, factory: Callable[[], Awaitable[AsyncSession]]) -> None:
        self._factory = factory
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    async def session(self) -> AsyncSession:
        return await self._factory()

    async def va_headers(self) -> tuple[User, dict[str, str]]:
        """A committed vulnerability analyst and its Bearer credential."""
        db = await self.session()
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"carol.va.{suffix}",
            email=f"carol.va.{suffix}@example.com",
            full_name="Carol Analyst",
            password_hash="$2b$12$" + "c" * 53,
        )
        db.add(user)
        await db.flush()
        self.user_ids.append(user.id)
        db.add(UserRole(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value))
        created = await create_session(
            db, user, SessionCreationReason.LOCAL_LOGIN, expected_password_hash=None
        )
        assert created is not None
        await db.commit()
        return user, {"Authorization": f"Bearer {created.token}"}

    async def ticket(self, *, is_confidential: bool) -> Ticket:
        db = await self.session()
        ticket = Ticket(
            status=TicketStatus.NEW.value,
            is_confidential=is_confidential,
            created_at=_CREATED_AT,
        )
        db.add(ticket)
        await db.flush()
        self.ticket_ids.append(ticket.id)
        await db.commit()
        return ticket

    async def cleanup(self) -> None:
        db = await self.session()
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(SessionRow).where(SessionRow.user_id.in_(self.user_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await db.execute(statement)
        await db.commit()


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[tuple[_CommittedApp, AsyncClient]]:
    world = _CommittedApp(db_session_factory)

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        session = await world.session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as committed_client:
            yield world, committed_client
    finally:
        app.dependency_overrides.pop(get_db, None)
        await world.cleanup()


@pytest.mark.e2e
class TestIndependentTransactions:
    async def test_role_removal_committed_after_the_load_spares_the_in_flight_request(
        self,
        committed_app: tuple[_CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another transaction commits the removal of the caller's only role
        right after the request's single role load. The in-flight request
        keeps `triage_ticket` and the `all` scope for a confidential Ticket
        without a grant; any reload of the caller in the request would
        observe the committed removal and deny with 403 or 404. The next
        request is denied with the generic 403 before any Ticket lookup."""
        world, committed_client = committed_app
        user, headers = await world.va_headers()
        target = await world.ticket(is_confidential=True)
        original = user_service.get_user_roles
        loads: list[uuid.UUID] = []

        async def _load_then_commit_removal(
            db: AsyncSession, user_id: uuid.UUID
        ) -> list[Role]:
            loads.append(user_id)
            roles = await original(db, user_id)
            racer = await world.session()
            await racer.execute(delete(UserRole).where(UserRole.user_id == user_id))
            await racer.commit()
            return roles

        monkeypatch.setattr(user_service, "get_user_roles", _load_then_commit_removal)
        in_flight = await asyncio.wait_for(
            committed_client.patch(
                _url(target), json={"severity": "high"}, headers=headers
            ),
            timeout=10,
        )
        monkeypatch.setattr(user_service, "get_user_roles", original)
        resolver = AsyncMock()
        monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
        next_request = await committed_client.patch(
            _url(target), json={"severity": "low"}, headers=headers
        )

        assert in_flight.status_code == 200
        data = in_flight.json()["data"]
        assert data["severity"] == "high"
        # Auto-assignment is not authorization: it uses the locked-current
        # VA membership, which no longer exists (ticket-mutations.md,
        # `auto_assign_actor()` step 3).
        assert data["assignee"] is None
        assert data["status"] == "new"
        assert loads == [user.id]
        assert next_request.status_code == 403
        assert next_request.json() == _FORBIDDEN
        resolver.assert_not_awaited()
        fresh = await world.session()
        state = await _state(fresh, target.id)
        assert state["severity_manual"] == Severity.HIGH.value
        assert state["assignee_id"] is None
        assert await _events(fresh, target.id) == [
            (
                TicketAuditEventType.SEVERITY_CHANGED.value,
                user.id,
                None,
                Severity.HIGH.value,
                None,
            ),
            (
                TicketAuditEventType.PRIORITY_CHANGED.value,
                None,
                None,
                TicketPriority.P3.value,
                None,
            ),
        ]

    async def test_failed_assembly_rolls_back_the_real_transaction(
        self,
        committed_app: tuple[_CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With a real per-request transaction, an assembly failure after
        the mutation leaves no write and no audit event visible to an
        independent session."""
        world, committed_client = committed_app
        _, headers = await world.va_headers()
        target = await world.ticket(is_confidential=False)
        before = await _state(await world.session(), target.id)
        pre_failure: list[tuple[str | None, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            pre_failure.append(
                (
                    (await _state(db, target.id))["severity_manual"],
                    await _event_count(db, target.id),
                )
            )
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)

        response = await committed_client.patch(
            _url(target), json={"severity": "critical"}, headers=headers
        )

        assert response.status_code == 500
        assert pre_failure == [(Severity.CRITICAL.value, 4)]
        fresh = await world.session()
        assert await _state(fresh, target.id) == before
        assert await _events(fresh, target.id) == []


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

    def test_path_parameter_is_a_plain_string(self) -> None:
        operation = self._operation()
        (path_param,) = [p for p in operation["parameters"] if p["in"] == "path"]

        assert path_param["name"] == "ticket_id"
        assert path_param["schema"]["type"] == "string"
        assert "pattern" not in path_param["schema"]
        assert "format" not in path_param["schema"]
        assert [p for p in operation["parameters"] if p["in"] == "query"] == []
        assert operation["tags"] == ["Tickets"]

    def test_request_body_requires_a_nullable_lowercase_severity(self) -> None:
        request_body = self._operation()["requestBody"]
        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TicketSeverityUpdateRequest"

        schema = self._resolve(request_body["content"]["application/json"]["schema"])
        assert schema["required"] == ["severity"]
        assert set(schema["properties"]) == {"severity"}
        variants = [self._resolve(v) for v in schema["properties"]["severity"]["anyOf"]]
        assert {"type": "null"} in variants
        (enum_variant,) = [v for v in variants if "enum" in v]
        assert enum_variant["type"] == "string"
        assert enum_variant["enum"] == ["critical", "high", "medium", "low", "none"]

    def test_responses_declare_detail_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_SEVERITY_DERIVED" in responses["409"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "422" in responses
