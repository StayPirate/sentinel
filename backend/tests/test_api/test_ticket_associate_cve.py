"""End-to-end tests for the Associate CVE endpoint
(`POST /api/v1/tickets/{ticket_id}/associate-cve`,
`backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Associate CVE; Associating a CVE
Later; CVE Resolution Behavior; Tickets Without CVE; Mutability Guard;
Response Schemas > TicketDetail; Endpoint -> Schema Mapping),
docs/features/tickets/ticket-service.md (`associate_cve`;
`get_ticket_detail()` mutation assembly; Caller category and Ticket
accessibility), docs/features/tickets/ticket-audit-log.md (Event Type
Contract; Cross-Event Ordering), docs/features/tickets/ticket-deadlines.md
(SLA Tier; Due Dates), docs/features/tickets/ticket-priority.md (Decision
Table), docs/api-spec.md (Authorization Chain Evaluation Order flow 3; Ticket
Accessibility Check; Anti-Enumeration Boundary; Manual-Zone Mutability Guard;
Response Format: `existing_ticket_id`; What belongs in an endpoint error
table; Ticket Identifier Resolution), docs/features/identity/rbac.md
(Endpoint Permission Map; `require_capability()`), and
docs/features/platform/testing-strategy.md (Ticket Accessibility; Audit Trail
Testing; API Endpoints).

The service-level association matrix (every event combination, lock order,
races, and every rollback position) lives in
tests/test_services/test_associate_cve*.py; these tests cover the HTTP
boundary. Step 14 of the service specification (the CVE freshness refresh)
is deferred and is neither tested nor expected here. Expected values are
transcribed from the specifications.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

import app.main as main_module
from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import tickets as route
from app.core.enums import (
    PackageStatus,
    Role,
    SessionCreationReason,
    Severity,
    TicketStatus,
)
from app.core.errors import AppError
from app.core.identifiers import format_ticket_id
from app.database import get_db
from app.main import app
from app.models.cve import CVE
from app.models.product import Product
from app.models.session import Session as SessionRow
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import ticket_mutations, ticket_service, user_service
from app.services.session_service import create_session
from app.services.ticket_audit_log import TicketAuditLog
from tests.support.suse_cvss import V31_CRITICAL
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/associate-cve"
_NOT_FOUND = b'{"code":"TICKET_NOT_FOUND","detail":"Ticket not found."}'
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_CVE_INVALID_FORMAT = {
    "code": "CVE_INVALID_FORMAT",
    "detail": "CVE identifier format is invalid.",
}
_NOT_MUTABLE = {"code": "TICKET_NOT_MUTABLE", "detail": "Ticket is not mutable."}
_ALREADY_SET = {
    "code": "TICKET_CVE_ALREADY_SET",
    "detail": "Ticket already has a CVE associated.",
}
_CONFLICT_DETAIL = "CVE is already associated with another Ticket."
_MAX_SEQUENCE = 2_147_483_647

_NEW_CVE_ID = "CVE-2099-0201"
"""A CVE-ID with no row: a successful association inserts a placeholder."""

_CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, tzinfo=UTC)
_UPDATED_AT = datetime(2026, 3, 10, 16, 0, tzinfo=UTC)

# ticket-deadlines.md (Due Dates): field -> cumulative milestone percent.
_DUE_MILESTONES = {
    "triage_due_at": 10,
    "submission_due_at": 60,
    "um_due_at": 70,
    "qa_due_at": 100,
    "release_due_at": 100,
}
_SECONDS_PER_DAY_PERCENT = 864

# A statement touching a Ticket- or CVE-domain table (ticket, ticket_*,
# cve, cve_*); authentication reads only session, user, and user_role.
_DOMAIN_TABLE = re.compile(r'\b(?:FROM|INTO|UPDATE|JOIN)\s+"?(?:ticket|cve)\w*"?\b')
_CVE_TABLE = re.compile(r'\b(?:FROM|INTO|UPDATE|JOIN)\s+"?cve\w*"?\b')
_ROW_LOCK = re.compile(r"\bFOR (?:UPDATE|SHARE|NO KEY UPDATE|KEY SHARE)\b")


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
    """The five due dates for an SLA tier (`None`: no SLA)."""
    if sla_days is None:
        return dict.fromkeys(_DUE_MILESTONES)
    return {
        field: _iso(
            created_at
            + timedelta(seconds=sla_days * _SECONDS_PER_DAY_PERCENT * milestone)
        )
        for field, milestone in _DUE_MILESTONES.items()
    }


def _domain_statements(recorder: StatementRecorder) -> list[str]:
    return [s for s in recorder.statements if _DOMAIN_TABLE.search(s)]


def _cve_statements(recorder: StatementRecorder) -> list[str]:
    return [s for s in recorder.statements if _CVE_TABLE.search(s)]


def _writes(recorder: StatementRecorder) -> list[str]:
    """Every write except transaction-control statements."""
    return [
        w
        for w in recorder.writes()
        if not w.startswith(("SAVEPOINT", "RELEASE SAVEPOINT", "ROLLBACK"))
    ]


def _assert_read_only_ticket_resolution(recorder: StatementRecorder) -> None:
    """Only the delegated preliminary locator resolution touched the Ticket
    domain: no CVE table, no lock, and no write (the request ended before
    `associate_cve()`)."""
    assert _cve_statements(recorder) == []
    assert [s for s in recorder.statements if _ROW_LOCK.search(s)] == []
    assert _writes(recorder) == []
    assert all(s.lstrip().startswith("SELECT") for s in _domain_statements(recorder))


async def _counts(db: AsyncSession) -> tuple[int, int, int]:
    """`(tickets, cves, ticket audit events)` visible to `db`."""
    row = (
        await db.execute(
            select(
                select(func.count()).select_from(Ticket).scalar_subquery(),
                select(func.count()).select_from(CVE).scalar_subquery(),
                select(func.count()).select_from(TicketAuditEvent).scalar_subquery(),
            )
        )
    ).one()
    return (row[0], row[1], row[2])


async def _cve_row(db: AsyncSession, cve_id: str) -> CVE | None:
    return (
        await db.execute(
            select(CVE)
            .where(CVE.cve_id == cve_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _snapshot(db: AsyncSession, *ticket_ids: uuid.UUID) -> tuple[Any, ...]:
    """Everything a rejected request must leave unchanged: every column of
    the Tickets, of their audit events, of their Product occurrences, and of
    every CVE row. Never rolls back the session."""
    tickets = (
        await db.execute(
            select(Ticket.__table__)
            .where(Ticket.id.in_(ticket_ids))
            .order_by(Ticket.id)
        )
    ).all()
    events = (
        await db.execute(
            select(TicketAuditEvent.__table__)
            .where(TicketAuditEvent.ticket_id.in_(ticket_ids))
            .order_by(TicketAuditEvent.id)
        )
    ).all()
    products = (await db.execute(select(TicketPackageProduct.__table__))).all()
    cves = (await db.execute(select(CVE.__table__).order_by(CVE.id))).all()
    return tuple(
        [tuple(row) for row in rows] for rows in (tickets, events, products, cves)
    )


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted Ticket columns touched by the association."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.cve_id,
                Ticket.severity_manual,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.created_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return dict(row._mapping)


def _spy_association(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Wrap `ticket_service.associate_cve` in a pass-through spy."""
    spy = AsyncMock(side_effect=ticket_service.associate_cve)
    monkeypatch.setattr(ticket_service, "associate_cve", spy)
    return spy


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the delegated locator resolution and the association with
    spies that must stay unused."""
    resolver = AsyncMock()
    association = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, "associate_cve", association)
    return resolver, association


@pytest.fixture(autouse=True)
async def default_setting(
    request: pytest.FixtureRequest,
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting | None:
    """The persisted `default_cvss_version` (the test schema has none).

    Skipped for the independent-session tests, which commit their own row:
    an uncommitted duplicate would block on the primary key.
    """
    if "committed_app" in request.fixturenames:
        return None
    return await system_setting_factory(key="default_cvss_version", value="3.1")


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


class _CommitApp:
    """Builds clients whose `get_db` override commits after the handler and
    rolls back when an exception escapes, like production
    `app.database.get_db`.

    The shared `client` fixture never commits or rolls back, so it cannot
    prove that a rejected or failed request leaves no placeholder CVE.
    Commits and rollbacks act on `db_session`'s savepoint; the outer test
    transaction still reverts everything at teardown.
    `raise_app_exceptions=False` returns the 500 response instead of
    re-raising into the test.
    """

    def __init__(
        self,
        db: AsyncSession,
        user_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        self._db = db
        self._user_factory = user_factory
        self._user_role_factory = user_role_factory
        self._counter = 0
        self._clients: list[AsyncClient] = []
        self._tokens: dict[uuid.UUID, str] = {}

    async def login(self, *roles: Role) -> tuple[User, AsyncClient]:
        """A user holding `roles` and a committing client for it."""
        self._counter += 1
        user = await self._user_factory(
            username=f"alice.commit{self._counter}", full_name="Alice Analyst"
        )
        for index, role in enumerate(roles):
            await self._user_role_factory(
                user_id=user.id, role=role.value, group_name=f"_origin{index}"
            )
        created = await create_session(
            self._db,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        client = AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        )
        client.cookies.set(SESSION_COOKIE_NAME, created.token)
        self._clients.append(client)
        self._tokens[user.id] = created.token
        return user, client

    def token_of(self, user: User) -> str:
        """The session token of a logged-in user."""
        return self._tokens[user.id]

    async def override_db(self) -> AsyncGenerator[AsyncSession]:
        try:
            yield self._db
            await self._db.commit()
        except Exception:
            await self._db.rollback()
            raise

    async def close(self) -> None:
        for client in self._clients:
            await client.aclose()


@pytest_asyncio.fixture
async def commit_app(
    db_session: AsyncSession,
    user_factory: Factory,
    user_role_factory: Factory,
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[_CommitApp]:
    holder = _CommitApp(db_session, user_factory, user_role_factory)
    app.dependency_overrides[get_db] = holder.override_db
    try:
        yield holder
    finally:
        app.dependency_overrides.pop(get_db, None)
        await holder.close()


# ---------------------------------------------------------------------------
# Authentication (flow 3, step 1)
# ---------------------------------------------------------------------------


_PRE_CAPABILITY_BODIES = [
    pytest.param({"cve_id": _NEW_CVE_ID}, id="new-cve"),
    pytest.param({"cve_id": "not-a-cve"}, id="malformed-cve"),
    pytest.param({}, id="missing-field"),
    pytest.param({"cve_id": None}, id="null-cve"),
]


@pytest.mark.e2e
class TestAuthentication:
    @pytest.mark.parametrize("body", _PRE_CAPABILITY_BODIES)
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_credential_failure_returns_401_before_any_work(
        self,
        body: dict[str, Any],
        headers: dict[str, str],
        client: AsyncClient,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public: Ticket = await ticket_factory()
        hidden: Ticket = await ticket_factory(is_confidential=True)
        before = await _snapshot(db_session, public.id, hidden.id)
        resolver, association = _forbid_lookups(monkeypatch)
        role_loader = AsyncMock()
        monkeypatch.setattr(user_service, "get_user_roles", role_loader)

        bodies = []
        with StatementRecorder(db_session) as recorder:
            for locator in (
                _locator(public),
                _locator(hidden),
                f"SNTL-{_MAX_SEQUENCE}",
                "not-a-ticket",
            ):
                response = await client.post(_url(locator), json=body, headers=headers)
                assert response.status_code == 401, locator
                assert response.json() == _UNAUTHENTICATED
                bodies.append(response.content)

        assert len(set(bodies)) == 1
        resolver.assert_not_awaited()
        association.assert_not_awaited()
        role_loader.assert_not_awaited()
        assert _domain_statements(recorder) == []
        assert await _snapshot(db_session, public.id, hidden.id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None


# ---------------------------------------------------------------------------
# Capability `triage_ticket` (flow 3, step 1), before any lookup
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCapability:
    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    @pytest.mark.parametrize("body", _PRE_CAPABILITY_BODIES)
    async def test_caller_without_triage_ticket_gets_the_generic_403_before_lookup(
        self,
        roles: list[Role],
        body: dict[str, Any],
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The caller can see the public and the granted confidential Ticket,
        yet every locator (visible, missing, malformed, UUID, inaccessible)
        and every body (valid, malformed, schema-invalid) returns the
        identical 403 without any Ticket or CVE statement."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        public: Ticket = await ticket_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=granted.id, user_id=authenticated_user.id
        )
        before = await _snapshot(db_session, public.id, granted.id, hidden.id)
        resolver, association = _forbid_lookups(monkeypatch)

        bodies = []
        with StatementRecorder(db_session) as recorder:
            for locator in (
                _locator(public),
                _locator(granted),
                _locator(hidden),
                f"SNTL-{_MAX_SEQUENCE}",
                "sntl-1",
                str(public.id),
            ):
                response = await authenticated_client.post(_url(locator), json=body)
                assert response.status_code == 403, locator
                assert response.json() == _FORBIDDEN, locator
                bodies.append(response.content)

        assert len(set(bodies)) == 1
        resolver.assert_not_awaited()
        association.assert_not_awaited()
        assert _domain_statements(recorder) == []
        assert await _snapshot(db_session, public.id, granted.id, hidden.id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    async def test_403_precedes_an_absent_body(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target: Ticket = await ticket_factory()
        resolver, association = _forbid_lookups(monkeypatch)

        response = await authenticated_client.post(_url(target))

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        resolver.assert_not_awaited()
        association.assert_not_awaited()

    async def test_visibility_without_capability_reads_but_cannot_associate(
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
        mutate = await authenticated_client.post(
            _url(target), json={"cve_id": _NEW_CVE_ID}
        )

        assert read.status_code == 200
        assert mutate.status_code == 403
        assert mutate.json() == _FORBIDDEN
        assert (await _state(db_session, target.id))["cve_id"] is None
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    @pytest.mark.parametrize(
        ("roles", "status", "status_value", "assigned"),
        [
            pytest.param([], 403, None, None, id="no-roles"),
            pytest.param([Role.ADMIN], 403, None, None, id="admin"),
            pytest.param([Role.VULNERABILITY_ANALYST], 200, "analysis", True, id="va"),
            pytest.param([Role.RESTRICTED_ANALYST], 200, "new", False, id="ra"),
            pytest.param(
                [Role.VULNERABILITY_ANALYST, Role.ADMIN],
                200,
                "analysis",
                True,
                id="va-admin",
            ),
            pytest.param(
                [Role.RESTRICTED_ANALYST, Role.ADMIN],
                200,
                "new",
                False,
                id="ra-admin",
            ),
        ],
    )
    async def test_capability_matrix_over_every_role_combination(
        self,
        roles: list[Role],
        status: int,
        status_value: str | None,
        assigned: bool | None,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        """`vulnerability_analyst` and `restricted_analyst` hold
        `triage_ticket` (rbac.md, Predefined Roles); `admin` does not
        inherit it. Only an active VA is auto-assigned (tickets.md,
        Auto-Assignment on Unassigned Tickets)."""
        for index, role in enumerate(roles):
            await user_role_factory(
                user_id=authenticated_user.id,
                role=role.value,
                group_name=f"_origin{index}",
            )
        target: Ticket = await ticket_factory()
        before = await _snapshot(db_session, target.id)

        response = await authenticated_client.post(
            _url(target), json={"cve_id": _NEW_CVE_ID}
        )

        assert response.status_code == status
        if status == 403:
            assert response.json() == _FORBIDDEN
            assert await _snapshot(db_session, target.id) == before
            assert await _cve_row(db_session, _NEW_CVE_ID) is None
            return
        data = response.json()["data"]
        assert data["status"] == status_value
        assert (data["assignee"] is not None) is assigned
        if assigned:
            assert data["assignee"]["id"] == str(authenticated_user.id)
        assert data["cve"]["cve_id"] == _NEW_CVE_ID
        state = await _state(db_session, target.id)
        cve = await _cve_row(db_session, _NEW_CVE_ID)
        assert cve is not None
        assert state["cve_id"] == cve.id


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
    ("bare-number", lambda t: str(t.sequence_id)),
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
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        target: Ticket = await ticket_factory()
        target_id = target.id
        locator = build_locator(target)
        await db_session.commit()
        before = await _snapshot(db_session, target_id)
        association = _spy_association(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await commit_client.post(
                _url(locator), json={"cve_id": _NEW_CVE_ID}
            )

        assert response.status_code == 404
        assert response.content == _NOT_FOUND
        association.assert_not_awaited()
        _assert_read_only_ticket_resolution(recorder)
        assert await _snapshot(db_session, target_id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    @pytest.mark.parametrize("cve_kind", ["placeholder", "existing"])
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        cve_kind: str,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """A restricted analyst holds `triage_ticket`, but the capability
        never makes a confidential Ticket without a grant visible."""
        _, commit_client = await commit_app.login(Role.RESTRICTED_ANALYST)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        hidden_id = hidden.id
        cve_id = (await cve_factory()).cve_id if cve_kind == "existing" else _NEW_CVE_ID
        hidden_url = _url(hidden)
        await db_session.commit()
        before = await _snapshot(db_session, hidden_id)

        inaccessible = await commit_client.post(hidden_url, json={"cve_id": cve_id})
        missing = await commit_client.post(
            _url(f"SNTL-{_MAX_SEQUENCE}"), json={"cve_id": cve_id}
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == _NOT_FOUND
        assert inaccessible.headers.get("content-length") == missing.headers.get(
            "content-length"
        )
        assert await _snapshot(db_session, hidden_id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"cve_id": "not-a-cve"}, id="malformed-cve"),
            pytest.param({"cve_id": _NEW_CVE_ID}, id="valid-cve"),
        ],
    )
    async def test_missing_ticket_gives_the_same_404_for_any_valid_json_string_body(
        self,
        body: dict[str, str],
        commit_app: _CommitApp,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A malformed CVE-ID never turns a missing Ticket into a different
        response than a well-formed one: the delegated preliminary Ticket
        resolution precedes the CVE-ID pre-validation."""
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        association = _spy_association(monkeypatch)

        response = await commit_client.post(_url(f"SNTL-{_MAX_SEQUENCE}"), json=body)

        assert response.status_code == 404
        assert response.content == _NOT_FOUND
        association.assert_not_awaited()


# ---------------------------------------------------------------------------
# Request validation: 422 CVE_INVALID_FORMAT and the global 422
# ---------------------------------------------------------------------------


_MALFORMED_CVE_IDS = [
    pytest.param("", id="empty"),
    pytest.param("CVE-2024-123", id="three-digit-number"),
    pytest.param("cve-2024-1234", id="lowercase"),
    pytest.param("Cve-2024-1234", id="mixed-case"),
    pytest.param(" CVE-2024-1234", id="leading-space"),
    pytest.param("CVE-2024-1234 ", id="trailing-space"),
    pytest.param("  CVE-2024-1234  ", id="padded"),
    pytest.param("CVE-2024-1234\n", id="trailing-newline"),
    pytest.param("\tCVE-2024-1234", id="leading-tab"),
    pytest.param("CVE 2024 1234", id="spaces-instead-of-dashes"),
    pytest.param("CVE-2024-12 34", id="inner-space"),
    pytest.param("CVE-24-1234", id="two-digit-year"),
    pytest.param("CVE-20244-1234", id="five-digit-year"),
    pytest.param("CVE-2024-12a4", id="non-digit"),
    pytest.param("CVE-2024-", id="missing-number"),
    pytest.param("20241234", id="digits-only"),
    pytest.param("GHSA-abcd-efgh-ijkl", id="other-identifier"),
    pytest.param("CVE-2024-123456789012", id="21-characters"),
    pytest.param("CVE-2024-" + "1" * 200, id="very-long"),
]


@pytest.mark.e2e
class TestCVEInvalidFormat:
    @pytest.mark.parametrize("cve_id", _MALFORMED_CVE_IDS)
    @pytest.mark.parametrize(
        "role",
        [Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
        ids=["va", "restricted-analyst"],
    )
    async def test_malformed_cve_id_is_rejected_before_any_cve_or_write_work(
        self,
        cve_id: str,
        role: Role,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The pre-validation follows only the delegated preliminary
        (read-only) Ticket resolution: no CVE statement, no lock, no write,
        no placeholder CVE, and no service call."""
        _, commit_client = await commit_app.login(role)
        target: Ticket = await ticket_factory()
        target_id = target.id
        target_url = _url(target)
        await db_session.commit()
        before = await _snapshot(db_session, target_id)
        association = _spy_association(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await commit_client.post(target_url, json={"cve_id": cve_id})

        assert response.status_code == 422
        assert response.json() == _CVE_INVALID_FORMAT
        association.assert_not_awaited()
        _assert_read_only_ticket_resolution(recorder)
        assert await _snapshot(db_session, target_id) == before

    async def test_format_check_precedes_the_ticket_state_guards(
        self,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """A malformed CVE-ID on an Ignored Ticket and on a Ticket that
        already has a CVE is `CVE_INVALID_FORMAT`; the state guards run in
        the service, which is never reached."""
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        ignored: Ticket = await ticket_factory(status=TicketStatus.IGNORED.value)
        associated: Ticket = await ticket_factory(cve_id=(await cve_factory()).id)
        urls = [_url(ignored), _url(associated)]
        await db_session.commit()

        for target_url in urls:
            response = await commit_client.post(target_url, json={"cve_id": "CVE-1"})
            assert response.status_code == 422
            assert response.json() == _CVE_INVALID_FORMAT

    @pytest.mark.parametrize(
        "cve_id",
        [
            pytest.param("CVE-2024-1234", id="four-digits"),
            pytest.param("CVE-2024-12345", id="five-digits"),
            pytest.param("CVE-2024-12345678901", id="20-characters"),
        ],
    )
    async def test_accepted_boundary_cve_ids_create_a_placeholder(
        self,
        cve_id: str,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        assert len(cve_id) <= 20
        target: Ticket = await ticket_factory()

        response = await authenticated_client.post(
            _url(target), json={"cve_id": cve_id}
        )

        assert response.status_code == 200
        assert response.json()["data"]["cve"]["cve_id"] == cve_id
        assert await _cve_row(db_session, cve_id) is not None

    async def test_service_backstop_maps_to_the_same_response(
        self,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With the handler pre-validation bypassed, the service's
        `CVEIdFormatError` still maps to `422 CVE_INVALID_FORMAT`, raised
        before any CVE statement, lock, or write."""
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        target: Ticket = await ticket_factory()
        target_id = target.id
        target_url = _url(target)
        await db_session.commit()
        before = await _snapshot(db_session, target_id)
        monkeypatch.setattr(route, "is_valid_cve_id", lambda value: True)
        association = _spy_association(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await commit_client.post(
                target_url, json={"cve_id": "CVE-2024-123456789012"}
            )

        assert response.status_code == 422
        assert response.json() == _CVE_INVALID_FORMAT
        association.assert_awaited_once()
        _assert_read_only_ticket_resolution(recorder)
        assert await _snapshot(db_session, target_id) == before


def _cve_id_error(msg: str, type_: str) -> list[dict[str, Any]]:
    return [{"loc": ["body", "cve_id"], "msg": msg, "type": type_}]


_NOT_A_STRING = _cve_id_error("Input should be a valid string", "string_type")

_VALIDATION_CASES = [
    pytest.param({}, _cve_id_error("Field required", "missing"), id="missing-field"),
    pytest.param({"cve_id": None}, _NOT_A_STRING, id="null"),
    pytest.param({"cve_id": 20241234}, _NOT_A_STRING, id="int"),
    pytest.param({"cve_id": 1.5}, _NOT_A_STRING, id="float"),
    pytest.param({"cve_id": ["CVE-2024-1234"]}, _NOT_A_STRING, id="list"),
    pytest.param({"cve_id": True}, _NOT_A_STRING, id="bool"),
    pytest.param({"cve_id": {"id": "CVE-2024-1234"}}, _NOT_A_STRING, id="object"),
    pytest.param(
        {"CVE_ID": "CVE-2024-1234"},
        _cve_id_error("Field required", "missing"),
        id="wrong-field-name",
    ),
    pytest.param(
        [],
        [
            {
                "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract "
                "fields from",
                "type": "model_attributes_type",
            }
        ],
        id="non-object-body",
    ),
]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("body", "errors"), _VALIDATION_CASES)
    async def test_invalid_body_returns_the_validation_envelope_without_effect(
        self,
        body: Any,
        errors: list[dict[str, Any]],
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        target: Ticket = await ticket_factory()
        target_id = target.id
        target_url = _url(target)
        await db_session.commit()
        before = await _snapshot(db_session, target_id)
        association = _spy_association(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await commit_client.post(target_url, json=body)

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": errors,
        }
        association.assert_not_awaited()
        _assert_read_only_ticket_resolution(recorder)
        assert await _snapshot(db_session, target_id) == before

    async def test_absent_body_is_a_validation_error(
        self,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        target: Ticket = await ticket_factory()
        target_url = _url(target)
        await db_session.commit()

        response = await commit_client.post(target_url)

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [{"loc": ["body"], "msg": "Field required", "type": "missing"}],
        }

    async def test_unknown_fields_are_ignored(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """`TicketAssociateCVERequest` declares no extra-field policy, so
        Pydantic's default applies: an undeclared field, even one named like
        another endpoint's field, is ignored and has no effect."""
        target: Ticket = await ticket_factory(
            severity_manual=Severity.LOW.value, priority_auto="P4"
        )

        response = await authenticated_client.post(
            _url(target),
            json={
                "cve_id": _NEW_CVE_ID,
                "severity": "critical",
                "is_confidential": True,
                "ticket_id": "SNTL-1",
            },
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["ticket_id"] == _locator(target)
        assert data["is_confidential"] is False
        assert data["severity"] is None
        assert (await _state(db_session, target.id))["severity_manual"] is None


# ---------------------------------------------------------------------------
# Domain errors: 400 TICKET_CVE_ALREADY_SET, 409 TICKET_CVE_CONFLICT and
# TICKET_NOT_MUTABLE
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAlreadySet:
    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param("same", id="equals-the-current-cve"),
            pytest.param("other-existing", id="differs-existing"),
            pytest.param("other-new", id="differs-placeholder"),
            pytest.param("associated-elsewhere", id="precedes-the-conflict"),
        ],
    )
    @pytest.mark.parametrize(
        "role",
        [Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
        ids=["va", "restricted-analyst"],
    )
    async def test_ticket_with_a_cve_is_rejected_without_effect(
        self,
        requested: str,
        role: Role,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """An unassigned `New` Ticket and a VA caller: an assignment before
        the rejection would be observable."""
        _, commit_client = await commit_app.login(role)
        own: CVE = await cve_factory(severity=Severity.LOW.value)
        target: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=own.id, priority_auto="P4"
        )
        target_id = target.id
        target_url = _url(target)
        if requested == "same":
            cve_id = own.cve_id
        elif requested == "other-existing":
            cve_id = (await cve_factory()).cve_id
        elif requested == "other-new":
            cve_id = _NEW_CVE_ID
        else:
            elsewhere: CVE = await cve_factory()
            await ticket_factory(cve_id=elsewhere.id)
            cve_id = elsewhere.cve_id
        await db_session.commit()
        before = await _snapshot(db_session, target_id)

        response = await commit_client.post(target_url, json={"cve_id": cve_id})

        assert response.status_code == 400
        assert response.json() == _ALREADY_SET
        assert await _snapshot(db_session, target_id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None


@pytest.mark.e2e
class TestConflict:
    @pytest.mark.parametrize(
        ("role", "confidential"),
        [
            pytest.param(Role.VULNERABILITY_ANALYST, False, id="va-public"),
            pytest.param(Role.VULNERABILITY_ANALYST, True, id="va-confidential"),
            pytest.param(Role.RESTRICTED_ANALYST, False, id="ra-public"),
            pytest.param(Role.RESTRICTED_ANALYST, True, id="ra-inaccessible"),
        ],
    )
    async def test_associated_cve_returns_only_the_existing_identifier(
        self,
        role: Role,
        confidential: bool,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """tickets.md, Identifier Disclosure Boundary: the conflict body is
        exactly the envelope plus the top-level `existing_ticket_id`, even
        when the conflicting Ticket is inaccessible to the caller; nothing
        else about that Ticket or its CVE is disclosed."""
        _, commit_client = await commit_app.login(role)
        cve: CVE = await cve_factory(title="Embargoed issue", severity="Critical")
        existing: Ticket = await ticket_factory(
            cve_id=cve.id, is_confidential=confidential
        )
        existing_id = existing.id
        existing_ticket_id = _locator(existing)
        cve_string = cve.cve_id
        # An unassigned `New` Ticket: an assignment before the rejection
        # would be observable.
        target: Ticket = await ticket_factory()
        target_id = target.id
        target_url = _url(target)
        await db_session.commit()
        before = await _snapshot(db_session, target_id, existing_id)

        response = await commit_client.post(target_url, json={"cve_id": cve_string})

        assert response.status_code == 409
        assert response.json() == {
            "code": "TICKET_CVE_CONFLICT",
            "detail": _CONFLICT_DETAIL,
            "existing_ticket_id": existing_ticket_id,
        }
        assert "Embargoed issue" not in response.text
        assert str(existing_id) not in response.text
        assert await _snapshot(db_session, target_id, existing_id) == before
        assert await ticket_events_by_id(db_session, existing_id) == []
        follow = await commit_client.get(f"/api/v1/tickets/{existing_ticket_id}")
        if role is Role.RESTRICTED_ANALYST and confidential:
            assert follow.status_code == 404
            assert follow.content == _NOT_FOUND
        else:
            assert follow.status_code == 200

    async def test_conflict_with_the_ticket_created_by_a_first_association(
        self,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """One placeholder CVE, associated through the endpoint to a first
        Ticket, conflicts for the second Ticket with the first one's
        identifier."""
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        first: Ticket = await ticket_factory()
        second: Ticket = await ticket_factory()
        first_url, first_id = _url(first), _locator(first)
        second_id, second_url = second.id, _url(second)
        await db_session.commit()

        won = await commit_client.post(first_url, json={"cve_id": _NEW_CVE_ID})
        before = await _snapshot(db_session, second_id)
        lost = await commit_client.post(second_url, json={"cve_id": _NEW_CVE_ID})

        assert won.status_code == 200
        assert lost.status_code == 409
        assert lost.json() == {
            "code": "TICKET_CVE_CONFLICT",
            "detail": _CONFLICT_DETAIL,
            "existing_ticket_id": first_id,
        }
        assert await _snapshot(db_session, second_id) == before
        cve = await _cve_row(db_session, _NEW_CVE_ID)
        assert cve is not None
        assert (await _state(db_session, second_id))["cve_id"] is None


@pytest.mark.e2e
class TestNotMutable:
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED.value, TicketStatus.DUPLICATED.value]
    )
    @pytest.mark.parametrize(
        "cve_kind",
        [
            pytest.param("placeholder", id="placeholder"),
            pytest.param("existing", id="existing-cve"),
            pytest.param("associated-elsewhere", id="precedes-the-conflict"),
        ],
    )
    async def test_manual_zone_ticket_is_rejected_without_effect(
        self,
        status: str,
        cve_kind: str,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        target: Ticket = await ticket_factory(
            status=status, severity_manual=Severity.LOW.value, priority_auto="P4"
        )
        target_id = target.id
        target_url = _url(target)
        if cve_kind == "placeholder":
            cve_id = _NEW_CVE_ID
        else:
            cve: CVE = await cve_factory()
            cve_id = cve.cve_id
            if cve_kind == "associated-elsewhere":
                await ticket_factory(cve_id=cve.id)
        await db_session.commit()
        before = await _snapshot(db_session, target_id)

        response = await commit_client.post(target_url, json={"cve_id": cve_id})

        assert response.status_code == 409
        assert response.json() == _NOT_MUTABLE
        assert "existing_ticket_id" not in response.json()
        assert await _snapshot(db_session, target_id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    async def test_operability_precedes_the_already_set_check(
        self,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        own: CVE = await cve_factory()
        own_cve_id = own.cve_id
        target: Ticket = await ticket_factory(
            status=TicketStatus.IGNORED.value, cve_id=own.id
        )
        target_url = _url(target)
        await db_session.commit()

        response = await commit_client.post(target_url, json={"cve_id": own_cve_id})

        assert response.status_code == 409
        assert response.json() == _NOT_MUTABLE


# ---------------------------------------------------------------------------
# Successful association (200 TicketDetail)
# ---------------------------------------------------------------------------

_NEW_TITLE = "Example heap overflow"
_NEW_DESCRIPTION = "Fictional description of the flaw."
_GS_END = date(2099, 1, 1)
"""A General Support end long after every evaluation date of the tests."""


def _placeholder_cve(cve_id: str) -> dict[str, Any]:
    """The expanded `CVEDetail` of a placeholder CVE: only `cve_id` set,
    `cve_state` defaulted to `published`, and no evidence."""
    return {
        "cve_id": cve_id,
        "title": None,
        "description": None,
        "published_date": None,
        "modified_date": None,
        "cve_state": "published",
        "date_rejected": None,
        "severity": None,
        "external_identifiers": [],
        "kev": None,
        "epss": None,
        "ssvc": None,
        "cwes": [],
    }


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


def _wire_events(items: list[dict[str, Any]]) -> list[EventRow]:
    """Audit-log API items (newest first) as insertion-ordered rows."""
    return [
        EventRow(
            item["event_type"],
            uuid.UUID(item["actor"]["id"]) if item["actor"] else None,
            item["old_value"],
            item["new_value"],
            item["comment"],
            item["detail"],
        )
        for item in reversed(items)
    ]


async def _api_events(client: AsyncClient, locator: str) -> list[EventRow]:
    """The Ticket's audit events read back through the audit-log API."""
    response = await client.get(
        f"/api/v1/tickets/{locator}/audit-log", params={"per_page": 100}
    )
    assert response.status_code == 200
    return _wire_events(response.json()["data"])


class _Composed:
    """One unassigned `New` CVE-less Ticket with a manual `Medium` severity
    and a package tree, plus a CVE carrying a canonical SUSE assessment and
    a KEV entry.

    The tree has one package with one `affected` track and two Product
    occurrences whose `eligible` values are stale against the CVE's
    assessment (SUSE 9.8): the first occurrence (threshold 9.9, eligible)
    flips to ineligible; the second (no threshold, ineligible) flips to
    eligible. Occurrence IDs are pre-sorted so the Product events follow
    the creation order.
    """

    ticket: Ticket
    cve: CVE
    ticket_id: uuid.UUID
    locator: str
    url: str
    cve_string: str
    package_id: uuid.UUID
    track_id: uuid.UUID
    cpes: list[str]


@pytest.fixture
def composed(
    ticket_factory: Factory,
    cve_factory: Factory,
    cve_cvss_assessment_factory: Factory,
    cve_kev_entry_factory: Factory,
    product_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ticket_package_product_factory: Factory,
) -> Callable[..., Awaitable[_Composed]]:
    async def _build(*, is_confidential: bool = False) -> _Composed:
        world = _Composed()
        world.cve = await cve_factory(
            title=_NEW_TITLE, description=_NEW_DESCRIPTION, severity=None
        )
        await cve_cvss_assessment_factory(
            cve_id=world.cve.id,
            provider_name="SUSE",
            cvss_version="3.1",
            score=Decimal("9.8"),
        )
        await cve_kev_entry_factory(cve_id=world.cve.id)
        world.ticket = await ticket_factory(
            status=TicketStatus.NEW.value,
            severity_manual=Severity.MEDIUM.value,
            priority_auto="P4",
            is_confidential=is_confidential,
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )
        package = await ticket_package_factory(
            ticket_id=world.ticket.id, package_name="fictional-alpha"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Alpha:Update",
            status=PackageStatus.AFFECTED.value,
        )
        first_id, second_id = sorted(uuid.uuid7() for _ in range(2))
        world.cpes = []
        for n, (occurrence_id, threshold, eligible) in enumerate(
            [(first_id, Decimal("9.9"), True), (second_id, None, False)], start=1
        ):
            product = await product_factory(
                name=f"fictional-server-{n}",
                display_name=f"Fictional Server {n}",
                cpe=f"cpe:/o:example:fictional_server:{n}",
                general_support_end_date=_GS_END,
                cvss_threshold=threshold,
            )
            world.cpes.append(product.cpe)
            await ticket_package_product_factory(
                id=occurrence_id,
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=eligible,
            )
        world.ticket_id = world.ticket.id
        world.locator = _locator(world.ticket)
        world.url = _url(world.ticket)
        world.cve_string = world.cve.cve_id
        world.package_id = package.id
        world.track_id = track.id
        return world

    return _build


def _composed_events(
    actor: User,
    world: _Composed,
    subject_rows: list[dict[str, str]],
    *,
    assigned: bool,
) -> list[EventRow]:
    """The contractual event sequence of the composed association
    (ticket-service.md, `associate_cve` Audit events; ticket-audit-log.md,
    Cross-Event Ordering): optional assignment and `New -> Analysis`, then
    `cve_associated` (acting user), the system severity handover, the
    Product events in occurrence-ID order, the system priority change, and
    the one final gate event."""
    events: list[EventRow] = []
    if assigned:
        events += [
            EventRow("assignment", actor.id, None, actor.username, None, None),
            EventRow("status_change", None, "New", "Analysis", None, None),
        ]
    events += [
        EventRow("cve_associated", actor.id, None, world.cve_string, None, None),
        EventRow("severity_changed", None, "Medium", "Critical", None, None),
        EventRow(
            "product_eligibility_changed",
            None,
            "true",
            "false",
            None,
            subject_rows[0],
        ),
        EventRow(
            "product_eligibility_changed",
            None,
            "false",
            "true",
            None,
            subject_rows[1],
        ),
        EventRow("priority_changed", None, "P4", "P1", None, None),
    ]
    if assigned:
        events.append(
            EventRow("status_change", None, "Analysis", "Analyzed", None, None)
        )
    return events


async def _subject_rows(db: AsyncSession, ticket_id: uuid.UUID) -> list[dict[str, str]]:
    """The `product_eligibility_changed` detail (`reason = cvss`) of every
    Product occurrence in occurrence-ID order, from the fixture rows."""
    rows = await db.execute(
        select(
            TicketPackageTrack.reference,
            TicketPackage.package_name,
            Product.display_name,
            Product.cpe,
        )
        .select_from(TicketPackageProduct)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Product, Product.id == TicketPackageProduct.product_id)
        .where(TicketPackage.ticket_id == ticket_id)
        .order_by(TicketPackageProduct.id)
    )
    return [
        {
            "track": row.reference,
            "package": row.package_name,
            "product_name": row.display_name,
            "product_cpe": row.cpe,
            "reason": "cvss",
        }
        for row in rows
    ]


async def _eligibility(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[tuple[bool, bool]]:
    """`(eligible, is_eligible_override)` of every occurrence in
    occurrence-ID order."""
    rows = await db.execute(
        select(TicketPackageProduct.eligible, TicketPackageProduct.is_eligible_override)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(TicketPackage.ticket_id == ticket_id)
        .order_by(TicketPackageProduct.id)
    )
    return [(row.eligible, row.is_eligible_override) for row in rows]


def _package_projection(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The identity, eligibility, and deadline fields of the response's
    package tree (milestone projections are owned by ticket-deadlines.md)."""
    return [
        {
            "package_name": package["package_name"],
            "tracks": [
                {
                    "reference": track["reference"],
                    "status": track["status"],
                    "due": {field: track[field] for field in _DUE_MILESTONES},
                    "products": [
                        {
                            "product_cpe": product["product_cpe"],
                            "eligible": product["eligible"],
                            "is_eligible_override": product["is_eligible_override"],
                            "lifecycle_phase": product["lifecycle_phase"],
                            "actionable": product["actionable"],
                        }
                        for product in track["products"]
                    ],
                }
                for track in package["tracks"]
            ],
        }
        for package in data["packages"]
    ]


@pytest.mark.e2e
class TestAssociateCve:
    async def test_va_associates_an_existing_cve_with_evidence_and_assessments(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        composed: Callable[..., Awaitable[_Composed]],
    ) -> None:
        world = await composed()
        assignee = await _user_reference(db_session, va_user.id)
        subject_rows = await _subject_rows(db_session, world.ticket_id)
        cves_before = (await _counts(db_session))[1]

        response = await authenticated_client.post(
            world.url, json={"cve_id": world.cve_string}
        )

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        data = body["data"]
        assert str(world.ticket_id) not in response.text
        assert isinstance(data.pop("updated_at"), str)
        packages = _package_projection(data)
        del data["packages"]
        due = _due_dates(_CREATED_AT, 30)
        assert data == {
            "ticket_id": world.locator,
            "status": "analyzed",
            "severity": "critical",
            "priority": "p1",
            "priority_automatic": "p1",
            "priority_override": None,
            "assignee": assignee,
            "cve": {
                **_placeholder_cve(world.cve_string),
                "title": _NEW_TITLE,
                "description": _NEW_DESCRIPTION,
                "severity": "critical",
                "kev": {"date_added": "2099-01-15", "reference_url": None},
            },
            "duplicate_of_ticket_id": None,
            "is_confidential": False,
            "coordinated_release_at": None,
            **due,
            "created_at": _iso(_CREATED_AT),
        }
        assert packages == [
            {
                "package_name": "fictional-alpha",
                "tracks": [
                    {
                        "reference": "Example:Alpha:Update",
                        "status": "affected",
                        "due": due,
                        "products": [
                            {
                                "product_cpe": world.cpes[0],
                                "eligible": False,
                                "is_eligible_override": False,
                                "lifecycle_phase": "general_support",
                                "actionable": True,
                            },
                            {
                                "product_cpe": world.cpes[1],
                                "eligible": True,
                                "is_eligible_override": False,
                                "lifecycle_phase": "general_support",
                                "actionable": True,
                            },
                        ],
                    }
                ],
            }
        ]

        cve = await _cve_row(db_session, world.cve_string)
        assert cve is not None
        assert cve.severity == Severity.CRITICAL.value
        assert (await _counts(db_session))[1] == cves_before
        assert await _state(db_session, world.ticket_id) == {
            "status": TicketStatus.ANALYZED.value,
            "assignee_id": va_user.id,
            "cve_id": cve.id,
            "severity_manual": None,
            "priority_auto": "P1",
            "priority_override": None,
            "created_at": _CREATED_AT,
        }
        assert await _eligibility(db_session, world.ticket_id) == [
            (False, False),
            (True, False),
        ]
        expected = _composed_events(va_user, world, subject_rows, assigned=True)
        assert await ticket_events_by_id(db_session, world.ticket_id) == expected
        assert await _api_events(authenticated_client, world.locator) == expected

    async def test_non_va_holder_associates_without_assignment(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        composed: Callable[..., Awaitable[_Composed]],
    ) -> None:
        """A `restricted_analyst` holds `triage_ticket` but is not a VA: the
        Ticket stays `New` and unassigned, `New` is outside the gate zone, so
        no assignment, promotion, or gate event exists (tickets.md,
        Auto-Assignment on Unassigned Tickets; Automatic Status Evaluation)."""
        world = await composed()
        subject_rows = await _subject_rows(db_session, world.ticket_id)

        response = await authenticated_client.post(
            world.url, json={"cve_id": world.cve_string}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "new"
        assert data["assignee"] is None
        assert data["severity"] == "critical"
        assert data["priority"] == data["priority_automatic"] == "p1"
        assert data["cve"]["cve_id"] == world.cve_string
        state = await _state(db_session, world.ticket_id)
        assert state["status"] == TicketStatus.NEW.value
        assert state["assignee_id"] is None
        assert state["severity_manual"] is None
        assert await _eligibility(db_session, world.ticket_id) == [
            (False, False),
            (True, False),
        ]
        expected = _composed_events(ra_user, world, subject_rows, assigned=False)
        assert await ticket_events_by_id(db_session, world.ticket_id) == expected
        assert await _api_events(authenticated_client, world.locator) == expected

    async def test_placeholder_cve_is_created_and_associated(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
    ) -> None:
        """An unknown CVE-ID creates a minimal record (`published`, no
        severity, no evidence); the empty assessment set resolves the
        severity to `null`, so the manual severity handover, priority, and
        deadlines fall to the unresolved 30-day worst case."""
        target: Ticket = await ticket_factory(created_at=_CREATED_AT)
        assignee = await _user_reference(db_session, va_user.id)
        before = await _counts(db_session)

        response = await authenticated_client.post(
            _url(target), json={"cve_id": _NEW_CVE_ID}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert isinstance(data.pop("updated_at"), str)
        assert data == {
            "ticket_id": _locator(target),
            "status": "analysis",
            "severity": None,
            "priority": None,
            "priority_automatic": None,
            "priority_override": None,
            "assignee": assignee,
            "cve": _placeholder_cve(_NEW_CVE_ID),
            "duplicate_of_ticket_id": None,
            "is_confidential": False,
            "coordinated_release_at": None,
            **_due_dates(_CREATED_AT, 30),
            "packages": [],
            "created_at": _iso(_CREATED_AT),
        }
        cve = await _cve_row(db_session, _NEW_CVE_ID)
        assert cve is not None
        assert (cve.cve_state, cve.severity, cve.title) == ("PUBLISHED", None, None)
        assert (await _counts(db_session))[1] == before[1] + 1
        state = await _state(db_session, target.id)
        assert state["cve_id"] == cve.id
        assert state["status"] == TicketStatus.ANALYSIS.value
        expected = [
            EventRow("assignment", va_user.id, None, va_user.username, None, None),
            EventRow("status_change", None, "New", "Analysis", None, None),
            EventRow("cve_associated", va_user.id, None, _NEW_CVE_ID, None, None),
        ]
        assert await ticket_events_by_id(db_session, target.id) == expected
        assert await _api_events(authenticated_client, _locator(target)) == expected

    @pytest.mark.parametrize(
        ("score", "label", "priority", "sla_days"),
        [
            pytest.param("9.8", "critical", "p2", 30, id="critical"),
            pytest.param("7.5", "high", "p3", 30, id="high"),
            pytest.param("5.0", "medium", "p4", 90, id="medium"),
            pytest.param("3.1", "low", "p4", 180, id="low"),
            pytest.param("0.0", "none", "p4", None, id="none"),
        ],
    )
    async def test_severity_and_due_dates_follow_the_cve_never_the_start(
        self,
        score: str,
        label: str,
        priority: str,
        sla_days: int | None,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        """A manual `Low` severity (180-day tier) is replaced by the CVE's
        CVSS-derived severity: the SLA tier (ticket-deadlines.md, SLA Tier)
        and priority (ticket-priority.md, Decision Table, `unknown` row)
        follow it, while `created_at` never moves."""
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id,
            provider_name="SUSE",
            cvss_version="3.1",
            score=Decimal(score),
        )
        target: Ticket = await ticket_factory(
            severity_manual=Severity.LOW.value,
            priority_auto="P4",
            created_at=_CREATED_AT,
        )
        before = await authenticated_client.get(f"/api/v1/tickets/{_locator(target)}")
        assert {f: before.json()["data"][f] for f in _DUE_MILESTONES} == _due_dates(
            _CREATED_AT, 180
        )

        response = await authenticated_client.post(
            _url(target), json={"cve_id": cve.cve_id}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["severity"] == label
        assert data["cve"]["severity"] == label
        assert data["priority"] == data["priority_automatic"] == priority
        assert {f: data[f] for f in _DUE_MILESTONES} == _due_dates(
            _CREATED_AT, sla_days
        )
        assert data["created_at"] == before.json()["data"]["created_at"]
        assert data["created_at"] == _iso(_CREATED_AT)
        assert (await _state(db_session, target.id))["created_at"] == _CREATED_AT

    async def test_analyzed_ticket_regresses_without_a_suse_assessment(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        user_role_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """The empty assessment set fails gates 3 and 4 (tickets.md,
        Associating a CVE Later): `Analyzed` regresses to `Analysis`, the
        manual severity hands over to `null`, and an assigned Ticket keeps
        its owner (no second assignment)."""
        owner = await user_factory(username="bob.owner", full_name="Bob Owner")
        await user_role_factory(user_id=owner.id, role=Role.VULNERABILITY_ANALYST.value)
        target: Ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value,
            assignee_id=owner.id,
            severity_manual=Severity.HIGH.value,
            priority_auto="P3",
            created_at=_CREATED_AT,
        )
        package = await ticket_package_factory(ticket_id=target.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.AFFECTED.value
        )
        product = await product_factory(general_support_end_date=_GS_END)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
        owner_reference = await _user_reference(db_session, owner.id)

        response = await authenticated_client.post(
            _url(target), json={"cve_id": _NEW_CVE_ID}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "analysis"
        assert data["assignee"] == owner_reference
        assert data["severity"] is None
        assert data["priority"] is None
        assert {f: data[f] for f in _DUE_MILESTONES} == _due_dates(_CREATED_AT, 30)
        assert await ticket_events_by_id(db_session, target.id) == [
            EventRow("cve_associated", va_user.id, None, _NEW_CVE_ID, None, None),
            EventRow("severity_changed", None, "High", None, None, None),
            EventRow("priority_changed", None, "P3", None, None, None),
            EventRow("status_change", None, "Analyzed", "Analysis", None, None),
        ]

    @pytest.mark.parametrize(
        ("holder", "assigned"),
        [
            pytest.param("va-scope", True, id="va-scope-all"),
            pytest.param("ra-grant", False, id="ra-explicit-grant"),
            pytest.param("ra-maintainer", False, id="ra-included-package-maintainer"),
        ],
    )
    async def test_accessible_confidential_ticket_is_associated(
        self,
        holder: str,
        assigned: bool,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        user_role_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        """Every additive visibility branch lets an authorized caller
        associate a CVE with a confidential Ticket (rbac.md, Scope and
        Confidential Ticket Visibility)."""
        role = (
            Role.VULNERABILITY_ANALYST
            if holder == "va-scope"
            else Role.RESTRICTED_ANALYST
        )
        await user_role_factory(user_id=authenticated_user.id, role=role.value)
        target: Ticket = await ticket_factory(is_confidential=True)
        if holder == "ra-grant":
            await ticket_access_grant_factory(
                ticket_id=target.id, user_id=authenticated_user.id
            )
        elif holder == "ra-maintainer":
            package = await ticket_package_factory(ticket_id=target.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.post(
            _url(target), json={"cve_id": _NEW_CVE_ID}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["ticket_id"] == _locator(target)
        assert data["is_confidential"] is True
        assert data["cve"]["cve_id"] == _NEW_CVE_ID
        assert (data["assignee"] is not None) is assigned
        state = await _state(db_session, target.id)
        assert state["cve_id"] is not None
        assert (state["assignee_id"] == authenticated_user.id) is assigned

    async def test_already_rejected_cve_keeps_the_ordinary_status(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """tickets.md, CVE Resolution Behavior (Already rejected, manual
        operation): no automatic `Ignored` and no `CVE rejected` event."""
        cve: CVE = await cve_factory(
            cve_state="REJECTED", date_rejected=datetime(2099, 3, 4, tzinfo=UTC)
        )
        target: Ticket = await ticket_factory()

        response = await authenticated_client.post(
            _url(target), json={"cve_id": cve.cve_id}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "analysis"
        assert data["cve"]["cve_state"] == "rejected"
        assert await ticket_events_by_id(db_session, target.id) == [
            EventRow("assignment", va_user.id, None, va_user.username, None, None),
            EventRow("status_change", None, "New", "Analysis", None, None),
            EventRow("cve_associated", va_user.id, None, cve.cve_id, None, None),
        ]


# ---------------------------------------------------------------------------
# Transaction: commit, final assembly, and whole-transaction rollback
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTransaction:
    async def test_committed_detail_is_assembled_from_the_post_state_and_equals_a_get(
        self,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        composed: Callable[..., Awaitable[_Composed]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The detail is assembled from the mutation's flushed, uncommitted
        post-state (association, all eight events) and matches the
        committed read that follows."""
        user, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        world = await composed()
        await db_session.commit()
        observed: list[tuple[bool, str | None, int]] = []
        original = ticket_service.assemble_ticket_detail

        async def _observe(db: AsyncSession, **kwargs: Any) -> Any:
            state = await _state(db, world.ticket_id)
            events = await ticket_events_by_id(db, world.ticket_id)
            observed.append(
                (state["cve_id"] is not None, state["severity_manual"], len(events))
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _observe)

        response = await commit_client.post(
            world.url, json={"cve_id": world.cve_string}
        )

        assert response.status_code == 200
        assert observed == [(True, None, 8)]
        data = response.json()["data"]
        assert data["assignee"]["id"] == str(user.id)
        detail = await commit_client.get(f"/api/v1/tickets/{world.locator}")
        assert detail.status_code == 200
        assert detail.json()["data"] == data
        assert (await _state(db_session, world.ticket_id))["cve_id"] is not None


_INTERNAL_ERROR = {"code": "INTERNAL_ERROR", "detail": "An unexpected error occurred."}


class _Injection:
    """What an armed failure recorded."""

    def __init__(self) -> None:
        self.reached = False
        self.mutated_at_failure: bool | None = None


_FAILURES = ["assembly", "chain"]
"""The request-level injections. Every other failure position (settings,
database, eligibility, flush, each audit event, reconciliation) is proven by
the service-level rollback matrix in
`tests/test_services/test_associate_cve_atomicity.py`; here only a failure
after the complete service chain (in the handler's detail assembly, or right
after the CVSS chain) must still roll back through the request's `get_db`."""


@pytest.mark.e2e
class TestAtomicity:
    """An unexpected failure after the service mutated rolls back the
    association, the cleared manual severity, the assignment, the Product
    values, the automatic priority, the status, every event, and a
    placeholder CVE together (ticket-service.md, `associate_cve`;
    tickets.md, Associating a CVE Later). The commit client's `get_db` rolls
    back exactly like production when the handler raises."""

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize("failure", _FAILURES)
    async def test_injected_failure_rolls_back_everything(
        self,
        failure: str,
        cve_kind: str,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        composed: Callable[..., Awaitable[_Composed]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        world = await composed()
        ticket_id = world.ticket_id
        cve_string = world.cve_string if cve_kind == "existing" else _NEW_CVE_ID
        injection = _Injection()
        injected = RuntimeError(f"injected {failure} failure")

        async def _mutated(db: AsyncSession) -> bool:
            return (await _state(db, ticket_id))["cve_id"] is not None

        await db_session.commit()
        before = await _snapshot(db_session, ticket_id)

        if failure == "assembly":

            async def failing_assembly(db: AsyncSession, **kwargs: Any) -> Any:
                injection.reached = True
                injection.mutated_at_failure = await _mutated(db)
                raise injected

            monkeypatch.setattr(
                ticket_service, "assemble_ticket_detail", failing_assembly
            )
        else:
            original_chain = ticket_mutations.recalculate_cvss_chain

            async def failing_chain(*args: Any, **kwargs: Any) -> Any:
                await original_chain(*args, **kwargs)
                injection.reached = True
                injection.mutated_at_failure = await _mutated(args[0])
                raise injected

            monkeypatch.setattr(ticket_service, "recalculate_cvss_chain", failing_chain)

        response = await commit_client.post(world.url, json={"cve_id": cve_string})
        monkeypatch.undo()

        # The body is not asserted: the test app runs Starlette's debug
        # error page, which is not the production envelope (see
        # `TestInternalError`).
        assert response.status_code == 500
        assert injection.reached is True
        assert injection.mutated_at_failure is True
        assert await _snapshot(db_session, ticket_id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_unfailed_request_persists_what_the_failures_roll_back(
        self,
        cve_kind: str,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        composed: Callable[..., Awaitable[_Composed]],
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same request, committed, changes every value the failures leave
        untouched."""
        _, commit_client = await commit_app.login(Role.VULNERABILITY_ANALYST)
        world = await composed()
        cve_string = world.cve_string if cve_kind == "existing" else _NEW_CVE_ID
        await db_session.commit()
        before = await _snapshot(db_session, world.ticket_id)

        response = await commit_client.post(world.url, json={"cve_id": cve_string})

        assert response.status_code == 200
        assert await _snapshot(db_session, world.ticket_id) != before
        state = await _state(db_session, world.ticket_id)
        assert state["cve_id"] is not None
        assert state["assignee_id"] is not None
        assert state["severity_manual"] is None
        assert len(await ticket_events_by_id(db_session, world.ticket_id)) == (
            8 if cve_kind == "existing" else 6
        )
        assert (await _cve_row(db_session, _NEW_CVE_ID) is not None) is (
            cve_kind == "placeholder"
        )


@pytest.mark.e2e
class TestInternalError:
    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_missing_default_version_is_the_generic_500_and_rolls_back(
        self,
        cve_kind: str,
        commit_app: _CommitApp,
        db_session: AsyncSession,
        composed: Callable[..., Awaitable[_Composed]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """`RequiredSystemSettingMissingError` is not caught by the handler
        (system-settings.md, Service Exceptions), so it renders as the global
        `500 INTERNAL_ERROR` (api-spec.md, Global Responses) without leaking
        the setting name, and the request's transaction rolls back. The
        shared test app runs Starlette's debug error page, so the envelope
        is observed on a production-configured app that mounts the same
        router with the application's own exception handlers."""
        user, _ = await commit_app.login(Role.VULNERABILITY_ANALYST)
        session_token = commit_app.token_of(user)
        world = await composed()
        cve_string = world.cve_string if cve_kind == "existing" else _NEW_CVE_ID
        await db_session.execute(
            delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
        )
        await db_session.commit()
        before = await _snapshot(db_session, world.ticket_id)
        handlers: dict[Any, Any] = {
            Exception: main_module._unhandled_exception_handler,
            AppError: main_module._app_error_handler,
            RequestValidationError: main_module._validation_error_handler,
        }
        production = FastAPI(debug=False, exception_handlers=handlers)
        production.include_router(route.router)
        production.dependency_overrides = app.dependency_overrides

        async with AsyncClient(
            transport=ASGITransport(app=production, raise_app_exceptions=False),
            base_url="http://test",
            cookies={SESSION_COOKIE_NAME: session_token},
        ) as client:
            with caplog.at_level("ERROR"):
                response = await client.post(world.url, json={"cve_id": cve_string})

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert "default_cvss_version" not in response.text
        assert "RequiredSystemSettingMissingError" in caplog.text
        assert await _snapshot(db_session, world.ticket_id) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None


# ---------------------------------------------------------------------------
# Independent transactions: real commits, rollback observed by another session
# ---------------------------------------------------------------------------


class _CommittedApp(CommittedWorld):
    """Committed rows and credentials for tests whose every request runs in
    its own independent session, committed or rolled back like production
    `app.database.get_db` (testing-strategy.md, Concurrency Testing).

    Owns the committed `default_cvss_version` setting (the test schema has
    none) unless a test omits it, and deletes every Session, CVE (including
    the placeholders a request may create, found by CVE-ID string), Ticket,
    and event at teardown, even after a failed assertion.
    """

    probe: AsyncSession
    """The independent session that observes committed state; separate from
    `session`, whose committed model instances the tests keep reading."""

    def __init__(
        self, factory: Callable[[], Awaitable[AsyncSession]], session: AsyncSession
    ) -> None:
        super().__init__(factory, session)
        self.cve_id_strings: list[str] = []
        self._owns_setting = False

    def new_cve_id(self) -> str:
        cve_id = f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"
        self.cve_id_strings.append(cve_id)
        return cve_id

    async def ensure_default_setting(self) -> None:
        if await self.session.get(SystemSetting, "default_cvss_version") is None:
            self.session.add(SystemSetting(key="default_cvss_version", value="3.1"))
            self._owns_setting = True
        await self.session.commit()

    async def credential(self, user: User) -> dict[str, str]:
        created = await create_session(
            self.session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        await self.session.commit()
        return {"Authorization": f"Bearer {created.token}"}

    async def observed_state(
        self, ticket_id: uuid.UUID, cve_string: str
    ) -> tuple[list[tuple[Any, ...]], ...]:
        """Everything the association may change, read through the
        independent probe: the Ticket row, its events, its Product
        occurrences, and the CVE rows with this CVE-ID string."""
        db = self.probe
        tickets = (
            await db.execute(select(Ticket.__table__).where(Ticket.id == ticket_id))
        ).all()
        events = (
            await db.execute(
                select(TicketAuditEvent.__table__)
                .where(TicketAuditEvent.ticket_id == ticket_id)
                .order_by(TicketAuditEvent.id)
            )
        ).all()
        products = (
            await db.execute(
                select(TicketPackageProduct.__table__)
                .join(
                    TicketPackageTrack,
                    TicketPackageTrack.id
                    == TicketPackageProduct.ticket_package_track_id,
                )
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageTrack.ticket_package_id,
                )
                .where(TicketPackage.ticket_id == ticket_id)
                .order_by(TicketPackageProduct.id)
            )
        ).all()
        cves = (
            await db.execute(select(CVE.__table__).where(CVE.cve_id == cve_string))
        ).all()
        await db.rollback()
        return tuple(
            [tuple(r) for r in rows] for rows in (tickets, events, products, cves)
        )

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        found = (
            await self.session.scalars(
                select(CVE.id).where(CVE.cve_id.in_(self.cve_id_strings))
            )
        ).all()
        self.cve_ids.extend(set(found) - set(self.cve_ids))
        tickets = (
            await self.session.scalars(
                select(Ticket.id).where(
                    or_(
                        Ticket.cve_id.in_(self.cve_ids),
                        Ticket.assignee_id.in_(self.user_ids),
                    )
                )
            )
        ).all()
        self.ticket_ids.extend(set(tickets) - set(self.ticket_ids))
        await self.session.execute(
            delete(SessionRow).where(SessionRow.user_id.in_(self.user_ids))
        )
        await self.session.commit()
        await super().cleanup()
        if self._owns_setting:
            await self.session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
            await self.session.commit()


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[tuple[_CommittedApp, AsyncClient]]:
    world = _CommittedApp(db_session_factory, await db_session_factory())
    world.probe = await world.open_session()

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        session = await world.open_session()
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
    async def _prepare(
        self, world: _CommittedApp, cve_kind: str
    ) -> tuple[User, dict[str, str], Ticket, str]:
        """A committed VA, an unassigned `New` CVE-less Ticket with a manual
        `Medium` severity and one stale-eligible affected Product, and the
        CVE-ID to associate (an existing CVE with a SUSE 9.8 assessment, or
        an unknown one)."""
        user = await world.user(role=Role.VULNERABILITY_ANALYST)
        headers = await world.credential(user)
        ticket = await world.ticket(
            cve_id=None,
            status=TicketStatus.NEW,
            severity_manual=Severity.MEDIUM,
            priority_auto="P4",
        )
        await world.affected_product(ticket, threshold=Decimal("9.9"), eligible=True)
        if cve_kind == "existing":
            cve = await world.cve(V31_CRITICAL, severity=None)
            world.cve_id_strings.append(cve.cve_id)
            cve_string = cve.cve_id
        else:
            cve_string = world.new_cve_id()
        return user, headers, ticket, cve_string

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize(
        "failure",
        ["assembly", "settings", "reconciliation", "audit-priority_changed"],
    )
    async def test_failed_request_leaves_no_trace_for_an_independent_session(
        self,
        failure: str,
        cve_kind: str,
        committed_app: tuple[_CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_app
        if failure != "settings":
            await world.ensure_default_setting()
        _, headers, ticket, cve_string = await self._prepare(world, cve_kind)
        ticket_id = ticket.id
        url = _url(ticket)
        before = await world.observed_state(ticket_id, cve_string)
        seen: list[bool] = []
        injected = RuntimeError(f"injected {failure} failure")

        if failure == "assembly":

            async def failing_assembly(db: AsyncSession, **kwargs: Any) -> Any:
                # The request's own transaction sees the association; the
                # independent probe must not.
                seen.append((await _state(db, ticket_id))["cve_id"] is not None)
                assert await world.observed_state(ticket_id, cve_string) == before
                raise injected

            monkeypatch.setattr(
                ticket_service, "assemble_ticket_detail", failing_assembly
            )
        elif failure == "reconciliation":
            original_reconcile = ticket_mutations.reconcile_ticket_status

            async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                await original_reconcile(*args, **kwargs)
                seen.append(True)
                raise injected

            monkeypatch.setattr(
                ticket_service, "reconcile_ticket_status", failing_reconcile
            )
        elif failure.startswith("audit-"):
            event_type = failure.removeprefix("audit-")
            original_log = TicketAuditLog.log_event

            async def failing_log(*args: Any, **kwargs: Any) -> None:
                if kwargs["event_type"].value == event_type:
                    seen.append(True)
                    raise injected
                await original_log(*args, **kwargs)

            monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)

        response = await committed_client.post(
            url, json={"cve_id": cve_string}, headers=headers
        )
        monkeypatch.undo()

        assert response.status_code == 500
        if failure != "settings":
            assert seen == [True]
        after = await world.observed_state(ticket_id, cve_string)
        assert after == before
        assert not after[3] if cve_kind == "placeholder" else len(after[3]) == 1

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_successful_request_is_visible_to_an_independent_session(
        self,
        cve_kind: str,
        committed_app: tuple[_CommittedApp, AsyncClient],
    ) -> None:
        """Control for the failure matrix: the same request commits the
        association, every event, and the placeholder before responding."""
        world, committed_client = committed_app
        await world.ensure_default_setting()
        user, headers, ticket, cve_string = await self._prepare(world, cve_kind)
        ticket_id = ticket.id
        before = await world.observed_state(ticket_id, cve_string)

        response = await committed_client.post(
            _url(ticket), json={"cve_id": cve_string}, headers=headers
        )

        assert response.status_code == 200
        after = await world.observed_state(ticket_id, cve_string)
        assert after != before
        assert len(after[3]) == 1
        committed = (
            await world.probe.execute(
                select(Ticket.cve_id, Ticket.assignee_id, Ticket.severity_manual).where(
                    Ticket.id == ticket_id
                )
            )
        ).one()
        cve_uuid = await world.probe.scalar(
            select(CVE.id).where(CVE.cve_id == cve_string)
        )
        events = await ticket_events_by_id(world.probe, ticket_id)
        await world.probe.rollback()
        assert committed.cve_id == cve_uuid
        assert committed.assignee_id == user.id
        assert committed.severity_manual is None
        assert [e.event_type for e in events][:3] == [
            "assignment",
            "status_change",
            "cve_associated",
        ]
        assert events[2].new_value == cve_string


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured date across UTC midnight
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.instant


def _sql_dates(recorder: StatementRecorder) -> set[date]:
    """Every pure `date` bound in the recorded statements."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


@pytest.mark.e2e
class TestEvaluationDate:
    async def test_one_date_captured_before_midnight_is_reused_after_it(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The handler captures 2026-09-27 just before UTC midnight; every
        later step runs after midnight. The Product leaves General Support
        and enters Reactive Support (ineligible) on 2026-09-28, so its
        recalculated eligibility and projected lifecycle phase reveal the
        date each step used."""
        captured = date(2026, 9, 27)
        handler_clock = _Clock(datetime(2026, 9, 27, 23, 59, 59, 900000, tzinfo=UTC))
        projection_clock = _Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        mutation_clock = _Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", projection_clock.now)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id,
            provider_name="SUSE",
            cvss_version="3.1",
            score=Decimal("9.8"),
        )
        target: Ticket = await ticket_factory(
            severity_manual=Severity.MEDIUM.value, priority_auto="P4"
        )
        package = await ticket_package_factory(ticket_id=target.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.AFFECTED.value
        )
        product = await product_factory(
            general_support_end_date=captured,
            extended_support_end_date=captured,
            reactive_support_end_date=_GS_END,
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=False
        )
        seen: dict[str, list[Any]] = {
            "association": [],
            "chain": [],
            "reconcile": [],
            "assembly": [],
            "statement": [],
        }
        original_association = ticket_service.associate_cve
        original_chain = ticket_mutations.recalculate_cvss_chain
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_assembly = ticket_service.assemble_ticket_detail
        original_statement = ticket_service._detail_statement

        async def _association(db: AsyncSession, **kwargs: Any) -> Ticket:
            seen["association"].append(kwargs.get("evaluation_date"))
            return await original_association(db, **kwargs)

        async def _chain(db: AsyncSession, **kwargs: Any) -> Any:
            seen["chain"].append(kwargs.get("evaluation_date"))
            return await original_chain(db, **kwargs)

        async def _reconcile(
            ticket: Ticket, db: AsyncSession, *args: Any, **kwargs: Any
        ) -> None:
            seen["reconcile"].append(kwargs.get("evaluation_date"))
            await original_reconcile(ticket, db, *args, **kwargs)

        async def _assembly(db: AsyncSession, **kwargs: Any) -> Any:
            seen["assembly"].append(kwargs.get("evaluation_date"))
            return await original_assembly(db, **kwargs)

        def _statement(evaluation_date: date) -> Any:
            seen["statement"].append(evaluation_date)
            return original_statement(evaluation_date)

        monkeypatch.setattr(ticket_service, "associate_cve", _association)
        monkeypatch.setattr(ticket_service, "recalculate_cvss_chain", _chain)
        monkeypatch.setattr(ticket_service, "reconcile_ticket_status", _reconcile)
        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        monkeypatch.setattr(ticket_service, "_detail_statement", _statement)

        with StatementRecorder(db_session) as recorder:
            response = await authenticated_client.post(
                _url(target), json={"cve_id": cve.cve_id}
            )

        assert response.status_code == 200
        assert seen == {
            "association": [captured],
            "chain": [captured],
            "reconcile": [captured],
            "assembly": [captured],
            "statement": [captured],
        }
        # One handler date; the projection instant is captured once by the
        # assembly; neither the service nor the mutations capture another.
        assert handler_clock.calls == 1
        assert projection_clock.calls == 1
        assert mutation_clock.calls == 0
        assert _sql_dates(recorder) == {captured}
        data = response.json()["data"]
        (packaged,) = data["packages"][0]["tracks"][0]["products"]
        # On the captured date the Product is in General Support: the
        # recalculation made it eligible and the projection reports the phase
        # of the same date, although the wall clock had passed midnight.
        assert packaged["lifecycle_phase"] == "general_support"
        assert packaged["eligible"] is True
        assert await _eligibility(db_session, target.id) == [(True, False)]

    async def test_handler_captures_a_fresh_date_per_request(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The date belongs to the request: two requests at different
        instants pass their own dates."""
        clock = _Clock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", clock.now)
        association = _spy_association(monkeypatch)
        first: Ticket = await ticket_factory()
        second: Ticket = await ticket_factory()

        assert (
            await authenticated_client.post(
                _url(first), json={"cve_id": "CVE-2099-0301"}
            )
        ).status_code == 200
        clock.instant = datetime(2026, 9, 28, 0, 0, 1, tzinfo=UTC)
        assert (
            await authenticated_client.post(
                _url(second), json={"cve_id": "CVE-2099-0302"}
            )
        ).status_code == 200

        assert [c.kwargs["evaluation_date"] for c in association.await_args_list] == [
            date(2026, 9, 27),
            date(2026, 9, 28),
        ]


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------

_OPENAPI_PATH = "/api/v1/tickets/{ticket_id}/associate-cve"


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_OPENAPI_PATH]["post"]
        return operation

    def _schema(self, name: str) -> dict[str, Any]:
        schema: dict[str, Any] = self._spec()["components"]["schemas"][name]
        return schema

    @staticmethod
    def _ref_name(schema: dict[str, Any]) -> str:
        ref: str = schema["$ref"]
        return ref.rsplit("/", 1)[-1]

    def _content_schema(self, response: dict[str, Any]) -> dict[str, Any]:
        content: dict[str, Any] = response["content"]["application/json"]["schema"]
        return content

    def test_operation_is_documented(self) -> None:
        operation = self._operation()

        assert operation["tags"] == ["Tickets"]
        assert operation["summary"] == "Associate CVE"
        description = operation["description"]
        assert "triage_ticket" in description
        assert "placeholder" in description
        assert "TicketDetail" in description or "Ticket detail" in description
        assert set(self._spec()["paths"][_OPENAPI_PATH]) == {"post"}

    def test_path_parameter_is_a_plain_string(self) -> None:
        operation = self._operation()
        (path_param,) = [p for p in operation["parameters"] if p["in"] == "path"]

        assert path_param["name"] == "ticket_id"
        assert path_param["schema"]["type"] == "string"
        assert "pattern" not in path_param["schema"]
        assert "format" not in path_param["schema"]
        assert [p for p in operation["parameters"] if p["in"] == "query"] == []

    def test_request_body_requires_an_unbounded_string_cve_id(self) -> None:
        request_body = self._operation()["requestBody"]
        assert request_body["required"] is True
        content = request_body["content"]["application/json"]["schema"]
        assert self._ref_name(content) == "TicketAssociateCVERequest"

        schema = self._schema("TicketAssociateCVERequest")
        assert schema["required"] == ["cve_id"]
        assert set(schema["properties"]) == {"cve_id"}
        cve_id = schema["properties"]["cve_id"]
        assert cve_id["type"] == "string"
        assert cve_id["examples"] == ["CVE-2024-1234"]
        # No schema length/pattern limit: over-length and malformed strings
        # reach `CVE_INVALID_FORMAT` rather than the global 422.
        assert not {"maxLength", "minLength", "pattern", "format", "enum"} & set(cve_id)
        assert "maxLength" not in str(schema)
        assert "CVE_INVALID_FORMAT" in cve_id["description"]

    def test_success_response_is_the_detail_envelope(self) -> None:
        responses = self._operation()["responses"]

        assert "201" not in responses
        assert self._ref_name(self._content_schema(responses["200"])) == (
            "TicketDetailResponse"
        )
        envelope = self._schema("TicketDetailResponse")
        assert set(envelope["properties"]) == {"data"}
        assert self._ref_name(envelope["properties"]["data"]) == "TicketDetail"

    def test_error_responses_are_documented(self) -> None:
        responses = self._operation()["responses"]

        assert {"200", "400", "404", "409", "422"} <= set(responses)
        for status in ("400", "404", "422"):
            assert self._ref_name(self._content_schema(responses[status])) == (
                "ErrorResponse"
            ), status
        assert "TICKET_CVE_ALREADY_SET" in responses["400"]["description"]
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        conflict = self._content_schema(responses["409"])
        assert sorted(self._ref_name(v) for v in conflict["anyOf"]) == [
            "ErrorResponse",
            "TicketCVEConflictErrorResponse",
        ]
        assert "TICKET_CVE_CONFLICT" in responses["409"]["description"]
        assert "existing_ticket_id" in responses["409"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "CVE_INVALID_FORMAT" in responses["422"]["description"]
        assert "VALIDATION_ERROR" in responses["422"]["description"]

    def test_conflict_schema_requires_the_existing_ticket_identifier(self) -> None:
        schema = self._schema("TicketCVEConflictErrorResponse")

        assert set(schema["properties"]) == {"code", "detail", "existing_ticket_id"}
        assert set(schema["required"]) == {"code", "detail", "existing_ticket_id"}
        assert "SNTL-{n}" in schema["properties"]["existing_ticket_id"]["description"]


@pytest.mark.e2e
class TestIndependentRaces:
    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_visibility_lost_to_a_committed_change_after_the_preliminary_check(
        self,
        cve_kind: str,
        committed_app: tuple[_CommittedApp, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another session commits the confidentiality flag after the
        preliminary dependency check but before the service locks the
        Ticket: locked-current accessibility (api-spec.md, flow 3) yields
        the identical 404 with no association, assignment, event, or
        placeholder CVE."""
        world, committed_client = committed_app
        await world.ensure_default_setting()
        user = await world.user(role=Role.RESTRICTED_ANALYST)
        headers = await world.credential(user)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        if cve_kind == "existing":
            cve = await world.cve(V31_CRITICAL, severity=None)
            world.cve_id_strings.append(cve.cve_id)
            cve_string = cve.cve_id
        else:
            cve_string = world.new_cve_id()
        ticket_id, url = ticket.id, _url(ticket)
        original = ticket_service.associate_cve
        reached: list[bool] = []

        async def _lose_then_associate(db: AsyncSession, **kwargs: Any) -> Ticket:
            reached.append(True)
            racer = await world.open_session()
            await racer.execute(
                update(Ticket)
                .where(Ticket.id == ticket_id)
                .values(is_confidential=True)
            )
            await racer.commit()
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "associate_cve", _lose_then_associate)

        response = await committed_client.post(
            url, json={"cve_id": cve_string}, headers=headers
        )
        monkeypatch.undo()

        assert response.status_code == 404
        assert response.content == _NOT_FOUND
        assert reached == [True]
        fresh = await world.open_session()
        state = await _state(fresh, ticket_id)
        events = await ticket_events_by_id(fresh, ticket_id)
        cves = (
            await fresh.scalars(select(CVE.id).where(CVE.cve_id == cve_string))
        ).all()
        await fresh.rollback()
        assert state["cve_id"] is None
        assert state["assignee_id"] is None
        assert state["status"] == TicketStatus.NEW.value
        assert events == []
        assert len(cves) == (1 if cve_kind == "existing" else 0)
