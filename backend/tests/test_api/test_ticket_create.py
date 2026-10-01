"""End-to-end tests for the Create Ticket endpoint (`POST /api/v1/tickets`,
`backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (Create Ticket; CVE Resolution Behavior;
Manual Creation; Identifier Disclosure Boundary; Coordinated Release Date;
Response Schemas > TicketDetail; Endpoint -> Schema Mapping),
docs/features/tickets/ticket-service.md (`create_ticket`;
`get_ticket_detail()` mutation assembly), docs/features/identity/rbac.md
(Endpoint Permission Map `POST /api/v1/tickets` and the † note; Business
Rules 11 and 13), docs/api-spec.md (Authorization Chain Evaluation Order
flow 3; Response Format: `existing_ticket_id`; What belongs in an endpoint
error table > Conditional authorization; Anti-Enumeration Boundary; Ticket
Identifier Resolution), and docs/features/platform/testing-strategy.md
(Ticket Accessibility; Audit Trail Testing).

The service-level creation matrix (every optional event combination, lock
order, ingestion, every rollback position, and the concurrent-creation race)
lives in tests/test_services/test_create_ticket*.py; these tests cover the HTTP
boundary. Expected values are transcribed from the specifications.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import tickets as route
from app.core.enums import (
    Role,
    SessionCreationReason,
)
from app.core.identifiers import format_ticket_id
from app.database import get_db
from app.main import app
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import ticket_mutations, ticket_service, user_service
from app.services.session_service import create_session
from app.services.ticket_service import TicketDetailProjection
from tests.support.ticket_creation import creation_events
from tests.support.ticket_mutations import (
    StatementRecorder,
    ticket_events_by_id,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets"
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
_SEVERITY_DERIVED = {
    "code": "TICKET_SEVERITY_DERIVED",
    "detail": "Ticket severity is derived from CVSS assessments.",
}
_CONFLICT_DETAIL = "CVE is already associated with another Ticket."
_TICKET_NOT_FOUND = {"code": "TICKET_NOT_FOUND", "detail": "Ticket not found."}
_LITERAL_MESSAGE = "Input should be 'critical', 'high', 'medium', 'low' or 'none'"

_NEW_CVE_ID = "CVE-2099-0201"
"""A CVE-ID with no row: a successful creation inserts a placeholder."""
_CRD = "2026-10-06T14:00:00Z"
_CRD_INSTANT = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _due_dates(created_at: str, sla_days: int | None) -> dict[str, datetime | None]:
    """The five Ticket due dates for an SLA tier (`None`: no SLA)."""
    if sla_days is None:
        return dict.fromkeys(_DUE_MILESTONES)
    start = _parse(created_at)
    return {
        field: start
        + timedelta(seconds=sla_days * _SECONDS_PER_DAY_PERCENT * milestone)
        for field, milestone in _DUE_MILESTONES.items()
    }


def _response_due_dates(data: dict[str, Any]) -> dict[str, datetime | None]:
    return {
        field: _parse(data[field]) if data[field] is not None else None
        for field in _DUE_MILESTONES
    }


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
        await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    ).scalar_one_or_none()


async def _ticket_uuid(db: AsyncSession, ticket_id: str) -> uuid.UUID:
    """The internal UUID of the Ticket named by a returned `SNTL-{n}`."""
    sequence = int(ticket_id.removeprefix("SNTL-"))
    return (
        await db.execute(select(Ticket.id).where(Ticket.sequence_id == sequence))
    ).scalar_one()


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted creation-relevant columns of a Ticket."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.cve_id,
                Ticket.severity_manual,
                Ticket.is_confidential,
                Ticket.coordinated_release_at,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.duplicate_of_id,
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


def _domain_statements(recorder: StatementRecorder) -> list[str]:
    return [s for s in recorder.statements if _DOMAIN_TABLE.search(s)]


def _spy_creation(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Wrap `ticket_service.create_ticket` in a pass-through spy."""
    spy = AsyncMock(side_effect=ticket_service.create_ticket)
    monkeypatch.setattr(ticket_service, "create_ticket", spy)
    return spy


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest_asyncio.fixture
async def va_user(authenticated_user: User, user_role_factory: Factory) -> User:
    """`authenticated_client`'s user holding only `vulnerability_analyst`
    (`create_ticket` and `manage_confidentiality`)."""
    await user_role_factory(
        user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
    )
    return authenticated_user


@pytest_asyncio.fixture
async def ra_user(authenticated_user: User, user_role_factory: Factory) -> User:
    """`authenticated_client`'s user holding only `restricted_analyst`
    (`create_ticket` without `manage_confidentiality`)."""
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

    Commits and rollbacks act on `db_session`'s savepoint; the outer test
    transaction still reverts everything at teardown.
    `raise_app_exceptions=False` returns the 500 response instead of
    re-raising into the test.
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
# Authentication and the base capability (flow 3, step 1)
# ---------------------------------------------------------------------------


_PRE_CAPABILITY_BODIES = [
    pytest.param({}, id="empty"),
    pytest.param({"cve_id": _NEW_CVE_ID}, id="new-cve"),
    pytest.param({"is_confidential": True, "coordinated_release_at": _CRD}, id="crd"),
    pytest.param({"cve_id": "not-a-cve"}, id="malformed-cve"),
    pytest.param({"severity": "High"}, id="schema-invalid"),
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
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _counts(db_session)
        creation = _spy_creation(monkeypatch)
        role_loader = AsyncMock()
        monkeypatch.setattr(user_service, "get_user_roles", role_loader)

        with StatementRecorder(db_session) as recorder:
            response = await client.post(_PATH, json=body, headers=headers)

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        creation.assert_not_awaited()
        role_loader.assert_not_awaited()
        assert _domain_statements(recorder) == []
        assert await _counts(db_session) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None


@pytest.mark.e2e
class TestCapability:
    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_create_ticket_gets_the_generic_403_first(
        self,
        roles: list[Role],
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Every body — valid, confidential, malformed CVE, or schema-invalid
        — returns the identical 403 without any Ticket or CVE statement."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        before = await _counts(db_session)
        creation = _spy_creation(monkeypatch)

        bodies = []
        with StatementRecorder(db_session) as recorder:
            for param in _PRE_CAPABILITY_BODIES:
                (body,) = param.values
                response = await authenticated_client.post(_PATH, json=body)
                assert response.status_code == 403, param.id
                assert response.json() == _FORBIDDEN, param.id
                bodies.append(response.content)

        assert len(set(bodies)) == 1
        creation.assert_not_awaited()
        assert _domain_statements(recorder) == []
        assert await _counts(db_session) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None


# ---------------------------------------------------------------------------
# Presence-based field-level `manage_confidentiality` (rbac.md BR13, †)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestConfidentialityCapability:
    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"is_confidential": True}, id="true"),
            pytest.param({"is_confidential": False}, id="false"),
            pytest.param(
                {"is_confidential": True, "cve_id": _NEW_CVE_ID}, id="true-cve"
            ),
            pytest.param(
                {"is_confidential": True, "coordinated_release_at": _CRD}, id="crd"
            ),
            pytest.param(
                {"is_confidential": True, "cve_id": "not-a-cve"},
                id="precedes-cve-format",
            ),
            pytest.param(
                {"is_confidential": False, "cve_id": _NEW_CVE_ID, "severity": "high"},
                id="precedes-severity-derived",
            ),
        ],
    )
    async def test_present_field_without_the_capability_is_403_without_effect(
        self,
        body: dict[str, Any],
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _counts(db_session)
        creation = _spy_creation(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await authenticated_client.post(_PATH, json=body)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        creation.assert_not_awaited()
        assert _domain_statements(recorder) == []
        assert await _counts(db_session) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    @pytest.mark.parametrize(
        ("body", "severity", "priority"),
        [
            pytest.param({}, None, None, id="empty"),
            pytest.param({"severity": "medium"}, "Medium", "P4", id="severity"),
            pytest.param({"coordinated_release_at": None}, None, None, id="null-crd"),
        ],
    )
    async def test_absent_field_is_not_checked(
        self,
        body: dict[str, Any],
        severity: str | None,
        priority: str | None,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
    ) -> None:
        """`create_ticket` alone suffices; a non-VA creator starts `new` and
        unassigned (rbac.md BR11)."""
        response = await authenticated_client.post(_PATH, json=body)

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["status"] == "new"
        assert data["assignee"] is None
        assert data["is_confidential"] is False
        assert data["coordinated_release_at"] is None
        assert data["cve"] is None
        ticket_id = await _ticket_uuid(db_session, data["ticket_id"])
        assert await ticket_events_by_id(db_session, ticket_id) == creation_events(
            creator_id=ra_user.id, severity=severity, priority=priority
        )

    @pytest.mark.parametrize("value", [True, False])
    async def test_holder_may_supply_either_value(
        self,
        value: bool,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
    ) -> None:
        response = await authenticated_client.post(
            _PATH, json={"is_confidential": value}
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["is_confidential"] is value
        ticket_id = await _ticket_uuid(db_session, data["ticket_id"])
        assert (await _state(db_session, ticket_id))["is_confidential"] is value

    @pytest.mark.parametrize(
        ("body", "errors"),
        [
            pytest.param(
                {"is_confidential": True, "severity": "bogus"},
                [
                    {
                        "loc": ["body", "severity"],
                        "msg": _LITERAL_MESSAGE,
                        "type": "literal_error",
                    }
                ],
                id="invalid-severity",
            ),
            pytest.param(
                {"is_confidential": True, "coordinated_release_at": "not-a-date"},
                [
                    {
                        "loc": ["body", "coordinated_release_at"],
                        "msg": "Value error, coordinated_release_at must be a "
                        "valid ISO 8601 datetime.",
                        "type": "value_error",
                    }
                ],
                id="invalid-crd",
            ),
            pytest.param(
                {"is_confidential": False, "coordinated_release_at": _CRD},
                [
                    {
                        "loc": ["body"],
                        "msg": "Value error, coordinated_release_at requires "
                        "is_confidential to be true.",
                        "type": "value_error",
                    }
                ],
                id="crd-without-confidential",
            ),
        ],
    )
    async def test_validation_error_precedes_the_field_level_403(
        self,
        body: dict[str, Any],
        errors: list[dict[str, Any]],
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
    ) -> None:
        before = await _counts(db_session)

        response = await authenticated_client.post(_PATH, json=body)

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": errors,
        }
        assert await _counts(db_session) == before


@pytest.mark.e2e
class TestCallerResolution:
    @pytest.mark.parametrize(
        ("role", "body", "status"),
        [
            pytest.param(
                Role.VULNERABILITY_ANALYST,
                {"is_confidential": True, "coordinated_release_at": _CRD},
                201,
                id="field-capability-held",
            ),
            pytest.param(Role.RESTRICTED_ANALYST, {}, 201, id="field-absent"),
            pytest.param(
                Role.RESTRICTED_ANALYST,
                {"is_confidential": False},
                403,
                id="field-capability-missing",
            ),
        ],
    )
    async def test_roles_are_loaded_once_per_request(
        self,
        role: Role,
        body: dict[str, Any],
        status: int,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The base `create_ticket` and the field-level
        `manage_confidentiality` checks share one role load (api-spec.md,
        Authorization Chain Evaluation Order); the service reloads none."""
        await user_role_factory(user_id=authenticated_user.id, role=role.value)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.post(_PATH, json=body)

        assert response.status_code == status
        assert calls == [authenticated_user.id]


# ---------------------------------------------------------------------------
# Request validation (global 422)
# ---------------------------------------------------------------------------


def _field_error(field: str, msg: str, type_: str) -> list[dict[str, Any]]:
    return [{"loc": ["body", field], "msg": msg, "type": type_}]


_CRD_REQUIRES_CONFIDENTIAL = [
    {
        "loc": ["body"],
        "msg": "Value error, coordinated_release_at requires is_confidential "
        "to be true.",
        "type": "value_error",
    }
]
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
_CVE_NOT_A_STRING = _field_error(
    "cve_id", "Input should be a valid string", "string_type"
)


def _confidential_crd(value: Any) -> dict[str, Any]:
    return {"is_confidential": True, "coordinated_release_at": value}


_VALIDATION_CASES = [
    pytest.param(
        {"coordinated_release_at": _CRD},
        _CRD_REQUIRES_CONFIDENTIAL,
        id="crd-confidential-omitted",
    ),
    pytest.param(
        {"is_confidential": False, "coordinated_release_at": _CRD},
        _CRD_REQUIRES_CONFIDENTIAL,
        id="crd-confidential-false",
    ),
    pytest.param(
        {"cve_id": _NEW_CVE_ID, "coordinated_release_at": "2026-10-06T14:00:00"},
        _CRD_REQUIRES_CONFIDENTIAL,
        id="naive-crd-confidential-omitted",
    ),
    pytest.param({"cve_id": 20241234}, _CVE_NOT_A_STRING, id="cve-int"),
    pytest.param({"cve_id": ["CVE-2024-1234"]}, _CVE_NOT_A_STRING, id="cve-list"),
    pytest.param({"cve_id": True}, _CVE_NOT_A_STRING, id="cve-bool"),
    pytest.param(
        {"cve_id": {"id": "CVE-2024-1234"}}, _CVE_NOT_A_STRING, id="cve-object"
    ),
    *[
        pytest.param(
            {"severity": value},
            _field_error("severity", _LITERAL_MESSAGE, "literal_error"),
            id=f"severity-{value!r}",
        )
        for value in ("High", "unresolved", "critical ", "", 1, True)
    ],
    pytest.param(
        {"is_confidential": None},
        _field_error("is_confidential", "Input should be a valid boolean", "bool_type"),
        id="confidential-null",
    ),
    # Strict JSON boolean (docs/api-spec.md, JSON Request Body Scalar
    # Types): values Pydantic's lax mode would coerce are rejected too.
    *[
        pytest.param(
            {"is_confidential": value},
            _field_error(
                "is_confidential", "Input should be a valid boolean", "bool_type"
            ),
            id=f"confidential-{value!r}",
        )
        for value in ("true", "false", "yes", "1", "maybe", 1, 0)
    ],
    # Representative parser wiring; tests/test_schemas/test_ticket.py owns
    # the complete Coordinated Release Date parser matrix.
    pytest.param(_confidential_crd("2026-10-06"), _CRD_NO_TIME, id="crd-date-only"),
    pytest.param(_confidential_crd(1791295200), _CRD_NOT_A_STRING, id="crd-number"),
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
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _counts(db_session)
        creation = _spy_creation(monkeypatch)

        response = await authenticated_client.post(_PATH, json=body)

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": errors,
        }
        creation.assert_not_awaited()
        assert await _counts(db_session) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None

    async def test_absent_body_is_a_validation_error(
        self, authenticated_client: AsyncClient, va_user: User
    ) -> None:
        response = await authenticated_client.post(_PATH)

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [{"loc": ["body"], "msg": "Field required", "type": "missing"}],
        }


# ---------------------------------------------------------------------------
# CVE_INVALID_FORMAT (caller validation before any database work)
# ---------------------------------------------------------------------------


_MALFORMED_CVE_IDS = [
    pytest.param("", id="empty"),
    pytest.param("cve-2024-1234", id="lowercase"),
    pytest.param("CVE-2024-123456789012", id="21-characters"),
    pytest.param("CVE-2024-" + "1" * 200, id="very-long"),
]


@pytest.mark.e2e
class TestCVEInvalidFormat:
    @pytest.mark.parametrize("cve_id", _MALFORMED_CVE_IDS)
    async def test_malformed_cve_id_is_rejected_before_any_database_work(
        self,
        cve_id: str,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _counts(db_session)
        creation = _spy_creation(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await authenticated_client.post(_PATH, json={"cve_id": cve_id})

        assert response.status_code == 422
        assert response.json() == _CVE_INVALID_FORMAT
        creation.assert_not_awaited()
        assert _domain_statements(recorder) == []
        assert await _counts(db_session) == before

    async def test_format_check_precedes_the_severity_derived_conflict(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        creation = _spy_creation(monkeypatch)

        response = await authenticated_client.post(
            _PATH, json={"cve_id": "CVE-2024-123", "severity": "high"}
        )

        assert response.status_code == 422
        assert response.json() == _CVE_INVALID_FORMAT
        creation.assert_not_awaited()

    async def test_twenty_character_cve_id_is_accepted(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
    ) -> None:
        cve_id = "CVE-2024-12345678901"
        assert len(cve_id) == 20

        response = await authenticated_client.post(_PATH, json={"cve_id": cve_id})

        assert response.status_code == 201
        assert response.json()["data"]["cve"] == _placeholder_cve(cve_id)
        assert await _cve_row(db_session, cve_id) is not None

    async def test_service_backstop_maps_to_the_same_response(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With the handler pre-validation bypassed, the service's
        `CVEIdFormatError` still maps to `422 CVE_INVALID_FORMAT` without
        any Ticket or CVE statement."""
        monkeypatch.setattr(route, "is_valid_cve_id", lambda value: True)
        before = await _counts(db_session)
        creation = _spy_creation(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            response = await authenticated_client.post(
                _PATH, json={"cve_id": "CVE-2024-123456789012"}
            )

        assert response.status_code == 422
        assert response.json() == _CVE_INVALID_FORMAT
        creation.assert_awaited_once()
        assert _domain_statements(recorder) == []
        assert await _counts(db_session) == before


# ---------------------------------------------------------------------------
# Domain conflicts (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestConflicts:
    @pytest.mark.parametrize("severity", ["high", "none"])
    async def test_cve_with_severity_is_severity_derived_without_effect(
        self,
        severity: str,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
    ) -> None:
        before = await _counts(db_session)

        with StatementRecorder(db_session) as recorder:
            response = await authenticated_client.post(
                _PATH, json={"cve_id": _NEW_CVE_ID, "severity": severity}
            )

        assert response.status_code == 409
        assert response.json() == _SEVERITY_DERIVED
        assert "existing_ticket_id" not in response.json()
        assert _domain_statements(recorder) == []
        assert await _counts(db_session) == before
        assert (await _cve_row(db_session, _NEW_CVE_ID)) is None

    @pytest.mark.parametrize(
        ("role", "confidential"),
        [pytest.param(Role.RESTRICTED_ANALYST, True, id="ra-inaccessible")],
    )
    async def test_associated_cve_returns_only_the_existing_identifier(
        self,
        role: Role,
        confidential: bool,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        user_role_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        """tickets.md, Identifier Disclosure Boundary: the conflict body is
        exactly the envelope plus the top-level `existing_ticket_id`, even
        when the conflicting Ticket is inaccessible to the caller."""
        await user_role_factory(user_id=authenticated_user.id, role=role.value)
        cve: CVE = await cve_factory(title="Embargoed issue", severity="Critical")
        existing: Ticket = await ticket_factory(
            cve_id=cve.id, is_confidential=confidential
        )
        existing_ticket_id = format_ticket_id(existing.sequence_id)
        before = await _counts(db_session)

        response = await authenticated_client.post(_PATH, json={"cve_id": cve.cve_id})

        assert response.status_code == 409
        assert response.json() == {
            "code": "TICKET_CVE_CONFLICT",
            "detail": _CONFLICT_DETAIL,
            "existing_ticket_id": existing_ticket_id,
        }
        assert await _counts(db_session) == before
        assert await ticket_events_by_id(db_session, existing.id) == []
        follow = await authenticated_client.get(f"{_PATH}/{existing_ticket_id}")
        assert follow.status_code == 404
        assert follow.json() == _TICKET_NOT_FOUND


# ---------------------------------------------------------------------------
# Successful creation (201 TicketDetail)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCreateTicket:
    async def test_va_creates_a_confidential_ticket_with_a_placeholder_cve_and_crd(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
    ) -> None:
        assignee = await _user_reference(db_session, va_user.id)

        response = await authenticated_client.post(
            _PATH,
            json={
                "cve_id": _NEW_CVE_ID,
                "is_confidential": True,
                "coordinated_release_at": _CRD,
            },
        )

        assert response.status_code == 201
        body = response.json()
        assert set(body) == {"data"}
        data = body["data"]
        ticket_id = data.pop("ticket_id")
        created_at = data.pop("created_at")
        assert isinstance(data.pop("updated_at"), str)
        due = {field: data.pop(field) for field in _DUE_MILESTONES}
        assert data == {
            "status": "analysis",
            "severity": None,
            "priority": None,
            "priority_automatic": None,
            "priority_override": None,
            "assignee": assignee,
            "cve": _placeholder_cve(_NEW_CVE_ID),
            "duplicate_of_ticket_id": None,
            "is_confidential": True,
            "coordinated_release_at": _CRD,
            "packages": [],
        }
        assert re.fullmatch(r"SNTL-[1-9][0-9]*", ticket_id)
        # An unresolved severity uses the worst-case 30-day tier.
        assert _response_due_dates(due) == _due_dates(created_at, 30)

        cve = await _cve_row(db_session, _NEW_CVE_ID)
        assert cve is not None
        assert (cve.cve_state, cve.severity, cve.title) == ("PUBLISHED", None, None)
        sources = await db_session.scalar(
            select(func.count())
            .select_from(CVESource)
            .where(CVESource.cve_id == cve.id)
        )
        assert sources == 0
        ticket_uuid = await _ticket_uuid(db_session, ticket_id)
        assert await _state(db_session, ticket_uuid) == {
            "status": "Analysis",
            "assignee_id": va_user.id,
            "cve_id": cve.id,
            "severity_manual": None,
            "is_confidential": True,
            "coordinated_release_at": _CRD_INSTANT,
            "priority_auto": None,
            "priority_override": None,
            "duplicate_of_id": None,
        }
        assert await ticket_events_by_id(db_session, ticket_uuid) == creation_events(
            creator_id=va_user.id,
            assignee_username=assignee["username"],
            coordinated_release=_CRD,
            cve_id=_NEW_CVE_ID,
        )

    async def test_va_creates_a_cve_less_ticket_with_manual_severity(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
    ) -> None:
        before_cves = (await _counts(db_session))[1]

        response = await authenticated_client.post(_PATH, json={"severity": "high"})

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["status"] == "analysis"
        assert data["assignee"]["id"] == str(va_user.id)
        assert data["cve"] is None
        assert data["severity"] == "high"
        assert data["priority"] == data["priority_automatic"] == "p3"
        assert data["priority_override"] is None
        assert data["is_confidential"] is False
        assert (await _counts(db_session))[1] == before_cves
        ticket_uuid = await _ticket_uuid(db_session, data["ticket_id"])
        assert await ticket_events_by_id(db_session, ticket_uuid) == creation_events(
            creator_id=va_user.id,
            assignee_username=va_user.username,
            severity="High",
            priority="P3",
        )

    @pytest.mark.parametrize(
        "body",
        [{"cve_id": None, "severity": None}],
        ids=["explicit-nulls"],
    )
    async def test_empty_body_creates_an_assigned_bare_ticket(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        body: dict[str, None],
    ) -> None:
        """Omitting `cve_id`/`severity` and sending JSON `null` are the two
        documented "no CVE" / "no severity" spellings (tickets.md, Create
        Ticket)."""
        response = await authenticated_client.post(_PATH, json=body)

        assert response.status_code == 201
        data = response.json()["data"]
        assert (data["status"], data["is_confidential"], data["cve"]) == (
            "analysis",
            False,
            None,
        )
        assert data["severity"] is data["priority"] is None
        ticket_uuid = await _ticket_uuid(db_session, data["ticket_id"])
        assert await ticket_events_by_id(db_session, ticket_uuid) == creation_events(
            creator_id=va_user.id, assignee_username=va_user.username
        )


# ---------------------------------------------------------------------------
# Coordinated Release Date normalization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCoordinatedReleaseDate:
    # Representative end-to-end cases; tests/test_schemas/test_ticket.py
    # owns the complete Coordinated Release Date parser matrix.
    @pytest.mark.parametrize(
        ("supplied", "expected"),
        [
            pytest.param(_CRD, _CRD, id="utc-z"),
            pytest.param("2026-10-06T14:00:00", _CRD, id="naive-is-utc"),
            pytest.param("2026-10-06T16:00:00+02:00", _CRD, id="offset"),
            pytest.param("2020-01-02T03:04:05Z", "2020-01-02T03:04:05Z", id="past"),
        ],
    )
    async def test_crd_is_stored_returned_and_audited_as_the_utc_instant(
        self,
        supplied: str,
        expected: str,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
    ) -> None:
        response = await authenticated_client.post(
            _PATH,
            json={"is_confidential": True, "coordinated_release_at": supplied},
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["coordinated_release_at"] == expected
        ticket_uuid = await _ticket_uuid(db_session, data["ticket_id"])
        stored = (await _state(db_session, ticket_uuid))["coordinated_release_at"]
        assert stored == _parse(expected)
        assert stored.utcoffset() == timedelta(0)
        assert await ticket_events_by_id(db_session, ticket_uuid) == creation_events(
            creator_id=va_user.id,
            assignee_username=va_user.username,
            coordinated_release=expected,
        )


# ---------------------------------------------------------------------------
# Transaction: commit, final assembly, and whole-transaction rollback
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTransaction:
    async def test_committed_detail_equals_a_subsequent_get(
        self,
        va_commit_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The detail is assembled from the transaction-owned new Ticket
        (flushed, uncommitted) and matches the committed read."""
        user, commit_client = va_commit_client
        await db_session.commit()
        before = await _counts(db_session)
        observed: list[tuple[int, int, int]] = []
        original = ticket_service.assemble_ticket_detail

        async def _observe(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            observed.append(await _counts(db))
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _observe)

        response = await commit_client.post(
            _PATH,
            json={
                "cve_id": _NEW_CVE_ID,
                "is_confidential": True,
                "coordinated_release_at": _CRD,
            },
        )

        assert response.status_code == 201
        # Ticket, placeholder CVE, and four events existed at assembly time.
        after = (before[0] + 1, before[1] + 1, before[2] + 4)
        assert observed == [after]
        assert await _counts(db_session) == after
        data = response.json()["data"]
        detail = await commit_client.get(f"{_PATH}/{data['ticket_id']}")
        assert detail.status_code == 200
        assert detail.json()["data"] == data
        assert data["assignee"]["id"] == str(user.id)

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(
                {
                    "cve_id": _NEW_CVE_ID,
                    "is_confidential": True,
                    "coordinated_release_at": _CRD,
                },
                id="placeholder-crd",
            ),
        ],
    )
    async def test_failed_final_assembly_rolls_back_everything(
        self,
        body: dict[str, Any],
        va_commit_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, commit_client = va_commit_client
        # Checkpoint the fixtures: the failing request rolls back its work.
        await db_session.commit()
        before = await _counts(db_session)
        pre_failure: list[tuple[int, int, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            pre_failure.append(await _counts(db))
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)

        response = await commit_client.post(_PATH, json=body)

        # The body is not asserted: the test app runs Starlette's debug
        # error page, which is not the production envelope.
        assert response.status_code == 500
        (at_failure,) = pre_failure
        assert at_failure[0] == before[0] + 1
        assert at_failure[2] > before[2]
        assert await _counts(db_session) == before
        assert await _cve_row(db_session, _NEW_CVE_ID) is None


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


@pytest.mark.e2e
class TestEvaluationDate:
    async def test_one_date_captured_before_midnight_is_reused_after_it(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handler_clock = _Clock(datetime(2026, 9, 27, 23, 59, 59, 900000, tzinfo=UTC))
        projection_clock = _Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        mutation_clock = _Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", projection_clock.now)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        seen: dict[str, list[date | None]] = {"assembly": [], "statement": []}
        original_assembly = ticket_service.assemble_ticket_detail
        original_statement = ticket_service._detail_statement

        async def _assembly(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            seen["assembly"].append(kwargs.get("evaluation_date"))
            return await original_assembly(db, **kwargs)

        def _statement(evaluation_date: date) -> Any:
            seen["statement"].append(evaluation_date)
            return original_statement(evaluation_date)

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _assembly)
        monkeypatch.setattr(ticket_service, "_detail_statement", _statement)

        response = await authenticated_client.post(_PATH, json={"severity": "critical"})

        assert response.status_code == 201
        assert response.json()["data"]["status"] == "analysis"
        captured = date(2026, 9, 27)
        assert seen == {"assembly": [captured], "statement": [captured]}
        # One handler date; the projection instant is captured once by the
        # assembly; neither the service nor the serializer captures another.
        assert handler_clock.calls == 1
        assert projection_clock.calls == 1
        assert mutation_clock.calls == 0


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


_TICKET_IDENTITY_FIELDS = {"ticket_id", "duplicate_of_ticket_id", "existing_ticket_id"}
_OCCURRENCE_LOCATOR_PARAMETERS = {"ticket_package_product_id"}
"""Nested package-tree occurrence locators whose documented path names
contain `ticket` but which are not Ticket identities: they remain UUIDs
(api-spec.md, Ticket Identifier Resolution; package-model.md, API
Endpoints)."""
_EMBEDDED_TICKET_REFERENCES = {"ticket": "TicketPackageRef"}
"""Embedded Ticket reference objects (property name -> schema). Their
schema identifies the Ticket only by `ticket_id` (package-model.md,
Response Schema: `PackageListItem` > `TicketPackageRef`)."""
_TICKET_FILTER_PARAMETERS = {"ticket_status"}
"""Query filters whose names contain `ticket` but which are Ticket
attributes, not Ticket identities (package-model.md, Search Packages
Across Tickets, naming note)."""


def _walk_properties(node: Any, found: list[tuple[str, dict[str, Any]]]) -> None:
    """Collect every `(property name, property schema)` in the document."""
    if isinstance(node, dict):
        for name, schema in (node.get("properties") or {}).items():
            found.append((name, schema))
        for value in node.values():
            _walk_properties(value, found)
    elif isinstance(node, list):
        for value in node:
            _walk_properties(value, found)


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_PATH]["post"]
        return operation

    def _schema(self, name: str) -> dict[str, Any]:
        schema: dict[str, Any] = self._spec()["components"]["schemas"][name]
        return schema

    @staticmethod
    def _ref_name(schema: dict[str, Any]) -> str:
        ref: str = schema["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_request_body_is_the_optional_field_create_schema(self) -> None:
        operation = self._operation()
        request_body = operation["requestBody"]

        assert operation["tags"] == ["Tickets"]
        assert [p for p in operation.get("parameters", []) if p["in"] != "header"] == []
        assert request_body["required"] is True
        content = request_body["content"]["application/json"]["schema"]
        assert self._ref_name(content) == "TicketCreateRequest"

        schema = self._schema("TicketCreateRequest")
        assert "required" not in schema
        properties = schema["properties"]
        assert set(properties) == {
            "cve_id",
            "severity",
            "is_confidential",
            "coordinated_release_at",
        }
        cve_id = properties["cve_id"]
        assert {"type": "string"} in cve_id["anyOf"]
        assert {"type": "null"} in cve_id["anyOf"]
        # No schema length/pattern limit: over-length and malformed strings
        # reach `CVE_INVALID_FORMAT` rather than the global 422.
        assert "maxLength" not in str(cve_id)
        assert "pattern" not in cve_id
        assert not any("pattern" in v or "maxLength" in v for v in cve_id["anyOf"])
        severity_refs = [
            self._schema(self._ref_name(v)) if "$ref" in v else v
            for v in properties["severity"]["anyOf"]
        ]
        assert {"type": "null"} in severity_refs
        (enum_variant,) = [v for v in severity_refs if "enum" in v]
        assert enum_variant["enum"] == ["critical", "high", "medium", "low", "none"]
        assert properties["is_confidential"]["type"] == "boolean"
        assert properties["is_confidential"]["default"] is False
        assert "manage_confidentiality" in properties["is_confidential"]["description"]
        assert {"type": "string", "format": "date-time"} in properties[
            "coordinated_release_at"
        ]["anyOf"]

    def test_responses_declare_detail_and_both_conflict_shapes(self) -> None:
        responses = self._operation()["responses"]

        assert "200" not in responses
        created = responses["201"]["content"]["application/json"]["schema"]
        assert self._ref_name(created) == "TicketDetailResponse"
        conflict = responses["409"]["content"]["application/json"]["schema"]
        assert sorted(self._ref_name(v) for v in conflict["anyOf"]) == [
            "ErrorResponse",
            "TicketCVEConflictErrorResponse",
        ]
        assert "TICKET_CVE_CONFLICT" in responses["409"]["description"]
        assert "TICKET_SEVERITY_DERIVED" in responses["409"]["description"]
        invalid = responses["422"]["content"]["application/json"]["schema"]
        assert self._ref_name(invalid) == "ErrorResponse"
        assert "CVE_INVALID_FORMAT" in responses["422"]["description"]

    def test_conflict_schema_requires_the_existing_ticket_identifier(self) -> None:
        schema = self._schema("TicketCVEConflictErrorResponse")

        assert set(schema["properties"]) == {"code", "detail", "existing_ticket_id"}
        assert set(schema["required"]) == {"code", "detail", "existing_ticket_id"}
        existing = schema["properties"]["existing_ticket_id"]
        assert existing["type"] == "string"
        assert "format" not in existing
        assert "SNTL-{n}" in existing["description"]

    def test_the_document_exposes_only_the_canonical_ticket_identity_fields(
        self,
    ) -> None:
        """api-spec.md, Ticket Identifier Resolution: Ticket references are
        `ticket_id`, `duplicate_of_ticket_id`, and `existing_ticket_id`, all
        plain `SNTL-{n}` strings; no parallel `id`, `identifier`, or
        `ticket_sequence_id` Ticket field exists."""
        spec = self._spec()
        found: list[tuple[str, dict[str, Any]]] = []
        _walk_properties(spec, found)

        ticket_fields = {name for name, _ in found if "ticket" in name.lower()}
        assert ticket_fields == _TICKET_IDENTITY_FIELDS | set(
            _EMBEDDED_TICKET_REFERENCES
        )
        for name, schema in found:
            if name in _EMBEDDED_TICKET_REFERENCES:
                reference = _EMBEDDED_TICKET_REFERENCES[name]
                assert schema["$ref"] == f"#/components/schemas/{reference}", name
                assert set(self._schema(reference)["properties"]) == {
                    "ticket_id",
                    "status",
                    "severity",
                }
        for name, schema in found:
            if name in _TICKET_IDENTITY_FIELDS:
                assert "format" not in str(schema), name
        assert not {"ticket_sequence_id", "ticket_uuid", "sequence_id"} & {
            name for name, _ in found
        }
        for name in ("TicketSummary", "TicketDetail"):
            assert not {"id", "identifier", "ticket_sequence_id"} & set(
                self._schema(name)["properties"]
            ), name
        for path, operations in spec["paths"].items():
            for method, operation in operations.items():
                for parameter in operation.get("parameters", []):
                    if parameter["name"] in _OCCURRENCE_LOCATOR_PARAMETERS:
                        assert parameter["schema"]["format"] == "uuid", (path, method)
                    elif parameter["name"] in _TICKET_FILTER_PARAMETERS:
                        assert parameter["in"] == "query", (path, method)
                    elif "ticket" in parameter["name"].lower():
                        assert parameter["name"] == "ticket_id", (path, method)
                        assert parameter["in"] == "path", (path, method)
                        assert "format" not in parameter["schema"], (path, method)
