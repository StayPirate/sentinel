"""End-to-end tests for Set or Update SUSE CVSS Assessment
(`POST /api/v1/cves/{cve_id}/cvss/suse`, `backend/app/api/v1/cves.py`).

See docs/features/tickets/cvss-scoring.md (Set or Update SUSE CVSS
Assessment, Shared Assessment Item, Input Rules, Serialization and
Concurrent Outcomes), docs/features/tickets/ticket-mutations.md
(`upsert_cvss_assessment()`, Service Exceptions), docs/api-spec.md
(Authorization Chain Evaluation Order flow 3, Global Responses, CVE
Accessibility Check including the post-accessibility `TICKET_NOT_MUTABLE`,
CVE Identifier Resolution, Error Code Categories), docs/features/identity/
rbac.md (Endpoint Permission Map), and docs/features/platform/
testing-strategy.md (Ticket Accessibility; API Endpoints). The service
matrix, races, and rollback live in tests/test_services; these tests cover
the HTTP boundary.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.enums import Role, SessionCreationReason, TicketStatus
from app.database import get_db
from app.main import app
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import cve_service, ticket_mutations, user_service
from app.services.session_service import create_session

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/cves/{cve_id}/cvss/suse"
_NOT_FOUND = b'{"code":"CVE_NOT_FOUND","detail":"CVE not found."}'
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_INVALID_VECTOR = {"code": "CVSS_INVALID_VECTOR", "detail": "Invalid CVSS vector."}
_NOT_MUTABLE = {"code": "TICKET_NOT_MUTABLE", "detail": "Ticket is not mutable."}
_INTERNAL_ERROR = {"code": "INTERNAL_ERROR", "detail": "An unexpected error occurred."}
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$")

V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_CRITICAL_REORDERED = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
V31_MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
V40_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V3_CRITICAL_METRICS = {
    "attack_vector": "network",
    "attack_complexity": "low",
    "privileges_required": "none",
    "user_interaction": "none",
    "scope": "unchanged",
    "confidentiality_impact": "high",
    "integrity_impact": "high",
    "availability_impact": "high",
}


def _url(target: CVE | str) -> str:
    return _PATH.format(cve_id=target if isinstance(target, str) else target.cve_id)


def _body(vector: Any) -> dict[str, Any]:
    return {"vector_string": vector}


async def _assessments(db: AsyncSession, cve_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = await db.execute(
        select(CVECVSSAssessment.provider_name, CVECVSSAssessment.vector_string)
        .where(CVECVSSAssessment.cve_id == cve_id)
        .order_by(CVECVSSAssessment.cvss_version)
    )
    return [(row.provider_name, row.vector_string) for row in rows]


async def _event_count(db: AsyncSession) -> int:
    return (
        await db.execute(select(func.count()).select_from(TicketAuditEvent))
    ).scalar_one()


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the CVE lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(cve_service, "resolve_cve_locator", resolver)
    monkeypatch.setattr(ticket_mutations, "upsert_cvss_assessment", mutation)
    return resolver, mutation


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value="3.1"
    )
    return setting


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
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[AsyncClient]:
    """A vulnerability-analyst client whose `get_db` override commits after
    the handler and rolls back when an exception escapes, like production
    `app.database.get_db`, and that returns the transmitted 500 response.

    Commits and rollbacks act on `db_session`'s savepoint; the outer test
    transaction still reverts everything at teardown. Debug mode is forced
    off so the production 500 handler renders the response (mirrors
    `tests/test_api/test_cves.py`).
    """
    monkeypatch.setattr(app, "debug", False)
    monkeypatch.setattr(app, "middleware_stack", None)
    user = await user_factory()
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
            yield commit_client
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Authentication and capability (flow 3, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthentication:
    @pytest.mark.parametrize(
        "credential",
        [
            pytest.param({}, id="missing"),
            pytest.param(
                {"headers": {"Authorization": "Bearer invalid-token"}}, id="bearer"
            ),
            pytest.param(
                {"cookies": {SESSION_COOKIE_NAME: "invalid-session"}}, id="cookie"
            ),
        ],
    )
    async def test_absent_or_invalid_credential_returns_401_before_any_lookup(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
    ) -> None:
        cve: CVE = await cve_factory()
        resolver, mutation = _forbid_lookups(monkeypatch)
        role_loader = AsyncMock()
        monkeypatch.setattr(user_service, "get_user_roles", role_loader)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        for target in (cve.cve_id, "CVE-2099-99999", "not-a-cve"):
            response = await client.post(
                _url(target),
                json=_body(V31_CRITICAL),
                headers=credential.get("headers", {}),
            )
            assert response.status_code == 401, target
            assert response.json() == _UNAUTHENTICATED, target

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        role_loader.assert_not_awaited()


@pytest.mark.e2e
class TestCapability:
    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_manage_cvss_gets_the_generic_403_before_lookup(
        self,
        roles: list[Role],
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        visible: CVE = await cve_factory()
        hidden: CVE = await cve_factory()
        await ticket_factory(cve_id=hidden.id, is_confidential=True)
        resolver, mutation = _forbid_lookups(monkeypatch)

        bodies = []
        for target in (visible.cve_id, hidden.cve_id, "CVE-2099-99999", "cve-1"):
            response = await authenticated_client.post(
                _url(target), json=_body(V31_CRITICAL)
            )
            assert response.status_code == 403, target
            assert response.json() == _FORBIDDEN, target
            bodies.append(response.content)

        assert len(set(bodies)) == 1
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _event_count(db_session) == 0

    async def test_capability_precedes_body_validation(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()

        response = await authenticated_client.post(_url(cve), json=_body(3.1))

        assert response.status_code == 403

    async def test_roles_are_loaded_once_for_capability_and_scope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.post(_url(cve), json=_body(V31_CRITICAL))

        assert response.status_code == 201
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# CVE accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCVENotFound:
    async def test_every_not_found_cause_returns_the_identical_response(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        """A restricted analyst holds `manage_cvss`, but the capability never
        makes a CVE of a confidential Ticket without a path visible."""
        visible: CVE = await cve_factory(cve_id="CVE-2099-0001")
        hidden: CVE = await cve_factory()
        await ticket_factory(cve_id=hidden.id, is_confidential=True)
        targets = [
            "not-a-cve",
            "cve-2099-0001",
            "%20CVE-2099-0001",
            "CVE-2099-0001%20",
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            "CVE-2099-99999",
            hidden.cve_id,
        ]

        responses = [
            await authenticated_client.post(_url(t), json=_body(V31_CRITICAL))
            for t in targets
        ]

        for target, response in zip(targets, responses, strict=True):
            assert response.status_code == 404, target
            assert response.content == _NOT_FOUND, target
        assert await _assessments(db_session, hidden.id) == []
        assert await _event_count(db_session) == 0

    async def test_not_found_precedes_body_validation(
        self, authenticated_client: AsyncClient, va_user: User
    ) -> None:
        response = await authenticated_client.post(
            _url("CVE-2099-99999"), json=_body(3.1)
        )

        assert response.status_code == 404
        assert response.content == _NOT_FOUND

    async def test_access_lost_after_the_preliminary_check_is_404_without_effect(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The grant disappears after the preliminary dependency but before
        the mutation locks its roots; locked-current accessibility decides
        (api-spec.md, Authorization Chain Evaluation Order, flow 3)."""
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=ra_user.id)
        original = ticket_mutations.upsert_cvss_assessment

        async def _revoke_then_mutate(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_mutations, "upsert_cvss_assessment", _revoke_then_mutate
        )

        response = await authenticated_client.post(_url(cve), json=_body(V31_CRITICAL))

        assert response.status_code == 404
        assert response.content == _NOT_FOUND
        assert await _assessments(db_session, cve.id) == []
        assert await _event_count(db_session) == 0


# ---------------------------------------------------------------------------
# Request validation: global 422 (Pydantic) versus domain 422 (parser)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        ("body", "error"),
        [
            pytest.param(
                {},
                {
                    "loc": ["body", "vector_string"],
                    "msg": "Field required",
                    "type": "missing",
                },
                id="missing-field",
            ),
            *[
                pytest.param(
                    _body(value),
                    {
                        "loc": ["body", "vector_string"],
                        "msg": "Input should be a valid string",
                        "type": "string_type",
                    },
                    id=f"non-string-{value!r}",
                )
                for value in (3.1, None, True, ["x"])
            ],
            pytest.param(
                _body(" " + V31_CRITICAL + " " * (200 - len(V31_CRITICAL))),
                {
                    "loc": ["body", "vector_string"],
                    "msg": "String should have at most 200 characters",
                    "type": "string_too_long",
                },
                id="201-received-characters",
            ),
        ],
    )
    async def test_schema_failure_returns_the_validation_envelope_without_effect(
        self,
        body: dict[str, Any],
        error: dict[str, Any],
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve: CVE = await cve_factory()
        mutation = AsyncMock()
        monkeypatch.setattr(ticket_mutations, "upsert_cvss_assessment", mutation)

        response = await authenticated_client.post(_url(cve), json=body)

        assert response.status_code == 422
        payload = response.json()
        assert (payload["code"], payload["detail"]) == (
            "VALIDATION_ERROR",
            "Request validation failed",
        )
        assert [
            {k: e[k] for k in ("loc", "msg", "type")} for e in payload["errors"]
        ] == [error]
        mutation.assert_not_awaited()

    async def test_absent_body_is_a_validation_error(
        self, authenticated_client: AsyncClient, va_user: User, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        response = await authenticated_client.post(_url(cve))

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_exactly_200_received_characters_reach_the_parser(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
    ) -> None:
        """A 200-character value padded with outer whitespace is accepted by
        the schema, trimmed by the parser, and stored canonically."""
        cve: CVE = await cve_factory()
        padding = 200 - len(V31_CRITICAL_REORDERED)
        value = (
            " " * (padding // 2)
            + V31_CRITICAL_REORDERED
            + "\t" * (padding - padding // 2)
        )
        assert len(value) == 200

        response = await authenticated_client.post(_url(cve), json=_body(value))

        assert response.status_code == 201
        assert response.json()["data"]["vector_string"] == V31_CRITICAL
        assert await _assessments(db_session, cve.id) == [("SUSE", V31_CRITICAL)]

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty"),
            pytest.param("x" * 200, id="200-characters-invalid"),
        ],
    )
    async def test_domain_failure_is_cvss_invalid_vector_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        value: str,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)

        response = await authenticated_client.post(_url(cve), json=_body(value))

        assert response.status_code == 422
        assert response.json() == _INVALID_VECTOR
        assert await _assessments(db_session, cve.id) == []
        assert await _event_count(db_session) == 0


# ---------------------------------------------------------------------------
# Created (201), updated and unchanged (200)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUpsert:
    async def test_create_update_and_unchanged_status_codes_and_items(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id
        )

        created = await authenticated_client.post(_url(cve), json=_body(V31_MEDIUM))
        updated = await authenticated_client.post(
            _url(cve), json=_body(f"  {V31_CRITICAL_REORDERED} ")
        )
        unchanged = await authenticated_client.post(_url(cve), json=_body(V31_CRITICAL))

        assert (created.status_code, updated.status_code, unchanged.status_code) == (
            201,
            200,
            200,
        )
        item = updated.json()["data"]
        assert list(item) == [
            "id",
            "provider_name",
            "cvss_version",
            "score",
            "severity",
            "vector_string",
            "metrics",
            "created_at",
            "updated_at",
        ]
        assert {k: item[k] for k in list(item)[1:7]} == {
            "provider_name": "SUSE",
            "cvss_version": "3.1",
            "score": 9.8,
            "severity": "critical",
            "vector_string": V31_CRITICAL,
            "metrics": V3_CRITICAL_METRICS,
        }
        assert item["id"] == created.json()["data"]["id"]
        assert item["created_at"] == created.json()["data"]["created_at"]
        assert _TIMESTAMP.match(item["created_at"])
        assert _TIMESTAMP.match(item["updated_at"])
        assert unchanged.json() == updated.json()
        events = (
            await db_session.execute(
                select(TicketAuditEvent.event_type, TicketAuditEvent.user_id)
                .where(TicketAuditEvent.ticket_id == ticket.id)
                .order_by(TicketAuditEvent.id)
            )
        ).all()
        assert [tuple(e) for e in events] == [
            ("assignment", va_user.id),
            ("status_change", None),
            ("cvss_assessment_changed", va_user.id),
            ("severity_changed", None),
            ("priority_changed", None),
            ("cvss_assessment_changed", va_user.id),
            ("severity_changed", None),
            ("priority_changed", None),
        ]

    async def test_other_versions_are_separate_assessments(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()

        first = await authenticated_client.post(_url(cve), json=_body(V31_CRITICAL))
        second = await authenticated_client.post(_url(cve), json=_body(V40_CRITICAL))

        assert (first.status_code, second.status_code) == (201, 201)
        assert second.json()["data"]["cvss_version"] == "4.0"
        assert await _assessments(db_session, cve.id) == [
            ("SUSE", V31_CRITICAL),
            ("SUSE", V40_CRITICAL),
        ]

    async def test_restricted_analyst_with_a_grant_upserts_without_assignment(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=ra_user.id)

        response = await authenticated_client.post(_url(cve), json=_body(V31_CRITICAL))

        assert response.status_code == 201
        state = (
            await db_session.execute(
                select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
            )
        ).one()
        assert tuple(state) == (TicketStatus.NEW.value, None)

    async def test_manual_zone_ticket_is_not_mutable(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(status=TicketStatus.IGNORED.value, cve_id=cve.id)

        response = await authenticated_client.post(_url(cve), json=_body(V31_CRITICAL))

        assert response.status_code == 409
        assert response.json() == _NOT_MUTABLE
        assert await _assessments(db_session, cve.id) == []
        assert await _event_count(db_session) == 0


# ---------------------------------------------------------------------------
# Unhandled failures roll back and map to the generic 500
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestServerErrors:
    async def test_missing_setting_rolls_back_and_is_a_generic_500(
        self,
        va_commit_client: AsyncClient,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id
        )
        cve_id, ticket_id, cve_ref = cve.id, ticket.id, cve.cve_id
        # Release the setup savepoint so the request's rollback reverts only
        # the request's own work.
        await db_session.commit()

        response = await va_commit_client.post(_url(cve_ref), json=_body(V31_CRITICAL))

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert await _assessments(db_session, cve_id) == []
        state = (
            await db_session.execute(
                select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket_id)
            )
        ).one()
        assert tuple(state) == (TicketStatus.NEW.value, None)
        assert await _event_count(db_session) == 0


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

    def test_path_parameter_is_an_unconstrained_string(self) -> None:
        operation = self._operation()
        (path_param,) = [p for p in operation["parameters"] if p["in"] == "path"]

        assert path_param["name"] == "cve_id"
        assert path_param["schema"]["type"] == "string"
        assert "pattern" not in path_param["schema"]
        assert [p for p in operation["parameters"] if p["in"] != "path"] == []
        assert operation["tags"] == ["CVEs"]

    def test_request_body_requires_a_string_of_at_most_200_characters(self) -> None:
        request_body = self._operation()["requestBody"]

        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "SUSECVSSAssessmentRequest"
        schema = self._spec()["components"]["schemas"]["SUSECVSSAssessmentRequest"]
        assert schema["required"] == ["vector_string"]
        assert set(schema["properties"]) == {"vector_string"}
        field = schema["properties"]["vector_string"]
        assert (field["type"], field["maxLength"]) == ("string", 200)
        assert "minLength" not in field
        assert "pattern" not in field

    def test_responses_declare_200_201_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "CVSSAssessmentResponse"
        assert self._ref_name(responses["201"]["content"]) == "CVSSAssessmentResponse"
        for code in ("404", "409", "422"):
            assert self._ref_name(responses[code]["content"]) == "ErrorResponse"
        assert "CVE_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "CVSS_INVALID_VECTOR" in responses["422"]["description"]
