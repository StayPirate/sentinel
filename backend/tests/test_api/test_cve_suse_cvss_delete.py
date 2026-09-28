"""End-to-end tests for Delete SUSE CVSS Assessment
(`DELETE /api/v1/cves/{cve_id}/cvss/suse/{cvss_version}`,
`backend/app/api/v1/cves.py`).

See docs/features/tickets/cvss-scoring.md (Delete SUSE CVSS Assessment,
including the input-only version check that precedes CVE-ID resolution;
Assessment Persistence and Ticket Status; Direct Audit Summary;
Serialization and Concurrent Outcomes; Required Tests > Persistence and API
Tests, DELETE rows), docs/features/tickets/ticket-mutations.md (CVSS
Mutation Authority and Result: `deleted` -> 204, `not_found` -> 404;
`delete_cvss_assessment()`; Service Exceptions), docs/api-spec.md
(Authorization Chain Evaluation Order flow 3, Global Responses, CVE
Accessibility Check including the post-accessibility `TICKET_NOT_MUTABLE`,
Manual-Zone Mutability Guard, Response Applicability Derivation, CVE
Identifier Resolution, Error Code Categories), docs/features/identity/
rbac.md (Endpoint Permission Map; `manage_cvss` is held by
`vulnerability_analyst` and `restricted_analyst`), and docs/features/
platform/testing-strategy.md (Ticket Accessibility; API Endpoints). The
service matrix, races, and rollback live in tests/test_services; these
tests cover the HTTP boundary. Fixtures mirror
`tests/test_api/test_cve_suse_cvss.py` (the POST endpoint).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.enums import (
    PackageStatus,
    Role,
    SessionCreationReason,
    Severity,
    TicketStatus,
)
from app.database import get_db
from app.main import app
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services import cve_service, ticket_mutations, user_service
from app.services.session_service import create_session
from app.services.ticket_mutations import CVSSAssessmentNotFoundError
from tests.support.cvss_chain import (
    cve_severity,
    severity_event,
    ticket_state,
    total_ticket_events,
)
from tests.support.suse_cvss import (
    V20_CRITICAL,
    V30_CRITICAL,
    V31_CRITICAL,
    V31_MEDIUM,
    V40_CRITICAL,
    Vector,
    persisted_assessments,
    unit,
)
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/cves/{cve_id}/cvss/suse/{cvss_version}"
_CVE_NOT_FOUND = b'{"code":"CVE_NOT_FOUND","detail":"CVE not found."}'
_ASSESSMENT_NOT_FOUND = (
    b'{"code":"CVSS_ASSESSMENT_NOT_FOUND","detail":"CVSS assessment not found."}'
)
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_NOT_MUTABLE = {"code": "TICKET_NOT_MUTABLE", "detail": "Ticket is not mutable."}
_INTERNAL_ERROR = {"code": "INTERNAL_ERROR", "detail": "An unexpected error occurred."}

ACCEPTED = [
    pytest.param("2.0", V20_CRITICAL, id="v2.0"),
    pytest.param("3.0", V30_CRITICAL, id="v3.0"),
    pytest.param("3.1", V31_CRITICAL, id="v3.1"),
    pytest.param("4.0", V40_CRITICAL, id="v4.0"),
]

UNRECOGNIZED_VERSIONS = [
    pytest.param("3", "3", id="major-only"),
    pytest.param("3.10", "3.10", id="extra-digit"),
    pytest.param("v3.1", "v3.1", id="v-prefix"),
    pytest.param("5.0", "5.0", id="future"),
    pytest.param("CVSS:3.1", "CVSS:3.1", id="vector-prefix"),
    pytest.param("V3_1", "V3_1", id="enum-name"),
    pytest.param("%203.1", " 3.1", id="leading-space"),
    pytest.param("3.1%20", "3.1 ", id="trailing-space"),
    pytest.param("3.1%0A", "3.1\n", id="trailing-newline"),
]
"""`(raw path segment, decoded value)` pairs; the decoded value is what the
version check receives. None is trimmed or otherwise normalized."""


def _url(target: CVE | str, version: str) -> str:
    cve_id = target if isinstance(target, str) else target.cve_id
    return _PATH.format(cve_id=cve_id, cvss_version=version)


def _delete_event(actor_id: uuid.UUID, old: Vector) -> EventRow:
    """The acting-user `cvss_assessment_changed` of a deletion (`new_value`
    SQL `NULL`), for an actor known only by its id."""
    return EventRow(
        "cvss_assessment_changed", actor_id, old.audit_value, None, None, None
    )


def _spy_lookups(
    monkeypatch: pytest.MonkeyPatch, version_check: MagicMock
) -> tuple[MagicMock, AsyncMock, AsyncMock]:
    """Install `version_check` as the version check and replace the CVE
    lookup and the mutation with spies that must stay unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(
        ticket_mutations, "require_accepted_cvss_version", version_check
    )
    monkeypatch.setattr(cve_service, "resolve_cve_locator", resolver)
    monkeypatch.setattr(ticket_mutations, "delete_cvss_assessment", mutation)
    return version_check, resolver, mutation


def _forbid_lookups(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, AsyncMock, AsyncMock]:
    """Replace the version check, the CVE lookup, and the mutation with
    spies that must stay unused."""
    return _spy_lookups(monkeypatch, MagicMock())


def _forbid_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, AsyncMock, AsyncMock]:
    """Spy on the real version check and replace the CVE lookup and the
    mutation with spies that must stay unused."""
    real = ticket_mutations.require_accepted_cvss_version
    return _spy_lookups(monkeypatch, MagicMock(wraps=real))


def _resource_statements(recorder: StatementRecorder) -> list[str]:
    """Every recorded CVE, assessment, or Ticket read and every row lock."""
    return [
        *recorder.selects_from("cve"),
        *recorder.selects_from("ticket"),
        *recorder.row_locks(),
    ]


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


@pytest.fixture
def cve_of(
    cve_factory: Factory, cve_cvss_assessment_factory: Factory
) -> Callable[..., Awaitable[CVE]]:
    """Create a CVE with a persisted `severity` and `(provider, vector)`
    assessments whose vector-derived units are consistent."""

    async def _create(
        *assessments: tuple[str, Vector], severity: Severity | None = None
    ) -> CVE:
        cve: CVE = await cve_factory(severity=severity.value if severity else None)
        for provider, vector in assessments:
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **vector.columns()
            )
        return cve

    return _create


CVEOf = Callable[..., Awaitable[CVE]]


@pytest_asyncio.fixture
async def _va_commit_user_and_client(
    db_session: AsyncSession,
    user_factory: Factory,
    user_role_factory: Factory,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[tuple[User, AsyncClient]]:
    """A vulnerability analyst and its client whose `get_db` override
    commits after the handler and rolls back when an exception escapes,
    like production `app.database.get_db`, and that returns the transmitted
    500 response.

    Commits and rollbacks act on `db_session`'s savepoint; the outer test
    transaction still reverts everything at teardown. Debug mode is forced
    off so the production 500 handler renders the response (mirrors
    `va_commit_client` in `tests/test_api/test_cve_suse_cvss.py`).
    """
    monkeypatch.setattr(app, "debug", False)
    monkeypatch.setattr(app, "middleware_stack", None)
    user: User = await user_factory()
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


@pytest.fixture
def va_commit_client(
    _va_commit_user_and_client: tuple[User, AsyncClient],
) -> AsyncClient:
    """The committing vulnerability-analyst client."""
    return _va_commit_user_and_client[1]


@pytest.fixture
def va_commit_user_id(
    _va_commit_user_and_client: tuple[User, AsyncClient],
) -> uuid.UUID:
    """The id of the `User` behind `va_commit_client`."""
    return _va_commit_user_and_client[0].id


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
        version_check, resolver, mutation = _forbid_lookups(monkeypatch)
        role_loader = AsyncMock()
        monkeypatch.setattr(user_service, "get_user_roles", role_loader)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        for target in (cve.cve_id, "CVE-2099-99999", "not-a-cve"):
            for version in ("3.1", "5.0"):
                response = await client.delete(
                    _url(target, version), headers=credential.get("headers", {})
                )
                assert response.status_code == 401, (target, version)
                assert response.json() == _UNAUTHENTICATED, (target, version)

        version_check.assert_not_called()
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
        cve_of: CVEOf,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The 403 also precedes the version check: an unrecognized version
        returns the same 403 rather than `CVSS_ASSESSMENT_NOT_FOUND`."""
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        visible = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        hidden = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        await ticket_factory(cve_id=hidden.id, is_confidential=True)
        version_check, resolver, mutation = _forbid_lookups(monkeypatch)

        bodies = []
        for target in (visible.cve_id, hidden.cve_id, "CVE-2099-99999", "cve-1"):
            for version in ("3.1", "4.0", "3", "5.0"):
                response = await authenticated_client.delete(_url(target, version))
                assert response.status_code == 403, (target, version)
                assert response.json() == _FORBIDDEN, (target, version)
                bodies.append(response.content)

        assert len(set(bodies)) == 1
        version_check.assert_not_called()
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        for cve in (visible, hidden):
            assert await persisted_assessments(db_session, cve.id) == [
                unit("SUSE", V31_CRITICAL)
            ]
        assert await total_ticket_events(db_session) == 0

    async def test_roles_are_loaded_once_for_capability_and_scope(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.delete(_url(cve, "3.1"))

        assert response.status_code == 204
        assert calls == [va_user.id]


# ---------------------------------------------------------------------------
# Unrecognized version: input-only 404 before CVE-ID resolution
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUnrecognizedVersion:
    @pytest.mark.parametrize(("raw", "decoded"), UNRECOGNIZED_VERSIONS)
    async def test_every_cve_id_returns_the_identical_404_without_lookup(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        raw: str,
        decoded: str,
    ) -> None:
        """A restricted analyst holds `manage_cvss`; the targets span an
        existing ticketless CVE, a malformed CVE-ID, a missing CVE, a CVE of
        an inaccessible confidential Ticket, and CVEs of `Ignored` and
        `Duplicated` Tickets. None is looked up, locked, or mutated."""
        ticketless = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        hidden = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        await ticket_factory(cve_id=hidden.id, is_confidential=True)
        ignored = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        await ticket_factory(cve_id=ignored.id, status=TicketStatus.IGNORED.value)
        duplicated = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        await ticket_factory(cve_id=duplicated.id, status=TicketStatus.DUPLICATED.value)
        targets = [
            ticketless.cve_id,
            "not-a-cve",
            "cve-2099-0001",
            str(ticketless.id),
            "CVE-2099-99999",
            hidden.cve_id,
            ignored.cve_id,
            duplicated.cve_id,
        ]
        version_check, resolver, mutation = _forbid_resolution(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            responses = [
                await authenticated_client.delete(_url(t, raw)) for t in targets
            ]

        for target, response in zip(targets, responses, strict=True):
            assert response.status_code == 404, target
            assert response.content == _ASSESSMENT_NOT_FOUND, target
        assert [c.args for c in version_check.call_args_list] == [(decoded,)] * len(
            targets
        )
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert recorder.statements  # the authentication queries were recorded
        assert _resource_statements(recorder) == []
        for cve in (ticketless, hidden, ignored, duplicated):
            assert await persisted_assessments(db_session, cve.id) == [
                unit("SUSE", V31_CRITICAL)
            ]
            assert await cve_severity(db_session, cve.id) == "Critical"
        assert await total_ticket_events(db_session) == 0

    async def test_unrecognized_version_is_never_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        cve_factory: Factory,
    ) -> None:
        """The path parameter is a plain string: even a long or
        non-numeric value is the domain 404, never the global 422."""
        cve: CVE = await cve_factory()

        for version in ("x" * 600, "3.1.0", "-1", "null", "%E2%80%8B3.1"):
            response = await authenticated_client.delete(_url(cve, version))
            assert response.status_code == 404, version
            assert response.content == _ASSESSMENT_NOT_FOUND, version


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
        cve_of: CVEOf,
        ticket_factory: Factory,
    ) -> None:
        """A restricted analyst holds `manage_cvss`, but the capability never
        makes a CVE of a confidential Ticket without a path visible."""
        visible = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        hidden = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        hidden_ticket: Ticket = await ticket_factory(
            cve_id=hidden.id, is_confidential=True
        )
        visible_ref = visible.cve_id
        targets = [
            "not-a-cve",
            visible_ref.lower(),
            f"%20{visible_ref}",
            f"{visible_ref}%20",
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            "CVE-2099-99999",
            hidden.cve_id,
        ]

        responses = [await authenticated_client.delete(_url(t, "3.1")) for t in targets]

        for target, response in zip(targets, responses, strict=True):
            assert response.status_code == 404, target
            assert response.content == _CVE_NOT_FOUND, target
        assert await persisted_assessments(db_session, hidden.id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await cve_severity(db_session, hidden.id) == "Critical"
        assert await ticket_state(db_session, hidden_ticket.id) == (
            TicketStatus.NEW.value,
            None,
            None,
            None,
            None,
        )
        assert await total_ticket_events(db_session) == 0

    async def test_access_lost_after_the_preliminary_check_is_404_without_effect(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The grant disappears after the preliminary dependency but before
        the mutation locks its roots; locked-current accessibility decides
        (api-spec.md, Authorization Chain Evaluation Order, flow 3)."""
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=ra_user.id)
        original = ticket_mutations.delete_cvss_assessment

        async def _revoke_then_mutate(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_mutations, "delete_cvss_assessment", _revoke_then_mutate
        )

        response = await authenticated_client.delete(_url(cve, "3.1"))

        assert response.status_code == 404
        assert response.content == _CVE_NOT_FOUND
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await total_ticket_events(db_session) == 0


# ---------------------------------------------------------------------------
# Deleted (204), not found (404), manual-zone rejection (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDelete:
    @pytest.mark.parametrize(("version", "vector"), ACCEPTED)
    async def test_each_accepted_version_returns_an_empty_204_and_commits(
        self,
        va_commit_client: AsyncClient,
        va_commit_user_id: uuid.UUID,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        version: str,
        vector: Vector,
    ) -> None:
        """An already-assigned `Analysis` Ticket isolates the direct events:
        the only assessment is removed, the unified severity becomes `NULL`,
        and the deletion event carries the acting user and `new_value`
        SQL `NULL`."""
        cve = await cve_of(("SUSE", vector), severity=Severity.CRITICAL)
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=va_commit_user_id,
        )
        cve_id, ticket_id, cve_ref = cve.id, ticket.id, cve.cve_id
        await db_session.commit()

        response = await va_commit_client.delete(_url(cve_ref, version))

        assert response.status_code == 204
        assert response.content == b""
        assert "content-type" not in response.headers
        assert await persisted_assessments(db_session, cve_id) == []
        assert await cve_severity(db_session, cve_id) is None
        assert await ticket_events_by_id(db_session, ticket_id) == [
            _delete_event(va_commit_user_id, vector),
            severity_event("Critical", None),
        ]

    async def test_ticketless_cve_updates_severity_without_any_event(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
    ) -> None:
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )

        response = await authenticated_client.delete(_url(cve, "3.1"))

        assert response.status_code == 204
        assert response.content == b""
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V40_CRITICAL)
        ]
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await total_ticket_events(db_session) == 0

    async def test_restricted_analyst_with_a_grant_deletes_without_assignment(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=ra_user.id)

        response = await authenticated_client.delete(_url(cve, "3.1"))

        assert response.status_code == 204
        assert await persisted_assessments(db_session, cve.id) == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW.value,
            None,
            None,
            None,
            None,
        )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _delete_event(ra_user.id, V31_CRITICAL),
            severity_event("Critical", None),
        ]

    async def test_deleting_the_last_suse_assessment_reopens_the_analysis(
        self,
        va_commit_client: AsyncClient,
        va_commit_user_id: uuid.UUID,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        product_factory: Factory,
    ) -> None:
        """An external assessment keeps the unified severity `Critical` and
        the in-support Product stays eligible under the fallback: only
        canonical-SUSE presence changes, and the committed Ticket moves
        `Analyzed -> Analysis` (cvss-scoring.md, Workflow Gate)."""
        cve = await cve_of(
            ("SUSE", V31_CRITICAL), ("NVD", V31_CRITICAL), severity=Severity.CRITICAL
        )
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value,
            cve_id=cve.id,
            assignee_id=va_commit_user_id,
            priority_auto="P2",
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.AFFECTED.value
        )
        product = await product_factory(
            general_support_end_date=datetime.now(UTC).date() + timedelta(days=365)
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
        cve_id, ticket_id, cve_ref = cve.id, ticket.id, cve.cve_id
        await db_session.commit()

        response = await va_commit_client.delete(_url(cve_ref, "3.1"))

        assert response.status_code == 204
        assert response.content == b""
        assert await persisted_assessments(db_session, cve_id) == [
            unit("NVD", V31_CRITICAL)
        ]
        assert await cve_severity(db_session, cve_id) == "Critical"
        assert (await ticket_state(db_session, ticket_id))[:2] == (
            TicketStatus.ANALYSIS.value,
            va_commit_user_id,
        )
        assert await ticket_events_by_id(db_session, ticket_id) == [
            _delete_event(va_commit_user_id, V31_CRITICAL),
            status_event(TicketStatus.ANALYZED.value, TicketStatus.ANALYSIS.value),
        ]

    @pytest.mark.parametrize(
        ("assessments", "version"),
        [
            pytest.param((), "3.1", id="no-assessment"),
            pytest.param((("NVD", V31_CRITICAL),), "3.1", id="external-same-version"),
            pytest.param((("SUSE", V31_CRITICAL),), "4.0", id="suse-other-version"),
        ],
    )
    async def test_absent_suse_assessment_is_404_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        assessments: tuple[tuple[str, Vector], ...],
        version: str,
    ) -> None:
        """An unassigned `New` Ticket and a VA caller prove that `not_found`
        performs no assignment, write, or audit."""
        severity = Severity.CRITICAL if assessments else None
        cve = await cve_of(*assessments, severity=severity)
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id
        )

        response = await authenticated_client.delete(_url(cve, version))

        assert response.status_code == 404
        assert response.content == _ASSESSMENT_NOT_FOUND
        assert await persisted_assessments(db_session, cve.id) == [
            unit(provider, vector) for provider, vector in assessments
        ]
        assert await cve_severity(db_session, cve.id) == (
            severity.value if severity else None
        )
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW.value,
            None,
            None,
            None,
            None,
        )
        assert await total_ticket_events(db_session) == 0

    async def test_repeated_delete_is_404_after_the_effective_delete(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
    ) -> None:
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)

        first = await authenticated_client.delete(_url(cve, "3.1"))
        second = await authenticated_client.delete(_url(cve, "3.1"))

        assert (first.status_code, second.status_code) == (204, 404)
        assert second.content == _ASSESSMENT_NOT_FOUND
        assert await persisted_assessments(db_session, cve.id) == []

    async def test_service_raised_not_found_maps_to_the_same_404(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The handler maps `CVSSAssessmentNotFoundError` from the service
        (ticket-mutations.md, Service Exceptions) to the same response."""
        cve: CVE = await cve_factory()
        mutation = AsyncMock(side_effect=CVSSAssessmentNotFoundError())
        monkeypatch.setattr(ticket_mutations, "delete_cvss_assessment", mutation)

        response = await authenticated_client.delete(_url(cve, "3.1"))

        assert response.status_code == 404
        assert response.content == _ASSESSMENT_NOT_FOUND
        mutation.assert_awaited_once()

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize(
        "version",
        [pytest.param("3.1", id="effective"), pytest.param("4.0", id="absent")],
    )
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_of: CVEOf,
        ticket_factory: Factory,
        status: TicketStatus,
        version: str,
    ) -> None:
        """The rejection precedes the `not_found` classification."""
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket: Ticket = await ticket_factory(status=status.value, cve_id=cve.id)

        response = await authenticated_client.delete(_url(cve, version))

        assert response.status_code == 409
        assert response.json() == _NOT_MUTABLE
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert (await ticket_state(db_session, ticket.id))[:2] == (status.value, None)
        assert await total_ticket_events(db_session) == 0


# ---------------------------------------------------------------------------
# Unhandled failures roll back and map to the generic 500
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestServerErrors:
    async def test_missing_setting_rolls_back_and_is_a_generic_500(
        self,
        va_commit_client: AsyncClient,
        db_session: AsyncSession,
        cve_of: CVEOf,
        ticket_factory: Factory,
    ) -> None:
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id
        )
        cve_id, ticket_id, cve_ref = cve.id, ticket.id, cve.cve_id
        # Release the setup savepoint so the request's rollback reverts only
        # the request's own work.
        await db_session.commit()

        response = await va_commit_client.delete(_url(cve_ref, "3.1"))

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert await persisted_assessments(db_session, cve_id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await cve_severity(db_session, cve_id) == "Critical"
        assert (await ticket_state(db_session, ticket_id))[:2] == (
            TicketStatus.NEW.value,
            None,
        )
        assert await total_ticket_events(db_session) == 0


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_PATH]["delete"]
        return operation

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_path_is_registered_for_delete_only(self) -> None:
        assert set(self._spec()["paths"][_PATH]) == {"delete"}
        assert self._operation()["tags"] == ["CVEs"]

    def test_path_parameters_are_unconstrained_strings(self) -> None:
        operation = self._operation()
        params = {p["name"]: p for p in operation["parameters"] if p["in"] == "path"}

        assert set(params) == {"cve_id", "cvss_version"}
        for param in params.values():
            assert param["required"] is True
            assert param["schema"]["type"] == "string"
            assert "enum" not in param["schema"]
            assert "pattern" not in param["schema"]
            assert "$ref" not in param["schema"]
        assert [p for p in operation["parameters"] if p["in"] != "path"] == []
        assert "requestBody" not in operation

    def test_responses_declare_an_empty_204_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert "content" not in responses["204"]
        assert "200" not in responses
        for code in ("404", "409"):
            assert self._ref_name(responses[code]["content"]) == "ErrorResponse"
        assert "CVSS_ASSESSMENT_NOT_FOUND" in responses["404"]["description"]
        assert "CVE_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
