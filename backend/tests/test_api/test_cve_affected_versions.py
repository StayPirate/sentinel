"""End-to-end tests for `GET /api/v1/cves/{cve_id}/affected-versions`
(`backend/app/api/v1/cves.py`).

See docs/features/tickets/cve-tracking.md (Get CVE Affected Versions),
docs/features/tickets/cve-service.md (Service Read Contracts > CVE Affected
Versions), docs/api-spec.md (Optional Authentication on Public Endpoints;
CVE Accessibility Check; Anti-Enumeration Boundary; Undeclared Query
Parameters), and docs/features/platform/testing-strategy.md (CVE and Source
Reads > Per-CVE affected versions).

Grouping, ordering, snapshot, and independent-session race coverage lives
in tests/test_services/test_cve_affected_versions.py; these tests cover
the HTTP contract: envelope and wire format, optional authentication,
anti-enumeration, and handler delegation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, event
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.enums import Role
from app.main import app
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services import cve_service
from app.services.cve_service import (
    CVEAffectedVersionEntryProjection,
    CVEAffectedVersionGroupProjection,
    CVEAffectedVersionsResult,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

Factory = Callable[..., Awaitable[Any]]

_PATH: Final = "/api/v1/cves/{cve_id}/affected-versions"
_NOT_FOUND: Final = {"code": "CVE_NOT_FOUND", "detail": "CVE not found."}
_UNAUTHENTICATED: Final = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_ENTRY_FIELDS: Final = {
    "vendor",
    "product",
    "package_url",
    "collection_url",
    "package_name",
    "repo",
    "version",
    "version_type",
    "version_end",
    "version_end_inclusive",
    "program_files",
    "cpe",
    "ecosystem",
    "status",
    "default_status",
}
_FULL_ENTRY: Final[dict[str, Any]] = {
    "vendor": "Example Vendor",
    "product": "Example Product",
    "package_url": "pkg:generic/example-product@1.0",
    "collection_url": "https://example.test/packages",
    "package_name": "example-product",
    "repo": "https://example.test/example-product.git",
    "version": "1.0",
    "version_type": "semver",
    "version_end": "1.5",
    "version_end_inclusive": False,
    "program_files": ["src/alpha.c", "src/beta.c"],
    "cpe": "cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*",
    "ecosystem": "PyPI",
    "status": "affected",
    "default_status": "unaffected",
}
_EMPTY_ENTRY: Final[dict[str, Any]] = dict.fromkeys(_ENTRY_FIELDS)


def _url(cve_id: str) -> str:
    return _PATH.format(cve_id=cve_id)


class _StatementRecorder:
    """Records every SQL statement executed through the session's engine."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less (`non_confidential` scope) `User` behind
    `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.mark.e2e
class TestGetCVEAffectedVersions:
    async def test_returns_the_grouped_entries_in_the_wire_format(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-70001")
        ticket: Ticket = await ticket_factory(cve_id=cve.id)
        rows = [
            await cve_affected_version_factory(
                cve_id=cve.id, source_container="osv", version="2.0"
            ),
            await cve_affected_version_factory(
                cve_id=cve.id, source_container="cna", **_FULL_ENTRY
            ),
            await cve_affected_version_factory(
                cve_id=cve.id,
                source_container="osv",
                version="1.0",
                version_type="git",
                version_end="1.1",
                version_end_inclusive=True,
            ),
        ]

        response = await client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {"source_container": "cna", "entries": [_FULL_ENTRY]},
                {
                    "source_container": "osv",
                    "entries": [
                        {
                            **_EMPTY_ENTRY,
                            "version": "1.0",
                            "version_type": "git",
                            "version_end": "1.1",
                            "version_end_inclusive": True,
                        },
                        {**_EMPTY_ENTRY, "version": "2.0"},
                    ],
                },
            ]
        }
        for group in response.json()["data"]:
            assert set(group) == {"source_container", "entries"}
            for entry in group["entries"]:
                assert set(entry) == _ENTRY_FIELDS
        for secret in (cve.id, ticket.id, *(row.id for row in rows)):
            assert str(secret) not in response.text
        assert "created_at" not in response.text

    async def test_cve_without_entries_returns_an_empty_list_anonymously(
        self, client: AsyncClient, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-70002")

        response = await client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {"data": []}

    async def test_every_not_found_cause_is_identical_for_both_callers(
        self,
        authenticated_client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        visible: CVE = await cve_factory(cve_id="CVE-2099-70003")
        confidential: CVE = await cve_factory(cve_id="CVE-2099-70004")
        await ticket_factory(cve_id=confidential.id, is_confidential=True)
        await cve_affected_version_factory(cve_id=confidential.id, version="1.0")
        targets = [
            "not-a-cve",
            "cve-2099-70003",
            "CVE-2099-70003%20",
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            "CVE-2099-99999",
            confidential.cve_id,
        ]
        token = authenticated_client.cookies[SESSION_COOKIE_NAME]

        authenticated = [await authenticated_client.get(_url(t)) for t in targets]
        authenticated_client.cookies.delete(SESSION_COOKIE_NAME)
        anonymous = [await authenticated_client.get(_url(t)) for t in targets]
        authenticated_client.cookies.set(SESSION_COOKIE_NAME, token)

        for target, response in zip(
            targets * 2, authenticated + anonymous, strict=True
        ):
            assert response.status_code == 404, target
            assert response.json() == _NOT_FOUND, target
            assert response.headers["content-type"] == "application/json"
        assert len({r.content for r in authenticated + anonymous}) == 1
        visible_response = await authenticated_client.get(_url(visible.cve_id))
        assert visible_response.status_code == 200

    @pytest.mark.parametrize("path", ["scope-all", "grant"])
    async def test_confidential_cve_is_visible_through_a_qualifying_path(
        self,
        path: str,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_role_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-70005")
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await cve_affected_version_factory(cve_id=cve.id, version="1.0")
        if path == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        else:
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
            )

        response = await authenticated_client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "source_container": "cna",
                    "entries": [{**_EMPTY_ENTRY, "version": "1.0"}],
                }
            ]
        }

    async def test_grant_revoked_before_the_protected_selection(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The caller was resolved before the revocation; the one protected
        selection alone decides."""
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        url = _url(cve.cve_id)
        assert (await authenticated_client.get(url)).status_code == 200
        original = cve_service.get_cve_affected_versions

        async def _revoke_then_read(
            db: AsyncSession, caller: TicketCaller, cve_id: str
        ) -> CVEAffectedVersionsResult:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, caller, cve_id)

        monkeypatch.setattr(cve_service, "get_cve_affected_versions", _revoke_then_read)

        response = await authenticated_client.get(url)

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "cookie"],
    )
    @pytest.mark.parametrize("cve_id", ["CVE-2099-70006", "x"])
    async def test_invalid_selected_credential_returns_401_before_the_read(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
        cve_id: str,
    ) -> None:
        await cve_factory(cve_id="CVE-2099-70006")
        spy = AsyncMock()
        monkeypatch.setattr(cve_service, "get_cve_affected_versions", spy)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(_url(cve_id), headers=credential.get("headers", {}))

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_undeclared_query_parameters_are_ignored(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-70007")
        await cve_affected_version_factory(cve_id=cve.id, version="1.0")

        plain = await client.get(_url(cve.cve_id))
        with_params = await client.get(
            _url(cve.cve_id),
            params={"page": "0", "per_page": "x", "sort_by": "bogus", "q": "y" * 600},
        )

        assert plain.status_code == with_params.status_code == 200
        assert with_params.json() == plain.json()

    @pytest.mark.parametrize("cve_id", ["CVE-2099-70008", "not-a-cve", "cve-2099-1"])
    async def test_handler_passes_the_raw_path_value_and_runs_no_query(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        cve_id: str,
    ) -> None:
        entry = CVEAffectedVersionEntryProjection(
            **{**_EMPTY_ENTRY, "version": "1.0", "program_files": ("src/a.c",)}
        )
        spy = AsyncMock(
            return_value=CVEAffectedVersionsResult(
                groups=(
                    CVEAffectedVersionGroupProjection("cna", (entry,)),
                    CVEAffectedVersionGroupProjection("osv", (entry, entry)),
                )
            )
        )
        monkeypatch.setattr(cve_service, "get_cve_affected_versions", spy)

        with _StatementRecorder(db_session) as recorder:
            response = await client.get(_url(cve_id))

        assert response.status_code == 200
        expected = {**_EMPTY_ENTRY, "version": "1.0", "program_files": ["src/a.c"]}
        assert response.json() == {
            "data": [
                {"source_container": "cna", "entries": [expected]},
                {"source_container": "osv", "entries": [expected, expected]},
            ]
        }
        assert recorder.statements == []
        spy.assert_awaited_once_with(db_session, ANONYMOUS_CALLER, cve_id)


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_declares_only_the_path_parameter_and_a_404(self) -> None:
        operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
        (parameter,) = operation["parameters"]

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["CVEs"]
        assert (parameter["name"], parameter["in"]) == ("cve_id", "path")
        assert "pattern" not in parameter["schema"]
        responses = operation["responses"]
        assert responses["404"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/ErrorResponse")
        assert responses["200"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/CVEAffectedVersionsResponse")

    def test_response_schemas_expose_exactly_the_specified_fields(self) -> None:
        schemas: dict[str, Any] = app.openapi()["components"]["schemas"]

        assert set(schemas["CVEAffectedVersionsResponse"]["properties"]) == {"data"}
        assert set(schemas["CVEAffectedVersionGroup"]["properties"]) == {
            "source_container",
            "entries",
        }
        assert set(schemas["CVEAffectedVersionEntry"]["properties"]) == _ENTRY_FIELDS
        assert set(schemas["CVEAffectedVersionEntry"]["required"]) == _ENTRY_FIELDS
