"""End-to-end tests for the Ticket detail endpoint
(`backend/app/api/v1/tickets.py`).

See docs/features/tickets/tickets.md (API Endpoints > Get Ticket, Response
Schemas > CVEDetail and TicketDetail), docs/features/tickets/ticket-priority.md
(API Surface), docs/features/tickets/ticket-deadlines.md (Actors and Phases,
API Surface), docs/api-spec.md (Optional Authentication on Public Endpoints,
Ticket Accessibility Check, Anti-Enumeration Boundary, Ticket Identifier
Resolution, User References in Responses, Response Format), and
docs/features/platform/testing-strategy.md (Ticket Accessibility). Detail
projection, evaluation-instant, mutation-assembly, N+1, and
independent-session race coverage lives in
tests/test_services/test_ticket_service.py; these tests cover the HTTP
contract.
"""

from __future__ import annotations

import typing
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import ticket_packages as packages_route
from app.api.v1 import tickets as route
from app.core.enums import CveState, Role, Severity, TicketPriority, TicketStatus
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.schemas import common, cve, ticket
from app.services import ticket_service
from app.services.ticket_service import TicketDetailProjection

Factory = Callable[..., Awaitable[Any]]

_NOT_FOUND = {"code": "TICKET_NOT_FOUND", "detail": "Ticket not found."}
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_PATH = "/api/v1/tickets/{ticket_id}"
_CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, tzinfo=UTC)
_UPDATED_AT = datetime(2026, 3, 10, 16, 0, tzinfo=UTC)
_NOW = datetime(2026, 3, 11, 12, 0, tzinfo=UTC)
_DUE_FIELDS = (
    "triage_due_at",
    "submission_due_at",
    "um_due_at",
    "qa_due_at",
    "release_due_at",
)
_TICKET_DETAIL_FIELDS = {
    "ticket_id",
    "status",
    "severity",
    "priority",
    "priority_automatic",
    "priority_override",
    "assignee",
    "cve",
    "duplicate_of_ticket_id",
    "is_confidential",
    "coordinated_release_at",
    *_DUE_FIELDS,
    "packages",
    "created_at",
    "updated_at",
}
_CVE_DETAIL_FIELDS = {
    "cve_id",
    "title",
    "description",
    "published_date",
    "modified_date",
    "cve_state",
    "date_rejected",
    "severity",
    "external_identifiers",
    "kev",
    "epss",
    "ssvc",
    "cwes",
}


def _url(target: Ticket | str) -> str:
    locator = (
        target if isinstance(target, str) else format_ticket_id(target.sequence_id)
    )
    return _PATH.format(ticket_id=locator)


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


class Clock:
    """Controlled evaluation-instant source recording every capture."""

    def __init__(self) -> None:
        self.calls: list[datetime] = []

    def now(self) -> datetime:
        self.calls.append(_NOW)
        return _NOW


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Replaces the single evaluation-instant capture of the detail read
    and of the standalone package-tree endpoint (for parity checks)."""
    clock = Clock()
    monkeypatch.setattr(ticket_service, "_utc_now", clock.now)
    monkeypatch.setattr(packages_route, "_utc_now", clock.now)
    return clock


@pytest.mark.e2e
class TestAuthentication:
    async def test_anonymous_caller_reads_a_non_confidential_ticket(
        self, client: AsyncClient, ticket_factory: Factory
    ) -> None:
        target: Ticket = await ticket_factory()

        response = await client.get(_url(target))

        assert response.status_code == 200
        assert response.json()["data"]["ticket_id"] == format_ticket_id(
            target.sequence_id
        )

    async def test_invalid_credential_returns_401_before_lookup(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(ticket_service, "get_ticket_detail", spy)

        for locator in ("SNTL-1", "not-a-ticket"):
            response = await client.get(
                _url(locator), headers={"Authorization": "Bearer invalid-token"}
            )
            assert response.status_code == 401
            assert response.json() == _UNAUTHENTICATED

        spy.assert_not_awaited()


@pytest.mark.e2e
class TestGetTicketEndpoint:
    async def test_returns_the_complete_detail_in_the_wire_format(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_epss_score_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
        cve_cwe_factory: Factory,
        cve_external_identifier_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        assignee = await user_factory(
            username="fictional.analyst", full_name="Fictional Analyst"
        )
        detail_cve = await cve_factory(
            cve_id="CVE-2099-50001",
            title="Fictional overflow",
            description="A fictional heap overflow.",
            published_date=datetime(2026, 2, 1, 8, 30, tzinfo=UTC),
            modified_date=datetime(2026, 2, 3, 9, 45, tzinfo=UTC),
            severity=Severity.HIGH.value,
        )
        await cve_kev_entry_factory(cve_id=detail_cve.id, date_added=date(2026, 2, 6))
        await cve_epss_score_factory(
            cve_id=detail_cve.id,
            score=0.97125,
            percentile=0.99876,
            assessed_at=date(2026, 2, 7),
        )
        await cve_ssvc_assessment_factory(
            cve_id=detail_cve.id,
            exploitation="poc",
            automatable="no",
            technical_impact="partial",
            version="2.0.3",
        )
        await cve_cwe_factory(cve_id=detail_cve.id, cwe_id="CWE-79", source="NVD")
        await cve_cwe_factory(cve_id=detail_cve.id, cwe_id="CWE-79", source="MITRE")
        await cve_external_identifier_factory(
            cve_id=detail_cve.id,
            source="GHSA",
            identifier="GHSA-abcd-efgh-ijkl",
            url="https://advisories.example.com/GHSA-abcd-efgh-ijkl",
        )
        target: Ticket = await ticket_factory(
            cve_id=detail_cve.id,
            assignee_id=assignee.id,
            priority_auto=TicketPriority.P2.value,
            priority_override=TicketPriority.P1.value,
            status=TicketStatus.ANALYSIS.value,
            coordinated_release_at=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
            created_at=_CREATED_AT,
            updated_at=_UPDATED_AT,
        )
        package = await ticket_package_factory(
            ticket_id=target.id, package_name="example-lib"
        )
        track = await ticket_package_track_factory(ticket_package_id=package.id)
        await ticket_package_product_factory(ticket_package_track_id=track.id)

        response = await client.get(_url(target))
        packages = await client.get(_url(target) + "/packages")

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        data = body["data"]
        assert data == {
            "ticket_id": format_ticket_id(target.sequence_id),
            "status": "analysis",
            "severity": "high",
            "priority": "p1",
            "priority_automatic": "p2",
            "priority_override": "p1",
            "assignee": {
                "id": str(assignee.id),
                "username": "fictional.analyst",
                "full_name": "Fictional Analyst",
                "active": True,
            },
            "cve": {
                "cve_id": "CVE-2099-50001",
                "title": "Fictional overflow",
                "description": "A fictional heap overflow.",
                "published_date": "2026-02-01T08:30:00Z",
                "modified_date": "2026-02-03T09:45:00Z",
                "cve_state": "published",
                "date_rejected": None,
                "severity": "high",
                "external_identifiers": [
                    {
                        "source": "ghsa",
                        "identifier": "GHSA-abcd-efgh-ijkl",
                        "url": "https://advisories.example.com/GHSA-abcd-efgh-ijkl",
                    }
                ],
                "kev": {"date_added": "2026-02-06", "reference_url": None},
                "epss": {
                    "score": 0.97125,
                    "percentile": 0.99876,
                    "assessed_at": "2026-02-07",
                },
                "ssvc": {
                    "exploitation": "poc",
                    "automatable": "no",
                    "technical_impact": "partial",
                    "version": "2.0.3",
                    "assessed_at": None,
                },
                "cwes": [{"cwe_id": "CWE-79", "sources": ["MITRE", "NVD"]}],
            },
            "duplicate_of_ticket_id": None,
            "is_confidential": False,
            "coordinated_release_at": "2026-04-01T12:00:00Z",
            "triage_due_at": "2026-03-13T14:37:21Z",
            "submission_due_at": "2026-03-28T14:37:21Z",
            "um_due_at": "2026-03-31T14:37:21Z",
            "qa_due_at": "2026-04-09T14:37:21Z",
            "release_due_at": "2026-04-09T14:37:21Z",
            "packages": packages.json()["data"],
            "created_at": "2026-03-10T14:37:21Z",
            "updated_at": "2026-03-10T16:00:00Z",
        }
        assert [p["id"] for p in data["packages"]] == [str(package.id)]
        assert fixed_clock.calls == [_NOW, _NOW]

    async def test_null_sla_severity_labels_and_rejected_cve(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """The `none` severity label has no SLA and is distinct from an
        unresolved `null` (30-day tier); the manual zone nulls every due
        date."""
        ignored: Ticket = await ticket_factory(
            status=TicketStatus.IGNORED.value, severity_manual=Severity.HIGH.value
        )
        none_label: Ticket = await ticket_factory(
            cve_id=(
                await cve_factory(
                    severity=Severity.NONE.value,
                    cve_state=CveState.REJECTED.value,
                    date_rejected=datetime(2026, 3, 1, tzinfo=UTC),
                )
            ).id
        )
        unresolved: Ticket = await ticket_factory()

        bodies = [
            (await client.get(_url(t))).json()["data"]
            for t in (ignored, none_label, unresolved)
        ]

        assert bodies[0]["status"] == "ignored"
        assert bodies[0]["severity"] == "high"
        assert {f: bodies[0][f] for f in _DUE_FIELDS} == dict.fromkeys(_DUE_FIELDS)
        assert bodies[1]["severity"] == "none"
        assert bodies[1]["cve"]["severity"] == "none"
        assert bodies[1]["cve"]["cve_state"] == "rejected"
        assert bodies[1]["cve"]["date_rejected"] == "2026-03-01T00:00:00Z"
        assert {f: bodies[1][f] for f in _DUE_FIELDS} == dict.fromkeys(_DUE_FIELDS)
        assert bodies[2]["severity"] is None
        assert bodies[2]["cve"] is None
        assert (bodies[2]["priority"], bodies[2]["assignee"]) == (None, None)
        assert all(bodies[2][f] is not None for f in _DUE_FIELDS)

    async def test_duplicate_of_inaccessible_target_exposes_only_its_identifier(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(
            is_confidential=True,
            cve_id=(await cve_factory(severity=Severity.CRITICAL.value)).id,
        )
        duplicate: Ticket = await ticket_factory(duplicate_of_id=target.id)

        response = await client.get(_url(duplicate))
        followed = await client.get(_url(target))

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "duplicated"
        assert data["duplicate_of_ticket_id"] == format_ticket_id(target.sequence_id)
        assert (data["cve"], data["severity"], data["packages"]) == (None, None, [])
        assert "duplicate_of_id" not in data
        assert followed.status_code == 404
        assert followed.json() == _NOT_FOUND

    async def test_undeclared_query_parameters_are_ignored(
        self, client: AsyncClient, ticket_factory: Factory
    ) -> None:
        target: Ticket = await ticket_factory()

        response = await client.get(
            _url(target), params={"evaluation_date": "2020-01-01", "caller": "x"}
        )

        assert response.status_code == 200
        assert response.json()["data"]["ticket_id"] == format_ticket_id(
            target.sequence_id
        )


@pytest.mark.e2e
class TestTicketAccessibility:
    async def test_every_not_found_cause_returns_the_identical_response(
        self, client: AsyncClient, ticket_factory: Factory
    ) -> None:
        visible: Ticket = await ticket_factory()
        confidential: Ticket = await ticket_factory(is_confidential=True)
        visible_id = format_ticket_id(visible.sequence_id)
        locators = [
            visible_id.lower(),
            "Sntl-" + visible_id.removeprefix("SNTL-"),
            f"%20{visible_id}",
            f"{visible_id}%20",
            f"SNTL-0{visible.sequence_id}",
            "SNTL-0",
            "SNTL-2147483648",
            "SNTL-99999999999999999999",
            "SNTL-",
            str(visible.id),
            "SNTL-2147483647",
            format_ticket_id(confidential.sequence_id),
        ]

        responses = [await client.get(_url(loc)) for loc in locators]

        for locator, response in zip(locators, responses, strict=True):
            assert response.status_code == 404, locator
            assert response.json() == _NOT_FOUND, locator
            assert response.headers["content-type"] == "application/json"
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(
        "branch", ["va_scope", "admin_scope", "grant", "maintainer"]
    )
    async def test_each_visibility_branch_allows_the_read(
        self,
        branch: str,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=target.id)
        if branch == "va_scope":
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
            )
        elif branch == "admin_scope":
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.ADMIN.value
            )
        elif branch == "grant":
            await ticket_access_grant_factory(
                ticket_id=target.id, user_id=authenticated_user.id
            )
        else:
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.get(_url(target))

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["is_confidential"] is True
        assert [p["id"] for p in data["packages"]] == [str(package.id)]
        assert "maintainers" not in data["packages"][0]

    async def test_authenticated_caller_without_a_path_gets_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
        )

        response = await authenticated_client.get(_url(target))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_mixed_visibility_exposes_only_visible_tickets(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        public: Ticket = await ticket_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=granted.id, user_id=authenticated_user.id
        )

        statuses = [
            (await authenticated_client.get(_url(t))).status_code
            for t in (public, granted, hidden)
        ]

        assert statuses == [200, 200, 404]

    async def test_access_lost_before_the_protected_selection_is_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Caller resolution happened before the grant is revoked; the
        protected selection alone decides the response."""
        target: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=target.id, user_id=authenticated_user.id
        )
        original = ticket_service.get_ticket_detail

        async def _revoke_then_read(
            db: AsyncSession, **kwargs: Any
        ) -> TicketDetailProjection:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == target.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "get_ticket_detail", _revoke_then_read)

        response = await authenticated_client.get(_url(target))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target: Ticket = await ticket_factory(is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = ticket_service.get_ticket_detail

        async def _remove_role_then_read(
            db: AsyncSession, **kwargs: Any
        ) -> TicketDetailProjection:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_service, "get_ticket_detail", _remove_role_then_read)
        in_flight = await authenticated_client.get(_url(target))
        monkeypatch.setattr(ticket_service, "get_ticket_detail", original)
        next_request = await authenticated_client.get(_url(target))

        assert in_flight.status_code == 200
        assert in_flight.json()["data"]["ticket_id"] == format_ticket_id(
            target.sequence_id
        )
        assert next_request.status_code == 404


# ---------------------------------------------------------------------------
# OpenAPI and schema contract
# ---------------------------------------------------------------------------


def _literal_values(alias: Any) -> set[str]:
    """The values of a `type X = Literal[...]` alias."""
    return set(typing.get_args(alias.__value__))


@pytest.mark.unit
class TestSchemaEnumerations:
    @pytest.mark.parametrize(
        ("alias", "expected"),
        [
            (ticket.TicketStatusValue, {s.value.lower() for s in TicketStatus}),
            (ticket.TicketPriorityValue, {p.value.lower() for p in TicketPriority}),
            (common.SeverityValue, {s.value.lower() for s in Severity}),
            (cve.CveStateValue, {s.value.lower() for s in CveState}),
        ],
    )
    def test_wire_values_are_the_lowercase_domain_values(
        self, alias: Any, expected: set[str]
    ) -> None:
        assert _literal_values(alias) == expected


@pytest.mark.unit
class TestSerializer:
    def test_ticket_without_sla_serializes_five_null_due_dates(self) -> None:
        serialized = route.serialize_ticket_detail(
            TicketDetailProjection(
                ticket_id="SNTL-1",
                status=TicketStatus.DUPLICATED,
                severity=None,
                priority=None,
                priority_automatic=None,
                priority_override=None,
                assignee=None,
                cve=None,
                duplicate_of_ticket_id="SNTL-2",
                is_confidential=False,
                coordinated_release_at=None,
                due_dates=None,
                packages=(),
                created_at=_CREATED_AT,
                updated_at=_UPDATED_AT,
            )
        )

        assert serialized.status == "duplicated"
        assert serialized.duplicate_of_ticket_id == "SNTL-2"
        assert {f: getattr(serialized, f) for f in _DUE_FIELDS} == dict.fromkeys(
            _DUE_FIELDS
        )


@pytest.mark.unit
class TestOpenApiContract:
    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
        return operation

    def _schemas(self) -> dict[str, Any]:
        schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
        return schemas

    def test_ticket_id_is_a_string_sntl_identity_and_no_query_is_declared(
        self,
    ) -> None:
        parameters = self._operation()["parameters"]
        (path_param,) = [p for p in parameters if p["in"] == "path"]

        assert path_param["name"] == "ticket_id"
        assert path_param["schema"]["type"] == "string"
        assert "pattern" not in path_param["schema"]
        assert "format" not in path_param["schema"]
        assert [p for p in parameters if p["in"] == "query"] == []

    def test_declares_the_single_resource_envelope_and_404(self) -> None:
        operation = self._operation()

        assert "404" in operation["responses"]
        assert operation["tags"] == ["Tickets"]
        assert set(self._schemas()["TicketDetailResponse"]["properties"]) == {"data"}

    def test_ticket_detail_fields_are_exactly_the_specified_ones(self) -> None:
        properties = self._schemas()["TicketDetail"]["properties"]

        assert set(properties) == _TICKET_DETAIL_FIELDS
        assert not {
            "id",
            "identifier",
            "ticket_sequence_id",
            "duplicate_of_id",
            "package_names",
            "cvss",
            "cvss_assessments",
            "maintainers",
        } & set(properties)

    def test_cve_detail_fields_exclude_priority_and_inline_cvss(self) -> None:
        properties = self._schemas()["CVEDetail"]["properties"]

        assert set(properties) == _CVE_DETAIL_FIELDS
        assert not {"priority", "cvss", "cvss_assessments"} & set(properties)

    def test_nested_schemas_are_reused(self) -> None:
        properties = self._schemas()["TicketDetail"]["properties"]

        assert properties["packages"]["items"]["$ref"].endswith("/PackageDetail")
        assignee_refs = {
            item.get("$ref", "") for item in properties["assignee"]["anyOf"]
        }
        assert any(ref.endswith("/UserReference") for ref in assignee_refs)
        cve_refs = {item.get("$ref", "") for item in properties["cve"]["anyOf"]}
        assert any(ref.endswith("/CVEDetail") for ref in cve_refs)

    def test_required_consumer_guidance_is_documented(self) -> None:
        properties = self._schemas()["TicketDetail"]["properties"]

        assert "qa_due_at" in properties["release_due_at"]["description"]
        assert "release_due_at" in properties["qa_due_at"]["description"]
        for field, actor in (
            ("triage_due_at", "VA (Vulnerability Analyst)"),
            ("submission_due_at", "maintainer"),
            ("um_due_at", "UM (SUSE maintenance update team)"),
            ("qa_due_at", "QA (quality assurance)"),
        ):
            assert actor in properties[field]["description"], field
        assert "distinct from `null`" in properties["severity"]["description"]
        assert "404" in properties["duplicate_of_ticket_id"]["description"]
