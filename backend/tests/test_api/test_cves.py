"""End-to-end tests for the CVE CVSS read endpoint
(`backend/app/api/v1/cves.py`).

See docs/features/tickets/cvss-scoring.md (API Endpoints > Shared
Assessment Item and Get CVSS Assessments for a CVE; Accepted Base
Vectors), docs/api-spec.md (Optional Authentication on Public Endpoints,
CVE Accessibility Check, CVE Identifier Resolution), and
docs/features/platform/testing-strategy.md (Ticket Accessibility >
Authentication, authorization, and anti-enumeration). Service-level
predicate, ordering, resolution, integrity, and independent-session race
coverage lives in tests/test_services/test_cve_service.py; these tests
cover the HTTP contract.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.enums import Role
from app.database import get_db
from app.main import app
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services import cve_service
from app.services.cvss import validate_cvss_vector

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/cves/{cve_id}/cvss"
_NOT_FOUND = {"code": "CVE_NOT_FOUND", "detail": "CVE not found."}
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_INTERNAL_ERROR = {
    "code": "INTERNAL_ERROR",
    "detail": "An unexpected error occurred.",
}
_FALLBACK = {"score": 10.0, "source": "fallback"}

V20_HIGH = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
V20_ZERO = "AV:N/AC:L/Au:N/C:N/I:N/A:N"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

CREATED_AT = datetime(2026, 9, 10, 10, 30, tzinfo=UTC)
UPDATED_AT = datetime(2026, 9, 10, 10, 31, tzinfo=UTC)

V2_HIGH_METRICS = {
    "access_vector": "network",
    "access_complexity": "low",
    "authentication": "none",
    "confidentiality_impact": "complete",
    "integrity_impact": "complete",
    "availability_impact": "complete",
}
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
V3_MEDIUM_METRICS = {
    "attack_vector": "network",
    "attack_complexity": "high",
    "privileges_required": "none",
    "user_interaction": "none",
    "scope": "unchanged",
    "confidentiality_impact": "low",
    "integrity_impact": "low",
    "availability_impact": "none",
}
V4_METRICS = {
    "attack_vector": "network",
    "attack_complexity": "low",
    "attack_requirements": "none",
    "privileges_required": "none",
    "user_interaction": "none",
    "vulnerable_system_confidentiality": "high",
    "vulnerable_system_integrity": "high",
    "vulnerable_system_availability": "high",
    "subsequent_system_confidentiality": "none",
    "subsequent_system_integrity": "none",
    "subsequent_system_availability": "none",
}


def _url(target: CVE | str) -> str:
    return _PATH.format(cve_id=target if isinstance(target, str) else target.cve_id)


def _unit(vector: str) -> dict[str, Any]:
    """The consistent vector-derived column unit for a stored assessment."""
    parsed = validate_cvss_vector(vector)
    return {
        "cvss_version": parsed.version.value,
        "score": parsed.score,
        "severity": parsed.severity.value,
        "vector_string": parsed.canonical_vector,
    }


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


@pytest.fixture
async def transmitting_client(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> AsyncGenerator[AsyncClient]:
    """An anonymous client that returns the transmitted 500 response.

    Starlette's `ServerErrorMiddleware` re-raises an unhandled exception
    after the application's generic handler has sent its response;
    `raise_app_exceptions=False` lets the test observe that response
    (mirrors `tests/test_main.py`). Debug mode is forced off because a
    local `DEBUG=true` environment would replace the production handler's
    response with Starlette's traceback page; clearing the cached
    middleware stack makes the app rebuild it with that setting, and
    monkeypatch restores both attributes afterwards.
    """
    monkeypatch.setattr(app, "debug", False)
    monkeypatch.setattr(app, "middleware_stack", None)

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as ac:
        yield ac
    app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Optional authentication
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthentication:
    async def test_anonymous_caller_reads_a_ticketless_cve(
        self,
        client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name="SUSE")

        response = await client.get(_url(cve))

        assert response.status_code == 200
        data = response.json()["data"]
        assert [a["provider_name"] for a in data["assessments"]] == ["SUSE"]
        assert data["eligibility"] == {"score": 9.8, "source": "suse"}

    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "cookie"],
    )
    async def test_invalid_credential_returns_401_before_lookup(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
    ) -> None:
        cve: CVE = await cve_factory()
        spy = AsyncMock()
        monkeypatch.setattr(cve_service, "get_cvss_assessments", spy)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)
        headers = credential.get("headers", {})

        for target in (cve.cve_id, "CVE-2099-99999", "not-a-cve"):
            response = await client.get(_url(target), headers=headers)
            assert response.status_code == 401, target
            assert response.json() == _UNAUTHENTICATED, target

        spy.assert_not_awaited()


# ---------------------------------------------------------------------------
# CVE accessibility and anti-enumeration
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCVEAccessibility:
    async def test_every_not_found_cause_returns_the_identical_response(
        self,
        client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        visible: CVE = await cve_factory(cve_id="CVE-2099-0001")
        confidential: CVE = await cve_factory()
        await ticket_factory(cve_id=confidential.id, is_confidential=True)
        targets = [
            "not-a-cve",
            "cve-2099-0001",
            "%20CVE-2099-0001",
            "CVE-2099-0001%20",
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            "CVE-2099-99999",
            confidential.cve_id,
        ]

        responses = [await client.get(_url(target)) for target in targets]

        for target, response in zip(targets, responses, strict=True):
            assert response.status_code == 404, target
            assert response.json() == _NOT_FOUND, target
            assert response.headers["content-type"] == "application/json"
        assert len({response.content for response in responses}) == 1
        assert (await client.get(_url(visible))).status_code == 200

    async def test_authenticated_caller_without_access_gets_the_same_404(
        self,
        authenticated_client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        confidential: CVE = await cve_factory()
        await ticket_factory(cve_id=confidential.id, is_confidential=True)

        inaccessible = await authenticated_client.get(_url(confidential))
        missing = await authenticated_client.get(_url("CVE-2099-99999"))

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.json() == _NOT_FOUND
        assert inaccessible.content == missing.content

    async def test_admin_scope_reads_a_confidential_cve(
        self,
        admin_client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name="SUSE")

        response = await admin_client.get(_url(cve))

        assert response.status_code == 200
        assert len(response.json()["data"]["assessments"]) == 1

    @pytest.mark.parametrize("branch", ["grant", "maintainer"])
    async def test_visibility_branch_allows_a_role_less_caller(
        self,
        branch: str,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        if branch == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.get(_url(cve))

        assert response.status_code == 200
        assert response.json()["data"]["assessments"] == []

    async def test_restricted_analyst_without_a_path_gets_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
        )

        response = await authenticated_client.get(_url(cve))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestResponseContract:
    async def test_returns_the_complete_composite_in_the_wire_format(
        self,
        client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id)
        created = {}
        for provider, vector in (
            ("Example Vendor", V20_HIGH),
            ("SUSE", V31),
            ("Example Vendor", V30),
            ("Another Vendor", V31_MEDIUM),
            ("Example Vendor", V40),
        ):
            row = await cve_cvss_assessment_factory(
                cve_id=cve.id,
                provider_name=provider,
                created_at=CREATED_AT,
                updated_at=UPDATED_AT,
                **_unit(vector),
            )
            created[(provider, row.cvss_version)] = str(row.id)

        def item(
            provider: str,
            version: str,
            score: float,
            severity: str,
            vector: str,
            metrics: dict[str, str],
        ) -> dict[str, Any]:
            return {
                "id": created[(provider, version)],
                "provider_name": provider,
                "cvss_version": version,
                "score": score,
                "severity": severity,
                "vector_string": vector,
                "metrics": metrics,
                "created_at": "2026-09-10T10:30:00Z",
                "updated_at": "2026-09-10T10:31:00Z",
            }

        response = await client.get(_url(cve))

        assert response.status_code == 200
        body = response.json()
        assert body == {
            "data": {
                "assessments": [
                    item("Example Vendor", "4.0", 9.3, "critical", V40, V4_METRICS),
                    item(
                        "Another Vendor",
                        "3.1",
                        4.8,
                        "medium",
                        V31_MEDIUM,
                        V3_MEDIUM_METRICS,
                    ),
                    item("SUSE", "3.1", 9.8, "critical", V31, V3_CRITICAL_METRICS),
                    item(
                        "Example Vendor",
                        "3.0",
                        9.8,
                        "critical",
                        V30,
                        V3_CRITICAL_METRICS,
                    ),
                    item(
                        "Example Vendor", "2.0", 10.0, "high", V20_HIGH, V2_HIGH_METRICS
                    ),
                ],
                "default_cvss_version": "3.1",
                "severity": {
                    "score": 9.8,
                    "version": "3.1",
                    "provider": "SUSE",
                    "label": "critical",
                },
                "eligibility": {"score": 9.8, "source": "suse"},
            }
        }
        for assessment in body["data"]["assessments"]:
            assert list(assessment) == [
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
            assert isinstance(assessment["score"], float)
        assert '"score":9.3' in response.text
        assert cve.cve_id not in response.text
        assert str(cve.id) not in response.text

    async def test_empty_set_returns_null_severity_and_fallback_eligibility(
        self, client: AsyncClient, default_setting: SystemSetting, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        response = await client.get(_url(cve))

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "assessments": [],
                "default_cvss_version": "3.1",
                "severity": None,
                "eligibility": _FALLBACK,
            }
        }

    async def test_v2_zero_score_is_assessment_low_and_unified_none(
        self,
        client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="Example Vendor", **_unit(V20_ZERO)
        )

        data = (await client.get(_url(cve))).json()["data"]

        (assessment,) = data["assessments"]
        assert (assessment["score"], assessment["severity"]) == (0.0, "low")
        assert assessment["metrics"] == {
            "access_vector": "network",
            "access_complexity": "low",
            "authentication": "none",
            "confidentiality_impact": "none",
            "integrity_impact": "none",
            "availability_impact": "none",
        }
        assert data["severity"] == {
            "score": 0.0,
            "version": "2.0",
            "provider": "Example Vendor",
            "label": "none",
        }
        assert data["eligibility"] == _FALLBACK

    async def test_default_version_40_is_returned_and_applied(
        self,
        client: AsyncClient,
        default_setting: SystemSetting,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        default_setting.value = "4.0"
        await db_session.flush()
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="SUSE", **_unit(V31_MEDIUM)
        )
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="Example Vendor", **_unit(V40)
        )

        data = (await client.get(_url(cve))).json()["data"]

        assert data["default_cvss_version"] == "4.0"
        assert data["severity"] == {
            "score": 4.8,
            "version": "3.1",
            "provider": "SUSE",
            "label": "medium",
        }
        assert data["eligibility"] == _FALLBACK

    async def test_pagination_and_sort_parameters_are_ignored(
        self,
        client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        for provider, vector in (("Zeta", V31), ("B-Vendor", V31), ("a-vendor", V40)):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **_unit(vector)
            )

        plain = await client.get(_url(cve))
        with_params = await client.get(
            _url(cve),
            params={"page": "2", "per_page": "1", "sort_by": "provider_name"},
        )

        assert plain.status_code == with_params.status_code == 200
        assert with_params.json() == plain.json()
        assert [
            (a["cvss_version"], a["provider_name"])
            for a in plain.json()["data"]["assessments"]
        ] == [("4.0", "a-vendor"), ("3.1", "B-Vendor"), ("3.1", "Zeta")]


# ---------------------------------------------------------------------------
# Unhandled failures map to the generic 500
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestServerErrors:
    async def test_missing_setting_on_an_accessible_cve_is_a_generic_500(
        self,
        transmitting_client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        accessible: CVE = await cve_factory()
        confidential: CVE = await cve_factory()
        await ticket_factory(cve_id=confidential.id, is_confidential=True)

        response = await transmitting_client.get(_url(accessible))
        hidden = await transmitting_client.get(_url(confidential))
        missing = await transmitting_client.get(_url("CVE-2099-99999"))

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert (hidden.status_code, hidden.json()) == (404, _NOT_FOUND)
        assert (missing.status_code, missing.json()) == (404, _NOT_FOUND)

    async def test_integrity_violation_is_a_generic_500(
        self,
        transmitting_client: AsyncClient,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name="SUSE")
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="Example Vendor", score=Decimal("9.7")
        )

        response = await transmitting_client.get(_url(cve))

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert "CVSS:" not in response.text


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
        return operation

    def _schemas(self) -> dict[str, Any]:
        schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
        return schemas

    def test_cve_id_is_an_unconstrained_string_and_no_query_is_declared(
        self,
    ) -> None:
        parameters = self._operation()["parameters"]
        (path_param,) = [p for p in parameters if p["in"] == "path"]

        assert path_param["name"] == "cve_id"
        assert path_param["required"] is True
        assert path_param["schema"]["type"] == "string"
        assert "pattern" not in path_param["schema"]
        assert "format" not in path_param["schema"]
        assert [p for p in parameters if p["in"] != "path"] == []
        assert not {"page", "per_page", "sort_by", "sort_order"} & {
            p["name"] for p in parameters
        }

    def test_declares_the_single_resource_envelope_and_404(self) -> None:
        operation = self._operation()
        schemas = self._schemas()

        assert "404" in operation["responses"]
        assert operation["responses"]["404"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/ErrorResponse")
        assert operation["responses"]["200"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/CVECVSSAssessmentsResponse")
        assert set(schemas["CVECVSSAssessmentsResponse"]["properties"]) == {"data"}
        composite = schemas["CVECVSSAssessments"]
        assert list(composite["properties"]) == [
            "assessments",
            "default_cvss_version",
            "severity",
            "eligibility",
        ]
        assert set(composite["required"]) == set(composite["properties"])

    def test_assessment_item_is_discriminated_by_cvss_version(self) -> None:
        schemas = self._schemas()
        items = schemas["CVECVSSAssessments"]["properties"]["assessments"]["items"]
        item = schemas[items["$ref"].rsplit("/", 1)[1]]

        assert items["$ref"].endswith("/CVSSAssessmentItem")
        assert item["discriminator"]["propertyName"] == "cvss_version"
        mapping = item["discriminator"]["mapping"]
        assert set(mapping) == {"2.0", "3.0", "3.1", "4.0"}
        metrics_by_version = {
            version: schemas[ref.rsplit("/", 1)[1]]["properties"]["metrics"]["$ref"]
            for version, ref in mapping.items()
        }
        assert metrics_by_version == {
            "2.0": "#/components/schemas/CVSS2Metrics",
            "3.0": "#/components/schemas/CVSS3Metrics",
            "3.1": "#/components/schemas/CVSS3Metrics",
            "4.0": "#/components/schemas/CVSS4Metrics",
        }
        for ref in mapping.values():
            properties = schemas[ref.rsplit("/", 1)[1]]["properties"]
            assert list(properties) == [
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
            assert properties["score"]["type"] == "number"

    def test_no_response_schema_exposes_a_cve_uuid(self) -> None:
        schemas = self._schemas()
        names = [
            "CVECVSSAssessmentsResponse",
            "CVECVSSAssessments",
            "CVSS20Assessment",
            "CVSS30Assessment",
            "CVSS31Assessment",
            "CVSS40Assessment",
            "CVSSSeverityResult",
            "CVSSEligibilityResult",
        ]

        for name in names:
            properties = set(schemas[name]["properties"])
            assert "cve_uuid" not in properties, name
            assert "cve_id" not in properties, name
