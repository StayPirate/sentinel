"""End-to-end tests for `GET /api/v1/admin/settings/default-cvss-version/impact`
(`backend/app/api/v1/settings.py`, `get_default_cvss_version_impact`).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Access Control;
  Default-CVSS Impact Preview, all subsections; API Endpoints, Get
  Default-CVSS Impact Preview).
- docs/features/tickets/ticket-mutations.md (CVSS Status Matrix, the
  default-version paragraph), docs/features/tickets/cvss-scoring.md
  (Severity Resolution Cascade, Eligibility Score Resolution),
  docs/features/packages/package-model.md (Axis 2: Eligibility, Derived
  Actionability), and docs/features/tickets/tickets.md (Gate: Analysis →
  Analyzed, Gate: Analyzed → Resolved) for the expected projected values.
- docs/api-spec.md (Query Parameter Length Limit, Undeclared Query
  Parameters, NUL Characters in Request Input, Response Format, Global
  Responses).
- docs/features/platform/testing-strategy.md (Default-CVSS Impact Preview,
  E2E tests; Mandatory Test Scenarios, API Endpoints).

These tests cover the HTTP contract; the projection rules themselves belong
to the service tests. The OpenAPI surface of the route is asserted in
`tests/test_api/test_settings.py` (`TestSettingsOpenAPISurface`). The
endpoint addresses no resource, so the mandatory 404 scenario does not
apply.

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, time
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.v1.settings import _PREVIEW_TIMEOUT_DETAIL
from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.models.api_key import ApiKey
from app.models.cve import CVE
from app.models.product import Product
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import cvss_impact_preview
from app.services.cvss_impact_preview import DefaultCVSSVersionImpact
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]

_PATH = "/api/v1/admin/settings/default-cvss-version/impact"
_PROPOSE_4_0 = {"proposed_version": "4.0"}
_EVAL_NOW = datetime.combine(EVAL, time(12, 0), tzinfo=UTC)
"""A UTC instant on `EVAL`, so every lifecycle phase is deterministic."""

# default-cvss-version-operations.md, Timeout and Partial Results: one
# 30-second monotonic deadline started at function entry. A clock that has
# advanced past it has expired.
_PAST_DEADLINE = 31.0

# A catalog threshold that the SUSE `3.1` score of `_regressing_ticket`
# stays below and its SUSE `4.0` score meets (package-model.md, Axis 2:
# Eligibility, rule 5).
_T7 = Decimal("7.0")

# api-spec.md, Global Responses.
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}

# default-cvss-version-operations.md, Result and Count Units.
_FIELD_TYPES = {
    "observed_default_cvss_version": str,
    "proposed_default_cvss_version": str,
    "no_op": bool,
    "cves_evaluated": int,
    "cve_severity_changes": int,
    "product_eligibility_changes": int,
    "product_eligibility_override_skips": int,
    "resolved_ticket_regressions": int,
}

# The `population` fixture proposed at `4.0` with the setting at `3.1`:
# - the ticketless CVE projects `Medium → High` (one severity change);
# - the `Resolved` Ticket's CVE projects `Medium → Critical`, two automatic
#   eligibility changes, one override skip, and the projected gate
#   `Analyzed` (one Resolved regression), see `_regressing_ticket`;
# - the third CVE projects its persisted `High` again (no effect).
_POPULATION_IMPACT = {
    "data": {
        "observed_default_cvss_version": "3.1",
        "proposed_default_cvss_version": "4.0",
        "no_op": False,
        "cves_evaluated": 3,
        "cve_severity_changes": 2,
        "product_eligibility_changes": 2,
        "product_eligibility_override_skips": 1,
        "resolved_ticket_regressions": 1,
    }
}

# Every table the preview reads; the handler itself must read none of them.
_PREVIEW_TABLES = re.compile(
    r"\b(cve|cve_cvss_assessment|ticket|ticket_package|ticket_package_track"
    r"|ticket_package_product|product|system_setting)\b"
)
_CVE_TABLE = re.compile(r"\bcve\b")


def _zeroed(observed: str, proposed: str, *, no_op: bool) -> dict[str, Any]:
    """A response whose six counts are all `0`."""
    return {
        "data": {
            "observed_default_cvss_version": observed,
            "proposed_default_cvss_version": proposed,
            "no_op": no_op,
            "cves_evaluated": 0,
            "cve_severity_changes": 0,
            "product_eligibility_changes": 0,
            "product_eligibility_override_skips": 0,
            "resolved_ticket_regressions": 0,
        }
    }


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_settings.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


@pytest.fixture
def fixed_eval_date(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the invocation's UTC `evaluation_date` to `EVAL`."""
    monkeypatch.setattr(cvss_impact_preview, "_utc_now", lambda: _EVAL_NOW)


@pytest.fixture
def forbidden_preview(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Replace the preview service with a stub that must not run."""
    preview = AsyncMock(side_effect=AssertionError("preview must not run"))
    monkeypatch.setattr(cvss_impact_preview, "get_default_cvss_version_impact", preview)
    return preview


@pytest.fixture
def user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> tuple[User, AsyncClient]:
    """The shared `client` authenticated by a JWT session as a user holding
    no role."""
    return _authenticated_user_and_client


@pytest_asyncio.fixture
async def setting_3_1(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(key="default_cvss_version", value="3.1")


@pytest_asyncio.fixture
async def admin_api_key_client(
    client: AsyncClient,
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
    api_key_factory: Callable[..., Awaitable[ApiKey]],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncClient:
    """The shared `client`, authenticated as an admin via an API key
    (`Authorization: Bearer`) instead of a JWT session cookie. Mirrors the
    identical fixture in `tests/test_api/test_settings.py`."""
    user = await user_factory()
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    token, digest = _make_api_key_credential()
    await api_key_factory(user_id=user.id, key_hash=digest)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    client.headers["Authorization"] = f"Bearer {token}"
    return client


async def _regressing_ticket(
    cve_with: CVEBuilder,
    ticket_factory: TicketFactory,
    tree: TreeBuilder,
    *,
    confidential: bool,
) -> Ticket:
    """A `Resolved` Ticket converged under `3.1` that regresses under `4.0`.

    Its CVE has SUSE `3.1` = 5.0 and SUSE `4.0` = 9.0 and the converged
    persisted severity `Medium`; under `4.0` it projects `Critical` (one
    severity change). One `AFFECTED` track holds three occurrences with
    catalog threshold 7.0, all persisted `eligible = false`:

    - in support, automatic: 9.0 >= 7.0 projects `true` (one change);
    - in support, overridden: preserved and counted as one skip;
    - EOL, automatic: projects `true` (one change); EOL is not a formula
      input but makes the occurrence non-actionable.

    Under `3.1` (5.0 < 7.0) the actionable eligible set is empty, so the
    `AFFECTED` track is resolution-complete by clause (c). Under `4.0` the
    in-support automatic occurrence is actionable and eligible, so only the
    Analyzed predicate holds: the projected gate is `Analyzed`, one
    Resolved regression.
    """
    cve = await cve_with(
        Assessment("5.0", version="3.1"),
        Assessment("9.0", version="4.0"),
        severity=Severity.MEDIUM,
    )
    ticket = await ticket_factory(
        status=TicketStatus.RESOLVED.value,
        cve_id=cve.id,
        is_confidential=confidential,
    )
    await tree(
        ticket,
        status=PackageStatus.AFFECTED,
        products=(
            Prod(eligible=False, threshold=_T7),
            Prod(eligible=False, override=True, threshold=_T7),
            Prod(eligible=False, eol=True, threshold=_T7),
        ),
    )
    return ticket


@pytest_asyncio.fixture
async def population(
    setting_3_1: SystemSetting,
    cve_with: CVEBuilder,
    ticket_factory: TicketFactory,
    tree: TreeBuilder,
) -> None:
    """The setting at `3.1` and the three CVEs of `_POPULATION_IMPACT`."""
    # Non-SUSE only: the cascade takes the non-SUSE assessment at the
    # default version, 5.0 Medium under `3.1` and 8.0 High under `4.0`.
    await cve_with(
        Assessment("5.0", provider="NVD", version="3.1"),
        Assessment("8.0", provider="NVD", version="4.0"),
        severity=Severity.MEDIUM,
    )
    await _regressing_ticket(cve_with, ticket_factory, tree, confidential=False)
    # SUSE `3.1` only: under `4.0` the cascade takes the canonical SUSE
    # assessment at another accepted version, 7.5 High, as persisted.
    await cve_with(Assessment("7.5", version="3.1"), severity=Severity.HIGH)


async def _tree_identifiers(db: AsyncSession, ticket_id: uuid.UUID) -> list[str]:
    """Every package, track, occurrence, and catalog Product identifier
    (UUIDs and CPEs) under a Ticket."""
    rows = await db.execute(
        select(
            TicketPackage.id,
            TicketPackageTrack.id,
            TicketPackageProduct.id,
            Product.id,
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
    )
    return [str(value) for row in rows for value in row]


async def _derived_state(db: AsyncSession) -> dict[str, Any]:
    """Every persisted value the preview projects or could write."""
    return {
        "cve_severity": (
            await db.execute(select(CVE.id, CVE.severity).order_by(CVE.id))
        ).all(),
        "occurrences": (
            await db.execute(
                select(
                    TicketPackageProduct.id,
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.is_eligible_override,
                ).order_by(TicketPackageProduct.id)
            )
        ).all(),
        "ticket_status": (
            await db.execute(select(Ticket.id, Ticket.status).order_by(Ticket.id))
        ).all(),
        "setting": (
            await db.execute(
                select(SystemSetting.value).where(
                    SystemSetting.key == "default_cvss_version"
                )
            )
        ).scalar_one(),
        "ticket_events": await db.scalar(
            select(func.count()).select_from(TicketAuditEvent)
        ),
        "setting_events": await db.scalar(
            select(func.count()).select_from(SettingAuditEvent)
        ),
    }


# ---------------------------------------------------------------------------
# A. Authentication and authorization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndAuthorization:
    async def test_unauthenticated_returns_401_without_a_preview(
        self, client: AsyncClient, forbidden_preview: AsyncMock
    ) -> None:
        response = await client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        forbidden_preview.assert_not_awaited()

    async def test_without_manage_settings_returns_403_without_a_preview(
        self, authenticated_client: AsyncClient, forbidden_preview: AsyncMock
    ) -> None:
        response = await authenticated_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        forbidden_preview.assert_not_awaited()

    @pytest.mark.parametrize(
        "role", [Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST]
    )
    async def test_non_admin_role_returns_403(
        self,
        role: Role,
        user_and_client: tuple[User, AsyncClient],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        forbidden_preview: AsyncMock,
    ) -> None:
        """`manage_settings` is held only by Admin (rbac.md, Predefined
        Roles); the preview introduces no other capability."""
        user, client = user_and_client
        await user_role_factory(user_id=user.id, role=role.value)

        response = await client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        forbidden_preview.assert_not_awaited()

    async def test_admin_jwt_session_is_accepted(
        self,
        admin_client: AsyncClient,
        population: None,
        fixed_eval_date: None,
    ) -> None:
        response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 200
        assert response.json() == _POPULATION_IMPACT

    async def test_admin_api_key_is_accepted(
        self,
        admin_api_key_client: AsyncClient,
        population: None,
        fixed_eval_date: None,
    ) -> None:
        """The endpoint is not session-only: an administrator's API key is
        accepted."""
        response = await admin_api_key_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 200
        assert response.json() == _POPULATION_IMPACT


# ---------------------------------------------------------------------------
# B. Query validation
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestQueryValidation:
    async def test_missing_proposed_version_returns_422(
        self, admin_client: AsyncClient, forbidden_preview: AsyncMock
    ) -> None:
        response = await admin_client.get(_PATH)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [
            ["query", "proposed_version"]
        ]
        forbidden_preview.assert_not_awaited()

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("3.0", id="accepted-assessment-version-3.0"),
            pytest.param("2.0", id="accepted-assessment-version-2.0"),
            pytest.param("4", id="4"),
            pytest.param("40", id="40"),
            pytest.param("", id="empty"),
            pytest.param("3.1 ", id="trailing-whitespace"),
            pytest.param("4" * 501, id="over-length-501"),
        ],
    )
    async def test_unsupported_value_returns_422(
        self,
        value: str,
        admin_client: AsyncClient,
        forbidden_preview: AsyncMock,
    ) -> None:
        """Only `3.1` and `4.0` are proposable, although `2.0` and `3.0`
        are accepted assessment versions (default-cvss-version-operations.md,
        Get Default-CVSS Impact Preview; api-spec.md, Query Parameter Length
        Limit)."""
        response = await admin_client.get(_PATH, params={"proposed_version": value})

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert {tuple(error["loc"]) for error in body["errors"]} == {
            ("query", "proposed_version")
        }
        forbidden_preview.assert_not_awaited()

    async def test_nul_returns_422_without_echo_or_preview(
        self, admin_client: AsyncClient, forbidden_preview: AsyncMock
    ) -> None:
        """api-spec.md, NUL Characters in Request Input: a value containing
        U+0000 is rejected, not stripped, and is not echoed.
        `tests/test_api/test_request_nul.py` covers representative
        endpoints, not every route."""
        response = await admin_client.get(
            _PATH, params={"proposed_version": "4.0\x00fictional"}
        )

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [
            ["query", "proposed_version"]
        ]
        assert "fictional" not in response.text
        forbidden_preview.assert_not_awaited()

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("4.0\x00fictional", id="nul"),
            pytest.param("4" * 501, id="over-length-501"),
        ],
    )
    async def test_shared_input_checks_precede_authentication(
        self, value: str, client: AsyncClient, forbidden_preview: AsyncMock
    ) -> None:
        """api-spec.md, NUL Characters in Request Input and Query Parameter
        Length Limit: the shared checks inspect the string-valued
        `proposed_version` and run before authentication, so an
        unauthenticated request receives `422`, not `401`."""
        response = await client.get(_PATH, params={"proposed_version": value})

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [
            ["query", "proposed_version"]
        ]
        assert "fictional" not in response.text
        forbidden_preview.assert_not_awaited()


# ---------------------------------------------------------------------------
# C. Results
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestResults:
    async def test_happy_path_returns_exactly_the_eight_documented_fields(
        self,
        admin_client: AsyncClient,
        population: None,
        fixed_eval_date: None,
    ) -> None:
        response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 200
        body = response.json()
        assert body == _POPULATION_IMPACT
        # `{"data": ...}` only: the endpoint is not paginated and has no `meta`.
        assert set(body) == {"data"}
        # `True == 1`: equality alone does not distinguish bool from int.
        assert {key: type(value) for key, value in body["data"].items()} == (
            _FIELD_TYPES
        )

    @pytest.mark.parametrize("version", ["3.1", "4.0"])
    async def test_no_op_proposal_returns_zero_counts_without_a_scan(
        self,
        version: str,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        fixed_eval_date: None,
    ) -> None:
        """default-cvss-version-operations.md, No-op Proposal: every count,
        including `cves_evaluated`, is `0` although CVEs with projectable
        effects exist, and no CVE is read."""
        await system_setting_factory(key="default_cvss_version", value=version)
        await cve_with(
            Assessment("5.0", provider="NVD", version="3.1"),
            Assessment("8.0", provider="NVD", version="4.0"),
            severity=None,
        )
        await _regressing_ticket(cve_with, ticket_factory, tree, confidential=False)

        with StatementRecorder(db_session) as recorder:
            response = await admin_client.get(
                _PATH, params={"proposed_version": version}
            )

        assert response.status_code == 200
        assert response.json() == _zeroed(version, version, no_op=True)
        assert [s for s in recorder.statements if _CVE_TABLE.search(s)] == []

    async def test_empty_population_is_a_complete_evaluation(
        self,
        admin_client: AsyncClient,
        setting_3_1: SystemSetting,
        fixed_eval_date: None,
    ) -> None:
        response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 200
        assert response.json() == _zeroed("3.1", "4.0", no_op=False)

    async def test_undeclared_query_parameters_are_ignored(
        self,
        admin_client: AsyncClient,
        population: None,
        fixed_eval_date: None,
    ) -> None:
        """api-spec.md, Undeclared Query Parameters: pagination and sorting
        names are not declared by this endpoint."""
        response = await admin_client.get(
            _PATH,
            params={
                **_PROPOSE_4_0,
                "page": "2",
                "per_page": "1000",
                "sort_by": "foo",
                "sort_order": "asc",
            },
        )

        assert response.status_code == 200
        assert response.json() == _POPULATION_IMPACT
        assert "meta" not in response.json()


# ---------------------------------------------------------------------------
# D. Disclosure boundary
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDisclosure:
    async def test_confidential_ticket_contributes_only_aggregate_counts(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        setting_3_1: SystemSetting,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        fixed_eval_date: None,
    ) -> None:
        """default-cvss-version-operations.md, Get Default-CVSS Impact
        Preview: no consumer Ticket visibility filtering applies, and the
        count-only result exposes no CVE, Ticket, Product, or occurrence
        identifier. The confidential Ticket is the only population member,
        so every non-zero count is its own effect."""
        ticket = await _regressing_ticket(
            cve_with, ticket_factory, tree, confidential=True
        )
        cve = await db_session.get(CVE, ticket.cve_id)
        assert cve is not None
        identifiers = [
            cve.cve_id,
            str(cve.id),
            str(ticket.id),
            f"SNTL-{ticket.sequence_id}",
            *await _tree_identifiers(db_session, ticket.id),
        ]

        response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "observed_default_cvss_version": "3.1",
                "proposed_default_cvss_version": "4.0",
                "no_op": False,
                "cves_evaluated": 1,
                "cve_severity_changes": 1,
                "product_eligibility_changes": 2,
                "product_eligibility_override_skips": 1,
                "resolved_ticket_regressions": 1,
            }
        }
        # 4 Ticket/CVE identifiers and 5 per occurrence (3 occurrences).
        assert len(identifiers) == 19
        for identifier in identifiers:
            assert identifier not in response.text


# ---------------------------------------------------------------------------
# E. Timeout
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTimeout:
    async def test_expired_deadline_returns_503_without_partial_result(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        population: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """default-cvss-version-operations.md, Timeout and Partial Results
        and Get Default-CVSS Impact Preview. The controlled monotonic clock
        passes the deadline when the invocation captures its evaluation
        date, after the setting read and before the population scan; the
        expiry is client-side, so no PostgreSQL statement is cancelled and
        the shared test transaction stays usable."""
        clock = {"now": 0.0}

        def _utc_now() -> datetime:
            clock["now"] = _PAST_DEADLINE
            return _EVAL_NOW

        monkeypatch.setattr(cvss_impact_preview, "_monotonic", lambda: clock["now"])
        monkeypatch.setattr(cvss_impact_preview, "_utc_now", _utc_now)

        response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert clock["now"] == _PAST_DEADLINE
        assert response.status_code == 503
        assert response.json() == {
            "code": "CVSS_PREVIEW_TIMEOUT",
            "detail": _PREVIEW_TIMEOUT_DETAIL,
        }
        assert "data" not in response.json()
        assert await db_session.scalar(select(func.count()).select_from(CVE)) == 3


# ---------------------------------------------------------------------------
# F. Read-only
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestReadOnly:
    async def test_preview_changes_no_persisted_state(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        population: None,
        fixed_eval_date: None,
    ) -> None:
        """default-cvss-version-operations.md, Preview Service: no severity,
        eligibility, override, status, setting, or audit write, although the
        population has a projected effect of every kind."""
        before = await _derived_state(db_session)

        response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.json() == _POPULATION_IMPACT
        assert await _derived_state(db_session) == before

    async def test_repeated_previews_return_the_same_result(
        self,
        admin_client: AsyncClient,
        population: None,
        fixed_eval_date: None,
    ) -> None:
        """Idempotency: the endpoint is read-only and repeatable."""
        first = await admin_client.get(_PATH, params=_PROPOSE_4_0)
        second = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert first.json() == _POPULATION_IMPACT
        assert second.json() == _POPULATION_IMPACT


# ---------------------------------------------------------------------------
# G. The handler delegates to the service and runs no business query
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestHandlerDelegation:
    async def test_service_result_is_mapped_without_route_sql(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The handler passes the request session and the proposal to
        `get_default_cvss_version_impact()` and reads none of the preview's
        inputs itself; only authentication statements remain once the
        service is stubbed. Distinct stubbed counts prove each field is
        serialized from its own service field."""
        preview = AsyncMock(
            return_value=DefaultCVSSVersionImpact(
                observed_default_cvss_version="3.1",
                proposed_default_cvss_version="4.0",
                no_op=False,
                cves_evaluated=11,
                cve_severity_changes=7,
                product_eligibility_changes=5,
                product_eligibility_override_skips=3,
                resolved_ticket_regressions=2,
            )
        )
        monkeypatch.setattr(
            cvss_impact_preview, "get_default_cvss_version_impact", preview
        )

        with StatementRecorder(db_session) as recorder:
            response = await admin_client.get(_PATH, params=_PROPOSE_4_0)

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "observed_default_cvss_version": "3.1",
                "proposed_default_cvss_version": "4.0",
                "no_op": False,
                "cves_evaluated": 11,
                "cve_severity_changes": 7,
                "product_eligibility_changes": 5,
                "product_eligibility_override_skips": 3,
                "resolved_ticket_regressions": 2,
            }
        }
        preview.assert_awaited_once_with(db_session, "4.0")
        assert recorder.statements
        assert [s for s in recorder.statements if _PREVIEW_TABLES.search(s)] == []
