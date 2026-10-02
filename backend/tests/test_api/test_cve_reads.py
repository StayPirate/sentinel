"""End-to-end tests for the CVE read endpoints (`backend/app/api/v1/cves.py`).

Covers `GET /api/v1/cves`, `GET /api/v1/cves/{cve_id}`, and
`GET /api/v1/cve-sources`. See docs/features/tickets/cve-tracking.md (List
CVEs; Get CVE; Security), docs/features/tickets/cve-service.md (CVE Read
and Accessibility Boundary; Service Read Contracts; Global CVE Source
Listing), docs/features/tickets/tickets.md (Shared Sub-Schemas:
`CVEDetail`), docs/api-spec.md (Request Conventions; Optional
Authentication on Public Endpoints; CVE Accessibility Check;
Anti-Enumeration Boundary; CVE Identifier Resolution), and
docs/features/platform/testing-strategy.md (CVE and Source Reads; Ticket
Accessibility).

Search, filter, sort, fan-out, projection-ordering, stalled-boundary, and
independent-session race coverage lives in
tests/test_services/test_cve_reads.py and
tests/test_services/test_cve_source_listing.py; these tests cover the HTTP
contract: envelopes and wire format, query parsing and validation,
optional authentication, anti-enumeration, and handler delegation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, event
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.enums import (
    CVESortField,
    CVESourceSortField,
    CveState,
    Role,
    Severity,
    SortOrder,
)
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.services import cve_service
from app.services.cve_projection import CVEDetailProjection
from app.services.cve_service import (
    CVEDetailResult,
    CVEListResult,
    CVESourceListResult,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

Factory = Callable[..., Awaitable[Any]]

_CVES: Final = "/api/v1/cves"
_SOURCES: Final = "/api/v1/cve-sources"
_DETAIL: Final = "/api/v1/cves/{cve_id}"
_LISTS: Final = (_CVES, _SOURCES)
_SERVICE_FUNCTION: Final = {_CVES: "list_cves", _SOURCES: "list_cve_sources"}

_NOT_FOUND: Final = {"code": "CVE_NOT_FOUND", "detail": "CVE not found."}
_UNAUTHENTICATED: Final = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_EMPTY_PAGE: Final = {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}

_LIST_ITEM_FIELDS: Final = {
    "cve_id",
    "title",
    "description",
    "severity",
    "cve_state",
    "published_date",
    "ticket",
    "created_at",
    "updated_at",
}
_CVE_DETAIL_FIELDS: Final = {
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
_SOURCE_ITEM_FIELDS: Final = {
    "cve_id",
    "source",
    "status",
    "fetched_at",
    "first_failed_at",
    "created_at",
    "updated_at",
}

CREATED_AT: Final = datetime(2099, 1, 10, 8, 0, tzinfo=UTC)
UPDATED_AT: Final = datetime(2099, 1, 11, 9, 30, tzinfo=UTC)
MAR_1: Final = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
ONE_US: Final = timedelta(microseconds=1)


def _detail_url(cve_id: str) -> str:
    return _DETAIL.format(cve_id=cve_id)


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


async def _cve_ids(client: AsyncClient, **params: Any) -> list[str]:
    """CVE-IDs of one complete `GET /cves` page in code-point order; the
    total must equal the page."""
    response = await client.get(
        _CVES,
        params={"per_page": 100, "sort_by": "cve_id", "sort_order": "asc", **params},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["meta"]["total"] == len(body["data"])
    return [item["cve_id"] for item in body["data"]]


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


def _spy_all(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    """Replace the three read services with spies that must stay unused."""
    spies = {
        name: AsyncMock()
        for name in ("list_cves", "get_cve_detail", "list_cve_sources")
    }
    for name, spy in spies.items():
        monkeypatch.setattr(cve_service, name, spy)
    return spies


# ---------------------------------------------------------------------------
# GET /cves: envelope, wire format, parsing, visibility
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCVEList:
    async def test_paginated_envelope_and_wire_format(
        self, client: AsyncClient, cve_factory: Factory, ticket_factory: Factory
    ) -> None:
        with_ticket: CVE = await cve_factory(
            cve_id="CVE-2099-50001",
            title="Fictional title",
            description=None,
            severity=Severity.HIGH.value,
            published_date=MAR_1,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )
        ticket: Ticket = await ticket_factory(cve_id=with_ticket.id)
        ticketless: CVE = await cve_factory(
            cve_id="CVE-2099-50002",
            description="Fictional description",
            severity=Severity.NONE.value,
            cve_state=CveState.REJECTED.value,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )

        response = await client.get(
            _CVES, params={"sort_by": "cve_id", "sort_order": "asc"}
        )

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data", "meta"}
        assert body["meta"] == {"total": 2, "page": 1, "per_page": 20}
        assert body["data"] == [
            {
                "cve_id": "CVE-2099-50001",
                "title": "Fictional title",
                "description": None,
                "severity": "high",
                "cve_state": "published",
                "published_date": "2099-03-01T12:00:00Z",
                "ticket": {"ticket_id": _sntl(ticket)},
                "created_at": "2099-01-10T08:00:00Z",
                "updated_at": "2099-01-11T09:30:00Z",
            },
            {
                "cve_id": "CVE-2099-50002",
                "title": None,
                "description": "Fictional description",
                "severity": "none",
                "cve_state": "rejected",
                "published_date": None,
                "ticket": None,
                "created_at": "2099-01-10T08:00:00Z",
                "updated_at": "2099-01-11T09:30:00Z",
            },
        ]
        for item in body["data"]:
            assert set(item) == _LIST_ITEM_FIELDS
        for secret in (with_ticket.id, ticketless.id, ticket.id):
            assert str(secret) not in response.text

    async def test_mixed_visibility_rows_and_total_per_caller(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        ticketless = await cve_factory(cve_id="CVE-2099-51001")
        public = await cve_factory(cve_id="CVE-2099-51002")
        await ticket_factory(cve_id=public.id)
        granted = await cve_factory(cve_id="CVE-2099-51003")
        granted_ticket = await ticket_factory(cve_id=granted.id, is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=granted_ticket.id, user_id=authenticated_user.id
        )
        hidden = await cve_factory(cve_id="CVE-2099-51004")
        await ticket_factory(cve_id=hidden.id, is_confidential=True)

        token = authenticated_client.cookies[SESSION_COOKIE_NAME]
        authenticated_client.cookies.delete(SESSION_COOKIE_NAME)
        anonymous = await _cve_ids(authenticated_client)
        authenticated_client.cookies.set(SESSION_COOKIE_NAME, token)
        restricted = await _cve_ids(authenticated_client)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        scope_all = await _cve_ids(authenticated_client)

        assert anonymous == ["CVE-2099-51001", "CVE-2099-51002"]
        assert restricted == ["CVE-2099-51001", "CVE-2099-51002", "CVE-2099-51003"]
        assert scope_all == [
            cve.cve_id for cve in (ticketless, public, granted, hidden)
        ]

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            pytest.param(["high", "low"], ["high", "low"], id="repeated"),
            pytest.param(["high", "bogus"], ["high"], id="invalid-ignored"),
            pytest.param(["unresolved"], ["unresolved"], id="unresolved"),
            pytest.param(["none"], ["none"], id="none-label"),
            pytest.param(["high,low"], [], id="comma-literal-only"),
            pytest.param(["HIGH", "Critical"], [], id="stored-case-only"),
            pytest.param(["high,low", "low"], ["low"], id="comma-literal-ignored"),
        ],
    )
    async def test_repeatable_severity_is_parsed_from_wire_values(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        severity: list[str],
        expected: list[str],
    ) -> None:
        names = {
            "high": Severity.HIGH.value,
            "low": Severity.LOW.value,
            "none": Severity.NONE.value,
            "critical": Severity.CRITICAL.value,
            "unresolved": None,
        }
        ids = {
            name: (await cve_factory(cve_id=f"CVE-2099-5200{i}", severity=value)).cve_id
            for i, (name, value) in enumerate(names.items())
        }

        assert await _cve_ids(client, severity=severity) == [
            ids[name] for name in expected
        ]

    @pytest.mark.parametrize("cve_state", ["bogus", "PUBLISHED", "Rejected", ""])
    async def test_undocumented_cve_state_returns_an_empty_page(
        self, client: AsyncClient, cve_factory: Factory, cve_state: str
    ) -> None:
        await cve_factory()
        await cve_factory(cve_state=CveState.REJECTED.value)

        response = await client.get(_CVES, params={"cve_state": cve_state})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_documented_cve_state_and_has_ticket_filter(
        self, client: AsyncClient, cve_factory: Factory, ticket_factory: Factory
    ) -> None:
        rejected = await cve_factory(
            cve_id="CVE-2099-53001", cve_state=CveState.REJECTED.value
        )
        with_ticket = await cve_factory(cve_id="CVE-2099-53002")
        await ticket_factory(cve_id=with_ticket.id)

        assert await _cve_ids(client, cve_state="rejected") == [rejected.cve_id]
        assert await _cve_ids(client, cve_state="published") == [with_ticket.cve_id]
        assert await _cve_ids(client, has_ticket="true") == [with_ticket.cve_id]
        assert await _cve_ids(client, has_ticket="false") == [rejected.cve_id]

    async def test_date_only_to_date_includes_the_whole_utc_day(
        self, client: AsyncClient, cve_factory: Factory
    ) -> None:
        end_of_day = datetime(2099, 3, 1, 23, 59, 59, 999999, tzinfo=UTC)
        await cve_factory(cve_id="CVE-2099-54001", published_date=end_of_day)
        await cve_factory(cve_id="CVE-2099-54002", published_date=end_of_day + ONE_US)
        await cve_factory(cve_id="CVE-2099-54003", published_date=None)

        assert await _cve_ids(client, to_date="2099-03-01") == ["CVE-2099-54001"]
        assert await _cve_ids(client, from_date="2099-03-01", to_date="2099-03-01") == [
            "CVE-2099-54001"
        ]
        assert await _cve_ids(client, from_date="2099-03-02") == ["CVE-2099-54002"]

    async def test_offset_datetime_is_converted_to_utc(
        self, client: AsyncClient, cve_factory: Factory
    ) -> None:
        await cve_factory(cve_id="CVE-2099-55001", published_date=MAR_1 - ONE_US)
        await cve_factory(cve_id="CVE-2099-55002", published_date=MAR_1)

        # 14:00+02:00 is MAR_1 (12:00Z); a naive value is read as UTC.
        assert await _cve_ids(client, from_date="2099-03-01T14:00:00+02:00") == [
            "CVE-2099-55002"
        ]
        assert await _cve_ids(client, to_date="2099-03-01T14:00:00+02:00") == [
            "CVE-2099-55001",
            "CVE-2099-55002",
        ]
        assert await _cve_ids(client, to_date="2099-03-01T11:59:59.999999") == [
            "CVE-2099-55001"
        ]


# ---------------------------------------------------------------------------
# GET /cves/{cve_id}: wire format, accessibility, anti-enumeration
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCVEDetail:
    async def test_returns_the_resource_detail_in_the_wire_format(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_external_identifier_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_epss_score_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
        cve_cwe_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(
            cve_id="CVE-2099-60001",
            title="Fictional detail title",
            description="Fictional detail description",
            published_date=MAR_1,
            modified_date=datetime(2099, 3, 5, 8, 30, tzinfo=UTC),
            cve_state=CveState.REJECTED.value,
            date_rejected=datetime(2099, 3, 6, tzinfo=UTC),
            severity=Severity.CRITICAL.value,
        )
        ticket: Ticket = await ticket_factory(cve_id=cve.id, priority_auto="P1")
        await cve_external_identifier_factory(
            cve_id=cve.id, source="PYSEC", identifier="PYSEC-2099-1"
        )
        await cve_external_identifier_factory(
            cve_id=cve.id,
            source="GHSA",
            identifier="GHSA-test-6001-xxxx",
            url="https://example.com/advisories/6001",
        )
        await cve_kev_entry_factory(
            cve_id=cve.id,
            date_added=date(2099, 3, 2),
            reference_url="https://example.com/kev",
        )
        await cve_epss_score_factory(
            cve_id=cve.id, score=0.5, percentile=0.75, assessed_at=date(2099, 3, 3)
        )
        await cve_ssvc_assessment_factory(
            cve_id=cve.id,
            exploitation="poc",
            automatable="yes",
            technical_impact="total",
            assessed_at=datetime(2099, 3, 4, 10, 0, tzinfo=UTC),
        )
        for cwe_id, source in (
            ("CWE-79", "NVD"),
            ("CWE-20", "NVD"),
            ("CWE-79", "MITRE"),
        ):
            await cve_cwe_factory(cve_id=cve.id, cwe_id=cwe_id, source=source)
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name="SUSE")

        response = await client.get(_detail_url(cve.cve_id))

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        assert body["data"] == {
            "cve_id": "CVE-2099-60001",
            "title": "Fictional detail title",
            "description": "Fictional detail description",
            "published_date": "2099-03-01T12:00:00Z",
            "modified_date": "2099-03-05T08:30:00Z",
            "cve_state": "rejected",
            "date_rejected": "2099-03-06T00:00:00Z",
            "severity": "critical",
            "external_identifiers": [
                {
                    "source": "ghsa",
                    "identifier": "GHSA-test-6001-xxxx",
                    "url": "https://example.com/advisories/6001",
                },
                {"source": "pysec", "identifier": "PYSEC-2099-1", "url": None},
            ],
            "kev": {
                "date_added": "2099-03-02",
                "reference_url": "https://example.com/kev",
            },
            "epss": {"score": 0.5, "percentile": 0.75, "assessed_at": "2099-03-03"},
            "ssvc": {
                "exploitation": "poc",
                "automatable": "yes",
                "technical_impact": "total",
                "version": "2.0.3",
                "assessed_at": "2099-03-04T10:00:00Z",
            },
            "cwes": [
                {"cwe_id": "CWE-20", "sources": ["NVD"]},
                {"cwe_id": "CWE-79", "sources": ["MITRE", "NVD"]},
            ],
            "ticket": {"ticket_id": _sntl(ticket)},
        }
        assert set(body["data"]) == _CVE_DETAIL_FIELDS | {"ticket"}
        assert set(body["data"]["ticket"]) == {"ticket_id"}
        for secret in (str(cve.id), str(ticket.id), "priority", "cvss", "SUSE"):
            assert secret not in response.text

    async def test_ticketless_cve_is_visible_anonymously_with_absent_evidence(
        self, client: AsyncClient, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-61001")

        response = await client.get(_detail_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "cve_id": "CVE-2099-61001",
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
                "ticket": None,
            }
        }

    async def test_every_not_found_cause_is_identical_for_both_callers(
        self,
        authenticated_client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        visible: CVE = await cve_factory(cve_id="CVE-2099-62001")
        confidential: CVE = await cve_factory(cve_id="CVE-2099-62002")
        await ticket_factory(cve_id=confidential.id, is_confidential=True)
        targets = [
            "not-a-cve",
            "cve-2099-62001",
            "CVE-2099-62001%20",
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            "CVE-2099-99999",
            confidential.cve_id,
        ]
        token = authenticated_client.cookies[SESSION_COOKIE_NAME]

        authenticated = [
            await authenticated_client.get(_detail_url(t)) for t in targets
        ]
        authenticated_client.cookies.delete(SESSION_COOKIE_NAME)
        anonymous = [await authenticated_client.get(_detail_url(t)) for t in targets]
        authenticated_client.cookies.set(SESSION_COOKIE_NAME, token)

        for target, response in zip(
            targets * 2, authenticated + anonymous, strict=True
        ):
            assert response.status_code == 404, target
            assert response.json() == _NOT_FOUND, target
            assert response.headers["content-type"] == "application/json"
        assert len({r.content for r in authenticated + anonymous}) == 1
        visible_response = await authenticated_client.get(_detail_url(visible.cve_id))
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
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-63001")
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        if path == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        else:
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
            )

        response = await authenticated_client.get(_detail_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json()["data"]["ticket"] == {"ticket_id": _sntl(ticket)}


# ---------------------------------------------------------------------------
# GET /cve-sources: envelope, wire format, parsing, identifier-only exception
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCVESourceList:
    async def test_anonymous_listing_includes_a_confidential_ticket_cve(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_source_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(
            cve_id="CVE-2099-70001",
            title="Fictional confidential title",
            description="Fictional confidential description",
        )
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        row = await cve_source_factory(
            cve_id=cve.id,
            source="nvd",
            status="failure",
            fetched_at=datetime(2099, 6, 28, 2, 4, 12, tzinfo=UTC),
            first_failed_at=datetime(2099, 6, 27, 2, 4, 12, tzinfo=UTC),
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )

        response = await client.get(_SOURCES)

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "cve_id": "CVE-2099-70001",
                    "source": "nvd",
                    "status": "failure",
                    "fetched_at": "2099-06-28T02:04:12Z",
                    "first_failed_at": "2099-06-27T02:04:12Z",
                    "created_at": "2099-01-10T08:00:00Z",
                    "updated_at": "2099-01-11T09:30:00Z",
                }
            ],
            "meta": {"total": 1, "page": 1, "per_page": 20},
        }
        (item,) = response.json()["data"]
        assert set(item) == _SOURCE_ITEM_FIELDS
        for secret in (row.id, cve.id, ticket.id):
            assert str(secret) not in response.text
        assert _sntl(ticket) not in response.text
        assert "Fictional confidential" not in response.text

    @pytest.mark.parametrize(
        "source",
        ["NVD", "1nvd", "nv-d", "", "_nvd", "nvd ", "a" * 101],
        ids=[
            "upper",
            "digit-first",
            "hyphen",
            "empty",
            "underscore-first",
            "space",
            "overlength",
        ],
    )
    async def test_malformed_or_overlength_source_returns_422(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch, source: str
    ) -> None:
        spies = _spy_all(monkeypatch)

        response = await client.get(_SOURCES, params={"source": source})

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", "source"]]
        spies["list_cve_sources"].assert_not_awaited()

    async def test_longest_well_formed_absent_source_returns_an_empty_page(
        self, client: AsyncClient, cve_source_factory: Factory
    ) -> None:
        await cve_source_factory(source="nvd")

        response = await client.get(_SOURCES, params={"source": "a" + "_9" * 49 + "z"})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    @pytest.mark.parametrize("status", ["bogus", "FAILURE", "pending", "not_attempted"])
    async def test_non_persisted_status_returns_an_empty_page(
        self, client: AsyncClient, cve_source_factory: Factory, status: str
    ) -> None:
        await cve_source_factory(status="failure")
        await cve_source_factory(status="success")

        response = await client.get(_SOURCES, params={"status": status})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_source_status_and_stalled_filters_reach_the_service(
        self, client: AsyncClient, cve_factory: Factory, cve_source_factory: Factory
    ) -> None:
        stalled_cve = await cve_factory(cve_id="CVE-2099-71001")
        healthy_cve = await cve_factory(cve_id="CVE-2099-71002")
        now = datetime.now(UTC)
        await cve_source_factory(
            cve_id=stalled_cve.id,
            source="nvd",
            status="failure",
            first_failed_at=now - timedelta(days=40),
        )
        await cve_source_factory(cve_id=healthy_cve.id, source="mitre")

        async def cve_ids(**params: str) -> list[str]:
            response = await client.get(_SOURCES, params=params)
            assert response.status_code == 200, response.text
            return [item["cve_id"] for item in response.json()["data"]]

        assert await cve_ids(stalled="true") == ["CVE-2099-71001"]
        assert await cve_ids(stalled="false") == ["CVE-2099-71002"]
        assert await cve_ids(source="mitre") == ["CVE-2099-71002"]
        assert await cve_ids(status="failure") == ["CVE-2099-71001"]


# ---------------------------------------------------------------------------
# Optional authentication and access changes during the request
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndAccessChanges:
    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "cookie"],
    )
    @pytest.mark.parametrize(
        "path", [_CVES, _SOURCES, _detail_url("CVE-2099-80001"), _detail_url("x")]
    )
    async def test_invalid_selected_credential_returns_401_before_any_read(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
        path: str,
    ) -> None:
        await cve_factory(cve_id="CVE-2099-80001")
        spies = _spy_all(monkeypatch)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(path, headers=credential.get("headers", {}))

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        for spy in spies.values():
            spy.assert_not_awaited()

    async def test_grant_revoked_before_the_protected_list_selection(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The caller was resolved before the revocation; the one protected
        selection alone decides rows and total."""
        cve = await cve_factory()
        ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        assert await _cve_ids(authenticated_client) == [cve.cve_id]
        original = cve_service.list_cves

        async def _revoke_then_list(
            db: AsyncSession, caller: TicketCaller, **kwargs: Any
        ) -> CVEListResult:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, caller, **kwargs)

        monkeypatch.setattr(cve_service, "list_cves", _revoke_then_list)

        response = await authenticated_client.get(_CVES)

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_grant_revoked_before_the_protected_detail_selection(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        url = _detail_url(cve.cve_id)
        assert (await authenticated_client.get(url)).status_code == 200
        original = cve_service.get_cve_detail

        async def _revoke_then_read(
            db: AsyncSession, caller: TicketCaller, cve_id: str
        ) -> CVEDetailResult:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, caller, cve_id)

        monkeypatch.setattr(cve_service, "get_cve_detail", _revoke_then_read)

        response = await authenticated_client.get(url)

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = cve_service.list_cves

        async def _remove_role_then_list(
            db: AsyncSession, caller: TicketCaller, **kwargs: Any
        ) -> CVEListResult:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, caller, **kwargs)

        monkeypatch.setattr(cve_service, "list_cves", _remove_role_then_list)
        in_flight = await _cve_ids(authenticated_client)
        monkeypatch.setattr(cve_service, "list_cves", original)
        next_list = await _cve_ids(authenticated_client)
        next_detail = await authenticated_client.get(_detail_url(cve.cve_id))

        assert in_flight == [cve.cve_id]
        assert next_list == []
        assert (next_detail.status_code, next_detail.json()) == (404, _NOT_FOUND)


# ---------------------------------------------------------------------------
# Request validation and undeclared parameters
# ---------------------------------------------------------------------------


_SHARED_INVALID: Final = [
    ({"sort_by": "title"}, "sort_by"),
    ({"sort_by": "Published_Date"}, "sort_by"),
    ({"sort_order": "up"}, "sort_order"),
    ({"page": 0}, "page"),
    ({"per_page": 0}, "per_page"),
    ({"per_page": 101}, "per_page"),
    ({"from_date": "2024-13-01"}, "from_date"),
    ({"from_date": "1700000000"}, "from_date"),
    ({"to_date": "yesterday"}, "to_date"),
]
_INVALID_CASES: Final = [
    *[(path, params, field) for path in _LISTS for params, field in _SHARED_INVALID],
    (_CVES, {"search": "x" * 501}, "search"),
    (_CVES, {"has_ticket": "maybe"}, "has_ticket"),
    (_CVES, {"severity": ["high", "x" * 501]}, "severity"),
    (_SOURCES, {"stalled": "maybe"}, "stalled"),
    (_SOURCES, {"status": "x" * 501}, "status"),
]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("path", "params", "field"), _INVALID_CASES)
    async def test_invalid_parameter_returns_422_before_the_service(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
        params: dict[str, Any],
        field: str,
    ) -> None:
        spies = _spy_all(monkeypatch)

        response = await client.get(path, params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", field]]
        spies[_SERVICE_FUNCTION[path]].assert_not_awaited()

    @pytest.mark.parametrize(
        ("path", "sort_fields"),
        [(_CVES, list(CVESortField)), (_SOURCES, list(CVESourceSortField))],
    )
    async def test_every_sort_field_and_order_is_accepted(
        self,
        client: AsyncClient,
        cve_source_factory: Factory,
        path: str,
        sort_fields: list[str],
    ) -> None:
        await cve_source_factory()

        for sort_by in sort_fields:
            for sort_order in ("asc", "desc"):
                response = await client.get(
                    path, params={"sort_by": sort_by, "sort_order": sort_order}
                )
                assert response.status_code == 200, (sort_by, sort_order)
                assert response.json()["meta"]["total"] == 1

    @pytest.mark.parametrize("path", _LISTS)
    @pytest.mark.parametrize(
        ("from_date", "to_date"),
        [
            ("2099-03-02", "2099-03-01"),
            ("2099-03-01T12:00:00.000001Z", "2099-03-01T12:00:00Z"),
            ("2099-03-01T13:00:00+02:00", "2099-03-01T10:59:59Z"),
        ],
    )
    async def test_inverted_range_returns_400(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
        from_date: str,
        to_date: str,
    ) -> None:
        spies = _spy_all(monkeypatch)

        response = await client.get(
            path, params={"from_date": from_date, "to_date": to_date}
        )

        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"
        spies[_SERVICE_FUNCTION[path]].assert_not_awaited()

    @pytest.mark.parametrize("path", _LISTS)
    async def test_equal_bounds_and_boundary_page_sizes_are_accepted(
        self, client: AsyncClient, path: str
    ) -> None:
        for params in (
            {"per_page": 1},
            {"per_page": 100},
            {"page": 2_147_483_647},
            {"from_date": "2099-03-01", "to_date": "2099-03-01"},
            {
                "from_date": "2099-03-01T12:00:00Z",
                "to_date": "2099-03-01T14:00:00+02:00",
            },
        ):
            response = await client.get(path, params=params)
            assert response.status_code == 200, (params, response.text)

    async def test_search_of_500_characters_is_accepted(
        self, client: AsyncClient, cve_factory: Factory
    ) -> None:
        await cve_factory()

        response = await client.get(_CVES, params={"search": "x" * 500})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    @pytest.mark.parametrize(
        ("path", "extra"),
        [
            (_CVES, {"cve_id": "CVE-2099-0", "status": "failure"}),
            (_SOURCES, {"search": "nothing", "severity": "high"}),
            (
                _detail_url("CVE-2099-81001"),
                {"page": "0", "per_page": "x", "sort_by": "bogus"},
            ),
        ],
        ids=["cves", "cve-sources", "cve-detail"],
    )
    async def test_undeclared_query_parameters_are_ignored(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        cve_source_factory: Factory,
        path: str,
        extra: dict[str, str],
    ) -> None:
        cve = await cve_factory(cve_id="CVE-2099-81001")
        await cve_source_factory(cve_id=cve.id)

        plain = await client.get(path)
        with_params = await client.get(
            path,
            params={"bogus": "1", "ticket_id": "x", "q": "y" * 600, **extra},
        )

        assert plain.status_code == with_params.status_code == 200
        assert with_params.json() == plain.json()
        data = plain.json()["data"]
        if isinstance(data, list):
            assert [item["cve_id"] for item in data] == ["CVE-2099-81001"]
        else:
            assert data["cve_id"] == "CVE-2099-81001"


# ---------------------------------------------------------------------------
# Handlers delegate parsed input to the service and run no query themselves
# ---------------------------------------------------------------------------


def _utc(value: Any) -> datetime:
    assert isinstance(value, datetime)
    assert value.utcoffset() == timedelta(0)
    return value


@pytest.mark.e2e
class TestHandlerDelegation:
    async def test_cve_list_defaults_reach_the_service(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = AsyncMock(
            return_value=CVEListResult(items=(), total=0, page=1, per_page=20)
        )
        monkeypatch.setattr(cve_service, "list_cves", spy)

        with _StatementRecorder(db_session) as recorder:
            response = await client.get(_CVES)

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE
        assert recorder.statements == []
        spy.assert_awaited_once()
        assert spy.await_args is not None
        assert spy.await_args.args == (db_session, ANONYMOUS_CALLER)
        kwargs = spy.await_args.kwargs
        assert kwargs == {
            "search": None,
            "cve_state": None,
            "severity": None,
            "has_ticket": None,
            "from_date": None,
            "to_date": None,
            "page": 1,
            "per_page": 20,
            "sort_by": CVESortField.PUBLISHED_DATE,
            "sort_order": SortOrder.DESC,
        }
        assert type(kwargs["sort_by"]) is CVESortField
        assert type(kwargs["sort_order"]) is SortOrder

    async def test_cve_list_parsed_arguments_reach_the_service(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = AsyncMock(
            return_value=CVEListResult(items=(), total=7, page=2, per_page=5)
        )
        monkeypatch.setattr(cve_service, "list_cves", spy)

        with _StatementRecorder(db_session) as recorder:
            response = await client.get(
                _CVES,
                params={
                    "search": "  Fictional%  ",
                    "cve_state": "bogus",
                    "severity": ["high", "high,low", "unresolved"],
                    "has_ticket": "false",
                    "from_date": "2099-03-01T14:00:00+02:00",
                    "to_date": "2099-03-02",
                    "page": 2,
                    "per_page": 5,
                    "sort_by": "severity",
                    "sort_order": "asc",
                },
            )

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 7, "page": 2, "per_page": 5},
        }
        assert recorder.statements == []
        assert spy.await_args is not None
        kwargs = dict(spy.await_args.kwargs)
        assert _utc(kwargs.pop("from_date")) == MAR_1
        assert _utc(kwargs.pop("to_date")) == datetime(
            2099, 3, 2, 23, 59, 59, 999999, tzinfo=UTC
        )
        assert kwargs == {
            "search": "  Fictional%  ",
            "cve_state": "bogus",
            "severity": ["high", "high,low", "unresolved"],
            "has_ticket": False,
            "page": 2,
            "per_page": 5,
            "sort_by": CVESortField.SEVERITY,
            "sort_order": SortOrder.ASC,
        }
        assert type(kwargs["sort_by"]) is CVESortField

    @pytest.mark.parametrize("cve_id", ["CVE-2099-82001", "not-a-cve", "cve-2099-1"])
    async def test_cve_detail_passes_the_raw_path_value_to_the_service(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        cve_id: str,
    ) -> None:
        projection = CVEDetailProjection(
            cve_id=cve_id,
            title=None,
            description=None,
            published_date=None,
            modified_date=None,
            cve_state=CveState.PUBLISHED,
            date_rejected=None,
            severity=Severity.NONE,
            external_identifiers=(),
            kev=None,
            epss=None,
            ssvc=None,
            cwes=(),
        )
        spy = AsyncMock(
            return_value=CVEDetailResult(cve=projection, ticket_id="SNTL-7")
        )
        monkeypatch.setattr(cve_service, "get_cve_detail", spy)

        with _StatementRecorder(db_session) as recorder:
            response = await client.get(_detail_url(cve_id))

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["severity"], data["ticket"]) == ("none", {"ticket_id": "SNTL-7"})
        assert recorder.statements == []
        spy.assert_awaited_once_with(db_session, ANONYMOUS_CALLER, cve_id)

    async def test_cve_source_list_arguments_reach_the_service_without_a_caller(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = AsyncMock(
            return_value=CVESourceListResult(items=(), total=0, page=1, per_page=20)
        )
        monkeypatch.setattr(cve_service, "list_cve_sources", spy)

        with _StatementRecorder(db_session) as recorder:
            defaults = await client.get(_SOURCES)
            parsed = await client.get(
                _SOURCES,
                params={
                    "source": "retired_source",
                    "status": "bogus",
                    "stalled": "true",
                    "from_date": "2099-03-01",
                    "to_date": "2099-03-01T14:00:00+02:00",
                    "sort_by": "first_failed_at",
                    "sort_order": "asc",
                },
            )

        assert defaults.status_code == parsed.status_code == 200
        assert recorder.statements == []
        default_call, parsed_call = spy.await_args_list
        assert default_call.args == parsed_call.args == (db_session,)
        assert default_call.kwargs == {
            "source": None,
            "status": None,
            "stalled": None,
            "from_date": None,
            "to_date": None,
            "page": 1,
            "per_page": 20,
            "sort_by": CVESourceSortField.FETCHED_AT,
            "sort_order": SortOrder.DESC,
        }
        kwargs = dict(parsed_call.kwargs)
        assert _utc(kwargs.pop("from_date")) == datetime(2099, 3, 1, tzinfo=UTC)
        assert _utc(kwargs.pop("to_date")) == MAR_1
        assert kwargs == {
            "source": "retired_source",
            "status": "bogus",
            "stalled": True,
            "page": 1,
            "per_page": 20,
            "sort_by": CVESourceSortField.FIRST_FAILED_AT,
            "sort_order": SortOrder.ASC,
        }
        assert type(kwargs["sort_by"]) is CVESourceSortField


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


def _schemas() -> dict[str, Any]:
    schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
    return schemas


def _operation(path: str) -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][path]["get"]
    return operation


def _parameters(path: str) -> dict[str, dict[str, Any]]:
    return {p["name"]: p for p in _operation(path).get("parameters", [])}


def _branches(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """The schema itself plus its `anyOf`/`allOf` alternatives."""
    nested = [*schema.get("anyOf", []), *schema.get("allOf", [])]
    return [schema, *nested]


def _enum_values(schema: dict[str, Any]) -> set[str]:
    for branch in _branches(schema):
        if "$ref" in branch:
            return set(_schemas()[branch["$ref"].rsplit("/", 1)[1]]["enum"])
        if "enum" in branch:
            return set(branch["enum"])
    raise AssertionError(f"no enum in {schema}")


def _refs(schema: Any) -> set[str]:
    if isinstance(schema, dict):
        found = {schema["$ref"]} if "$ref" in schema else set()
        for value in schema.values():
            found |= _refs(value)
        return found
    if isinstance(schema, list):
        return set().union(*(_refs(item) for item in schema))
    return set()


@pytest.mark.unit
class TestOpenApiContract:
    @pytest.mark.parametrize("path", [_CVES, _DETAIL, _SOURCES])
    def test_operation_has_summary_description_and_tag(self, path: str) -> None:
        operation = _operation(path)

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["CVEs"]

    def test_cve_list_declares_exactly_the_specified_query_parameters(
        self,
    ) -> None:
        parameters = _parameters(_CVES)

        assert {n for n, p in parameters.items() if p["in"] == "query"} == {
            "search",
            "cve_state",
            "severity",
            "has_ticket",
            "from_date",
            "to_date",
            "page",
            "per_page",
            "sort_by",
            "sort_order",
        }
        assert all(p["in"] == "query" for p in parameters.values())
        assert parameters["severity"]["schema"]["type"] == "array"
        assert _enum_values(parameters["sort_by"]["schema"]) == {
            "cve_id",
            "published_date",
            "severity",
            "created_at",
        }
        assert parameters["sort_by"]["schema"].get("default") == "published_date"
        assert _enum_values(parameters["sort_order"]["schema"]) == {"asc", "desc"}

    def test_cve_source_list_declares_exactly_the_specified_query_parameters(
        self,
    ) -> None:
        parameters = _parameters(_SOURCES)

        assert {n for n, p in parameters.items() if p["in"] == "query"} == {
            "source",
            "status",
            "stalled",
            "from_date",
            "to_date",
            "page",
            "per_page",
            "sort_by",
            "sort_order",
        }
        assert all(p["in"] == "query" for p in parameters.values())
        (source,) = [
            branch
            for branch in _branches(parameters["source"]["schema"])
            if branch.get("type") == "string"
        ]
        assert source["pattern"] == "^[a-z][a-z0-9_]*$"
        assert source["maxLength"] == 100
        assert _enum_values(parameters["sort_by"]["schema"]) == {
            "fetched_at",
            "first_failed_at",
            "source",
            "status",
        }
        assert parameters["sort_by"]["schema"].get("default") == "fetched_at"

    def test_cve_detail_declares_only_the_path_parameter_and_a_404(self) -> None:
        operation = _operation(_DETAIL)
        (parameter,) = operation["parameters"]

        assert (parameter["name"], parameter["in"]) == ("cve_id", "path")
        assert "pattern" not in parameter["schema"]
        assert operation["responses"]["404"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/ErrorResponse")
        assert operation["responses"]["200"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/CVEResourceDetailResponse")

    def test_response_schemas_expose_exactly_the_specified_fields(self) -> None:
        schemas = _schemas()

        assert set(schemas["CVEListResponse"]["properties"]) == {"data", "meta"}
        assert set(schemas["CVESourceListResponse"]["properties"]) == {"data", "meta"}
        assert set(schemas["CVEResourceDetailResponse"]["properties"]) == {"data"}
        assert set(schemas["CVEListItem"]["properties"]) == _LIST_ITEM_FIELDS
        assert set(schemas["CVEDetail"]["properties"]) == _CVE_DETAIL_FIELDS
        assert set(schemas["CVEResourceDetail"]["properties"]) == set(
            schemas["CVEDetail"]["properties"]
        ) | {"ticket"}
        assert set(schemas["CVESourceListItem"]["properties"]) == _SOURCE_ITEM_FIELDS
        assert set(schemas["CVEAssociatedTicket"]["properties"]) == {"ticket_id"}
        for name in ("CVEListItem", "CVEResourceDetail", "CVESourceListItem"):
            properties = set(schemas[name]["properties"])
            assert not {"id", "priority", "cvss", "assessments"} & properties, name

    def test_ticket_detail_cve_still_references_cve_detail(self) -> None:
        schemas = _schemas()

        assert "#/components/schemas/CVEDetail" in _refs(
            schemas["TicketDetail"]["properties"]["cve"]
        )
        for name in ("CVEListItem", "CVEResourceDetail"):
            assert "#/components/schemas/CVEAssociatedTicket" in _refs(
                schemas[name]["properties"]["ticket"]
            ), name
