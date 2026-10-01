"""End-to-end tests for the cross-Ticket package search endpoint
(`GET /api/v1/packages`, `backend/app/api/v1/ticket_packages.py`).

See docs/features/packages/package-model.md (API Endpoints; Search
Packages Across Tickets, including Query Parameters and the
`PackageListItem`, `TicketPackageRef`, and `TrackSummary` schemas;
Security), docs/api-spec.md (Optional Authentication on Public Endpoints,
Authorization Chain Evaluation Order flow 1, Query Parameter Length Limit,
Undeclared Query Parameters, Pagination, Enum Filter Validation, Sort
Parameter Validation, Deterministic Pagination Ordering, Response Format,
Global Responses), docs/features/tickets/tickets.md (Response Schemas:
enum serialization and nullable enums), and
docs/features/platform/testing-strategy.md (Ticket Accessibility:
canonical predicate, list and count reads, Ticket identifier and
read-contract coverage, controlled clock; Parallel Execution).

These tests cover the HTTP contract: the wire shape, optional
authentication, visibility after a real exclusion request, query
validation, filters and sorting at the wire, pagination, the global query
length limit, undeclared parameters, OpenAPI, and the one handler-captured
UTC evaluation date. Search, actionability, aggregation, N+1, no-write,
and independent-session race coverage lives in
`tests/test_services/test_package_search.py` and
`tests/test_services/test_package_search_atomicity.py`.

Every non-committed test starts from an empty database (per-test
transaction rollback), so a search observes exactly the rows the test
creates.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import ticket_packages as route
from app.core.enums import (
    PackageSortField,
    PackageStatus,
    Role,
    Severity,
    SortOrder,
    TicketStatus,
)
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from tests.support.ticket_api import (
    UNAUTHENTICATED,
    Clock,
    CommittedApp,
    committed_app_client,
    locator,
    validation_error,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/packages"
_NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
_BASE = datetime(2026, 5, 15, 10, 30, tzinfo=UTC)

_ITEM_FIELDS = {
    "id",
    "package_name",
    "ticket",
    "track_summary",
    "created_at",
    "updated_at",
}
"""package-model.md, Response Schema: `PackageListItem`."""

_TICKET_REF_FIELDS = {"ticket_id", "status", "severity"}
"""package-model.md, `TicketPackageRef`."""

_SUMMARY_FIELDS = {"total", "affected", "fixed", "not_affected", "wont_fix", "analysis"}
"""package-model.md, `TrackSummary`."""

_QUERY_PARAMETERS = {
    "search",
    "name",
    "ticket_status",
    "sort_by",
    "sort_order",
    "page",
    "per_page",
}
"""package-model.md, Search Packages Across Tickets, Query Parameters."""

_TOO_LONG_MSG = "String should have at most 500 characters"


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _summary(**counts: int) -> dict[str, int]:
    """A `TrackSummary` with zero for every count not given."""
    result = dict.fromkeys(_SUMMARY_FIELDS, 0)
    result.update(counts)
    return result


async def _search(client: AsyncClient, **params: Any) -> dict[str, Any]:
    response = await client.get(_PATH, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def _names(client: AsyncClient, **params: Any) -> list[str]:
    """The package names of one complete page (and a coherent total)."""
    body = await _search(client, per_page=100, **params)
    assert body["meta"]["total"] == len(body["data"])
    return [item["package_name"] for item in body["data"]]


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Replaces the endpoint's single evaluation-instant capture."""
    clock = Clock(_NOW)
    monkeypatch.setattr(route, "_utc_now", clock.now)
    return clock


@dataclass(frozen=True, slots=True)
class Trees:
    """Builds actionable package trees through the raw model factories."""

    package_factory: Factory
    track_factory: Factory
    occurrence_factory: Factory
    product_factory: Factory

    async def package(
        self,
        ticket: Ticket,
        name: str,
        statuses: Sequence[PackageStatus] = (PackageStatus.ANALYSIS,),
        **columns: Any,
    ) -> TicketPackage:
        """A package with one track per status, each with one Product
        occurrence whose catalog Product has no lifecycle dates (`NULL`
        phase, actionable on every date); `columns` override package
        columns such as `created_at`."""
        package: TicketPackage = await self.package_factory(
            ticket_id=ticket.id, package_name=name, **columns
        )
        for status in statuses:
            await self.track(package, status)
        return package

    async def track(
        self,
        package: TicketPackage,
        status: PackageStatus = PackageStatus.ANALYSIS,
        *,
        gs_end: date | None = None,
    ) -> TicketPackageTrack:
        """A track with one Product occurrence; `gs_end` is the catalog
        Product's only lifecycle date."""
        track: TicketPackageTrack = await self.track_factory(
            ticket_package_id=package.id, status=status.value
        )
        product = await self.product_factory(general_support_end_date=gs_end)
        await self.occurrence_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        return track


@pytest.fixture
def trees(
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ticket_package_product_factory: Factory,
    product_factory: Factory,
) -> Trees:
    return Trees(
        ticket_package_factory,
        ticket_package_track_factory,
        ticket_package_product_factory,
        product_factory,
    )


# ---------------------------------------------------------------------------
# Envelope and wire shape
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestWireShape:
    async def test_returns_the_paginated_envelope_in_the_wire_format(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        """The `PackageListItem` example of package-model.md: five
        actionable tracks (two affected, one fixed, one not affected, one
        in analysis) on an `analysis` Ticket of `high` severity."""
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, severity_manual=Severity.HIGH.value
        )
        updated_at = _BASE + timedelta(hours=21, minutes=30)
        package = await trees.package(
            ticket,
            "example-lib",
            (
                PackageStatus.AFFECTED,
                PackageStatus.AFFECTED,
                PackageStatus.FIXED,
                PackageStatus.NOT_AFFECTED,
                PackageStatus.ANALYSIS,
            ),
            created_at=_BASE,
            updated_at=updated_at,
        )

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        body = response.json()
        assert set(body) == {"data", "meta"}
        assert body["meta"] == {"total": 1, "page": 1, "per_page": 20}
        (item,) = body["data"]
        assert set(item) == _ITEM_FIELDS
        assert set(item["ticket"]) == _TICKET_REF_FIELDS
        assert set(item["track_summary"]) == _SUMMARY_FIELDS
        assert item == {
            "id": str(package.id),
            "package_name": "example-lib",
            "ticket": {
                "ticket_id": format_ticket_id(ticket.sequence_id),
                "status": "analysis",
                "severity": "high",
            },
            "track_summary": {
                "total": 5,
                "affected": 2,
                "fixed": 1,
                "not_affected": 1,
                "wont_fix": 0,
                "analysis": 1,
            },
            "created_at": "2026-05-15T10:30:00Z",
            "updated_at": _iso(updated_at),
        }
        assert item["ticket"]["ticket_id"].startswith("SNTL-")
        assert fixed_clock.calls == 1

    async def test_wont_fix_tracks_are_counted(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await trees.package(
            ticket, "example-tool", (PackageStatus.WONT_FIX, PackageStatus.WONT_FIX)
        )

        (item,) = (await _search(client))["data"]

        assert item["track_summary"] == _summary(total=2, wont_fix=2)

    @pytest.mark.parametrize(
        ("columns", "expected"),
        [
            pytest.param({"severity_manual": Severity.NONE.value}, "none", id="none"),
            pytest.param({}, None, id="unresolved-null"),
            pytest.param({"severity_manual": Severity.LOW.value}, "low", id="low"),
            pytest.param({"cve": Severity.CRITICAL.value}, "critical", id="cve"),
        ],
    )
    async def test_severity_is_lowercase_and_none_is_distinct_from_null(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        trees: Trees,
        columns: dict[str, Any],
        expected: str | None,
    ) -> None:
        if "cve" in columns:
            cve = await cve_factory(severity=columns.pop("cve"))
            columns = {"cve_id": cve.id}
        ticket: Ticket = await ticket_factory(**columns)
        await trees.package(ticket, "example-lib")

        response = await client.get(_PATH)

        (item,) = response.json()["data"]
        # Key access: an unresolved severity is a present JSON `null`.
        assert item["ticket"]["severity"] == expected

    @pytest.mark.parametrize("status", list(TicketStatus), ids=str)
    async def test_ticket_status_is_the_lowercase_wire_value(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
        status: TicketStatus,
    ) -> None:
        ticket: Ticket = await ticket_factory(status=status.value)
        await trees.package(ticket, "example-lib")

        body = await _search(client, ticket_status=status.value.lower())

        assert [item["ticket"]["status"] for item in body["data"]] == [
            status.value.lower()
        ]

    async def test_no_package_returns_an_empty_page(
        self, client: AsyncClient, fixed_clock: Clock
    ) -> None:
        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_each_ticket_occurrence_is_a_separate_item(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        """One item per `(package_name, Ticket)` pair."""
        first: Ticket = await ticket_factory()
        second: Ticket = await ticket_factory()
        for ticket in (first, second):
            await trees.package(ticket, "example-lib")

        body = await _search(client, name="example-lib")

        assert body["meta"]["total"] == 2
        assert {item["ticket"]["ticket_id"] for item in body["data"]} == {
            locator(first),
            locator(second),
        }


# ---------------------------------------------------------------------------
# Optional authentication and visibility
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestOptionalAuthentication:
    async def test_anonymous_and_authenticated_callers_see_their_visible_set(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        fixed_clock: Clock,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_access_grant_factory: Factory,
        trees: Trees,
    ) -> None:
        public: Ticket = await ticket_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        await trees.package(public, "example-public")
        await trees.package(granted, "example-granted")
        await trees.package(hidden, "example-hidden")
        await ticket_access_grant_factory(
            ticket_id=granted.id, user_id=authenticated_user.id
        )

        # `authenticated_client` is the shared client with a session cookie;
        # drop it for one anonymous request.
        token = authenticated_client.cookies[SESSION_COOKIE_NAME]
        authenticated_client.cookies.delete(SESSION_COOKIE_NAME)
        anonymous = await _names(authenticated_client)
        authenticated_client.cookies.set(SESSION_COOKIE_NAME, token)
        role_less = await _names(authenticated_client)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        scope_all = await _names(authenticated_client)

        assert anonymous == ["example-public"]
        assert sorted(role_less) == ["example-granted", "example-public"]
        assert sorted(scope_all) == [
            "example-granted",
            "example-hidden",
            "example-public",
        ]

    @pytest.mark.parametrize(
        "credential",
        [
            pytest.param({"headers": {"Authorization": "Bearer invalid"}}, id="bearer"),
            pytest.param(
                {"cookies": {SESSION_COOKIE_NAME: "invalid-session"}}, id="cookie"
            ),
        ],
    )
    async def test_invalid_selected_credential_is_401_never_anonymous(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
    ) -> None:
        """A non-confidential package exists, so an anonymous fallback
        would have returned it; instead the global 401 is returned before
        the search runs."""
        await trees.package(await ticket_factory(), "example-public")
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "search_packages", spy)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(_PATH, headers=credential.get("headers"))

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()
        assert fixed_clock.calls == 0

    async def test_invalid_bearer_never_falls_back_to_a_valid_cookie(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        fixed_clock: Clock,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "search_packages", spy)

        response = await authenticated_client.get(
            _PATH, headers={"Authorization": "Bearer invalid"}
        )

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()


# ---------------------------------------------------------------------------
# Visibility after a real exclusion request (committed requests)
# ---------------------------------------------------------------------------


CommittedWorld = tuple[CommittedApp, AsyncClient, list[uuid.UUID]]


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[CommittedWorld]:
    """`committed_app_client()` that also deletes the committed package tree
    and maintainer associations of its Tickets and the listed catalog
    Products before the shared cleanup (the precedent of
    `tests/test_api/test_ticket_package_exclusion.py`)."""
    product_ids: list[uuid.UUID] = []
    async with committed_app_client(db_session_factory) as (world, client):
        try:
            yield world, client, product_ids
        finally:
            db = await world.session()
            packages = select(TicketPackage.id).where(
                TicketPackage.ticket_id.in_(world.ticket_ids)
            )
            tracks = select(TicketPackageTrack.id).where(
                TicketPackageTrack.ticket_package_id.in_(packages)
            )
            for statement in (
                delete(TicketPackageProduct).where(
                    TicketPackageProduct.ticket_package_track_id.in_(tracks)
                ),
                delete(TicketPackageTrack).where(
                    TicketPackageTrack.ticket_package_id.in_(packages)
                ),
                delete(TicketPackageMaintainer).where(
                    TicketPackageMaintainer.ticket_package_id.in_(packages)
                ),
                delete(TicketPackage).where(
                    TicketPackage.ticket_id.in_(world.ticket_ids)
                ),
                delete(Product).where(Product.id.in_(product_ids)),
            ):
                await db.execute(statement)
            await db.commit()


@pytest.mark.e2e
class TestVisibilityAfterExclusion:
    async def test_excluding_the_last_maintained_package_hides_the_whole_ticket(
        self, committed_app: CommittedWorld
    ) -> None:
        """testing-strategy.md, Ticket Accessibility (canonical predicate:
        included-package maintainer, package exclusion; list and count
        reads) and package-model.md, API Endpoints (self-loss affects only
        later requests): a `restricted_analyst` sees a confidential Ticket
        only through its maintained package A. The search returns A and
        the Ticket's other actionable package B; after the same caller
        excludes A through the real endpoint, a new search returns neither
        and `meta.total` excludes both."""
        world, committed_client, product_ids = committed_app
        analyst, headers = await world.va_headers(role=Role.RESTRICTED_ANALYST)
        confidential = await world.ticket(
            is_confidential=True, status=TicketStatus.ANALYSIS.value
        )
        public = await world.ticket(status=TicketStatus.ANALYSIS.value)
        suffix = uuid.uuid4().hex[:10]
        prefix = f"example-search-{suffix}"
        db = await world.session()
        product = Product(
            name=f"Example Product {suffix}",
            version="1",
            display_name=f"Example Product {suffix}",
            cpe=f"cpe:/o:example:search:{suffix}",
            catalog_last_seen_at=datetime.now(UTC),
        )
        maintained = TicketPackage(
            ticket_id=confidential.id, package_name=f"{prefix}-a"
        )
        other = TicketPackage(ticket_id=confidential.id, package_name=f"{prefix}-b")
        public_package = TicketPackage(ticket_id=public.id, package_name=f"{prefix}-c")
        packages = (maintained, other, public_package)
        db.add_all([product, *packages])
        await db.flush()
        product_ids.append(product.id)
        tracks = [
            TicketPackageTrack(
                ticket_package_id=package.id,
                workflow_type="ibs",
                reference="Example:Codestream:1:Update",
                status=PackageStatus.AFFECTED.value,
            )
            for package in packages
        ]
        db.add_all(tracks)
        await db.flush()
        db.add_all(
            [
                *(
                    TicketPackageProduct(
                        ticket_package_track_id=track.id, product_id=product.id
                    )
                    for track in tracks
                ),
                TicketPackageMaintainer(
                    ticket_package_id=maintained.id, user_id=analyst.id
                ),
            ]
        )
        await db.commit()

        async def search(**kwargs: Any) -> dict[str, Any]:
            response = await committed_client.get(
                _PATH,
                params={
                    "search": prefix,
                    "sort_by": "package_name",
                    "sort_order": "asc",
                },
                **kwargs,
            )
            assert response.status_code == 200, response.text
            body: dict[str, Any] = response.json()
            return body

        anonymous = await search()
        before = await search(headers=headers)
        excluded = await committed_client.post(
            f"/api/v1/tickets/{locator(confidential)}/packages/{maintained.id}/exclude",
            headers=headers,
        )
        after = await search(headers=headers)

        assert [i["package_name"] for i in anonymous["data"]] == [f"{prefix}-c"]
        assert anonymous["meta"]["total"] == 1
        assert [i["package_name"] for i in before["data"]] == [
            f"{prefix}-a",
            f"{prefix}-b",
            f"{prefix}-c",
        ]
        assert before["meta"]["total"] == 3
        assert {i["ticket"]["ticket_id"] for i in before["data"][:2]} == {
            locator(confidential)
        }
        assert excluded.status_code == 200, excluded.text
        assert excluded.json()["data"]["non_actionable_reason"] == "package_excluded"
        assert [i["package_name"] for i in after["data"]] == [f"{prefix}-c"]
        assert after["meta"]["total"] == 1


# ---------------------------------------------------------------------------
# search / name exclusivity and filters at the wire
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSearchAndNameExclusivity:
    @pytest.mark.parametrize(
        "search",
        [
            pytest.param("lib", id="plain"),
            pytest.param("  lib  ", id="outer-whitespace"),
        ],
    )
    async def test_non_empty_search_with_name_is_a_validation_error(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
        search: str,
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "search_packages", spy)

        response = await client.get(
            _PATH, params={"search": search, "name": "example-lib"}
        )

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert body["errors"]
        for error in body["errors"]:
            assert error["loc"][0] == "query"
            assert set(error) == {"loc", "msg", "type"}
        spy.assert_not_awaited()
        assert fixed_clock.calls == 0

    async def test_whitespace_only_search_is_absent_and_only_name_applies(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await trees.package(ticket, "example-lib")
        await trees.package(ticket, "example-lib-extra")

        assert await _names(client, search="   ", name="example-lib") == ["example-lib"]


@pytest.mark.e2e
class TestFilters:
    async def test_search_is_a_trimmed_case_insensitive_literal_substring(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for name in ("example-lib", "example%lib", "example_lib", "fictional-tool"):
            await trees.package(ticket, name)

        assert await _names(client, search="%") == ["example%lib"]
        assert await _names(client, search="_") == ["example_lib"]
        assert await _names(client, search="  EXAMPLE%LIB  ") == ["example%lib"]
        assert sorted(await _names(client, search="Example")) == [
            "example%lib",
            "example-lib",
            "example_lib",
        ]
        assert await _names(client, search="   ") == await _names(client)
        assert len(await _names(client)) == 4

    async def test_name_is_an_exact_match(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for name in ("example-lib", "example-lib-extra", "fictional-example-lib"):
            await trees.package(ticket, name)

        assert await _names(client, name="example-lib") == ["example-lib"]
        assert await _names(client, name="example") == []
        assert await _names(client, name="EXAMPLE-LIB") == []

    async def test_ticket_status_is_repeatable_with_or_semantics(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        for status in (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.RESOLVED):
            ticket: Ticket = await ticket_factory(status=status.value)
            await trees.package(ticket, f"example-{status.value.lower()}")

        assert sorted(await _names(client, ticket_status=["new", "analysis"])) == [
            "example-analysis",
            "example-new",
        ]
        assert await _names(client, ticket_status=["new", "bogus", "NEW"]) == [
            "example-new"
        ]
        assert len(await _names(client)) == 3

    @pytest.mark.parametrize(
        "values",
        [
            pytest.param(["bogus"], id="unknown"),
            pytest.param(["NEW"], id="uppercase"),
            pytest.param(["New"], id="pascal-case"),
            pytest.param(["new,analysis"], id="comma-separated"),
            pytest.param(["bogus", "ANALYSIS"], id="several-invalid"),
        ],
    )
    async def test_all_invalid_ticket_status_values_return_an_empty_page(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
        values: list[str],
    ) -> None:
        for status in (TicketStatus.NEW, TicketStatus.ANALYSIS):
            ticket: Ticket = await ticket_factory(status=status.value)
            await trees.package(ticket, f"example-{status.value.lower()}")

        response = await client.get(_PATH, params={"ticket_status": values})

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_filters_combine_with_and(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        new: Ticket = await ticket_factory(status=TicketStatus.NEW.value)
        resolved: Ticket = await ticket_factory(status=TicketStatus.RESOLVED.value)
        for ticket in (new, resolved):
            await trees.package(ticket, "example-lib")
            await trees.package(ticket, "fictional-tool")

        body = await _search(client, search="lib", ticket_status="resolved")

        assert [
            (item["package_name"], item["ticket"]["ticket_id"]) for item in body["data"]
        ] == [("example-lib", locator(resolved))]
        assert body["meta"]["total"] == 1


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSorting:
    @pytest.mark.parametrize(
        ("params", "expected"),
        [
            pytest.param(
                {}, ["example-a", "example-c", "example-B"], id="default-created-desc"
            ),
            pytest.param(
                {"sort_by": "created_at", "sort_order": "asc"},
                ["example-B", "example-c", "example-a"],
                id="created-asc",
            ),
            pytest.param(
                {"sort_by": "created_at", "sort_order": "desc"},
                ["example-a", "example-c", "example-B"],
                id="created-desc",
            ),
            pytest.param(
                {"sort_by": "package_name", "sort_order": "asc"},
                ["example-B", "example-a", "example-c"],
                id="name-asc",
            ),
            pytest.param(
                {"sort_by": "package_name", "sort_order": "desc"},
                ["example-c", "example-a", "example-B"],
                id="name-desc",
            ),
            pytest.param(
                {"sort_by": "package_name"},
                ["example-c", "example-a", "example-B"],
                id="name-default-desc",
            ),
        ],
    )
    async def test_sort_parameters_order_the_page(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
        params: dict[str, str],
        expected: list[str],
    ) -> None:
        """`package_name` uses Unicode code-point order (`B` < `a`);
        `created_at` is `TicketPackage.created_at`."""
        ticket: Ticket = await ticket_factory()
        await trees.package(ticket, "example-B", created_at=_BASE)
        await trees.package(ticket, "example-c", created_at=_BASE + timedelta(hours=1))
        await trees.package(ticket, "example-a", created_at=_BASE + timedelta(hours=2))

        assert await _names(client, **params) == expected

    async def test_equal_sort_keys_page_deterministically(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        """Deterministic Pagination Ordering: equal `created_at` values are
        paged without duplicates or gaps."""
        for index in range(4):
            ticket: Ticket = await ticket_factory()
            await trees.package(ticket, f"example-{index}", created_at=_BASE)

        for sort_order in SortOrder:
            pages = [
                (
                    await _search(
                        client,
                        sort_by="created_at",
                        sort_order=sort_order.value,
                        page=page,
                        per_page=1,
                    )
                )["data"]
                for page in (1, 2, 3, 4)
            ]
            ids = [item["id"] for page in pages for item in page]
            assert len(set(ids)) == 4, sort_order
            assert ids == [
                item["id"]
                for item in (
                    await _search(
                        client, sort_by="created_at", sort_order=sort_order.value
                    )
                )["data"]
            ]

    @pytest.mark.parametrize(
        ("params", "field"),
        [
            pytest.param({"sort_by": "ticket_id"}, "sort_by", id="sort-by-ticket-id"),
            pytest.param({"sort_by": "severity"}, "sort_by", id="sort-by-severity"),
            pytest.param({"sort_by": "updated_at"}, "sort_by", id="sort-by-updated-at"),
            pytest.param(
                {"sort_by": "Package_Name"}, "sort_by", id="sort-by-wrong-case"
            ),
            pytest.param({"sort_order": "up"}, "sort_order", id="sort-order-up"),
            pytest.param({"sort_order": "ASC"}, "sort_order", id="sort-order-upper"),
        ],
    )
    async def test_invalid_sort_parameters_return_422(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
        params: dict[str, str],
        field: str,
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "search_packages", spy)

        response = await client.get(_PATH, params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", field]]
        spy.assert_not_awaited()


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestPagination:
    @pytest.mark.parametrize("per_page", [1, 100], ids=["min", "max"])
    async def test_per_page_boundaries_are_accepted(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
        per_page: int,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await trees.package(ticket, "example-a")
        await trees.package(ticket, "example-b")

        body = await _search(client, per_page=per_page)

        assert body["meta"] == {"total": 2, "page": 1, "per_page": per_page}
        assert len(body["data"]) == min(per_page, 2)

    async def test_pages_partition_the_result(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for name in ("example-a", "example-b", "example-c"):
            await trees.package(ticket, name)

        pages = [
            await _search(
                client, sort_by="package_name", sort_order="asc", page=page, per_page=2
            )
            for page in (1, 2)
        ]

        assert [[i["package_name"] for i in p["data"]] for p in pages] == [
            ["example-a", "example-b"],
            ["example-c"],
        ]
        assert [p["meta"] for p in pages] == [
            {"total": 3, "page": 1, "per_page": 2},
            {"total": 3, "page": 2, "per_page": 2},
        ]

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for name in ("example-a", "example-b", "example-c"):
            await trees.package(ticket, name)

        response = await client.get(_PATH, params={"page": 3, "per_page": 2})

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 3, "page": 3, "per_page": 2},
        }

    @pytest.mark.parametrize(
        ("params", "field"),
        [
            pytest.param({"per_page": 101}, "per_page", id="per-page-101"),
            pytest.param({"per_page": 0}, "per_page", id="per-page-0"),
            pytest.param({"page": 0}, "page", id="page-0"),
            pytest.param({"page": -1}, "page", id="page-negative"),
            pytest.param({"page": "x"}, "page", id="page-not-integer"),
        ],
    )
    async def test_out_of_range_pagination_is_a_422_never_clamped(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
        params: dict[str, Any],
        field: str,
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "search_packages", spy)

        response = await client.get(_PATH, params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", field]]
        spy.assert_not_awaited()


# ---------------------------------------------------------------------------
# Query length limit and undeclared parameters
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestQueryLength:
    @pytest.mark.parametrize("field", ["search", "name"])
    async def test_a_500_character_value_is_accepted(
        self, client: AsyncClient, fixed_clock: Clock, field: str
    ) -> None:
        body = await _search(client, **{field: "x" * 500})

        assert body == {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}

    @pytest.mark.parametrize(
        ("params", "field"),
        [
            pytest.param({"search": "x" * 501}, "search", id="search"),
            pytest.param({"name": "x" * 501}, "name", id="name"),
            pytest.param(
                {"ticket_status": ["new", "x" * 501]},
                "ticket_status",
                id="ticket-status",
            ),
            pytest.param(
                {"search": "x" * 501, "name": "example-lib"},
                "search",
                id="search-before-exclusivity",
            ),
        ],
    )
    async def test_a_501_character_value_is_a_422(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
        params: dict[str, Any],
        field: str,
    ) -> None:
        """The global limit applies to each raw value before the
        `search`/`name` cross-field rule (package-model.md, Query
        Parameters)."""
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "search_packages", spy)

        response = await client.get(_PATH, params=params)

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["query", field], "msg": _TOO_LONG_MSG, "type": "string_too_long"}
        )
        spy.assert_not_awaited()


@pytest.mark.e2e
class TestUndeclaredParameters:
    async def test_undeclared_query_parameters_are_ignored(
        self,
        client: AsyncClient,
        fixed_clock: Clock,
        ticket_factory: Factory,
        trees: Trees,
    ) -> None:
        new: Ticket = await ticket_factory(status=TicketStatus.NEW.value)
        resolved: Ticket = await ticket_factory(status=TicketStatus.RESOLVED.value)
        await trees.package(new, "example-a", created_at=_BASE)
        await trees.package(resolved, "example-b", created_at=_BASE)

        baseline = await _search(client)
        with_undeclared = await _search(
            client,
            status="new",
            severity="bogus",
            foo="bar",
            q="y" * 600,
            evaluation_date="2000-01-01",
        )

        assert len(baseline["data"]) == 2
        assert with_undeclared == baseline


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured UTC date per request
# ---------------------------------------------------------------------------

_GS_END = date(2026, 9, 27)
"""The catalog Product's only lifecycle date: `general_support` through
this day and `eol` from the next UTC day (tests/support/lifecycle_matrix.py,
`gs_only_at_gs_end_general_support`, `gs_only_day_after_gs_end_eol`)."""

_PLUS_TWO = timezone(timedelta(hours=2))
_MINUS_FIVE = timezone(timedelta(hours=-5))


def _spy_evaluation_dates(monkeypatch: pytest.MonkeyPatch) -> list[date]:
    """Record the `evaluation_date` the handler passes to the service."""
    original = package_service.search_packages
    received: list[date] = []

    async def _spy(db: AsyncSession, **kwargs: Any) -> Any:
        received.append(kwargs["evaluation_date"])
        return await original(db, **kwargs)

    monkeypatch.setattr(package_service, "search_packages", _spy)
    return received


@pytest.mark.e2e
class TestEvaluationDate:
    @pytest.mark.parametrize(
        ("instant", "evaluation_date", "present"),
        [
            pytest.param(
                datetime(2026, 9, 27, 23, 59, 59, 999999, tzinfo=UTC),
                date(2026, 9, 27),
                True,
                id="utc-last-microsecond-of-gs-end",
            ),
            pytest.param(
                datetime(2026, 9, 28, 1, 30, tzinfo=_PLUS_TWO),
                date(2026, 9, 27),
                True,
                id="plus-two-offset-still-gs-end-in-utc",
            ),
            pytest.param(
                datetime(2026, 9, 28, 0, 0, tzinfo=UTC),
                date(2026, 9, 28),
                False,
                id="utc-midnight-first-eol-day",
            ),
            pytest.param(
                datetime(2026, 9, 27, 20, 0, tzinfo=_MINUS_FIVE),
                date(2026, 9, 28),
                False,
                id="minus-five-offset-already-eol-in-utc",
            ),
        ],
    )
    async def test_the_utc_date_of_the_captured_instant_decides_actionability(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        trees: Trees,
        monkeypatch: pytest.MonkeyPatch,
        instant: datetime,
        evaluation_date: date,
        present: bool,
    ) -> None:
        clock = Clock(instant)
        monkeypatch.setattr(route, "_utc_now", clock.now)
        received = _spy_evaluation_dates(monkeypatch)
        ticket: Ticket = await ticket_factory()
        package = await trees.package_factory(
            ticket_id=ticket.id, package_name="example-lib"
        )
        await trees.track(package, PackageStatus.AFFECTED, gs_end=_GS_END)

        body = await _search(client)

        assert clock.calls == 1
        assert received == [evaluation_date]
        if present:
            assert body["meta"]["total"] == 1
            (item,) = body["data"]
            assert item["id"] == str(package.id)
            assert item["track_summary"] == _summary(total=1, affected=1)
        else:
            assert body == {
                "data": [],
                "meta": {"total": 0, "page": 1, "per_page": 20},
            }

    async def test_one_date_drives_candidates_and_aggregates_across_midnight(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        trees: Trees,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two requests either side of UTC midnight, each capturing exactly
        one instant. `example-mixed` has one track that turns `eol` and one
        that is always actionable: its aggregate drops from two to one
        track while it stays listed. `example-eol` has only the track that
        turns `eol`: it is listed before midnight and omitted after."""
        before = datetime(2026, 9, 27, 23, 59, 59, 999999, tzinfo=UTC)
        after = before + timedelta(microseconds=1)
        clocks = [Clock(before), Clock(after)]
        received = _spy_evaluation_dates(monkeypatch)
        ticket: Ticket = await ticket_factory()
        mixed = await trees.package_factory(
            ticket_id=ticket.id, package_name="example-mixed"
        )
        await trees.track(mixed, PackageStatus.AFFECTED, gs_end=_GS_END)
        await trees.track(mixed, PackageStatus.FIXED)
        eol_only = await trees.package_factory(
            ticket_id=ticket.id, package_name="example-eol"
        )
        await trees.track(eol_only, PackageStatus.ANALYSIS, gs_end=_GS_END)

        bodies = []
        for clock in clocks:
            monkeypatch.setattr(route, "_utc_now", clock.now)
            bodies.append(
                await _search(client, sort_by="package_name", sort_order="asc")
            )

        assert [clock.calls for clock in clocks] == [1, 1]
        assert received == [date(2026, 9, 27), date(2026, 9, 28)]
        first, second = bodies
        assert first["meta"]["total"] == 2
        assert [
            (item["package_name"], item["track_summary"]) for item in first["data"]
        ] == [
            ("example-eol", _summary(total=1, analysis=1)),
            ("example-mixed", _summary(total=2, affected=1, fixed=1)),
        ]
        assert second["meta"]["total"] == 1
        assert [
            (item["package_name"], item["track_summary"]) for item in second["data"]
        ] == [("example-mixed", _summary(total=1, fixed=1))]


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_PATH]["get"]
        return operation

    def _ref_name(self, schema: dict[str, Any]) -> str:
        """The component name referenced directly or through `allOf`."""
        if "$ref" in schema:
            ref: str = schema["$ref"]
        else:
            (only,) = schema["allOf"]
            ref = only["$ref"]
        return ref.rsplit("/", 1)[1]

    def _component(self, schema: dict[str, Any]) -> dict[str, Any]:
        component: dict[str, Any] = self._spec()["components"]["schemas"][
            self._ref_name(schema)
        ]
        return component

    def test_declares_exactly_the_specified_query_parameters(self) -> None:
        parameters = self._operation()["parameters"]

        assert {p["name"] for p in parameters} == _QUERY_PARAMETERS
        assert {p["in"] for p in parameters} == {"query"}
        assert len(parameters) == len(_QUERY_PARAMETERS)
        assert not any(p.get("required") for p in parameters)

    def test_undeclared_names_are_absent(self) -> None:
        names = {p["name"] for p in self._operation()["parameters"]}

        assert not {"status", "foo", "evaluation_date", "caller", "q"} & names

    def test_ticket_status_is_a_repeatable_string_array(self) -> None:
        parameters = {p["name"]: p for p in self._operation()["parameters"]}
        schema = parameters["ticket_status"]["schema"]

        assert schema["type"] == "array"
        assert schema["items"]["type"] == "string"

    def test_sort_by_enumerates_exactly_the_package_sort_fields(self) -> None:
        parameters = {p["name"]: p for p in self._operation()["parameters"]}
        sort_by = parameters["sort_by"]["schema"]
        enum_schema = (
            self._component(sort_by)
            if "$ref" in sort_by or "allOf" in sort_by
            else sort_by
        )

        assert set(enum_schema["enum"]) == {field.value for field in PackageSortField}
        assert set(enum_schema["enum"]) == {"package_name", "created_at"}
        assert sort_by.get("default") == "created_at"

    def test_sort_order_and_pagination_defaults(self) -> None:
        parameters = {p["name"]: p for p in self._operation()["parameters"]}
        sort_order = parameters["sort_order"]["schema"]
        enum_schema = (
            self._component(sort_order)
            if "$ref" in sort_order or "allOf" in sort_order
            else sort_order
        )

        assert set(enum_schema["enum"]) == {"asc", "desc"}
        assert sort_order.get("default") == "desc"
        assert parameters["page"]["schema"]["default"] == 1
        assert parameters["page"]["schema"]["minimum"] == 1
        assert parameters["per_page"]["schema"]["default"] == 20
        assert parameters["per_page"]["schema"]["minimum"] == 1
        assert parameters["per_page"]["schema"]["maximum"] == 100

    def test_response_schemas_expose_only_the_documented_fields(self) -> None:
        operation = self._operation()
        response = operation["responses"]["200"]["content"]["application/json"]

        assert self._ref_name(response["schema"]) == "PackageListResponse"
        envelope = self._component(response["schema"])
        assert set(envelope["properties"]) == {"data", "meta"}
        assert self._ref_name(envelope["properties"]["meta"]) == "PaginationMeta"
        item_ref = envelope["properties"]["data"]["items"]
        assert self._ref_name(item_ref) == "PackageListItem"
        item = self._component(item_ref)
        assert set(item["properties"]) == _ITEM_FIELDS
        assert item["properties"]["id"]["format"] == "uuid"
        ticket_ref = item["properties"]["ticket"]
        assert self._ref_name(ticket_ref) == "TicketPackageRef"
        assert set(self._component(ticket_ref)["properties"]) == _TICKET_REF_FIELDS
        summary_ref = item["properties"]["track_summary"]
        assert self._ref_name(summary_ref) == "TrackSummary"
        assert set(self._component(summary_ref)["properties"]) == _SUMMARY_FIELDS

    def test_ticket_reference_exposes_no_ticket_uuid(self) -> None:
        """testing-strategy.md, Ticket identifier and read-contract
        coverage: an embedded Ticket reference exposes only
        `ticket_id: SNTL-{n}`."""
        ref = self._spec()["components"]["schemas"]["TicketPackageRef"]["properties"]

        assert not {"id", "uuid", "ticket_uuid", "identifier", "ticket_sequence_id"} & (
            set(ref)
        )
        assert ref["ticket_id"]["type"] == "string"
        assert "format" not in ref["ticket_id"]

    def test_ticket_reference_enumerates_lowercase_status_and_severity(self) -> None:
        ref = self._spec()["components"]["schemas"]["TicketPackageRef"]["properties"]
        severity_variants = ref["severity"]["anyOf"]
        (severity_ref,) = [v for v in severity_variants if v != {"type": "null"}]

        assert set(self._component(ref["status"])["enum"]) == {
            s.value.lower() for s in TicketStatus
        }
        assert {"type": "null"} in severity_variants
        assert set(self._component(severity_ref)["enum"]) == {
            s.value.lower() for s in Severity
        }
        assert {"severity", "status", "ticket_id"} <= set(
            self._spec()["components"]["schemas"]["TicketPackageRef"]["required"]
        )

    def test_operation_is_documented(self) -> None:
        operation = self._operation()

        assert operation["summary"]
        assert operation["description"]
        assert "422" in operation["responses"]
