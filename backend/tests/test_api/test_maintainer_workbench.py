"""End-to-end tests for the maintainer workbench endpoints
(`backend/app/api/v1/maintainer.py`).

See docs/features/packages/maintainer.md (API Endpoints > Pending
Packages, In-Progress Packages, Completed Packages, Package Details for
Ticket; Workbench Row and Privacy Contract; Shared Global-List Query
Contract), docs/features/identity/rbac.md (Endpoint Permission Map >
Maintainer Operations: Authenticated), docs/api-spec.md (Global Responses,
Maintainer Ticket Accessibility Check, Query Parameter Length Limit,
Undeclared Query Parameters, Pagination, Sorting, Ticket Identifier
Resolution), and docs/features/tickets/ticket-deadlines.md (Evaluation
Instant, Actors and Phases). Classification, ordering, fan-out, deadline
parity, bounded-query, read-only, and race coverage lives in
tests/test_services/test_maintainer_workbench.py and
test_maintainer_workbench_races.py; these tests cover the HTTP contract.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import maintainer as route
from app.core.enums import (
    DeliveryStatus,
    MaintainerWorkSortField,
    PackageStatus,
    Severity,
    SortOrder,
    TicketStatus,
    WorkflowType,
)
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.user import User
from app.services import package_service
from tests.support.maintainer_workbench import (
    INELIGIBLE,
    INSTANT,
    RECENT,
    SUBMISSION_OFFSET_30,
    Prod,
    WorkbenchSeed,
)
from tests.support.ticket_api import (
    INVALID_LOCATORS,
    NOT_FOUND,
    UNAUTHENTICATED,
    validation_error,
)

_LISTS: Final = {
    "pending": "/api/v1/my/packages/pending",
    "in_progress": "/api/v1/my/packages/in-progress",
    "completed": "/api/v1/my/packages/completed",
}
_SERVICES: Final = {
    "pending": "list_maintainer_pending_work",
    "in_progress": "list_maintainer_in_progress_work",
    "completed": "list_maintainer_completed_work",
}
_TICKET_PATH: Final = "/api/v1/my/packages/tickets/{ticket_id}"
_ALL_LISTS = pytest.mark.parametrize("classification", list(_LISTS))
_ITEM_FIELDS: Final = {
    "package_name",
    "ticket_id",
    "cve_id",
    "severity",
    "workflow_type",
    "reference",
    "status",
    "delivery_status",
    "submission_due_at",
    "submission_milestone",
}
"""maintainer.md, Workbench Row and Privacy Contract."""

_LIST_PARAMETERS: Final = {"package", "sort_by", "sort_order", "page", "per_page"}
_TOO_LONG_MSG = "String should have at most 500 characters"


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _ticket_url(ticket: Ticket | str) -> str:
    locator = (
        ticket if isinstance(ticket, str) else format_ticket_id(ticket.sequence_id)
    )
    return _TICKET_PATH.format(ticket_id=locator)


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.fixture
def seed(db_session: AsyncSession) -> WorkbenchSeed:
    return WorkbenchSeed(db_session)


class Clock:
    """Controlled evaluation-instant source: each capture pops the next
    queued instant (or reuses `INSTANT`) and is recorded in `calls`."""

    def __init__(self) -> None:
        self.queue: list[datetime] = []
        self.calls: list[datetime] = []

    def now(self) -> datetime:
        instant = self.queue.pop(0) if self.queue else INSTANT
        self.calls.append(instant)
        return instant


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Replaces the endpoint's single evaluation-instant capture."""
    controlled = Clock()
    monkeypatch.setattr(route, "_utc_now", controlled.now)
    return controlled


def _spy(monkeypatch: pytest.MonkeyPatch, name: str) -> list[dict[str, Any]]:
    """Record the keyword arguments the handler passes to a service query."""
    original = getattr(package_service, name)
    received: list[dict[str, Any]] = []

    async def _wrapper(db: AsyncSession, **kwargs: Any) -> Any:
        received.append(kwargs)
        return await original(db, **kwargs)

    monkeypatch.setattr(package_service, name, _wrapper)
    return received


# ---------------------------------------------------------------------------
# Authentication (rbac.md: Authenticated, no capability)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthentication:
    @pytest.mark.parametrize(
        "path", [*_LISTS.values(), _TICKET_PATH.format(ticket_id="SNTL-1")]
    )
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_missing_or_invalid_credentials_return_401_before_any_query(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
        headers: dict[str, str],
    ) -> None:
        spies = {
            name: AsyncMock()
            for name in (*_SERVICES.values(), "get_maintainer_ticket_work")
        }
        for name, spy in spies.items():
            monkeypatch.setattr(package_service, name, spy)

        response = await client.get(path, headers=headers)

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        for spy in spies.values():
            spy.assert_not_awaited()

    async def test_role_less_user_reads_own_work_without_any_capability(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        clock: Clock,
    ) -> None:
        """Maintainership supplies visibility of the confidential Ticket and
        workbench ownership, but no capability is checked."""
        ticket = await seed.ticket(confidential=True)
        await seed.work(authenticated_user, ticket=ticket)

        listed = await authenticated_client.get(_LISTS["pending"])
        detail = await authenticated_client.get(_ticket_url(ticket))

        assert listed.status_code == 200
        assert listed.json()["meta"]["total"] == 1
        assert detail.status_code == 200
        assert len(detail.json()["data"]["pending"]) == 1


# ---------------------------------------------------------------------------
# Wire shape
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestWireShape:
    async def test_list_returns_the_paginated_envelope_with_lowercase_values(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        db_session: AsyncSession,
        clock: Clock,
    ) -> None:
        ticket = await seed.ticket(severity=Severity.HIGH, created_at=RECENT)
        await seed.work(
            authenticated_user,
            ticket=ticket,
            name="fictional-kernel",
            reference="SUSE:SLE-15-SP6:Update",
        )
        cve_identifier = await db_session.scalar(
            select(CVE.cve_id).where(CVE.id == ticket.cve_id)
        )

        response = await authenticated_client.get(_LISTS["pending"])

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "package_name": "fictional-kernel",
                    "ticket_id": format_ticket_id(ticket.sequence_id),
                    "cve_id": cve_identifier,
                    "severity": "high",
                    "workflow_type": "ibs",
                    "reference": "SUSE:SLE-15-SP6:Update",
                    "status": "affected",
                    "delivery_status": "pending",
                    "submission_due_at": _iso(RECENT + SUBMISSION_OFFSET_30),
                    "submission_milestone": "pending",
                }
            ],
            "meta": {"total": 1, "page": 1, "per_page": 20},
        }

    async def test_lists_and_ticket_work_partition_by_classification(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        clock: Clock,
    ) -> None:
        ticket = await seed.ticket(cve=False, severity=None)
        package = await seed.package(
            ticket, "fictional-pkg", maintainers=(authenticated_user,)
        )
        await seed.track(package, reference="a-pending")
        await seed.track(
            package,
            reference="b-progress",
            status=PackageStatus.FIXED,
            delivery=DeliveryStatus.IN_PROGRESS,
            workflow=WorkflowType.GIT,
        )
        await seed.track(
            package,
            reference="c-done",
            status=PackageStatus.WONT_FIX,
            delivery=DeliveryStatus.RELEASED,
            products=(INELIGIBLE,),
        )

        lists = {
            c: (await authenticated_client.get(path)).json()
            for c, path in _LISTS.items()
        }
        detail = (await authenticated_client.get(_ticket_url(ticket))).json()

        assert {
            c: [i["reference"] for i in body["data"]] for c, body in lists.items()
        } == {
            "pending": ["a-pending"],
            "in_progress": ["b-progress"],
            "completed": ["c-done"],
        }
        assert set(detail) == {"data"}
        assert set(detail["data"]) == {"pending", "in_progress", "completed"}
        assert {c: detail["data"][c] for c in _LISTS} == {
            c: body["data"] for c, body in lists.items()
        }
        progress = detail["data"]["in_progress"][0]
        assert (progress["workflow_type"], progress["status"]) == ("git", "fixed")
        assert (progress["severity"], progress["cve_id"]) == (None, None)
        assert progress["submission_milestone"] is None
        done = detail["data"]["completed"][0]
        assert (done["status"], done["delivery_status"]) == ("wont_fix", "released")
        # A Ticket without a CVE cannot observe the submission phase.
        assert done["submission_milestone"] is None
        for item in (progress, done, detail["data"]["pending"][0]):
            assert set(item) == _ITEM_FIELDS

    async def test_accessible_ticket_without_work_returns_three_empty_arrays(
        self,
        authenticated_client: AsyncClient,
        seed: WorkbenchSeed,
        clock: Clock,
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket(status=TicketStatus.NEW)
        await seed.work(other, ticket=ticket)

        response = await authenticated_client.get(_ticket_url(ticket))

        assert response.status_code == 200
        assert response.json() == {
            "data": {"pending": [], "in_progress": [], "completed": []}
        }

    @_ALL_LISTS
    async def test_empty_list_and_page_beyond_the_last(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        classification: str,
    ) -> None:
        """Uses the real clock: the seeded track's Product has no lifecycle
        data, so its classification does not depend on the date."""
        delivery = {
            "pending": DeliveryStatus.PENDING,
            "in_progress": DeliveryStatus.IN_PROGRESS,
            "completed": DeliveryStatus.RELEASED,
        }[classification]
        path = _LISTS[classification]
        empty = (await authenticated_client.get(path)).json()
        await seed.work(authenticated_user, delivery=delivery)

        beyond = await authenticated_client.get(path, params={"page": 2, "per_page": 1})

        assert empty == {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}
        assert beyond.json() == {
            "data": [],
            "meta": {"total": 1, "page": 2, "per_page": 1},
        }


# ---------------------------------------------------------------------------
# Query parameters (maintainer.md, Shared Global-List Query Contract)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestQueryParameters:
    @_ALL_LISTS
    async def test_defaults_and_supplied_values_reach_the_service(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        clock: Clock,
        classification: str,
    ) -> None:
        received = _spy(monkeypatch, _SERVICES[classification])

        await authenticated_client.get(_LISTS[classification])
        await authenticated_client.get(
            _LISTS[classification],
            params={
                "package": " Fictional-Kernel ",
                "sort_by": "submission_due_at",
                "sort_order": "asc",
                "page": 3,
                "per_page": 100,
            },
        )

        selected = [
            {
                key: call[key]
                for key in ("package", "sort_by", "sort_order", "page", "per_page")
            }
            for call in received
        ]
        assert selected == [
            {
                "package": None,
                "sort_by": MaintainerWorkSortField.SEVERITY,
                "sort_order": SortOrder.DESC,
                "page": 1,
                "per_page": 20,
            },
            {
                "package": " Fictional-Kernel ",
                "sort_by": MaintainerWorkSortField.SUBMISSION_DUE_AT,
                "sort_order": SortOrder.ASC,
                "page": 3,
                "per_page": 100,
            },
        ]

    @_ALL_LISTS
    @pytest.mark.parametrize(
        ("params", "loc", "error_type"),
        [
            pytest.param({"page": 0}, "page", "greater_than_equal", id="page-zero"),
            pytest.param({"page": "x"}, "page", "int_parsing", id="page-not-int"),
            pytest.param(
                {"per_page": 0}, "per_page", "greater_than_equal", id="per-page-zero"
            ),
            pytest.param(
                {"per_page": 101}, "per_page", "less_than_equal", id="per-page-101"
            ),
            pytest.param({"sort_by": "days"}, "sort_by", "enum", id="sort-by-days"),
            pytest.param(
                {"sort_by": "package_name"}, "sort_by", "enum", id="sort-by-other"
            ),
            pytest.param({"sort_order": "up"}, "sort_order", "enum", id="sort-order"),
        ],
    )
    async def test_invalid_pagination_and_sort_values_return_422(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        classification: str,
        params: dict[str, Any],
        loc: str,
        error_type: str,
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(package_service, _SERVICES[classification], spy)

        response = await authenticated_client.get(_LISTS[classification], params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        (error,) = body["errors"]
        assert (error["loc"], error["type"]) == (["query", loc], error_type)
        spy.assert_not_awaited()

    async def test_package_of_500_characters_is_accepted_and_501_is_a_422(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        clock: Clock,
    ) -> None:
        accepted = await authenticated_client.get(
            _LISTS["pending"], params={"package": "x" * 500}
        )
        spy = AsyncMock()
        monkeypatch.setattr(package_service, "list_maintainer_pending_work", spy)
        rejected = await authenticated_client.get(
            _LISTS["pending"], params={"package": "x" * 501}
        )

        assert accepted.status_code == 200
        assert accepted.json()["meta"]["total"] == 0
        assert rejected.status_code == 422
        assert rejected.json() == validation_error(
            {
                "loc": ["query", "package"],
                "msg": _TOO_LONG_MSG,
                "type": "string_too_long",
            }
        )
        spy.assert_not_awaited()

    async def test_undeclared_parameters_are_ignored(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        clock: Clock,
    ) -> None:
        """Temporal lookback and other names are not declared: they never
        filter, sort, or fail, whatever their length."""
        ticket = await seed.ticket()
        await seed.work(authenticated_user, ticket=ticket, name="fictional-a")
        await seed.work(authenticated_user, ticket=ticket, name="fictional-b")

        baseline = (await authenticated_client.get(_LISTS["pending"])).json()
        undeclared = await authenticated_client.get(
            _LISTS["pending"],
            params={
                "days": "7",
                "waiting": "true",
                "since": "2026-01-01",
                "released": "true",
                "status": "affected",
                "evaluation_date": "2000-01-01",
                "q": "y" * 600,
            },
        )
        detail = await authenticated_client.get(
            _ticket_url(ticket), params={"sort_by": "severity", "page": "x"}
        )

        assert undeclared.status_code == 200
        assert undeclared.json() == baseline
        assert baseline["meta"]["total"] == 2
        assert detail.status_code == 200
        assert [i["package_name"] for i in detail.json()["data"]["pending"]] == [
            "fictional-a",
            "fictional-b",
        ]


# ---------------------------------------------------------------------------
# One evaluation instant per response (ticket-deadlines.md, Evaluation
# Instant; Testing Requirement 7)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEvaluationInstant:
    async def test_each_request_captures_one_instant_and_its_utc_date(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Requests either side of UTC midnight: a Product whose General
        Support ends on the first day makes the track pending before
        midnight and non-actionable after it, for rows and total alike."""
        gs_end = date(2026, 9, 27)
        ticket = await seed.ticket()
        await seed.work(
            authenticated_user, ticket=ticket, products=(Prod(gs_end=gs_end),)
        )
        before = datetime(2026, 9, 27, 23, 59, 59, 999999, tzinfo=UTC)
        after = before + timedelta(microseconds=1)
        clock.queue.extend([before, after, before, after])
        listed = _spy(monkeypatch, "list_maintainer_pending_work")
        detailed = _spy(monkeypatch, "get_maintainer_ticket_work")

        first = (await authenticated_client.get(_LISTS["pending"])).json()
        second = (await authenticated_client.get(_LISTS["pending"])).json()
        third = (await authenticated_client.get(_ticket_url(ticket))).json()
        fourth = (await authenticated_client.get(_ticket_url(ticket))).json()

        assert clock.calls == [before, after, before, after]
        received = [
            (call["evaluation_date"], call["evaluation_instant"])
            for call in (*listed, *detailed)
        ]
        assert received == [
            (date(2026, 9, 27), before),
            (date(2026, 9, 28), after),
            (date(2026, 9, 27), before),
            (date(2026, 9, 28), after),
        ]
        assert (first["meta"]["total"], len(first["data"])) == (1, 1)
        assert second == {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}
        assert len(third["data"]["pending"]) == 1
        assert fourth["data"] == {"pending": [], "in_progress": [], "completed": []}


# ---------------------------------------------------------------------------
# Per-Ticket accessibility (api-spec.md, Maintainer Ticket Accessibility
# Check)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketAccessibility:
    async def test_every_not_found_cause_returns_the_identical_response(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        seed: WorkbenchSeed,
        clock: Clock,
    ) -> None:
        """Malformed, lowercase, padded, overflow, UUID, missing, and
        inaccessible locators: the inaccessible Ticket has work owned by
        another maintainer that is never projected."""
        other = await seed.user()
        visible = await seed.ticket()
        await seed.work(authenticated_user, ticket=visible)
        inaccessible = await seed.ticket(confidential=True)
        await seed.work(other, ticket=inaccessible)
        locators = [build(visible) for _, build in INVALID_LOCATORS]
        locators += [
            "not-a-ticket",
            f"%20{format_ticket_id(visible.sequence_id)}",
            format_ticket_id(inaccessible.sequence_id),
        ]

        responses = [await authenticated_client.get(_ticket_url(x)) for x in locators]

        for locator, response in zip(locators, responses, strict=True):
            assert response.status_code == 404, locator
            assert response.content == NOT_FOUND, locator
        assert len({response.content for response in responses}) == 1

    async def test_scope_all_makes_the_ticket_accessible_but_returns_no_work(
        self,
        admin_client: AsyncClient,
        seed: WorkbenchSeed,
        clock: Clock,
    ) -> None:
        other = await seed.user()
        ticket = await seed.ticket(confidential=True)
        await seed.work(other, ticket=ticket)

        detail = await admin_client.get(_ticket_url(ticket))
        listed = await admin_client.get(_LISTS["pending"])

        assert detail.json() == {
            "data": {"pending": [], "in_progress": [], "completed": []}
        }
        assert listed.json()["meta"]["total"] == 0


# ---------------------------------------------------------------------------
# OpenAPI contract and privacy (maintainer.md, Workbench Row and Privacy
# Contract; ticket-deadlines.md, Actors and Phases)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self, path: str) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][path]["get"]
        return operation

    def _component(self, name: str) -> dict[str, Any]:
        component: dict[str, Any] = self._spec()["components"]["schemas"][name]
        return component

    def _ref(self, schema: dict[str, Any]) -> str:
        ref: str = schema["$ref"] if "$ref" in schema else schema["allOf"][0]["$ref"]
        return ref.rsplit("/", 1)[1]

    def _response_schema(self, path: str) -> str:
        content = self._operation(path)["responses"]["200"]["content"]
        return self._ref(content["application/json"]["schema"])

    def test_routes_are_exactly_the_four_maintainer_operations(self) -> None:
        routes = {
            (context.path, method)
            for context in fastapi_routing.iter_route_contexts(app.routes)
            if isinstance(context.original_route, APIRoute)
            and context.path is not None
            and context.path.startswith("/api/v1/my/")
            for method in (context.methods or set()) - {"HEAD", "OPTIONS"}
        }

        assert routes == {
            ("/api/v1/my/packages/pending", "GET"),
            ("/api/v1/my/packages/in-progress", "GET"),
            ("/api/v1/my/packages/completed", "GET"),
            ("/api/v1/my/packages/tickets/{ticket_id}", "GET"),
        }
        for path in (*_LISTS.values(), _TICKET_PATH):
            assert self._operation(path)["tags"] == ["Maintainer Operations"]

    @pytest.mark.parametrize("path", list(_LISTS.values()))
    def test_lists_declare_exactly_the_shared_query_parameters(self, path: str) -> None:
        operation = self._operation(path)
        parameters = {p["name"]: p for p in operation["parameters"]}
        sort_by = parameters["sort_by"]["schema"]
        sort_order = parameters["sort_order"]["schema"]

        assert set(parameters) == _LIST_PARAMETERS
        assert {p["in"] for p in parameters.values()} == {"query"}
        assert not any(p.get("required") for p in parameters.values())
        assert set(self._component(self._ref(sort_by))["enum"]) == {
            "severity",
            "package",
            "submission_due_at",
        }
        assert sort_by["default"] == "severity"
        assert set(self._component(self._ref(sort_order))["enum"]) == {"asc", "desc"}
        assert sort_order["default"] == "desc"
        assert parameters["page"]["schema"]["minimum"] == 1
        assert parameters["page"]["schema"]["default"] == 1
        assert parameters["per_page"]["schema"]["minimum"] == 1
        assert parameters["per_page"]["schema"]["maximum"] == 100
        assert parameters["per_page"]["schema"]["default"] == 20
        assert "404" not in operation["responses"]
        assert self._response_schema(path) == "MaintainerWorkListResponse"

    def test_ticket_work_declares_only_the_path_locator_and_its_404(self) -> None:
        operation = self._operation(_TICKET_PATH)

        assert [(p["name"], p["in"]) for p in operation["parameters"]] == [
            ("ticket_id", "path")
        ]
        assert "pattern" not in operation["parameters"][0]["schema"]
        assert "404" in operation["responses"]
        assert self._response_schema(_TICKET_PATH) == "MaintainerTicketWorkResponse"

    def test_response_envelopes(self) -> None:
        listed = self._component("MaintainerWorkListResponse")["properties"]
        ticket = self._component("MaintainerTicketWorkResponse")["properties"]
        work = self._component(self._ref(ticket["data"]))["properties"]

        assert set(listed) == {"data", "meta"}
        assert self._ref(listed["data"]["items"]) == "MaintainerWorkItem"
        assert self._ref(listed["meta"]) == "PaginationMeta"
        assert set(ticket) == {"data"}
        assert set(work) == {"pending", "in_progress", "completed"}
        for collection in work.values():
            assert self._ref(collection["items"]) == "MaintainerWorkItem"

    def test_item_exposes_exactly_the_ten_fields_and_no_private_data(self) -> None:
        item = self._component("MaintainerWorkItem")["properties"]
        texts = str(self._spec()["paths"]).lower()

        assert set(item) == _ITEM_FIELDS
        assert not any(
            value.get("format") == "uuid"
            for value in item.values()
            if "format" in value
        )
        for forbidden in (
            "maintainer_id",
            "user_id",
            "username",
            "email",
            "group",
            "maintainers",
            "maintainer_count",
            "smelt",
            "submission_chain",
            "effective_sr",
            "proving_rr",
            "analyzed_at",
            "first_sr_created_at",
            "completed_at",
            "waiting",
            "days",
            "since",
            "ticket_uuid",
        ):
            assert forbidden not in item, forbidden
        for path in (*_LISTS.values(), _TICKET_PATH):
            names = {p["name"] for p in self._operation(path)["parameters"]}
            assert not {"days", "waiting", "since", "released"} & names
        assert "/api/v1/my/packages" in texts

    def test_enumerations_are_lowercase(self) -> None:
        item = self._component("MaintainerWorkItem")["properties"]

        def values(field: str) -> set[str]:
            schema = item[field]
            variants = schema.get("anyOf", [schema])
            enums: set[str] = set()
            for variant in variants:
                if "$ref" in variant:
                    enums |= set(self._component(self._ref(variant))["enum"])
                elif "enum" in variant:
                    enums |= set(variant["enum"])
            return enums

        assert values("severity") == {s.value.lower() for s in Severity}
        assert values("workflow_type") == {w.value for w in WorkflowType}
        assert values("status") == {s.value.lower() for s in PackageStatus}
        assert values("delivery_status") == {d.value.lower() for d in DeliveryStatus}
        assert values("submission_milestone") == {
            "done",
            "pending",
            "overdue",
            "not_applicable",
        }

    def test_descriptions_name_the_maintainer_phase_and_the_pending_distinction(
        self,
    ) -> None:
        item = self._component("MaintainerWorkItem")["properties"]
        due = item["submission_due_at"]["description"]
        milestone = item["submission_milestone"]["description"]
        delivery = item["delivery_status"]["description"]

        assert "maintainer" in due
        assert "submission request" in due
        assert "maintainer submission milestone" in milestone
        assert "unrelated to `delivery_status = pending`" in milestone
        assert "submission milestone `pending`" in delivery
