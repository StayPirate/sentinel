"""End-to-end tests for the manual-zone exit endpoints
`POST /api/v1/tickets/{ticket_id}/reopen` (Reopen Ticket) and
`POST /api/v1/tickets/{ticket_id}/revert-duplicate` (Revert Duplicate
Status) in `backend/app/api/v1/tickets.py`.

See docs/features/tickets/tickets.md (Reopen Ticket, Revert Duplicate
Status, Ignored, Revert-Duplicate Operation, Response Schemas >
TicketDetail, Endpoint -> Schema Mapping), docs/features/tickets/
ticket-deadlines.md (Due Dates: Formula and Null Due Dates),
docs/api-spec.md (Authorization Chain Evaluation Order flow 3, Global
Responses, Ticket Accessibility Check, Anti-Enumeration Boundary,
Manual-Zone Mutability Guard exceptions), docs/features/identity/rbac.md
(Endpoint Permission Map: `triage_ticket`; Business Rule 12), and
docs/features/platform/testing-strategy.md (Tier Responsibility and
Proportionality; API Endpoints; Ticket Accessibility).

These tests cover only the HTTP boundary, parametrized over both exits:
authentication, capability before lookup, the identical 404 family, the
complete body of the one error mapping of each endpoint (one
representative request per case), the absent request body, the response
shape, OpenAPI, and the handler-owned steps (the one captured date shared
by the service and the final `TicketDetail` assembly, and the rollback of
the whole exit when that assembly fails). The service matrix (every source
status, VA/non-VA/inactive actor, sanitation, event sequence, guard order,
lock order, the eligibility formula, registration and discard of the
convergence effect, and the races) is proven once in
`tests/test_services/test_manual_zone_exits.py`,
`tests/test_services/test_manual_zone_exit_eligibility.py`, and
`tests/test_services/test_manual_zone_exit_atomicity.py`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import tickets as route
from app.core.enums import PackageStatus, Role, TicketStatus
from app.main import app
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service, ticket_mutations, ticket_service
from app.services.ticket_service import TicketDetailProjection
from tests.support.ticket_api import (
    FORBIDDEN,
    INTERNAL_ERROR,
    INVALID_LOCATORS,
    MAX_SEQUENCE,
    NOT_FOUND,
    TICKET_DETAIL_FIELDS,
    UNAUTHENTICATED,
    Clock,
    CommittedApp,
    committed_app_client,
    event_count,
    force_production_error_page,
    locator,
    ticket_row,
    user_reference,
)

Factory = Callable[..., Awaitable[Any]]

_INVALID_TRANSITION = {
    "code": "TICKET_INVALID_TRANSITION",
    "detail": "Ticket status transition is not allowed.",
}
_DEFAULT_VERSION = "3.1"
"""The committed `default_cvss_version` read by the package boundary."""

_THRESHOLD = Decimal("9.9")
"""Below the 10.0 fallback eligibility score of a Ticket without a CVE
(cvss-scoring.md, Eligibility Score Resolution): an automatic occurrence
persisted `false` becomes `true` during the exit."""

_CREATED_AT = datetime(2026, 3, 10, 14, 37, tzinfo=UTC)
"""`CommittedApp.ticket()`'s fixed `created_at`, the start of every due date."""

_DUE_DAYS = {
    "triage_due_at": 3,
    "submission_due_at": 18,
    "um_due_at": 21,
    "qa_due_at": 30,
    "release_due_at": 30,
}
"""ticket-deadlines.md, Formula: the 30-day tier of a `High` Ticket."""


@dataclass(frozen=True, slots=True)
class _Exit:
    """One manual-zone exit endpoint."""

    path: str
    summary: str
    service: str
    """The `ticket_service` function the handler delegates to."""
    source: TicketStatus
    """The exact source status the exit accepts."""

    def url(self, target: Ticket | str) -> str:
        return self.path.format(
            ticket_id=target if isinstance(target, str) else locator(target)
        )


REOPEN = _Exit(
    "/api/v1/tickets/{ticket_id}/reopen",
    "Reopen Ticket",
    "reopen_from_ignored",
    TicketStatus.IGNORED,
)
REVERT = _Exit(
    "/api/v1/tickets/{ticket_id}/revert-duplicate",
    "Revert Duplicate Status",
    "revert_duplicate",
    TicketStatus.DUPLICATED,
)
EXITS = [pytest.param(REOPEN, id="reopen"), pytest.param(REVERT, id="revert")]


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _forbid_lookups(
    monkeypatch: pytest.MonkeyPatch, exit_: _Exit
) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the exit with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_service, exit_.service, mutation)
    return resolver, mutation


async def _eligible(db: AsyncSession, occurrence_id: uuid.UUID) -> bool:
    value: bool = (
        await db.execute(
            select(TicketPackageProduct.eligible).where(
                TicketPackageProduct.id == occurrence_id
            )
        )
    ).scalar_one()
    return value


class _Catalog:
    """Committed package trees and the `default_cvss_version` setting for
    the Tickets of a `CommittedApp`, deleted explicitly before the world's
    own cleanup (testing-strategy.md, Concurrency Testing)."""

    def __init__(self, world: CommittedApp) -> None:
        self._world = world
        self.product_ids: list[uuid.UUID] = []
        self._owns_setting = False

    async def ensure_default_setting(self) -> None:
        db = await self._world.session()
        setting = await db.get(SystemSetting, "default_cvss_version")
        if setting is None:
            db.add(SystemSetting(key="default_cvss_version", value=_DEFAULT_VERSION))
            self._owns_setting = True
        else:
            assert setting.value == _DEFAULT_VERSION
        await db.commit()

    async def affected_product(self, ticket: Ticket, *, eligible: bool) -> uuid.UUID:
        """One manually included `AFFECTED` IBS track with one in-support
        automatic Product occurrence (threshold 9.9); returns the
        occurrence ID. With a manual severity and no CVE, the track passes
        the Analyzed gate and, undelivered, fails the Resolved gate
        (tickets.md, Gates)."""
        db = await self._world.session()
        suffix = uuid.uuid4().hex[:10]
        product = Product(
            name=f"Example Product {suffix}",
            version="1",
            display_name=f"EP {suffix}",
            cpe=f"cpe:/o:example:product:{suffix}",
            catalog_last_seen_at=datetime.now(UTC),
            cvss_threshold=_THRESHOLD,
            general_support_end_date=datetime.now(UTC).date() + timedelta(days=365),
        )
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-exit")
        db.add_all([product, package])
        await db.flush()
        self.product_ids.append(product.id)
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Codestream:{suffix}:Update",
            status=PackageStatus.AFFECTED.value,
        )
        db.add(track)
        await db.flush()
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id, product_id=product.id, eligible=eligible
        )
        db.add(occurrence)
        await db.commit()
        return occurrence.id

    async def cleanup(self) -> None:
        db = await self._world.session()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self._world.ticket_ids)
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
            delete(TicketPackage).where(
                TicketPackage.ticket_id.in_(self._world.ticket_ids)
            ),
            delete(Product).where(Product.id.in_(self.product_ids)),
        ):
            await db.execute(statement)
        if self._owns_setting:
            await db.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
        await db.commit()


async def _committed_source(
    world: CommittedApp, exit_: _Exit, **columns: Any
) -> Ticket:
    """A committed Ticket in the exit's source status (a revert source is
    linked to a committed `Analysis` target)."""
    if exit_ is REOPEN:
        return await world.ticket(status=TicketStatus.IGNORED.value, **columns)
    target = await world.ticket(status=TicketStatus.ANALYSIS.value)
    return await world.ticket(
        status=TicketStatus.DUPLICATED.value, duplicate_of_id=target.id, **columns
    )


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
    """`authenticated_client`'s user holding only `restricted_analyst`
    (`non_confidential` scope, no grant)."""
    await user_role_factory(
        user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
    )
    return authenticated_user


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient, _Catalog]]:
    async with committed_app_client(db_session_factory) as (world, committed_client):
        catalog = _Catalog(world)
        try:
            await catalog.ensure_default_setting()
            yield world, committed_client, catalog
        finally:
            await catalog.cleanup()


# ---------------------------------------------------------------------------
# Successful request (200 TicketDetail)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestManualZoneExit:
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_bodiless_exit_returns_the_committed_re_evaluated_detail(
        self, committed_app: tuple[CommittedApp, AsyncClient, _Catalog], exit_: _Exit
    ) -> None:
        """The Ticket enters the manual zone through the real entry
        endpoint (its due dates disappear); a VA caller then exits with no
        request body. The response is the complete `TicketDetail`, equal to
        a subsequent GET: the eligibility converged (`false` -> `true`),
        the gates promoted the Ticket to `analyzed`, the caller replaced
        the other VA assignee (rbac.md, Business Rule 12), a revert cleared
        the link, and the due dates reappeared from `created_at`."""
        world, committed_client, catalog = committed_app
        caller, headers = await world.va_headers()
        other = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(severity_manual="High", assignee_id=other.id)
        occurrence_id = await catalog.affected_product(ticket, eligible=False)
        if exit_ is REOPEN:
            entered = await committed_client.post(
                f"/api/v1/tickets/{locator(ticket)}/ignore", headers=headers
            )
        else:
            target = await world.ticket(status=TicketStatus.ANALYSIS.value)
            entered = await committed_client.post(
                f"/api/v1/tickets/{locator(ticket)}/duplicate",
                json={"duplicate_of_ticket_id": locator(target)},
                headers=headers,
            )
        assert entered.status_code == 200
        manual = (
            await committed_client.get(
                f"/api/v1/tickets/{locator(ticket)}", headers=headers
            )
        ).json()["data"]
        assert manual["status"] == exit_.source.value.lower()
        assert manual["assignee"] == user_reference(other)
        assert {field: manual[field] for field in _DUE_DAYS} == dict.fromkeys(_DUE_DAYS)

        response = await committed_client.post(exit_.url(ticket), headers=headers)
        detail = await committed_client.get(
            f"/api/v1/tickets/{locator(ticket)}", headers=headers
        )

        assert response.status_code == 200
        assert set(response.json()) == {"data"}
        data = response.json()["data"]
        assert set(data) == TICKET_DETAIL_FIELDS
        assert data == detail.json()["data"]
        assert (data["ticket_id"], data["status"], data["duplicate_of_ticket_id"]) == (
            locator(ticket),
            "analyzed",
            None,
        )
        assert data["assignee"] == user_reference(caller)
        assert {field: data[field] for field in _DUE_DAYS} == {
            field: _iso(_CREATED_AT + timedelta(days=days))
            for field, days in _DUE_DAYS.items()
        }
        [package] = data["packages"]
        [track] = package["tracks"]
        [product] = track["products"]
        assert (product["id"], product["eligible"]) == (str(occurrence_id), True)
        fresh = await world.session()
        state = await ticket_row(fresh, ticket.id)
        assert (state["status"], state["duplicate_of_id"], state["assignee_id"]) == (
            TicketStatus.ANALYZED.value,
            None,
            caller.id,
        )
        assert await _eligible(fresh, occurrence_id) is True


# ---------------------------------------------------------------------------
# Authentication and capability (flow 3, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndCapability:
    @pytest.mark.parametrize("exit_", EXITS)
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_credential_failure_returns_401_before_any_lookup(
        self,
        client: AsyncClient,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
        exit_: _Exit,
    ) -> None:
        source: Ticket = await ticket_factory(status=exit_.source.value)
        resolver, mutation = _forbid_lookups(monkeypatch, exit_)

        for path in (exit_.url(source), exit_.url(f"SNTL-{MAX_SEQUENCE}")):
            response = await client.post(path, headers=headers)
            assert response.status_code == 401
            assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()

    @pytest.mark.parametrize("exit_", EXITS)
    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_caller_without_triage_ticket_gets_the_generic_403_before_lookup(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_role_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: list[Role],
        exit_: _Exit,
    ) -> None:
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        visible: Ticket = await ticket_factory(status=exit_.source.value)
        before = await ticket_row(db_session, visible.id)
        resolver, mutation = _forbid_lookups(monkeypatch, exit_)

        existing = await authenticated_client.post(exit_.url(visible))
        missing = await authenticated_client.post(exit_.url(f"SNTL-{MAX_SEQUENCE}"))

        assert existing.status_code == missing.status_code == 403
        assert existing.content == missing.content
        assert existing.json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await ticket_row(db_session, visible.id) == before


# ---------------------------------------------------------------------------
# Ticket accessibility and anti-enumeration (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize("exit_", EXITS)
    @pytest.mark.parametrize(
        "build_locator",
        [pytest.param(build, id=name) for name, build in INVALID_LOCATORS],
    )
    async def test_invalid_or_missing_locator_returns_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        build_locator: Callable[[Ticket], str],
        exit_: _Exit,
    ) -> None:
        source: Ticket = await ticket_factory(status=exit_.source.value)
        before = await ticket_row(db_session, source.id)

        response = await authenticated_client.post(exit_.url(build_locator(source)))

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert await ticket_row(db_session, source.id) == before
        assert await event_count(db_session, source.id) == 0

    @pytest.mark.parametrize("exit_", EXITS)
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        ra_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        exit_: _Exit,
    ) -> None:
        hidden: Ticket = await ticket_factory(
            status=exit_.source.value, is_confidential=True
        )
        before = await ticket_row(db_session, hidden.id)

        inaccessible = await authenticated_client.post(exit_.url(hidden))
        missing = await authenticated_client.post(exit_.url(f"SNTL-{MAX_SEQUENCE}"))

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await ticket_row(db_session, hidden.id) == before
        assert await event_count(db_session, hidden.id) == 0


# ---------------------------------------------------------------------------
# Error mapping (one representative request per case)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestErrorMappings:
    @pytest.mark.parametrize(
        ("exit_", "status"),
        [
            pytest.param(REOPEN, TicketStatus.DUPLICATED, id="reopen-duplicated"),
            pytest.param(REVERT, TicketStatus.IGNORED, id="revert-ignored"),
            pytest.param(REOPEN, TicketStatus.ANALYZED, id="reopen-analyzed"),
            pytest.param(REVERT, TicketStatus.NEW, id="revert-new"),
        ],
    )
    async def test_wrong_status_is_an_invalid_transition_without_effect(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        ticket_factory: Factory,
        exit_: _Exit,
        status: TicketStatus,
    ) -> None:
        """A dedicated manual-zone exit is not subject to the mutability
        guard (api-spec.md, Manual-Zone Mutability Guard exceptions): the
        other manual-zone status and a gate-zone status both map to the
        complete `TICKET_INVALID_TRANSITION` body, never
        `TICKET_NOT_MUTABLE`."""
        source: Ticket = await ticket_factory(status=status.value)
        before = await ticket_row(db_session, source.id)

        response = await authenticated_client.post(exit_.url(source))

        assert response.status_code == 409
        assert response.json() == _INVALID_TRANSITION
        assert b"TICKET_NOT_MUTABLE" not in response.content
        assert await ticket_row(db_session, source.id) == before
        assert await event_count(db_session, source.id) == 0


# ---------------------------------------------------------------------------
# Handler-owned final assembly in the real request transaction
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMutationAssembly:
    @pytest.mark.parametrize(
        ("exit_", "events"),
        [
            # assignment, product_eligibility_changed, status_change
            pytest.param(REOPEN, 3, id="reopen"),
            # assignment, duplicate_removed, product_eligibility_changed,
            # status_change
            pytest.param(REVERT, 4, id="revert"),
        ],
    )
    async def test_failed_assembly_rolls_back_the_complete_exit(
        self,
        committed_app: tuple[CommittedApp, AsyncClient, _Catalog],
        monkeypatch: pytest.MonkeyPatch,
        exit_: _Exit,
        events: int,
    ) -> None:
        """The exit (assignment, link clear, Product convergence, final
        status, and every event) exists in the request transaction when the
        final assembly fails; the response is the generic 500 and nothing
        survives. The registered convergence effect is transaction-local
        and not observable over HTTP; its discard is proven by the service
        tests."""
        world, committed_client, catalog = committed_app
        caller, headers = await world.va_headers()
        other = await world.user(role=Role.VULNERABILITY_ANALYST)
        source = await _committed_source(
            world, exit_, severity_manual="High", assignee_id=other.id
        )
        occurrence_id = await catalog.affected_product(source, eligible=False)
        before = await ticket_row(await world.session(), source.id)
        reached: list[tuple[str, uuid.UUID | None, uuid.UUID | None, bool, int]] = []

        async def _fail(db: AsyncSession, **kwargs: Any) -> TicketDetailProjection:
            state = await ticket_row(db, source.id)
            reached.append(
                (
                    state["status"],
                    state["duplicate_of_id"],
                    state["assignee_id"],
                    await _eligible(db, occurrence_id),
                    await event_count(db, source.id),
                )
            )
            raise RuntimeError("simulated assembly failure")

        monkeypatch.setattr(ticket_service, "assemble_ticket_detail", _fail)
        force_production_error_page(monkeypatch)

        response = await committed_client.post(exit_.url(source), headers=headers)

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        assert reached == [(TicketStatus.ANALYZED.value, None, caller.id, True, events)]
        fresh = await world.session()
        assert await ticket_row(fresh, source.id) == before
        assert before["assignee_id"] == other.id
        assert await _eligible(fresh, occurrence_id) is False
        assert await event_count(fresh, source.id) == 0


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured date across UTC midnight
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEvaluationDate:
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_one_date_captured_before_midnight_reaches_every_consumer(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        ticket_factory: Factory,
        system_setting_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        exit_: _Exit,
    ) -> None:
        """The handler captures one UTC date just before midnight; every
        later clock reads just after midnight. The exit receives that date
        and hands it to the package boundary and the final reconciliation,
        and the final assembly receives it too: no consumer captures a
        second workflow date."""
        await system_setting_factory(key="default_cvss_version", value=_DEFAULT_VERSION)
        handler_clock = Clock(datetime(2026, 9, 27, 23, 59, 59, 999000, tzinfo=UTC))
        service_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        mutation_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", service_clock.now)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        dates: dict[str, list[date]] = {
            "exit": [],
            "boundary": [],
            "reconcile": [],
            "assembly": [],
        }

        def _spy(module: Any, name: str, key: str) -> None:
            original = getattr(module, name)

            async def _wrapper(*args: Any, **kwargs: Any) -> Any:
                dates[key].append(kwargs["evaluation_date"])
                return await original(*args, **kwargs)

            monkeypatch.setattr(module, name, _wrapper)

        _spy(ticket_service, exit_.service, "exit")
        _spy(package_service, "converge_manual_zone_exit_eligibility", "boundary")
        _spy(ticket_service, "reconcile_ticket_status", "reconcile")
        _spy(ticket_service, "assemble_ticket_detail", "assembly")
        source: Ticket = await ticket_factory(status=exit_.source.value)

        response = await authenticated_client.post(exit_.url(source))

        assert response.status_code == 200
        assert response.json()["data"]["status"] == "analysis"
        assert dates == {key: [date(2026, 9, 27)] for key in dates}
        assert handler_clock.calls == 1
        # The service clock is read only for the assembly's own milestone
        # instant (ticket-deadlines.md, Evaluation Instant), never for the
        # workflow date; the mutation clock is never read.
        assert (service_clock.calls, mutation_clock.calls) == (1, 0)


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    @staticmethod
    def _operation(exit_: _Exit) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        operation: dict[str, Any] = spec["paths"][exit_.path]["post"]
        return operation

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    @pytest.mark.parametrize("exit_", EXITS)
    def test_operation_declares_no_request_body(self, exit_: _Exit) -> None:
        operation = self._operation(exit_)

        assert operation["tags"] == ["Tickets"]
        assert operation["summary"] == exit_.summary
        assert "requestBody" not in operation

    @pytest.mark.parametrize("exit_", EXITS)
    def test_responses_declare_detail_and_error_envelopes(self, exit_: _Exit) -> None:
        responses = self._operation(exit_)["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TicketDetailResponse"
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_INVALID_TRANSITION" in responses["409"]["description"]
        assert "TICKET_NOT_MUTABLE" not in responses["409"]["description"]
        assert "400" not in responses


# ---------------------------------------------------------------------------
# Locked-current accessibility through HTTP (handler mapping of the
# service's authoritative denial; api-spec.md, flow 3)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIndependentRaces:
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_visibility_lost_to_a_committed_change_after_the_preliminary_check(
        self,
        committed_app: tuple[CommittedApp, AsyncClient, _Catalog],
        monkeypatch: pytest.MonkeyPatch,
        exit_: _Exit,
    ) -> None:
        """Another session commits the confidentiality flag after the
        preliminary dependency check but before the service locks the
        Ticket. The service's locked-current denial maps to the identical
        `404 TICKET_NOT_FOUND` with no effect. The service tier owns the
        race matrix; this proves only the handler's mapping of that
        denial."""
        world, committed_client, _ = committed_app
        _, headers = await world.va_headers(role=Role.RESTRICTED_ANALYST)
        source = await _committed_source(world, exit_)
        ticket_id: uuid.UUID = source.id
        before = await ticket_row(await world.session(), ticket_id)
        original = getattr(ticket_service, exit_.service)
        reached: list[bool] = []

        async def _lose_then_call(db: AsyncSession, **kwargs: Any) -> Ticket:
            reached.append(True)
            racer = await world.session()
            await racer.execute(
                update(Ticket)
                .where(Ticket.id == ticket_id)
                .values(is_confidential=True)
            )
            await racer.commit()
            result: Ticket = await original(db, **kwargs)
            return result

        monkeypatch.setattr(ticket_service, exit_.service, _lose_then_call)

        response = await committed_client.post(exit_.url(source), headers=headers)
        monkeypatch.undo()

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert reached == [True]
        fresh = await world.session()
        after = await ticket_row(fresh, ticket_id)
        # Only the racer's own write (and its `updated_at`) is committed.
        assert {k: v for k, v in after.items() if k != "updated_at"} == {
            k: v for k, v in before.items() if k != "updated_at"
        }
        assert await event_count(fresh, ticket_id) == 0
