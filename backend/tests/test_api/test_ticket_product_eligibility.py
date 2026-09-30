"""End-to-end tests for the Override Product Eligibility endpoint
(`PATCH /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}
/products/{ticket_package_product_id}`, `backend/app/api/v1/ticket_packages.py`).

See docs/features/packages/package-model.md (API Endpoints; Override
Product Eligibility, including Reset behavior and the response field
table; Security), docs/api-spec.md (Authorization Chain Evaluation Order
flow 3, JSON Request Body Scalar Types, Partial Update Semantics, Global
Responses, Ticket Accessibility Check, Anti-Enumeration Boundary,
Manual-Zone Mutability Guard, Ticket Identifier Resolution),
docs/features/identity/rbac.md (Predefined Roles; Endpoint Permission
Map), docs/features/tickets/ticket-audit-log.md (Testing Requirement 21),
and docs/features/platform/testing-strategy.md (API Endpoints; Ticket
Accessibility).

These tests cover only the HTTP boundary: authentication, the
`manage_packages` check before any lookup, request validation, the
identical not-found bodies, each error mapping, the exact response shape
for effective and no-op requests, commit by the request transaction, the
one captured evaluation date, the once-resolved roles, and OpenAPI. The
service matrix (metadata transitions, reset recalculation, gate
transitions, auto-assignment, audit payload, ownership, scope, races) is
proven in `tests/test_services/test_set_product_eligibility*.py`.

Dependency ordering (recorded decision D4, following the single-capability
precedent of `PATCH /tickets/{ticket_id}/priority`): FastAPI resolves the
`manage_packages` and Ticket-accessibility dependencies before it
validates the body and the nested path parameters. The generic 403
therefore precedes everything, and for a caller holding
`manage_packages` a missing or inaccessible Ticket returns 404 even when
the body or a nested UUID is invalid; the global 422 is reachable only on
an accessible Ticket.
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
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import ticket_packages as route
from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.main import app
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service, ticket_mutations, ticket_service, user_service
from tests.support.product_eligibility import persisted_occurrence
from tests.support.suse_cvss import V31_MEDIUM
from tests.support.ticket_api import (
    FORBIDDEN,
    INVALID_LOCATORS,
    MAX_SEQUENCE,
    NOT_FOUND,
    NOT_MUTABLE,
    UNAUTHENTICATED,
    Clock,
    CommittedApp,
    committed_app_client,
    event_count,
    locator,
    ticket_row,
    validation_error,
)

Factory = Callable[..., Awaitable[Any]]

_PATH = (
    "/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
    "/products/{ticket_package_product_id}"
)
_RESOURCE_NOT_FOUND = b'{"code":"RESOURCE_NOT_FOUND","detail":"Resource not found."}'
_PACKAGE_NAME = "example-lib"
_REFERENCE = "Example:Codestream:15:Update"
_CPE = "cpe:/o:example:alpha:15"
_DISPLAY_NAME = "Example Alpha 15"
_THRESHOLD = Decimal("9.0")
"""The fixture Product threshold: the SUSE v3.1 medium score 4.8 is below
it; the 10.0 fallback reaches it (package-model.md, Axis 2: Eligibility)."""

PRODUCT_FIELDS = {
    "ticket_id",
    "package_name",
    "reference",
    "id",
    "product_cpe",
    "product_name",
    "eligible",
    "is_eligible_override",
    "lifecycle_phase",
    "actionable",
    "non_actionable_reason",
}
"""package-model.md, Override Product Eligibility response field table."""


@dataclass(frozen=True, slots=True)
class Tree:
    """One Ticket with one package, one `AFFECTED` track, and one Product
    occurrence of the catalog Product `product`."""

    ticket: Ticket
    package: TicketPackage
    track: TicketPackageTrack
    product: Product
    occurrence: TicketPackageProduct

    def url(
        self,
        *,
        ticket_id: str | None = None,
        package_id: uuid.UUID | str | None = None,
        track_id: uuid.UUID | str | None = None,
        occurrence_id: uuid.UUID | str | None = None,
    ) -> str:
        return _url(
            ticket_id if ticket_id is not None else self.ticket,
            package_id if package_id is not None else self.package.id,
            track_id if track_id is not None else self.track.id,
            occurrence_id if occurrence_id is not None else self.occurrence.id,
        )


def _url(
    ticket: Ticket | str,
    package_id: uuid.UUID | str,
    track_id: uuid.UUID | str,
    occurrence_id: uuid.UUID | str,
) -> str:
    return _PATH.format(
        ticket_id=ticket if isinstance(ticket, str) else locator(ticket),
        package_id=package_id,
        track_id=track_id,
        ticket_package_product_id=occurrence_id,
    )


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(package_service, "set_product_eligibility", mutation)
    return resolver, mutation


async def _eligibility_events(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[tuple[uuid.UUID | None, str | None, str | None, Any]]:
    """Every `product_eligibility_changed` `(user_id, old, new,
    override_action)` of a Ticket in insertion order."""
    rows = await db.execute(
        select(
            TicketAuditEvent.user_id,
            TicketAuditEvent.old_value,
            TicketAuditEvent.new_value,
            TicketAuditEvent.detail,
        )
        .where(
            TicketAuditEvent.ticket_id == ticket_id,
            TicketAuditEvent.event_type == "product_eligibility_changed",
        )
        .order_by(TicketAuditEvent.id)
    )
    return [
        (row.user_id, row.old_value, row.new_value, row.detail["override_action"])
        for row in rows
    ]


async def _snapshot(db: AsyncSession, tree: Tree) -> tuple[Any, ...]:
    """Everything a rejected request must leave unchanged."""
    return (
        await ticket_row(db, tree.ticket.id),
        await persisted_occurrence(db, tree.occurrence),
        await event_count(db, tree.ticket.id),
    )


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.fixture
def grant(
    authenticated_user: User, user_role_factory: Factory
) -> Callable[..., Awaitable[User]]:
    """Give `authenticated_client`'s user the given roles."""

    async def _grant(*roles: Role) -> User:
        for role in roles:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)
        return authenticated_user

    return _grant


@pytest_asyncio.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` an override clear reads (the
    test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value="3.1"
    )
    return setting


@pytest.fixture
def build(
    ticket_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    product_factory: Factory,
    ticket_package_product_factory: Factory,
) -> Callable[..., Awaitable[Tree]]:
    """Create a Ticket (columns from `ticket_columns`) with one package, one
    `AFFECTED` track, and one occurrence (`eligible`, `override`) of a
    catalog Product (threshold `_THRESHOLD`, in General Support through
    2030 unless `product_columns` override it). Each call uses a distinct
    CPE derived from the Ticket."""

    async def _build(
        *,
        eligible: bool = True,
        override: bool = False,
        product_columns: dict[str, Any] | None = None,
        **ticket_columns: Any,
    ) -> Tree:
        ticket: Ticket = await ticket_factory(**ticket_columns)
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name=_PACKAGE_NAME
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference=_REFERENCE,
            status=PackageStatus.AFFECTED.value,
        )
        columns: dict[str, Any] = {
            "cpe": f"{_CPE}:{ticket.sequence_id}",
            "display_name": _DISPLAY_NAME,
            "cvss_threshold": _THRESHOLD,
            "general_support_end_date": date(2030, 1, 1),
        }
        columns.update(product_columns or {})
        product = await product_factory(**columns)
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=override,
        )
        return Tree(ticket, package, track, product, occurrence)

    return _build


# ---------------------------------------------------------------------------
# Authentication and capability before any lookup (flow 3, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndCapability:
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
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
    ) -> None:
        tree = await build()
        before = await _snapshot(db_session, tree)
        resolver, mutation = _forbid_lookups(monkeypatch)

        for path in (tree.url(), tree.url(ticket_id=f"SNTL-{MAX_SEQUENCE}")):
            for body in ({"eligible": False}, {"eligible": None}, {}):
                response = await client.patch(path, json=body, headers=headers)
                assert response.status_code == 401
                assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param((), id="no-roles"),
            pytest.param((Role.ADMIN,), id="admin_ticket_ops-only"),
        ],
    )
    async def test_caller_without_manage_packages_gets_the_generic_403(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        roles: tuple[Role, ...],
    ) -> None:
        """The same generic 403, before any lookup or validation, for an
        existing, a missing, an inaccessible (confidential; the role-less
        caller's scope is `non_confidential`), a malformed, and a UUID-form
        `{ticket_id}`, for malformed nested UUIDs, and for invalid bodies.
        `admin` holds `admin_ticket_ops` but not `manage_packages`
        (rbac.md, Predefined Roles)."""
        await grant(*roles)
        tree = await build()
        cve = await cve_factory()
        hidden = await build(is_confidential=True, cve_id=cve.id)
        trees = (tree, hidden)
        before = [await _snapshot(db_session, t) for t in trees]
        resolver, mutation = _forbid_lookups(monkeypatch)

        paths = [
            tree.url(),
            tree.url(ticket_id=f"SNTL-{MAX_SEQUENCE}"),
            hidden.url(),
            tree.url(ticket_id="not-a-ticket"),
            tree.url(ticket_id=str(tree.ticket.id)),
            tree.url(
                package_id="not-a-uuid",
                track_id="not-a-uuid",
                occurrence_id="not-a-uuid",
            ),
        ]
        bodies: list[Any] = [
            {"eligible": False},
            {"eligible": None},
            {},
            {"eligible": 1},
        ]
        responses = [
            await authenticated_client.patch(path, json=body)
            for path in paths
            for body in bodies
        ]

        assert [r.status_code for r in responses] == [403] * len(responses)
        assert {r.content for r in responses} == {responses[0].content}
        assert responses[0].json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert [await _snapshot(db_session, t) for t in trees] == before

    @pytest.mark.parametrize(
        "role",
        [
            pytest.param(Role.VULNERABILITY_ANALYST, id="vulnerability_analyst"),
            pytest.param(Role.RESTRICTED_ANALYST, id="restricted_analyst"),
        ],
    )
    async def test_predefined_role_with_manage_packages_succeeds(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        role: Role,
    ) -> None:
        """rbac.md, Predefined Roles and Endpoint Permission Map: both
        analyst roles hold `manage_packages`."""
        await grant(role)
        tree = await build(status=TicketStatus.ANALYSIS.value)

        response = await authenticated_client.patch(
            tree.url(), json={"eligible": False}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["eligible"], data["is_eligible_override"]) == (False, True)
        assert await persisted_occurrence(db_session, tree.occurrence) == (False, True)
        assert len(await _eligibility_events(db_session, tree.ticket.id)) == 1

    async def test_roles_are_loaded_once_per_request(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The capability check and the Ticket caller (scope for the
        preliminary and the locked accessibility decisions) share one role
        load (api-spec.md, Authorization Chain Evaluation Order)."""
        user = await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(is_confidential=True, status=TicketStatus.ANALYSIS.value)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.patch(
            tree.url(), json={"eligible": False}
        )

        assert response.status_code == 200
        assert calls == [user.id]


# ---------------------------------------------------------------------------
# Request validation (global 422) on an accessible Ticket
# ---------------------------------------------------------------------------

_UUID_MESSAGE = "Input should be a valid UUID, invalid character: found `n` at 1"
_BOOL_MESSAGE = "Input should be a valid boolean"


def _uuid_error(name: str) -> dict[str, Any]:
    return {"loc": ["path", name], "msg": _UUID_MESSAGE, "type": "uuid_parsing"}


def _bool_error() -> dict[str, Any]:
    return {"loc": ["body", "eligible"], "msg": _BOOL_MESSAGE, "type": "bool_type"}


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        ("body", "error"),
        [
            pytest.param(
                {},
                {
                    "loc": ["body", "eligible"],
                    "msg": "Field required",
                    "type": "missing",
                },
                id="omitted",
            ),
            *[
                pytest.param({"eligible": value}, _bool_error(), id=name)
                for name, value in (
                    ("string-true", "true"),
                    ("string-false", "false"),
                    ("integer-1", 1),
                    ("integer-0", 0),
                    ("array", []),
                    ("object", {}),
                )
            ],
        ],
    )
    async def test_invalid_body_is_a_422_without_effect(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        body: dict[str, Any],
        error: dict[str, Any],
    ) -> None:
        """`eligible` is required and accepts only a JSON boolean or `null`
        (api-spec.md, Partial Update Semantics: single-field PATCH; JSON
        Request Body Scalar Types: no coercion)."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        before = await _snapshot(db_session, tree)
        mutation = AsyncMock()
        monkeypatch.setattr(package_service, "set_product_eligibility", mutation)

        response = await authenticated_client.patch(tree.url(), json=body)

        assert response.status_code == 422
        assert response.json() == validation_error(error)
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    async def test_absent_body_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        mutation = AsyncMock()
        monkeypatch.setattr(package_service, "set_product_eligibility", mutation)

        response = await authenticated_client.patch(tree.url())

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["body"], "msg": "Field required", "type": "missing"}
        )
        mutation.assert_not_awaited()

    @pytest.mark.parametrize(
        "levels",
        [
            pytest.param(("package_id",), id="package"),
            pytest.param(("track_id",), id="track"),
            pytest.param(("ticket_package_product_id",), id="occurrence"),
            pytest.param(
                ("package_id", "track_id", "ticket_package_product_id"), id="all"
            ),
        ],
    )
    async def test_malformed_nested_uuid_is_a_422_on_an_accessible_ticket(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        levels: tuple[str, ...],
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        before = await _snapshot(db_session, tree)
        mutation = AsyncMock()
        monkeypatch.setattr(package_service, "set_product_eligibility", mutation)
        url = tree.url(
            package_id="not-a-uuid" if "package_id" in levels else None,
            track_id="not-a-uuid" if "track_id" in levels else None,
            occurrence_id=(
                "not-a-uuid" if "ticket_package_product_id" in levels else None
            ),
        )

        response = await authenticated_client.patch(url, json={"eligible": False})

        assert response.status_code == 422
        assert response.json() == validation_error(*[_uuid_error(n) for n in levels])
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    async def test_path_and_body_errors_are_each_listed_once(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()

        response = await authenticated_client.patch(
            tree.url(occurrence_id="not-a-uuid"), json={"eligible": "true"}
        )

        assert response.status_code == 422
        assert response.json() == validation_error(
            _uuid_error("ticket_package_product_id"), _bool_error()
        )

    async def test_ticket_not_found_precedes_body_and_nested_path_validation(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Decision D4 (module docstring): for a `restricted_analyst`
        caller holding `manage_packages`, an invalid body or a malformed
        nested UUID sent to a missing, malformed, or inaccessible Ticket
        returns the identical `404 TICKET_NOT_FOUND`, because the Ticket
        accessibility dependency resolves before body and path
        validation. No mutation runs."""
        await grant(Role.RESTRICTED_ANALYST)
        cve = await cve_factory()
        hidden = await build(is_confidential=True, cve_id=cve.id)
        before = await _snapshot(db_session, hidden)
        mutation = AsyncMock()
        monkeypatch.setattr(package_service, "set_product_eligibility", mutation)

        responses = [
            await authenticated_client.patch(
                hidden.url(ticket_id=ticket_id, occurrence_id=occurrence_id),
                json=body,
            )
            for ticket_id in (
                locator(hidden.ticket),
                f"SNTL-{MAX_SEQUENCE}",
                "not-a-ticket",
            )
            for occurrence_id, body in (
                (None, {}),
                (None, {"eligible": "true"}),
                ("not-a-uuid", {"eligible": False}),
            )
        ]

        assert [r.status_code for r in responses] == [404] * len(responses)
        assert {r.content for r in responses} == {NOT_FOUND}
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, hidden) == before


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize("value", [False, None])
    @pytest.mark.parametrize(
        "build_locator",
        [
            *[pytest.param(build, id=name) for name, build in INVALID_LOCATORS],
            pytest.param(
                lambda t: f"SNTL-{t.sequence_id + 1_000_000}", id="missing-sequence"
            ),
        ],
    )
    async def test_invalid_or_missing_locator_returns_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        build_locator: Callable[[Ticket], str],
        value: bool | None,
    ) -> None:
        """Malformed `{ticket_id}` forms, the Ticket UUID in place of
        `SNTL-{n}`, and a well-formed missing `SNTL-{n}` (api-spec.md,
        Ticket Identifier Resolution)."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(override=True)
        before = await _snapshot(db_session, tree)
        mutation = AsyncMock()
        monkeypatch.setattr(package_service, "set_product_eligibility", mutation)

        response = await authenticated_client.patch(
            tree.url(ticket_id=build_locator(tree.ticket)), json={"eligible": value}
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
    ) -> None:
        """A `restricted_analyst` (scope `non_confidential`) cannot see a
        confidential Ticket: the same complete body as a missing one."""
        await grant(Role.RESTRICTED_ANALYST)
        cve = await cve_factory()
        hidden = await build(is_confidential=True, cve_id=cve.id)
        before = await _snapshot(db_session, hidden)

        inaccessible = await authenticated_client.patch(
            hidden.url(), json={"eligible": False}
        )
        missing = await authenticated_client.patch(
            hidden.url(ticket_id=f"SNTL-{MAX_SEQUENCE}"), json={"eligible": False}
        )

        assert inaccessible.status_code == missing.status_code == 404
        assert inaccessible.content == missing.content == NOT_FOUND
        assert await _snapshot(db_session, hidden) == before

    async def test_locked_current_denial_maps_to_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The preliminary check passes, but the service's authoritative
        locked-current accessibility denies (access lost while waiting for
        the Ticket lock, proven in the service race tests): the handler maps
        the shared `TicketNotFoundError` to the same 404 body."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        monkeypatch.setattr(
            package_service,
            "set_product_eligibility",
            AsyncMock(side_effect=TicketNotFoundError()),
        )

        response = await authenticated_client.patch(
            tree.url(), json={"eligible": False}
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND


# ---------------------------------------------------------------------------
# Nested-resource ownership (identical 404 RESOURCE_NOT_FOUND)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNestedResourceNotFound:
    async def test_missing_or_mismatched_nested_identifiers_share_one_404(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """package-model.md, API Endpoints: a missing ID or any ownership
        mismatch returns one identical `404 RESOURCE_NOT_FOUND`, never
        mutates or reveals the occurrence under the other path, and the
        occurrence locator is never the catalog `Product.id`."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(status=TicketStatus.ANALYSIS.value)
        sibling_package = await ticket_package_factory(
            ticket_id=tree.ticket.id, package_name="example-tool"
        )
        sibling_track = await ticket_package_track_factory(
            ticket_package_id=sibling_package.id
        )
        sibling_occurrence = await ticket_package_product_factory(
            ticket_package_track_id=sibling_track.id, product_id=tree.product.id
        )
        own_sibling_track = await ticket_package_track_factory(
            ticket_package_id=tree.package.id
        )
        other = await build(status=TicketStatus.ANALYSIS.value)
        occurrences = (tree.occurrence, sibling_occurrence, other.occurrence)
        before = (
            [await _snapshot(db_session, t) for t in (tree, other)],
            [await persisted_occurrence(db_session, o) for o in occurrences],
        )

        cases = {
            "missing-package": tree.url(package_id=uuid.uuid4()),
            "package-of-other-ticket": tree.url(
                package_id=other.package.id,
                track_id=other.track.id,
                occurrence_id=other.occurrence.id,
            ),
            "missing-track": tree.url(track_id=uuid.uuid4()),
            "track-of-other-package": tree.url(
                track_id=sibling_track.id, occurrence_id=sibling_occurrence.id
            ),
            "missing-occurrence": tree.url(occurrence_id=uuid.uuid4()),
            "occurrence-of-other-track": tree.url(occurrence_id=sibling_occurrence.id),
            "occurrence-of-own-empty-track": tree.url(track_id=own_sibling_track.id),
            "catalog-product-id": tree.url(occurrence_id=tree.product.id),
        }
        for name, path in cases.items():
            for value in (False, None):
                response = await authenticated_client.patch(
                    path, json={"eligible": value}
                )
                assert response.status_code == 404, name
                assert response.content == _RESOURCE_NOT_FOUND, name

        assert (
            [await _snapshot(db_session, t) for t in (tree, other)],
            [await persisted_occurrence(db_session, o) for o in occurrences],
        ) == before


# ---------------------------------------------------------------------------
# Manual-zone mutability guard (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNotMutable:
    @pytest.mark.parametrize("value", [False, None])
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        status: TicketStatus,
        value: bool | None,
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(override=True, status=status.value)
        before = await _snapshot(db_session, tree)

        response = await authenticated_client.patch(
            tree.url(), json={"eligible": value}
        )

        assert response.status_code == 409
        assert response.json() == NOT_MUTABLE
        assert await _snapshot(db_session, tree) == before


# ---------------------------------------------------------------------------
# Successful response (200): exact shape for effective and no-op requests
# ---------------------------------------------------------------------------


def _expected(tree: Tree, eligible: bool, override: bool) -> dict[str, Any]:
    """The documented response of the in-support fixture occurrence."""
    return {
        "data": {
            "ticket_id": locator(tree.ticket),
            "package_name": _PACKAGE_NAME,
            "reference": _REFERENCE,
            "id": str(tree.occurrence.id),
            "product_cpe": tree.product.cpe,
            "product_name": _DISPLAY_NAME,
            "eligible": eligible,
            "is_eligible_override": override,
            "lifecycle_phase": "general_support",
            "actionable": True,
            "non_actionable_reason": None,
        }
    }


@pytest.mark.e2e
class TestResponse:
    async def test_set_change_clear_and_no_ops_return_the_exact_projection(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An assigned `Resolved` Ticket whose CVE has SUSE v3.1 medium
        (4.8 < 9.0): the occurrence is automatically ineligible. The
        sequence sets `true`, repeats it (override no-op), changes to
        `false` and back to `true`, clears (recalculated `false` from 4.8),
        and clears again (automatic no-op). Every response has exactly the
        documented fields; each effective request records one event with
        `set`, `changed`, or `cleared` and each no-op none (ticket-audit-log
        .md, Testing Requirement 21)."""
        user = await grant(Role.VULNERABILITY_ANALYST)
        clock = Clock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", clock.now)
        cve = await cve_factory(severity=Severity.MEDIUM.value)
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="SUSE", **V31_MEDIUM.columns()
        )
        tree = await build(
            eligible=False,
            cve_id=cve.id,
            status=TicketStatus.RESOLVED.value,
            assignee_id=user.id,
        )

        steps: list[tuple[bool | None, bool, bool, bool]] = [
            # (request, eligible, is_eligible_override, effective)
            (True, True, True, True),
            (True, True, True, False),
            (False, False, True, True),
            (True, True, True, True),
            (None, False, False, True),
            (None, False, False, False),
        ]
        for value, eligible, override, effective in steps:
            before = await _snapshot(db_session, tree)
            response = await authenticated_client.patch(
                tree.url(), json={"eligible": value}
            )
            assert response.status_code == 200, value
            body = response.json()
            assert set(body) == {"data"}
            assert set(body["data"]) == PRODUCT_FIELDS
            assert body == _expected(tree, eligible, override)
            assert str(tree.ticket.id) not in response.text
            assert str(tree.product.id) not in response.text
            assert await persisted_occurrence(db_session, tree.occurrence) == (
                eligible,
                override,
            )
            if not effective:
                assert await _snapshot(db_session, tree) == before

        assert await _eligibility_events(db_session, tree.ticket.id) == [
            (user.id, "false", "true", "set"),
            (user.id, "true", "false", "changed"),
            (user.id, "false", "true", "changed"),
            (user.id, "true", "false", "cleared"),
        ]
        assert clock.calls == len(steps)

    async def test_non_actionable_occurrence_remains_editable(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A directly excluded EOL occurrence is still overridden; the
        response reports the first applicable reason `product_excluded`
        before `eol` (package-model.md, Derived Actionability;
        package-service.md, Excluded and Non-Actionable Records)."""
        await grant(Role.VULNERABILITY_ANALYST)
        monkeypatch.setattr(
            route, "_utc_now", Clock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC)).now
        )
        tree = await build(
            status=TicketStatus.ANALYSIS.value,
            product_columns={"general_support_end_date": date(2020, 1, 1)},
        )
        tree.occurrence.deleted_at = datetime(2026, 9, 1, tzinfo=UTC)
        await db_session.flush()

        response = await authenticated_client.patch(
            tree.url(), json={"eligible": False}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (
            data["eligible"],
            data["is_eligible_override"],
            data["lifecycle_phase"],
            data["actionable"],
            data["non_actionable_reason"],
        ) == (False, True, "eol", False, "product_excluded")
        assert len(await _eligibility_events(db_session, tree.ticket.id)) == 1


# ---------------------------------------------------------------------------
# Commit by the request transaction
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient, list[uuid.UUID]]]:
    """`committed_app_client()` that also deletes the committed package tree
    of its Tickets and the listed catalog Products before the shared
    cleanup."""
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
                delete(TicketPackage).where(
                    TicketPackage.ticket_id.in_(world.ticket_ids)
                ),
                delete(Product).where(Product.id.in_(product_ids)),
            ):
                await db.execute(statement)
            await db.commit()


@pytest.mark.e2e
class TestTransaction:
    async def test_effective_override_is_committed_and_a_no_op_adds_nothing(
        self,
        committed_app: tuple[CommittedApp, AsyncClient, list[uuid.UUID]],
    ) -> None:
        """A VA overrides the occurrence of an unassigned CVE-less `New`
        Ticket without severity: auto-assignment and its promotion precede
        the one eligibility event, and without a resolved severity the
        Ticket stays in Analysis. A repeated request is a committed no-op."""
        world, committed_client, product_ids = committed_app
        actor, headers = await world.va_headers()
        ticket = await world.ticket()
        db = await world.session()
        package = TicketPackage(ticket_id=ticket.id, package_name=_PACKAGE_NAME)
        product = Product(
            name=f"Example Product {uuid.uuid4().hex[:10]}",
            version="15",
            display_name=_DISPLAY_NAME,
            cpe=f"{_CPE}:{uuid.uuid4().hex[:10]}",
            catalog_last_seen_at=datetime.now(UTC),
        )
        db.add_all([package, product])
        await db.flush()
        product_ids.append(product.id)
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=_REFERENCE,
            status=PackageStatus.AFFECTED.value,
        )
        db.add(track)
        await db.flush()
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id, product_id=product.id
        )
        db.add(occurrence)
        await db.commit()
        url = _url(ticket, package.id, track.id, occurrence.id)

        changed = await committed_client.patch(
            url, json={"eligible": False}, headers=headers
        )
        no_op = await committed_client.patch(
            url, json={"eligible": False}, headers=headers
        )

        assert changed.status_code == no_op.status_code == 200
        assert changed.json() == no_op.json()
        fresh = await world.session()
        assert await persisted_occurrence(fresh, occurrence) == (False, True)
        events = (
            await fresh.execute(
                select(TicketAuditEvent.event_type)
                .where(TicketAuditEvent.ticket_id == ticket.id)
                .order_by(TicketAuditEvent.id)
            )
        ).scalars()
        assert list(events) == [
            "assignment",
            "status_change",
            "product_eligibility_changed",
        ]
        state = await ticket_row(fresh, ticket.id)
        assert (state["status"], state["assignee_id"]) == (
            TicketStatus.ANALYSIS.value,
            actor.id,
        )


# ---------------------------------------------------------------------------
# Controlled clock: one handler-captured date across UTC midnight
# ---------------------------------------------------------------------------


class _DateClock:
    """A controlled UTC-date source counting its calls."""

    def __init__(self, value: date) -> None:
        self.value = value
        self.calls = 0

    def today(self) -> date:
        self.calls += 1
        return self.value


@pytest.mark.e2e
class TestEvaluationDate:
    async def test_one_date_captured_before_midnight_drives_clear_gate_and_response(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Extended support ends on `captured`: the Product is in Extended
        Support on `captured` and in Reactive Support the next day. Clearing
        an ineligible override of a CVE-less `High` Ticket recalculates from
        the 10.0 fallback (no threshold): eligible on `captured` (the gate
        moves `Resolved -> Analyzed`), while the next day's Reactive Support
        rule would keep it ineligible and the Ticket `Resolved`
        (package-model.md, Axis 2 rule 2). Every other clock returns the
        next day and must stay unread."""
        captured = date(2026, 12, 31)
        next_day = date(2027, 1, 1)
        handler_clock = Clock(datetime(2026, 12, 31, 23, 59, 59, 999000, tzinfo=UTC))
        service_clock = _DateClock(next_day)
        mutation_clock = Clock(datetime(2027, 1, 1, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(package_service, "_utc_today", service_clock.today)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        seen: dict[str, list[date | None]] = {"mutation": [], "reconcile": []}
        original_mutation = package_service.set_product_eligibility
        # `package_service` composes the `ticket_mutations` primitive by name.
        original_reconcile = ticket_mutations.reconcile_ticket_status

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Any:
            seen["mutation"].append(kwargs.get("evaluation_date"))
            return await original_mutation(db, **kwargs)

        async def _reconcile(ticket: Ticket, db: AsyncSession, **kwargs: Any) -> None:
            seen["reconcile"].append(kwargs.get("evaluation_date"))
            await original_reconcile(ticket, db, **kwargs)

        monkeypatch.setattr(package_service, "set_product_eligibility", _mutation)
        monkeypatch.setattr(package_service, "reconcile_ticket_status", _reconcile)
        user = await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(
            eligible=False,
            override=True,
            status=TicketStatus.RESOLVED.value,
            severity_manual=Severity.HIGH.value,
            assignee_id=user.id,
            product_columns={
                "cvss_threshold": None,
                "general_support_end_date": captured - timedelta(days=60),
                "extended_support_end_date": captured,
                "reactive_support_end_date": captured + timedelta(days=60),
            },
        )

        response = await authenticated_client.patch(tree.url(), json={"eligible": None})

        assert response.status_code == 200
        data = response.json()["data"]
        assert (
            data["eligible"],
            data["is_eligible_override"],
            data["lifecycle_phase"],
            data["actionable"],
            data["non_actionable_reason"],
        ) == (True, False, "extended_support", True, None)
        assert (await ticket_row(db_session, tree.ticket.id))[
            "status"
        ] == TicketStatus.ANALYZED.value
        assert seen == {"mutation": [captured], "reconcile": [captured]}
        assert handler_clock.calls == 1
        assert (service_clock.calls, mutation_clock.calls) == (0, 0)


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][_PATH]["patch"]
        return operation

    def _resolve(self, schema: dict[str, Any]) -> dict[str, Any]:
        ref = schema.get("$ref")
        if ref is None:
            return schema
        resolved: dict[str, Any] = self._spec()["components"]["schemas"][
            ref.rsplit("/", 1)[-1]
        ]
        return self._resolve(resolved)

    @staticmethod
    def _ref_name(content: dict[str, Any]) -> str:
        ref: str = content["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_operation_and_path_parameters(self) -> None:
        operation = self._operation()

        assert operation["summary"] == "Override Product Eligibility"
        assert operation["tags"] == ["Ticket Packages"]
        parameters = {p["name"]: p for p in operation["parameters"]}
        assert set(parameters) == {
            "ticket_id",
            "package_id",
            "track_id",
            "ticket_package_product_id",
        }
        assert all(
            p["in"] == "path" and p["required"] is True for p in parameters.values()
        )
        assert parameters["ticket_id"]["schema"]["type"] == "string"
        assert "format" not in parameters["ticket_id"]["schema"]
        for name in ("package_id", "track_id", "ticket_package_product_id"):
            schema = parameters[name]["schema"]
            assert (schema["type"], schema["format"]) == ("string", "uuid")

    def test_request_body_requires_a_nullable_boolean_eligible(self) -> None:
        request_body = self._operation()["requestBody"]

        assert request_body["required"] is True
        assert (
            self._ref_name(request_body["content"]) == "ProductEligibilityUpdateRequest"
        )
        schema = self._resolve(request_body["content"]["application/json"]["schema"])
        assert schema["required"] == ["eligible"]
        assert set(schema["properties"]) == {"eligible"}
        eligible = schema["properties"]["eligible"]
        assert eligible["anyOf"] == [{"type": "boolean"}, {"type": "null"}]

    def test_responses_declare_the_product_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert (
            self._ref_name(responses["200"]["content"]) == "ProductEligibilityResponse"
        )
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "RESOURCE_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "422" in responses

    def test_response_schema_has_exactly_the_documented_fields(self) -> None:
        envelope = self._resolve(
            {"$ref": "#/components/schemas/ProductEligibilityResponse"}
        )
        assert set(envelope["properties"]) == {"data"}
        product = self._resolve(envelope["properties"]["data"])
        assert set(product["properties"]) == PRODUCT_FIELDS
        assert set(product["required"]) == PRODUCT_FIELDS
        # The only UUID is the Product occurrence locator; no Ticket UUID.
        assert product["properties"]["ticket_id"]["type"] == "string"
        assert "format" not in product["properties"]["ticket_id"]
        assert [
            name
            for name, p in product["properties"].items()
            if self._resolve(p).get("format") == "uuid"
        ] == ["id"]
