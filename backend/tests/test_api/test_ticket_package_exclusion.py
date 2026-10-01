"""End-to-end tests for the six package-tree exclusion and restoration
endpoints (`backend/app/api/v1/ticket_packages.py`, Exclusion and
restoration):

- `POST /api/v1/tickets/{ticket_id}/packages/{package_id}/exclude|restore`;
- `POST .../packages/{package_id}/tracks/{track_id}/exclude|restore`;
- `POST .../tracks/{track_id}/products/{ticket_package_product_id}
  /exclude|restore`.

See docs/features/packages/package-model.md (API Endpoints; Soft-Delete
Package from Ticket, Restore Package, Soft-Delete Track, Restore Track,
Soft-Delete Product, Restore Product; Exclusion and Actionability),
docs/api-spec.md (Authorization Chain Evaluation Order flow 3, Global
Responses, Ticket Accessibility Check, Anti-Enumeration Boundary,
Manual-Zone Mutability Guard, Ticket Identifier Resolution),
docs/features/identity/rbac.md (Predefined Roles; Endpoint Permission
Map), and docs/features/platform/testing-strategy.md (API Endpoints;
Ticket Accessibility: Locked mutations, Authentication, authorization,
and anti-enumeration, Ticket identifier and read-contract coverage).

These tests cover only the HTTP boundary: authentication, the
`manage_packages` check before any lookup, path validation, the identical
not-found bodies, each error mapping, the exact documented response bodies
(including every non-actionable success example of package-model.md),
commit by the request transaction, maintainer self-loss, the once-resolved
roles, the one handler-captured evaluation date, and OpenAPI. The service
contract (marker independence, guards, gate transitions, auto-assignment,
audit payloads, scope, visibility, rollback, races) is proven in
`tests/test_services/test_package_exclusion*.py`.

Dependency ordering (the precedent of the Override Product Eligibility
endpoint, `tests/test_api/test_ticket_product_eligibility.py`): FastAPI
resolves the `manage_packages` dependency, then the Ticket-accessibility
dependency, and only then validates the endpoint's own nested path UUIDs.
The generic 403 therefore precedes everything; for a caller holding
`manage_packages`, a malformed, missing, or inaccessible Ticket returns
`404 TICKET_NOT_FOUND` even when a nested UUID is malformed, and the
global `422 VALIDATION_ERROR` for a nested UUID is reachable only on an
accessible Ticket. The endpoints have no request body.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import ticket_packages as route
from app.core.enums import PackageStatus, Role, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.main import app
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service, ticket_mutations, ticket_service, user_service
from tests.support.package_exclusion import (
    DIRECTIONS,
    LEVELS,
    MARKER_NOW,
    SEEDED_AT,
    Direction,
    Level,
    Markers,
    marker_event,
    markers,
    markers_by_id,
    patch_marker_now,
    with_target,
)
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
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    EventRow,
    ticket_events,
)

Factory = Callable[..., Awaitable[Any]]

_TEMPLATES = {
    Level.PACKAGE: "/api/v1/tickets/{ticket_id}/packages/{package_id}/{direction}",
    Level.TRACK: (
        "/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
        "/{direction}"
    ),
    Level.PRODUCT: (
        "/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
        "/products/{ticket_package_product_id}/{direction}"
    ),
}

_SERVICE = {
    (Level.PACKAGE, Direction.EXCLUDE): "soft_delete_ticket_package",
    (Level.TRACK, Direction.EXCLUDE): "soft_delete_ticket_package_track",
    (Level.PRODUCT, Direction.EXCLUDE): "soft_delete_ticket_package_product",
    (Level.PACKAGE, Direction.RESTORE): "restore_ticket_package",
    (Level.TRACK, Direction.RESTORE): "restore_ticket_package_track",
    (Level.PRODUCT, Direction.RESTORE): "restore_ticket_package_product",
}
"""The `package_service` operation each endpoint delegates to
(package-service.md, Exclusion and restoration operations)."""

ENDPOINTS = list(_SERVICE)

_NESTED_PARAMETERS = {
    Level.PACKAGE: ("package_id",),
    Level.TRACK: ("package_id", "track_id"),
    Level.PRODUCT: ("package_id", "track_id", "ticket_package_product_id"),
}

_RESOURCE_NOT_FOUND = b'{"code":"RESOURCE_NOT_FOUND","detail":"Resource not found."}'
_ALREADY_EXCLUDED = {
    "code": "PACKAGE_ALREADY_EXCLUDED",
    "detail": "Record is already excluded.",
}
_NOT_EXCLUDED = {
    "code": "PACKAGE_NOT_EXCLUDED",
    "detail": "Record is not directly excluded.",
}

# The package-model.md example values (Soft-Delete / Restore sections).
_PACKAGE_NAME = "openssl-3"
_REFERENCE = "SUSE:SLE-15-SP6:Update"
_SLES_CPE = "cpe:/o:suse:sles:15:sp6"
_SLES_NAME = "SLES 15-SP6"
_LTSS_CPE = "cpe:/o:suse:sles_ltss:15:sp4"
_LTSS_NAME = "SLES-LTSS 15-SP4"

FIELDS = {
    Level.PACKAGE: {"package_name", "actionable", "non_actionable_reason"},
    Level.TRACK: {"reference", "actionable", "non_actionable_reason"},
    Level.PRODUCT: {
        "id",
        "product_cpe",
        "product_name",
        "actionable",
        "non_actionable_reason",
    },
}
"""package-model.md, the response field table of each section."""

_SCHEMAS = {
    Level.PACKAGE: "PackageExclusionResponse",
    Level.TRACK: "TrackExclusionResponse",
    Level.PRODUCT: "ProductExclusionResponse",
}

_SUMMARIES = {
    (Level.PACKAGE, Direction.EXCLUDE): "Soft-Delete Package from Ticket",
    (Level.PACKAGE, Direction.RESTORE): "Restore Package",
    (Level.TRACK, Direction.EXCLUDE): "Soft-Delete Track",
    (Level.TRACK, Direction.RESTORE): "Restore Track",
    (Level.PRODUCT, Direction.EXCLUDE): "Soft-Delete Product",
    (Level.PRODUCT, Direction.RESTORE): "Restore Product",
}

_MARKER_EVENT_TYPES = {
    f"{level}_{suffix}" for level in Level for suffix in ("excluded", "restored")
}


def _endpoint_id(endpoint: tuple[Level, Direction]) -> str:
    return f"{endpoint[0]}-{endpoint[1]}"


ENDPOINT_PARAMS = pytest.mark.parametrize("endpoint", ENDPOINTS, ids=_endpoint_id)


def openapi_path(level: Level, direction: Direction) -> str:
    return _TEMPLATES[level].replace("{direction}", direction.value)


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
        level: Level,
        direction: Direction,
        *,
        ticket_id: str | None = None,
        package_id: uuid.UUID | str | None = None,
        track_id: uuid.UUID | str | None = None,
        occurrence_id: uuid.UUID | str | None = None,
    ) -> str:
        return _TEMPLATES[level].format(
            ticket_id=ticket_id if ticket_id is not None else locator(self.ticket),
            package_id=package_id if package_id is not None else self.package.id,
            track_id=track_id if track_id is not None else self.track.id,
            ticket_package_product_id=(
                occurrence_id if occurrence_id is not None else self.occurrence.id
            ),
            direction=direction.value,
        )


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> list[AsyncMock]:
    """Replace the Ticket lookup and all six operations with spies that
    must stay unused."""
    spies = [AsyncMock()]
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", spies[0])
    spies.extend(_forbid_mutations(monkeypatch))
    return spies


def _forbid_mutations(monkeypatch: pytest.MonkeyPatch) -> list[AsyncMock]:
    """Replace all six operations with spies that must stay unused."""
    spies = []
    for name in _SERVICE.values():
        spy = AsyncMock()
        monkeypatch.setattr(package_service, name, spy)
        spies.append(spy)
    return spies


def _assert_unused(spies: list[AsyncMock]) -> None:
    for spy in spies:
        spy.assert_not_awaited()


async def _snapshot(db: AsyncSession, *trees: Tree) -> list[tuple[Any, ...]]:
    """Everything a rejected request must leave unchanged."""
    return [
        (
            await ticket_row(db, tree.ticket.id),
            await markers(db, tree.occurrence),
            await event_count(db, tree.ticket.id),
        )
        for tree in trees
    ]


async def _marker_events(db: AsyncSession, ticket: Ticket) -> list[EventRow]:
    """The Ticket's exclusion and restoration events in insertion order."""
    return [
        e
        for e in await ticket_events(db, ticket)
        if e.event_type in _MARKER_EVENT_TYPES
    ]


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


@pytest.fixture
def build(
    ticket_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    product_factory: Factory,
    ticket_package_product_factory: Factory,
) -> Callable[..., Awaitable[Tree]]:
    """Create a Ticket (columns from `ticket_columns`) with one package, one
    `AFFECTED` track, and one eligible occurrence of a catalog Product that
    is in General Support on `EVAL` (or EOL on `EVAL` when `eol`). Each
    `*_excluded` seeds that direct marker with `SEEDED_AT`. Without an
    explicit `cpe`, the CPE is derived from the Ticket, so one test may
    build several trees."""

    async def _build(
        *,
        package_excluded: bool = False,
        track_excluded: bool = False,
        product_excluded: bool = False,
        eol: bool = False,
        cpe: str | None = None,
        product_name: str = _SLES_NAME,
        product_columns: dict[str, Any] | None = None,
        **ticket_columns: Any,
    ) -> Tree:
        ticket: Ticket = await ticket_factory(**ticket_columns)
        package = await ticket_package_factory(
            ticket_id=ticket.id,
            package_name=_PACKAGE_NAME,
            deleted_at=SEEDED_AT if package_excluded else None,
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference=_REFERENCE,
            status=PackageStatus.AFFECTED.value,
            deleted_at=SEEDED_AT if track_excluded else None,
        )
        columns: dict[str, Any] = {
            "cpe": cpe or f"cpe:/o:example:alpha:15:{ticket.sequence_id}",
            "display_name": product_name,
            "general_support_end_date": BEFORE_EVAL if eol else AFTER_EVAL,
        }
        columns.update(product_columns or {})
        product = await product_factory(**columns)
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            deleted_at=SEEDED_AT if product_excluded else None,
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
        spies = _forbid_lookups(monkeypatch)

        for level, direction in ENDPOINTS:
            for ticket_id in (None, f"SNTL-{MAX_SEQUENCE}"):
                response = await client.post(
                    tree.url(level, direction, ticket_id=ticket_id), headers=headers
                )
                assert response.status_code == 401, (level, direction)
                assert response.json() == UNAUTHENTICATED

        _assert_unused(spies)
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
        monkeypatch: pytest.MonkeyPatch,
        roles: tuple[Role, ...],
    ) -> None:
        """The same generic 403, before any lookup or validation, on every
        endpoint for an existing, a missing, an inaccessible (confidential;
        the role-less caller's scope is `non_confidential`), a malformed,
        and a UUID-form `{ticket_id}`, and for malformed nested UUIDs. A
        role-less user holds no capability; `admin` holds `admin_ticket_ops`
        but not `manage_packages` (rbac.md, Predefined Roles)."""
        await grant(*roles)
        tree = await build(package_excluded=True)
        hidden = await build(is_confidential=True)
        before = await _snapshot(db_session, tree, hidden)
        spies = _forbid_lookups(monkeypatch)

        responses = [
            await authenticated_client.post(url)
            for level, direction in ENDPOINTS
            for url in (
                tree.url(level, direction),
                tree.url(level, direction, ticket_id=f"SNTL-{MAX_SEQUENCE}"),
                hidden.url(level, direction),
                tree.url(level, direction, ticket_id="not-a-ticket"),
                tree.url(level, direction, ticket_id=str(tree.ticket.id)),
                tree.url(
                    level,
                    direction,
                    package_id="not-a-uuid",
                    track_id="not-a-uuid",
                    occurrence_id="not-a-uuid",
                ),
            )
        ]

        assert [r.status_code for r in responses] == [403] * len(responses)
        assert {r.content for r in responses} == {responses[0].content}
        assert responses[0].json() == FORBIDDEN
        _assert_unused(spies)
        assert await _snapshot(db_session, tree, hidden) == before

    @pytest.mark.parametrize(
        "role",
        [
            pytest.param(Role.VULNERABILITY_ANALYST, id="vulnerability_analyst"),
            pytest.param(Role.RESTRICTED_ANALYST, id="restricted_analyst"),
        ],
    )
    async def test_predefined_role_with_manage_packages_uses_every_endpoint(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        role: Role,
    ) -> None:
        """rbac.md, Predefined Roles and Endpoint Permission Map: both
        analyst roles hold `manage_packages`. The six endpoints applied
        bottom-up and back each succeed and record their direct event."""
        user = await grant(role)
        tree = await build(status=TicketStatus.ANALYSIS.value)
        sequence = [
            (Level.PRODUCT, Direction.EXCLUDE),
            (Level.TRACK, Direction.EXCLUDE),
            (Level.PACKAGE, Direction.EXCLUDE),
            (Level.PACKAGE, Direction.RESTORE),
            (Level.TRACK, Direction.RESTORE),
            (Level.PRODUCT, Direction.RESTORE),
        ]

        for level, direction in sequence:
            response = await authenticated_client.post(tree.url(level, direction))
            assert response.status_code == 200, (level, direction)

        assert await markers(db_session, tree.occurrence) == (None, None, None)
        assert await _marker_events(db_session, tree.ticket) == [
            await marker_event(db_session, level, direction, tree.occurrence, user)
            for level, direction in sequence
        ]

    @ENDPOINT_PARAMS
    async def test_roles_are_loaded_once_per_request(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        endpoint: tuple[Level, Direction],
    ) -> None:
        """The capability check and the Ticket caller (scope for the
        preliminary and the locked accessibility decisions) share one role
        load (api-spec.md, Authorization Chain Evaluation Order)."""
        level, direction = endpoint
        user = await grant(Role.VULNERABILITY_ANALYST)
        restore = direction is Direction.RESTORE
        tree = await build(
            is_confidential=True,
            status=TicketStatus.ANALYSIS.value,
            package_excluded=restore and level is Level.PACKAGE,
            track_excluded=restore and level is Level.TRACK,
            product_excluded=restore and level is Level.PRODUCT,
        )
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.post(tree.url(level, direction))

        assert response.status_code == 200
        assert calls == [user.id]


# ---------------------------------------------------------------------------
# Nested path validation (global 422) and its ordering after the Ticket check
# ---------------------------------------------------------------------------

_UUID_MESSAGE = "Input should be a valid UUID, invalid character: found `n` at 1"


def _uuid_error(name: str) -> dict[str, Any]:
    return {"loc": ["path", name], "msg": _UUID_MESSAGE, "type": "uuid_parsing"}


_MALFORMED_CASES = [
    pytest.param(Level.PACKAGE, ("package_id",), id="package-package_id"),
    pytest.param(Level.TRACK, ("package_id",), id="track-package_id"),
    pytest.param(Level.TRACK, ("track_id",), id="track-track_id"),
    pytest.param(Level.TRACK, ("package_id", "track_id"), id="track-all"),
    pytest.param(Level.PRODUCT, ("package_id",), id="product-package_id"),
    pytest.param(Level.PRODUCT, ("track_id",), id="product-track_id"),
    pytest.param(
        Level.PRODUCT, ("ticket_package_product_id",), id="product-occurrence_id"
    ),
    pytest.param(
        Level.PRODUCT,
        ("package_id", "track_id", "ticket_package_product_id"),
        id="product-all",
    ),
]


@pytest.mark.e2e
class TestPathValidation:
    @DIRECTIONS
    @pytest.mark.parametrize(("level", "names"), _MALFORMED_CASES)
    async def test_malformed_nested_uuid_is_a_422_on_an_accessible_ticket(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        names: tuple[str, ...],
        direction: Direction,
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(
            package_excluded=True, track_excluded=True, product_excluded=True
        )
        before = await _snapshot(db_session, tree)
        spies = _forbid_mutations(monkeypatch)
        url = tree.url(
            level,
            direction,
            package_id="not-a-uuid" if "package_id" in names else None,
            track_id="not-a-uuid" if "track_id" in names else None,
            occurrence_id=(
                "not-a-uuid" if "ticket_package_product_id" in names else None
            ),
        )

        response = await authenticated_client.post(url)

        assert response.status_code == 422
        assert response.json() == validation_error(*[_uuid_error(n) for n in names])
        _assert_unused(spies)
        assert await _snapshot(db_session, tree) == before

    async def test_ticket_not_found_precedes_nested_path_validation(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Observed ordering (module docstring): for a `restricted_analyst`
        caller holding `manage_packages`, every endpoint returns the
        identical `404 TICKET_NOT_FOUND` for an inaccessible, a missing, and
        a malformed Ticket whether or not its nested UUIDs are malformed,
        because the Ticket accessibility dependency resolves before the
        endpoint's path validation. No operation runs."""
        await grant(Role.RESTRICTED_ANALYST)
        hidden = await build(is_confidential=True)
        before = await _snapshot(db_session, hidden)
        spies = _forbid_mutations(monkeypatch)

        responses = [
            await authenticated_client.post(
                hidden.url(
                    level,
                    direction,
                    ticket_id=ticket_id,
                    package_id=malformed,
                    track_id=malformed,
                    occurrence_id=malformed,
                )
            )
            for level, direction in ENDPOINTS
            for ticket_id in (
                locator(hidden.ticket),
                f"SNTL-{MAX_SEQUENCE}",
                "not-a-ticket",
            )
            for malformed in (None, "not-a-uuid")
        ]

        assert [r.status_code for r in responses] == [404] * len(responses)
        assert {r.content for r in responses} == {NOT_FOUND}
        _assert_unused(spies)
        assert await _snapshot(db_session, hidden) == before


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
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
    ) -> None:
        """Malformed `{ticket_id}` forms, the Ticket UUID in place of
        `SNTL-{n}`, and a well-formed missing `SNTL-{n}` on every endpoint
        (api-spec.md, Ticket Identifier Resolution)."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(track_excluded=True)
        before = await _snapshot(db_session, tree)
        spies = _forbid_mutations(monkeypatch)

        for level, direction in ENDPOINTS:
            response = await authenticated_client.post(
                tree.url(level, direction, ticket_id=build_locator(tree.ticket))
            )
            assert response.status_code == 404, (level, direction)
            assert response.content == NOT_FOUND

        _assert_unused(spies)
        assert await _snapshot(db_session, tree) == before

    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
    ) -> None:
        """A `restricted_analyst` (scope `non_confidential`, no grant, not a
        maintainer) cannot see a confidential Ticket: the same complete body
        as a missing one, with the operation never applied."""
        await grant(Role.RESTRICTED_ANALYST)
        hidden = await build(is_confidential=True, track_excluded=True)
        before = await _snapshot(db_session, hidden)

        for level, direction in ENDPOINTS:
            inaccessible = await authenticated_client.post(hidden.url(level, direction))
            missing = await authenticated_client.post(
                hidden.url(level, direction, ticket_id=f"SNTL-{MAX_SEQUENCE}")
            )
            assert inaccessible.status_code == missing.status_code == 404
            assert inaccessible.content == missing.content == NOT_FOUND

        assert await _snapshot(db_session, hidden) == before

    @ENDPOINT_PARAMS
    async def test_locked_current_denial_maps_to_the_identical_404(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        endpoint: tuple[Level, Direction],
    ) -> None:
        """The preliminary check passes, but the service's authoritative
        locked-current accessibility denies (access lost while waiting for
        the Ticket lock, proven in the service race tests): the handler maps
        the shared `TicketNotFoundError` to the same 404 body."""
        level, direction = endpoint
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        monkeypatch.setattr(
            package_service,
            _SERVICE[endpoint],
            AsyncMock(side_effect=TicketNotFoundError()),
        )

        response = await authenticated_client.post(tree.url(level, direction))

        assert response.status_code == 404
        assert response.content == NOT_FOUND


# ---------------------------------------------------------------------------
# Nested-resource ownership (identical 404 RESOURCE_NOT_FOUND)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNestedResourceNotFound:
    @DIRECTIONS
    @LEVELS
    async def test_missing_or_mismatched_nested_identifiers_share_one_404(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        level: Level,
        direction: Direction,
    ) -> None:
        """package-model.md, API Endpoints: a missing ID or any ownership
        mismatch at any level returns one identical `404
        RESOURCE_NOT_FOUND`, never changes or reveals the record under the
        other path, and the occurrence locator is never the catalog
        `Product.id`. For a restore, every marker is seeded so a wrongly
        accepted path would clear one."""
        await grant(Role.VULNERABILITY_ANALYST)
        seeded = direction is Direction.RESTORE
        marker = SEEDED_AT if seeded else None
        tree = await build(
            status=TicketStatus.ANALYSIS.value,
            package_excluded=seeded,
            track_excluded=seeded,
            product_excluded=seeded,
        )
        sibling_package = await ticket_package_factory(
            ticket_id=tree.ticket.id, package_name="example-tool", deleted_at=marker
        )
        sibling_track = await ticket_package_track_factory(
            ticket_package_id=sibling_package.id, deleted_at=marker
        )
        sibling_occurrence = await ticket_package_product_factory(
            ticket_package_track_id=sibling_track.id,
            product_id=tree.product.id,
            deleted_at=marker,
        )
        own_empty_track = await ticket_package_track_factory(
            ticket_package_id=tree.package.id, deleted_at=marker
        )
        other = await build(
            status=TicketStatus.ANALYSIS.value,
            package_excluded=seeded,
            track_excluded=seeded,
            product_excluded=seeded,
        )
        occurrences = (tree.occurrence, sibling_occurrence, other.occurrence)

        async def observe() -> tuple[Any, ...]:
            return (
                await _snapshot(db_session, tree, other),
                [await markers(db_session, o) for o in occurrences],
                (
                    await db_session.execute(
                        select(TicketPackageTrack.deleted_at).where(
                            TicketPackageTrack.id == own_empty_track.id
                        )
                    )
                ).scalar_one(),
            )

        before = await observe()

        cases: dict[str, dict[str, Any]] = {
            "missing-package": {"package_id": uuid.uuid4()},
            "package-of-other-ticket": {
                "package_id": other.package.id,
                "track_id": other.track.id,
                "occurrence_id": other.occurrence.id,
            },
        }
        if level is not Level.PACKAGE:
            cases |= {
                "missing-track": {"track_id": uuid.uuid4()},
                "track-of-other-package": {
                    "track_id": sibling_track.id,
                    "occurrence_id": sibling_occurrence.id,
                },
                "track-of-other-ticket": {
                    "track_id": other.track.id,
                    "occurrence_id": other.occurrence.id,
                },
            }
        if level is Level.PRODUCT:
            cases |= {
                "missing-occurrence": {"occurrence_id": uuid.uuid4()},
                "occurrence-of-other-track": {"occurrence_id": sibling_occurrence.id},
                "occurrence-of-own-empty-track": {"track_id": own_empty_track.id},
                "catalog-product-id": {"occurrence_id": tree.product.id},
            }
        for name, overrides in cases.items():
            response = await authenticated_client.post(
                tree.url(level, direction, **overrides)
            )
            assert response.status_code == 404, name
            assert response.content == _RESOURCE_NOT_FOUND, name

        assert await observe() == before


# ---------------------------------------------------------------------------
# Direct-marker guards (409 PACKAGE_ALREADY_EXCLUDED, 422 PACKAGE_NOT_EXCLUDED)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMarkerGuards:
    @LEVELS
    async def test_repeated_exclusion_is_a_409_without_effect(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        level: Level,
    ) -> None:
        """package-model.md, Soft-Delete sections: `409
        PACKAGE_ALREADY_EXCLUDED` when the record is already directly
        excluded; the repeat records no event and changes nothing."""
        user = await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(status=TicketStatus.ANALYSIS.value)
        url = tree.url(level, Direction.EXCLUDE)

        first = await authenticated_client.post(url)
        assert first.status_code == 200
        after_first = await _snapshot(db_session, tree)

        repeated = await authenticated_client.post(url)

        assert repeated.status_code == 409
        assert repeated.json() == _ALREADY_EXCLUDED
        assert await _snapshot(db_session, tree) == after_first
        assert await _marker_events(db_session, tree.ticket) == [
            await marker_event(
                db_session, level, Direction.EXCLUDE, tree.occurrence, user
            )
        ]

    @LEVELS
    async def test_restore_of_a_record_never_excluded_is_a_422_without_effect(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        level: Level,
    ) -> None:
        """package-model.md, Restore sections: `422 PACKAGE_NOT_EXCLUDED`
        for a record that is not directly soft-deleted. The unassigned `New`
        Ticket stays unassigned (the guard precedes auto-assignment)."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        before = await _snapshot(db_session, tree)

        response = await authenticated_client.post(tree.url(level, Direction.RESTORE))

        assert response.status_code == 422
        assert response.json() == _NOT_EXCLUDED
        assert await _snapshot(db_session, tree) == before
        assert (await ticket_row(db_session, tree.ticket.id))["assignee_id"] is None

    async def test_restore_of_a_record_excluded_only_through_an_ancestor_is_a_422(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
    ) -> None:
        """An exclusion inherited from an ancestor is not a direct marker
        (package-model.md, Restore; package-service.md, Service Exceptions:
        `PackageNotExcludedError` on `deleted_at IS NULL`). One HTTP
        representative; every ancestor combination is proven at the service
        tier (`test_package_exclusion.py`, `TestDirectMarkerGuard`)."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(package_excluded=True)
        before = await _snapshot(db_session, tree)

        response = await authenticated_client.post(
            tree.url(Level.PRODUCT, Direction.RESTORE)
        )

        assert response.status_code == 422
        assert response.json() == _NOT_EXCLUDED
        assert await _snapshot(db_session, tree) == before


# ---------------------------------------------------------------------------
# Manual-zone mutability guard (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNotMutable:
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
    ) -> None:
        """Every endpoint returns `409 TICKET_NOT_MUTABLE` with no effect on
        an otherwise valid request: exclusions target a clear tree and
        restores a tree whose three markers are set."""
        await grant(Role.VULNERABILITY_ANALYST)
        clear = await build(status=status.value)
        seeded = await build(
            status=status.value,
            package_excluded=True,
            track_excluded=True,
            product_excluded=True,
        )
        before = await _snapshot(db_session, clear, seeded)

        for level, direction in ENDPOINTS:
            tree = clear if direction is Direction.EXCLUDE else seeded
            response = await authenticated_client.post(tree.url(level, direction))
            assert response.status_code == 409, (level, direction)
            assert response.json() == NOT_MUTABLE

        assert await _snapshot(db_session, clear, seeded) == before


# ---------------------------------------------------------------------------
# Successful response (200): the exact documented bodies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Scenario:
    """One successful request and its documented `data` (for a Product,
    without the occurrence `id`, which is added from the fixture)."""

    level: Level
    direction: Direction
    expected: dict[str, Any]
    package_excluded: bool = False
    track_excluded: bool = False
    product_excluded: bool = False
    eol: bool = False
    cpe: str = _SLES_CPE
    product_name: str = _SLES_NAME


def _package(actionable: bool, reason: str | None) -> dict[str, Any]:
    return {
        "package_name": _PACKAGE_NAME,
        "actionable": actionable,
        "non_actionable_reason": reason,
    }


def _track(actionable: bool, reason: str | None) -> dict[str, Any]:
    return {
        "reference": _REFERENCE,
        "actionable": actionable,
        "non_actionable_reason": reason,
    }


def _product(
    actionable: bool,
    reason: str | None,
    cpe: str = _SLES_CPE,
    name: str = _SLES_NAME,
) -> dict[str, Any]:
    return {
        "product_cpe": cpe,
        "product_name": name,
        "actionable": actionable,
        "non_actionable_reason": reason,
    }


_SCENARIOS = [
    pytest.param(
        Scenario(Level.PACKAGE, Direction.EXCLUDE, _package(False, "package_excluded")),
        id="package-exclude-example",
    ),
    pytest.param(
        Scenario(
            Level.PACKAGE,
            Direction.RESTORE,
            _package(True, None),
            package_excluded=True,
        ),
        id="package-restore-example",
    ),
    pytest.param(
        Scenario(
            Level.PACKAGE,
            Direction.RESTORE,
            _package(False, "no_actionable_tracks"),
            package_excluded=True,
            track_excluded=True,
        ),
        id="package-restore-no-actionable-tracks",
    ),
    pytest.param(
        Scenario(Level.TRACK, Direction.EXCLUDE, _track(False, "track_excluded")),
        id="track-exclude-example",
    ),
    pytest.param(
        Scenario(
            Level.TRACK,
            Direction.EXCLUDE,
            _track(False, "package_excluded"),
            package_excluded=True,
        ),
        id="track-exclude-beneath-excluded-package-example",
    ),
    pytest.param(
        Scenario(
            Level.TRACK, Direction.RESTORE, _track(True, None), track_excluded=True
        ),
        id="track-restore-example",
    ),
    pytest.param(
        Scenario(
            Level.TRACK,
            Direction.RESTORE,
            _track(False, "no_actionable_products"),
            track_excluded=True,
            eol=True,
        ),
        id="track-restore-no-actionable-products",
    ),
    pytest.param(
        Scenario(Level.PRODUCT, Direction.EXCLUDE, _product(False, "product_excluded")),
        id="product-exclude-example",
    ),
    pytest.param(
        Scenario(
            Level.PRODUCT,
            Direction.EXCLUDE,
            _product(False, "track_excluded"),
            track_excluded=True,
            eol=True,
        ),
        id="product-exclude-eol-beneath-excluded-track",
    ),
    pytest.param(
        Scenario(
            Level.PRODUCT,
            Direction.RESTORE,
            _product(False, "eol", _LTSS_CPE, _LTSS_NAME),
            product_excluded=True,
            eol=True,
            cpe=_LTSS_CPE,
            product_name=_LTSS_NAME,
        ),
        id="product-restore-eol-example",
    ),
    pytest.param(
        Scenario(
            Level.PRODUCT,
            Direction.RESTORE,
            _product(True, None),
            product_excluded=True,
        ),
        id="product-restore-in-support",
    ),
]


@pytest.mark.e2e
class TestResponse:
    @pytest.mark.parametrize("scenario", _SCENARIOS)
    async def test_success_returns_the_exact_documented_body(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        scenario: Scenario,
    ) -> None:
        """package-model.md, the six endpoint sections: `{"data": {...}}`
        with exactly the documented fields and the first applicable reason
        (Derived Actionability) on the handler's UTC date `EVAL`, including
        every documented non-actionable success. Only the target marker
        changes (to the exclusion instant, or cleared), and exactly one
        direct event is recorded."""
        user = await grant(Role.VULNERABILITY_ANALYST)
        monkeypatch.setattr(
            route, "_utc_now", Clock(datetime.combine(EVAL, time(12), UTC)).now
        )
        patch_marker_now(monkeypatch)
        tree = await build(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=user.id,
            package_excluded=scenario.package_excluded,
            track_excluded=scenario.track_excluded,
            product_excluded=scenario.product_excluded,
            eol=scenario.eol,
            cpe=scenario.cpe,
            product_name=scenario.product_name,
        )
        before: Markers = await markers(db_session, tree.occurrence)
        expected = dict(scenario.expected)
        if scenario.level is Level.PRODUCT:
            expected = {"id": str(tree.occurrence.id), **expected}

        response = await authenticated_client.post(
            tree.url(scenario.level, scenario.direction)
        )

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        assert set(body["data"]) == FIELDS[scenario.level]
        assert body == {"data": expected}
        assert str(tree.ticket.id) not in response.text
        assert str(tree.product.id) not in response.text
        value = MARKER_NOW if scenario.direction is Direction.EXCLUDE else None
        assert await markers(db_session, tree.occurrence) == with_target(
            before, scenario.level, value
        )
        assert await _marker_events(db_session, tree.ticket) == [
            await marker_event(
                db_session, scenario.level, scenario.direction, tree.occurrence, user
            )
        ]

    async def test_excluded_eol_product_reports_product_excluded_after_track_restore(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """package-model.md, Soft-Delete Product example: excluding an EOL
        Product beneath an excluded track reports `track_excluded`; after
        the track is restored, the still directly excluded Product reports
        `product_excluded`, not `eol` (observed through the package tree)."""
        user = await grant(Role.VULNERABILITY_ANALYST)
        monkeypatch.setattr(
            route, "_utc_now", Clock(datetime.combine(EVAL, time(12), UTC)).now
        )
        tree = await build(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=user.id,
            track_excluded=True,
            eol=True,
        )

        excluded = await authenticated_client.post(
            tree.url(Level.PRODUCT, Direction.EXCLUDE)
        )
        restored = await authenticated_client.post(
            tree.url(Level.TRACK, Direction.RESTORE)
        )
        listed = await authenticated_client.get(
            f"/api/v1/tickets/{locator(tree.ticket)}/packages"
        )

        assert excluded.status_code == restored.status_code == listed.status_code == 200
        assert excluded.json()["data"]["non_actionable_reason"] == "track_excluded"
        assert restored.json() == {"data": _track(False, "no_actionable_products")}
        (package,) = listed.json()["data"]
        (track,) = package["tracks"]
        (product,) = track["products"]
        assert (
            product["lifecycle_phase"],
            product["actionable"],
            product["non_actionable_reason"],
        ) == ("eol", False, "product_excluded")


# ---------------------------------------------------------------------------
# Commit by the request transaction and maintainer self-loss
# ---------------------------------------------------------------------------


CommittedWorld = tuple[CommittedApp, AsyncClient, list[uuid.UUID]]


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[CommittedWorld]:
    """`committed_app_client()` that also deletes the committed package tree
    and maintainer associations of its Tickets and the listed catalog
    Products before the shared cleanup."""
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


def _packages_url(ticket: Ticket) -> str:
    return f"/api/v1/tickets/{locator(ticket)}/packages"


@pytest.mark.e2e
class TestTransaction:
    async def test_each_effective_change_is_committed_by_the_request_transaction(
        self, committed_app: CommittedWorld
    ) -> None:
        """A VA applies the six endpoints bottom-up and back on an
        unassigned CVE-less `New` Ticket without severity. Each response is
        the documented body (the restores walk through the
        `no_actionable_tracks` and `no_actionable_products` variants), each
        marker is visible to a fresh session after the request, and the
        committed events are the auto-assignment and its promotion followed
        by the six direct events; without a resolved severity the Ticket
        stays in Analysis."""
        world, committed_client, product_ids = committed_app
        actor, headers = await world.va_headers()
        ticket = await world.ticket()
        db = await world.session()
        suffix = uuid.uuid4().hex[:10]
        package = TicketPackage(ticket_id=ticket.id, package_name=_PACKAGE_NAME)
        product = Product(
            name=f"Example Product {suffix}",
            version="15",
            display_name=_SLES_NAME,
            cpe=f"cpe:/o:example:alpha:15:{suffix}",
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
        # The committed setup session is independent of every request
        # session; under READ COMMITTED each later statement observes only
        # committed request effects.
        observer = db
        tree = Tree(ticket, package, track, product, occurrence)
        product_data = {
            "id": str(occurrence.id),
            **_product(True, None, product.cpe, _SLES_NAME),
        }

        steps: list[tuple[Level, Direction, dict[str, Any], tuple[bool, ...]]] = [
            # (level, direction, data, persisted (package, track, Product) set)
            (
                Level.PRODUCT,
                Direction.EXCLUDE,
                {
                    **product_data,
                    "actionable": False,
                    "non_actionable_reason": "product_excluded",
                },
                (False, False, True),
            ),
            (
                Level.TRACK,
                Direction.EXCLUDE,
                _track(False, "track_excluded"),
                (False, True, True),
            ),
            (
                Level.PACKAGE,
                Direction.EXCLUDE,
                _package(False, "package_excluded"),
                (True, True, True),
            ),
            (
                Level.PACKAGE,
                Direction.RESTORE,
                _package(False, "no_actionable_tracks"),
                (False, True, True),
            ),
            (
                Level.TRACK,
                Direction.RESTORE,
                _track(False, "no_actionable_products"),
                (False, False, True),
            ),
            (Level.PRODUCT, Direction.RESTORE, product_data, (False, False, False)),
        ]
        for level, direction, data, persisted in steps:
            response = await committed_client.post(
                tree.url(level, direction), headers=headers
            )
            assert response.status_code == 200, (level, direction)
            assert response.json() == {"data": data}
            current = await markers_by_id(observer, occurrence.id)
            assert tuple(m is not None for m in current) == persisted

        events = await ticket_events(observer, ticket)
        assert [e.event_type for e in events] == [
            "assignment",
            "status_change",
            "product_excluded",
            "track_excluded",
            "package_excluded",
            "package_restored",
            "track_restored",
            "product_restored",
        ]
        assert {e.user_id for e in events[2:]} == {actor.id}
        state = await ticket_row(observer, ticket.id)
        assert (state["status"], state["assignee_id"]) == (
            TicketStatus.ANALYSIS.value,
            actor.id,
        )

    async def test_restricted_analyst_may_exclude_its_last_maintained_package(
        self, committed_app: CommittedWorld
    ) -> None:
        """testing-strategy.md, Ticket Accessibility (Locked mutations,
        self-loss; canonical predicate rows for package exclusion and
        multiple qualifying packages) and package-model.md, API Endpoints:
        a `restricted_analyst` sees a confidential Ticket only through two
        included maintained packages. Excluding the first preserves access;
        excluding the last returns the ordinary success body, and every
        later request returns `404 TICKET_NOT_FOUND`."""
        world, committed_client, _ = committed_app
        analyst, headers = await world.va_headers(role=Role.RESTRICTED_ANALYST)
        ticket = await world.ticket(
            is_confidential=True, status=TicketStatus.ANALYSIS.value
        )
        db = await world.session()
        first = TicketPackage(ticket_id=ticket.id, package_name="example-lib")
        last = TicketPackage(ticket_id=ticket.id, package_name="example-tool")
        db.add_all([first, last])
        await db.flush()
        db.add_all(
            [
                TicketPackageMaintainer(ticket_package_id=p.id, user_id=analyst.id)
                for p in (first, last)
            ]
        )
        await db.commit()

        def exclude_url(package: TicketPackage, direction: Direction) -> str:
            return _TEMPLATES[Level.PACKAGE].format(
                ticket_id=locator(ticket), package_id=package.id, direction=direction
            )

        visible = await committed_client.get(_packages_url(ticket), headers=headers)
        assert visible.status_code == 200

        kept = await committed_client.post(
            exclude_url(first, Direction.EXCLUDE), headers=headers
        )
        still_visible = await committed_client.get(
            _packages_url(ticket), headers=headers
        )
        lost = await committed_client.post(
            exclude_url(last, Direction.EXCLUDE), headers=headers
        )

        assert kept.status_code == still_visible.status_code == lost.status_code == 200
        assert lost.json() == {
            "data": {
                "package_name": "example-tool",
                "actionable": False,
                "non_actionable_reason": "package_excluded",
            }
        }
        for later in (
            await committed_client.get(_packages_url(ticket), headers=headers),
            await committed_client.post(
                exclude_url(last, Direction.RESTORE), headers=headers
            ),
        ):
            assert later.status_code == 404
            assert later.content == NOT_FOUND
        assert [
            (e.event_type, e.user_id, e.old_value)
            for e in await ticket_events(db, ticket)
        ] == [
            ("package_excluded", analyst.id, "example-lib"),
            ("package_excluded", analyst.id, "example-tool"),
        ]


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
    @ENDPOINT_PARAMS
    async def test_one_date_captured_before_midnight_drives_reconciliation_and_response(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        endpoint: tuple[Level, Direction],
    ) -> None:
        """The only Product's General Support ends on `captured` (inclusive)
        and it is EOL the next day (product-catalog.md, Lifecycle
        Evaluator). The handler captures `captured` just before UTC midnight
        and passes it to the operation, which reuses it for reconciliation
        and the locked-current projection (package-model.md, Derived
        Actionability). A restore therefore reports the record actionable
        (the next day would report `no_actionable_tracks`,
        `no_actionable_products`, or `eol`); an exclusion reports its own
        reason. Every other clock returns the next day and stays unread."""
        level, direction = endpoint
        captured = date(2026, 12, 31)
        next_day = date(2027, 1, 1)
        handler_clock = Clock(datetime(2026, 12, 31, 23, 59, 59, 999000, tzinfo=UTC))
        service_clock = _DateClock(next_day)
        mutation_clock = Clock(datetime(2027, 1, 1, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(package_service, "_utc_today", service_clock.today)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        seen: dict[str, list[date | None]] = {"operation": [], "reconcile": []}
        name = _SERVICE[endpoint]
        original_operation = getattr(package_service, name)
        # `package_service` composes the `ticket_mutations` primitive by name.
        original_reconcile = ticket_mutations.reconcile_ticket_status

        async def _operation(db: AsyncSession, **kwargs: Any) -> Any:
            seen["operation"].append(kwargs.get("evaluation_date"))
            return await original_operation(db, **kwargs)

        async def _reconcile(ticket: Ticket, db: AsyncSession, **kwargs: Any) -> None:
            seen["reconcile"].append(kwargs.get("evaluation_date"))
            await original_reconcile(ticket, db, **kwargs)

        monkeypatch.setattr(package_service, name, _operation)
        monkeypatch.setattr(package_service, "reconcile_ticket_status", _reconcile)
        user = await grant(Role.VULNERABILITY_ANALYST)
        restore = direction is Direction.RESTORE
        tree = await build(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=user.id,
            package_excluded=restore and level is Level.PACKAGE,
            track_excluded=restore and level is Level.TRACK,
            product_excluded=restore and level is Level.PRODUCT,
            product_columns={"general_support_end_date": captured},
        )

        response = await authenticated_client.post(tree.url(level, direction))

        assert response.status_code == 200
        data = response.json()["data"]
        expected = (True, None) if restore else (False, f"{level}_excluded")
        assert (data["actionable"], data["non_actionable_reason"]) == expected
        assert seen == {"operation": [captured], "reconcile": [captured]}
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

    @ENDPOINT_PARAMS
    def test_operation_is_a_body_less_post_with_uuid_nested_parameters(
        self, endpoint: tuple[Level, Direction]
    ) -> None:
        level, direction = endpoint
        path_item = self._spec()["paths"][openapi_path(level, direction)]

        assert set(path_item) == {"post"}
        operation = path_item["post"]
        assert operation["summary"] == _SUMMARIES[endpoint]
        assert operation["tags"] == ["Ticket Packages"]
        assert "requestBody" not in operation
        parameters = {p["name"]: p for p in operation["parameters"]}
        assert set(parameters) == {"ticket_id", *_NESTED_PARAMETERS[level]}
        assert all(
            p["in"] == "path" and p["required"] is True for p in parameters.values()
        )
        assert parameters["ticket_id"]["schema"]["type"] == "string"
        assert "format" not in parameters["ticket_id"]["schema"]
        for name in _NESTED_PARAMETERS[level]:
            schema = parameters[name]["schema"]
            assert (schema["type"], schema["format"]) == ("string", "uuid")

    @ENDPOINT_PARAMS
    def test_responses_declare_the_documented_envelopes(
        self, endpoint: tuple[Level, Direction]
    ) -> None:
        level, direction = endpoint
        responses = self._spec()["paths"][openapi_path(level, direction)]["post"][
            "responses"
        ]

        assert self._ref_name(responses["200"]["content"]) == _SCHEMAS[level]
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "RESOURCE_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "422" in responses
        if direction is Direction.EXCLUDE:
            assert "PACKAGE_ALREADY_EXCLUDED" in responses["409"]["description"]
        else:
            assert "PACKAGE_ALREADY_EXCLUDED" not in responses["409"]["description"]
            assert self._ref_name(responses["422"]["content"]) == "ErrorResponse"
            assert "PACKAGE_NOT_EXCLUDED" in responses["422"]["description"]

    @LEVELS
    def test_response_schema_has_exactly_the_documented_fields(
        self, level: Level
    ) -> None:
        envelope = self._resolve({"$ref": f"#/components/schemas/{_SCHEMAS[level]}"})
        assert set(envelope["properties"]) == {"data"}
        assert envelope["required"] == ["data"]
        record = self._resolve(envelope["properties"]["data"])
        assert set(record["properties"]) == FIELDS[level]
        assert set(record["required"]) == FIELDS[level]
        # The only UUID is the Product occurrence locator; no Ticket identity.
        assert [
            name
            for name, p in record["properties"].items()
            if self._resolve(p).get("format") == "uuid"
        ] == (["id"] if level is Level.PRODUCT else [])
