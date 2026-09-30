"""End-to-end tests for the Change Track Status endpoint
(`PATCH /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}`,
`backend/app/api/v1/ticket_packages.py`).

See docs/features/packages/package-model.md (API Endpoints; Change Track
Status, including the † capability note and the response field table;
Security), docs/api-spec.md (Authorization Chain Evaluation Order flow 3
and alternative capabilities, JSON Request Body Scalar Types, Global
Responses, Ticket Accessibility Check, Anti-Enumeration Boundary,
Manual-Zone Mutability Guard), docs/features/identity/rbac.md (Predefined
Roles; Endpoint Permission Map), and
docs/features/platform/testing-strategy.md (Ticket Accessibility).

These tests cover only the HTTP boundary: authentication, the capability
union and the value-dependent capability check before any lookup, request
validation, the identical not-found bodies, each error mapping, the exact
response shape, the one captured evaluation date, the once-resolved roles,
and OpenAPI. The service matrix (authority, no-op, gate transitions,
auto-assignment, audit payload, ownership, scope, races) is proven in
`tests/test_services/test_set_track_status*.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import ticket_packages as route
from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service, ticket_mutations, ticket_service, user_service
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

_PATH = "/api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
_RESOURCE_NOT_FOUND = b'{"code":"RESOURCE_NOT_FOUND","detail":"Resource not found."}'
_LITERAL_MESSAGE = (
    "Input should be 'analysis', 'affected', 'not_affected', 'fixed' or 'wont_fix'"
)
_ALL_TARGETS = ["analysis", "affected", "not_affected", "fixed", "wont_fix"]
_NON_FIXED_TARGETS = ["analysis", "affected", "not_affected", "wont_fix"]

TRACK_FIELDS = {
    "ticket_id",
    "package_name",
    "reference",
    "status",
    "delivery_status",
    "delivery_relevant",
    "actionable",
    "non_actionable_reason",
    "products",
}
"""package-model.md, Change Track Status response field table."""

PRODUCT_FIELDS = {
    "id",
    "product_cpe",
    "product_name",
    "eligible",
    "is_eligible_override",
    "lifecycle_phase",
    "actionable",
    "non_actionable_reason",
}
"""package-model.md, Change Track Status response field table (`products[]`)."""


@dataclass(frozen=True, slots=True)
class Tree:
    """One Ticket with one package and one track."""

    ticket: Ticket
    package: TicketPackage
    track: TicketPackageTrack

    def url(self, *, ticket_id: str | None = None) -> str:
        return _url(
            ticket_id if ticket_id is not None else self.ticket,
            self.package.id,
            self.track.id,
        )


def _url(
    ticket: Ticket | str, package_id: uuid.UUID | str, track_id: uuid.UUID | str
) -> str:
    return _PATH.format(
        ticket_id=ticket if isinstance(ticket, str) else locator(ticket),
        package_id=package_id,
        track_id=track_id,
    )


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace the Ticket lookup and the mutation with spies that must stay
    unused."""
    resolver = AsyncMock()
    mutation = AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(package_service, "set_track_status", mutation)
    return resolver, mutation


async def _track_status(db: AsyncSession, track: TicketPackageTrack) -> str:
    return (
        await db.execute(
            select(TicketPackageTrack.status).where(TicketPackageTrack.id == track.id)
        )
    ).scalar_one()


async def _track_event_count(db: AsyncSession, ticket_id: uuid.UUID) -> int:
    return (
        await db.execute(
            select(func.count(TicketAuditEvent.id)).where(
                TicketAuditEvent.ticket_id == ticket_id,
                TicketAuditEvent.event_type == "track_status_changed",
            )
        )
    ).scalar_one()


async def _snapshot(db: AsyncSession, tree: Tree) -> tuple[Any, ...]:
    """Everything a rejected request must leave unchanged."""
    return (
        await ticket_row(db, tree.ticket.id),
        await _track_status(db, tree.track),
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


@pytest.fixture
def build(
    ticket_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
) -> Callable[..., Awaitable[Tree]]:
    """Create a Ticket (columns from `ticket_columns`) with one package and
    one track in `track_status`."""

    async def _build(
        *, track_status: PackageStatus = PackageStatus.ANALYSIS, **ticket_columns: Any
    ) -> Tree:
        ticket: Ticket = await ticket_factory(**ticket_columns)
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-lib"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Codestream:15:Update",
            status=track_status.value,
        )
        return Tree(ticket, package, track)

    return _build


# ---------------------------------------------------------------------------
# Authentication and capabilities before any lookup (flow 3, step 1)
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
            for body in ({"status": "fixed"}, {"status": "affected"}, {}):
                response = await client.patch(path, json=body, headers=headers)
                assert response.status_code == 401
                assert response.json() == UNAUTHENTICATED

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    @pytest.mark.parametrize("target", _ALL_TARGETS)
    async def test_caller_without_either_capability_gets_the_generic_403(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        target: str,
    ) -> None:
        cve = await cve_factory()
        tree = await build(cve_id=cve.id)
        before = await _snapshot(db_session, tree)
        resolver, mutation = _forbid_lookups(monkeypatch)

        existing = await authenticated_client.patch(tree.url(), json={"status": target})
        missing = await authenticated_client.patch(
            tree.url(ticket_id=f"SNTL-{MAX_SEQUENCE}"), json={"status": target}
        )
        malformed_nested = await authenticated_client.patch(
            _url(tree.ticket, "not-a-uuid", "not-a-uuid"), json={"status": target}
        )

        assert (
            existing.status_code
            == missing.status_code
            == malformed_nested.status_code
            == 403
        )
        assert existing.content == missing.content == malformed_nested.content
        assert existing.json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    @pytest.mark.parametrize("target", _NON_FIXED_TARGETS)
    async def test_admin_only_caller_gets_403_for_a_non_fixed_target_before_lookup(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        target: str,
    ) -> None:
        """`admin_ticket_ops` satisfies the union, but a non-`fixed` target
        requires `manage_packages` (package-model.md †): the same generic
        403, never a 404, for existing, missing, malformed, and UUID-form
        Ticket identifiers."""
        await grant(Role.ADMIN)
        tree = await build(is_confidential=True)
        before = await _snapshot(db_session, tree)
        resolver, mutation = _forbid_lookups(monkeypatch)

        responses = [
            await authenticated_client.patch(
                tree.url(ticket_id=ticket_id), json={"status": target}
            )
            for ticket_id in (
                locator(tree.ticket),
                f"SNTL-{MAX_SEQUENCE}",
                "not-a-ticket",
                str(tree.ticket.id),
            )
        ]

        assert [r.status_code for r in responses] == [403] * 4
        assert {r.content for r in responses} == {responses[0].content}
        assert responses[0].json() == FORBIDDEN
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    async def test_roles_are_loaded_once_per_request(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The capability union, the value-dependent check, `force`, and the
        Ticket caller share one role load (api-spec.md, flow 3)."""
        user = await grant(Role.VULNERABILITY_ANALYST, Role.ADMIN)
        tree = await build(is_confidential=True)
        calls: list[uuid.UUID] = []
        original = user_service.get_user_roles

        async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
            calls.append(user_id)
            return await original(db, user_id)

        monkeypatch.setattr(user_service, "get_user_roles", _spy)

        response = await authenticated_client.patch(
            tree.url(), json={"status": "fixed"}
        )

        assert response.status_code == 200
        assert calls == [user.id]


# ---------------------------------------------------------------------------
# Request validation (global 422) before the value-dependent check and lookup
# ---------------------------------------------------------------------------

_CAPABLE_ROLES = [
    pytest.param(Role.VULNERABILITY_ANALYST, id="manage_packages"),
    pytest.param(Role.ADMIN, id="admin_ticket_ops-only"),
]


_LITERAL_ERROR = {
    "loc": ["body", "status"],
    "msg": _LITERAL_MESSAGE,
    "type": "literal_error",
}


def _uuid_error(name: str) -> dict[str, Any]:
    return {"loc": ["path", name], "msg": _UUID_MESSAGE, "type": "uuid_parsing"}


_UUID_MESSAGE = "Input should be a valid UUID, invalid character: found `n` at 1"


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize("role", _CAPABLE_ROLES)
    @pytest.mark.parametrize(
        ("body", "error"),
        [
            pytest.param(
                {},
                {"loc": ["body", "status"], "msg": "Field required", "type": "missing"},
                id="omitted",
            ),
            *[
                pytest.param({"status": value}, _LITERAL_ERROR, id=name)
                for name, value in (
                    ("null", None),
                    ("unknown-label", "resolved"),
                    ("uppercase-fixed", "FIXED"),
                    ("uppercase-affected", "AFFECTED"),
                    ("integer", 1),
                    ("boolean", True),
                    ("array", ["fixed"]),
                    ("object", {}),
                )
            ],
        ],
    )
    async def test_invalid_body_is_a_422_before_the_value_check_and_lookup(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        role: Role,
        body: dict[str, Any],
        error: dict[str, Any],
    ) -> None:
        """An `admin_ticket_ops`-only caller also receives 422, not the
        value-dependent 403: the body is validated before that check."""
        await grant(role)
        tree = await build()
        before = await _snapshot(db_session, tree)
        resolver, mutation = _forbid_lookups(monkeypatch)

        for path in (tree.url(), tree.url(ticket_id=f"SNTL-{MAX_SEQUENCE}")):
            response = await authenticated_client.patch(path, json=body)
            assert response.status_code == 422
            assert response.json() == validation_error(error)

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    @pytest.mark.parametrize("role", _CAPABLE_ROLES)
    async def test_absent_body_is_a_validation_error(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        role: Role,
    ) -> None:
        await grant(role)
        tree = await build()
        resolver, mutation = _forbid_lookups(monkeypatch)

        response = await authenticated_client.patch(tree.url())

        assert response.status_code == 422
        assert response.json() == validation_error(
            {"loc": ["body"], "msg": "Field required", "type": "missing"}
        )
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()

    @pytest.mark.parametrize("role", _CAPABLE_ROLES)
    @pytest.mark.parametrize(
        ("level", "errors"),
        [
            pytest.param("package", [_uuid_error("package_id")], id="package"),
            pytest.param("track", [_uuid_error("track_id")], id="track"),
            pytest.param(
                "both",
                [_uuid_error("package_id"), _uuid_error("track_id")],
                id="both",
            ),
        ],
    )
    @pytest.mark.parametrize("target", ["fixed", "affected"])
    async def test_malformed_nested_uuid_is_a_422_before_any_lookup(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
        role: Role,
        level: str,
        errors: list[dict[str, Any]],
        target: str,
    ) -> None:
        """Nested identifiers are UUID path parameters: a malformed value is
        the global 422 after the capability union and before the
        value-dependent check (so an `admin_ticket_ops`-only caller with a
        non-`fixed` target also receives 422) and before any lookup, for a
        missing Ticket too."""
        await grant(role)
        tree = await build()
        before = await _snapshot(db_session, tree)
        resolver, mutation = _forbid_lookups(monkeypatch)
        package_id = "not-a-uuid" if level in ("package", "both") else tree.package.id
        track_id = "not-a-uuid" if level in ("track", "both") else tree.track.id

        for ticket in (tree.ticket, f"SNTL-{MAX_SEQUENCE}"):
            response = await authenticated_client.patch(
                _url(ticket, package_id, track_id), json={"status": target}
            )
            assert response.status_code == 422
            assert response.json() == validation_error(*errors)

        resolver.assert_not_awaited()
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    async def test_path_and_body_errors_are_each_listed_once(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        build: Callable[..., Awaitable[Tree]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        resolver, mutation = _forbid_lookups(monkeypatch)

        response = await authenticated_client.patch(
            _url(tree.ticket, "not-a-uuid", "not-a-uuid"), json={"status": "FIXED"}
        )

        assert response.status_code == 422
        assert response.json() == validation_error(
            _uuid_error("package_id"),
            _uuid_error("track_id"),
            _LITERAL_ERROR,
        )
        resolver.assert_not_awaited()
        mutation.assert_not_awaited()


# ---------------------------------------------------------------------------
# Ticket accessibility and identifier resolution (identical 404)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    @pytest.mark.parametrize("target", ["affected", "fixed"])
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
        target: str,
    ) -> None:
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        before = await _snapshot(db_session, tree)
        mutation = AsyncMock()
        monkeypatch.setattr(package_service, "set_track_status", mutation)

        response = await authenticated_client.patch(
            tree.url(ticket_id=build_locator(tree.ticket)), json={"status": target}
        )

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        mutation.assert_not_awaited()
        assert await _snapshot(db_session, tree) == before

    @pytest.mark.parametrize("target", ["affected", "fixed"])
    async def test_inaccessible_ticket_is_indistinguishable_from_a_missing_one(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
        target: str,
    ) -> None:
        """A `restricted_analyst` (scope `non_confidential`) cannot see a
        confidential Ticket; the CVE-less `fixed` restriction is not
        evaluated before accessibility either."""
        await grant(Role.RESTRICTED_ANALYST)
        cve = await cve_factory()
        hidden = await build(is_confidential=True, cve_id=cve.id)
        before = await _snapshot(db_session, hidden)

        inaccessible = await authenticated_client.patch(
            hidden.url(), json={"status": target}
        )
        missing = await authenticated_client.patch(
            hidden.url(ticket_id=f"SNTL-{MAX_SEQUENCE}"), json={"status": target}
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
            "set_track_status",
            AsyncMock(side_effect=TicketNotFoundError()),
        )

        response = await authenticated_client.patch(
            tree.url(), json={"status": "affected"}
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
    ) -> None:
        """package-model.md, API Endpoints: a missing ID or any ownership
        mismatch returns one identical `404 RESOURCE_NOT_FOUND` and never
        reveals that the child exists under another path."""
        await grant(Role.VULNERABILITY_ANALYST)
        tree = await build()
        sibling_package = await ticket_package_factory(
            ticket_id=tree.ticket.id, package_name="example-tool"
        )
        sibling_track = await ticket_package_track_factory(
            ticket_package_id=sibling_package.id
        )
        other = await build()
        trees = (tree, other)
        tracks = (tree.track, sibling_track, other.track)
        before = (
            [await _snapshot(db_session, t) for t in trees],
            [await _track_status(db_session, t) for t in tracks],
        )

        cases = {
            "missing-package": (uuid.uuid4(), tree.track.id),
            "missing-track": (tree.package.id, uuid.uuid4()),
            "track-of-sibling-package": (tree.package.id, sibling_track.id),
            "package-of-other-ticket": (other.package.id, other.track.id),
            "package-of-other-ticket-own-track": (other.package.id, tree.track.id),
        }
        for name, (package_id, track_id) in cases.items():
            for target in ("affected", "fixed"):
                response = await authenticated_client.patch(
                    _url(tree.ticket, package_id, track_id), json={"status": target}
                )
                assert response.status_code == 404, name
                assert response.content == _RESOURCE_NOT_FOUND, name

        assert (
            [await _snapshot(db_session, t) for t in trees],
            [await _track_status(db_session, t) for t in tracks],
        ) == before


# ---------------------------------------------------------------------------
# Manual-zone mutability guard (409)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNotMutable:
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    @pytest.mark.parametrize(
        ("roles", "target"),
        [
            pytest.param((Role.VULNERABILITY_ANALYST,), "affected", id="va-affected"),
            pytest.param((Role.VULNERABILITY_ANALYST,), "fixed", id="va-fixed"),
            pytest.param((Role.ADMIN,), "fixed", id="admin-fixed"),
        ],
    )
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        status: TicketStatus,
        roles: tuple[Role, ...],
        target: str,
    ) -> None:
        await grant(*roles)
        tree = await build(status=status.value)
        before = await _snapshot(db_session, tree)

        response = await authenticated_client.patch(tree.url(), json={"status": target})

        assert response.status_code == 409
        assert response.json() == NOT_MUTABLE
        assert await _snapshot(db_session, tree) == before


# ---------------------------------------------------------------------------
# `fixed` authority: capability union before access, CVE condition after
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestFixedAuthority:
    async def test_manage_packages_only_fixed_on_a_cve_ticket_is_the_generic_403(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
    ) -> None:
        """The CVE condition is evaluated only after accessibility: the same
        request for a missing Ticket is the ordinary 404, not a 403."""
        await grant(Role.VULNERABILITY_ANALYST)
        cve = await cve_factory()
        tree = await build(cve_id=cve.id)
        before = await _snapshot(db_session, tree)

        restricted = await authenticated_client.patch(
            tree.url(), json={"status": "fixed"}
        )
        missing = await authenticated_client.patch(
            tree.url(ticket_id=f"SNTL-{MAX_SEQUENCE}"), json={"status": "fixed"}
        )

        assert restricted.status_code == 403
        assert restricted.json() == FORBIDDEN
        assert missing.status_code == 404
        assert missing.content == NOT_FOUND
        assert await _snapshot(db_session, tree) == before

    @pytest.mark.parametrize(
        ("roles", "with_cve", "target"),
        [
            pytest.param(
                (Role.VULNERABILITY_ANALYST,), False, "fixed", id="va-cveless-fixed"
            ),
            pytest.param((Role.ADMIN,), True, "fixed", id="admin-cve-fixed"),
            pytest.param((Role.ADMIN,), False, "fixed", id="admin-cveless-fixed"),
            pytest.param(
                (Role.VULNERABILITY_ANALYST, Role.ADMIN),
                True,
                "fixed",
                id="both-cve-fixed",
            ),
            pytest.param(
                (Role.VULNERABILITY_ANALYST, Role.ADMIN),
                True,
                "affected",
                id="both-cve-affected",
            ),
        ],
    )
    async def test_authorized_target_is_applied(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        cve_factory: Factory,
        roles: tuple[Role, ...],
        with_cve: bool,
        target: str,
    ) -> None:
        await grant(*roles)
        cve_id = (await cve_factory()).id if with_cve else None
        tree = await build(cve_id=cve_id)

        response = await authenticated_client.patch(tree.url(), json={"status": target})

        assert response.status_code == 200
        assert response.json()["data"]["status"] == target
        assert await _track_status(db_session, tree.track) == target.upper()
        assert await _track_event_count(db_session, tree.ticket.id) == 1


# ---------------------------------------------------------------------------
# Successful response (200): exact shape for a change and a no-op
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestResponse:
    async def test_change_and_no_op_return_the_exact_track_projection(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        product_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await grant(Role.VULNERABILITY_ANALYST)
        clock = Clock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", clock.now)
        tree = await build(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            assignee_id=user.id,
        )
        eol = await product_factory(
            cpe="cpe:/o:example:beta:15",
            display_name="Example Beta 15",
            general_support_end_date=date(2020, 1, 1),
        )
        supported = await product_factory(
            cpe="cpe:/o:example:alpha:15",
            display_name="Example Alpha 15",
            general_support_end_date=date(2030, 1, 1),
        )
        eol_occurrence = await ticket_package_product_factory(
            ticket_package_track_id=tree.track.id, product_id=eol.id, eligible=False
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=tree.track.id, product_id=supported.id
        )

        changed = await authenticated_client.patch(
            tree.url(), json={"status": "affected"}
        )
        after_change = await _snapshot(db_session, tree)
        no_op = await authenticated_client.patch(
            tree.url(), json={"status": "affected"}
        )

        assert changed.status_code == no_op.status_code == 200
        expected = {
            "data": {
                "ticket_id": locator(tree.ticket),
                "package_name": "example-lib",
                "reference": "Example:Codestream:15:Update",
                "status": "affected",
                "delivery_status": "pending",
                "delivery_relevant": True,
                "actionable": True,
                "non_actionable_reason": None,
                "products": [
                    {
                        "id": str(occurrence.id),
                        "product_cpe": "cpe:/o:example:alpha:15",
                        "product_name": "Example Alpha 15",
                        "eligible": True,
                        "is_eligible_override": False,
                        "lifecycle_phase": "general_support",
                        "actionable": True,
                        "non_actionable_reason": None,
                    },
                    {
                        "id": str(eol_occurrence.id),
                        "product_cpe": "cpe:/o:example:beta:15",
                        "product_name": "Example Beta 15",
                        "eligible": False,
                        "is_eligible_override": False,
                        "lifecycle_phase": "eol",
                        "actionable": False,
                        "non_actionable_reason": "eol",
                    },
                ],
            }
        }
        for response in (changed, no_op):
            body = response.json()
            assert set(body) == {"data"}
            assert set(body["data"]) == TRACK_FIELDS
            assert all(set(p) == PRODUCT_FIELDS for p in body["data"]["products"])
            assert body == expected
            assert str(tree.ticket.id) not in response.text
            assert tree.ticket.id.hex not in response.text
        # The effective change recorded exactly one track event and reached
        # the gate (Analysis -> Analyzed); the no-op changed nothing.
        assert await _track_event_count(db_session, tree.ticket.id) == 1
        assert after_change[0]["status"] == TicketStatus.ANALYZED.value
        assert await _snapshot(db_session, tree) == after_change
        assert clock.calls == 2


@pytest_asyncio.fixture
async def committed_app(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncGenerator[tuple[CommittedApp, AsyncClient]]:
    """`committed_app_client()` that also deletes the committed package tree
    of its Tickets before the shared cleanup."""
    async with committed_app_client(db_session_factory) as (world, client):
        try:
            yield world, client
        finally:
            db = await world.session()
            packages = select(TicketPackage.id).where(
                TicketPackage.ticket_id.in_(world.ticket_ids)
            )
            await db.execute(
                delete(TicketPackageTrack).where(
                    TicketPackageTrack.ticket_package_id.in_(packages)
                )
            )
            await db.execute(
                delete(TicketPackage).where(
                    TicketPackage.ticket_id.in_(world.ticket_ids)
                )
            )
            await db.commit()


@pytest.mark.e2e
class TestTransaction:
    async def test_effective_change_is_committed_by_the_request_transaction(
        self, committed_app: tuple[CommittedApp, AsyncClient]
    ) -> None:
        world, committed_client = committed_app
        actor, headers = await world.va_headers()
        ticket = await world.ticket()
        db = await world.session()
        package = TicketPackage(ticket_id=ticket.id, package_name="example-lib")
        db.add(package)
        await db.flush()
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference="Example:Codestream:15:Update",
        )
        db.add(track)
        await db.commit()

        response = await committed_client.patch(
            _url(ticket, package.id, track.id),
            json={"status": "affected"},
            headers=headers,
        )

        assert response.status_code == 200
        assert response.json()["data"]["status"] == "affected"
        fresh = await world.session()
        assert await _track_status(fresh, track) == PackageStatus.AFFECTED.value
        # Auto-assignment and its promotion precede the one track event;
        # without a resolved severity the Ticket stays in Analysis.
        events = (
            await fresh.execute(
                select(TicketAuditEvent.event_type)
                .where(TicketAuditEvent.ticket_id == ticket.id)
                .order_by(TicketAuditEvent.id)
            )
        ).scalars()
        assert list(events) == ["assignment", "status_change", "track_status_changed"]
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
    async def test_one_date_captured_before_midnight_drives_gate_and_response(
        self,
        authenticated_client: AsyncClient,
        grant: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        build: Callable[..., Awaitable[Tree]],
        product_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Product is in General Support through `captured` and EOL the
        next day. On `captured` the changed `analysis` track is actionable,
        so the gate moves `Analyzed -> Analysis`; on the next day the track
        would be non-actionable and the Ticket would stay `Analyzed`. Every
        other clock returns the next day and must stay unread."""
        captured = date(2026, 9, 27)
        next_day = date(2026, 9, 28)
        handler_clock = Clock(datetime(2026, 9, 27, 23, 59, 59, 999000, tzinfo=UTC))
        service_clock = _DateClock(next_day)
        mutation_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        ticket_clock = Clock(datetime(2026, 9, 28, 0, 0, 0, 1000, tzinfo=UTC))
        monkeypatch.setattr(route, "_utc_now", handler_clock.now)
        monkeypatch.setattr(package_service, "_utc_today", service_clock.today)
        monkeypatch.setattr(ticket_mutations, "_utc_now", mutation_clock.now)
        monkeypatch.setattr(ticket_service, "_utc_now", ticket_clock.now)
        seen: dict[str, list[date | None]] = {"mutation": [], "reconcile": []}
        original_mutation = package_service.set_track_status
        # `package_service` composes the `ticket_mutations` primitive by name.
        original_reconcile = ticket_mutations.reconcile_ticket_status

        async def _mutation(db: AsyncSession, **kwargs: Any) -> Any:
            seen["mutation"].append(kwargs.get("evaluation_date"))
            return await original_mutation(db, **kwargs)

        async def _reconcile(ticket: Ticket, db: AsyncSession, **kwargs: Any) -> None:
            seen["reconcile"].append(kwargs.get("evaluation_date"))
            await original_reconcile(ticket, db, **kwargs)

        monkeypatch.setattr(package_service, "set_track_status", _mutation)
        monkeypatch.setattr(package_service, "reconcile_ticket_status", _reconcile)
        user = await grant(Role.VULNERABILITY_ANALYST)
        tree = await build(
            track_status=PackageStatus.AFFECTED,
            status=TicketStatus.ANALYZED.value,
            severity_manual=Severity.HIGH.value,
            assignee_id=user.id,
        )
        product = await product_factory(general_support_end_date=captured)
        await ticket_package_product_factory(
            ticket_package_track_id=tree.track.id, product_id=product.id
        )

        response = await authenticated_client.patch(
            tree.url(), json={"status": "analysis"}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["status"], data["actionable"], data["non_actionable_reason"]) == (
            "analysis",
            True,
            None,
        )
        assert [
            (p["lifecycle_phase"], p["actionable"], p["non_actionable_reason"])
            for p in data["products"]
        ] == [("general_support", True, None)]
        assert (await ticket_row(db_session, tree.ticket.id))[
            "status"
        ] == TicketStatus.ANALYSIS.value
        assert seen == {"mutation": [captured], "reconcile": [captured]}
        assert handler_clock.calls == 1
        assert (service_clock.calls, mutation_clock.calls, ticket_clock.calls) == (
            0,
            0,
            0,
        )


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

        assert operation["summary"] == "Change Track Status"
        assert operation["tags"] == ["Ticket Packages"]
        parameters = {p["name"]: p for p in operation["parameters"]}
        assert set(parameters) == {"ticket_id", "package_id", "track_id"}
        assert all(
            p["in"] == "path" and p["required"] is True for p in parameters.values()
        )
        assert parameters["ticket_id"]["schema"]["type"] == "string"
        assert "format" not in parameters["ticket_id"]["schema"]
        for name in ("package_id", "track_id"):
            schema = parameters[name]["schema"]
            assert (schema["type"], schema["format"]) == ("string", "uuid")

    def test_request_body_requires_one_lowercase_status(self) -> None:
        request_body = self._operation()["requestBody"]

        assert request_body["required"] is True
        assert self._ref_name(request_body["content"]) == "TrackStatusUpdateRequest"
        schema = self._resolve(request_body["content"]["application/json"]["schema"])
        assert schema["required"] == ["status"]
        assert set(schema["properties"]) == {"status"}
        status = self._resolve(schema["properties"]["status"])
        assert status["type"] == "string"
        assert status["enum"] == _ALL_TARGETS

    def test_responses_declare_the_track_and_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert self._ref_name(responses["200"]["content"]) == "TrackStatusResponse"
        assert self._ref_name(responses["404"]["content"]) == "ErrorResponse"
        assert self._ref_name(responses["409"]["content"]) == "ErrorResponse"
        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "RESOURCE_NOT_FOUND" in responses["404"]["description"]
        assert "TICKET_NOT_MUTABLE" in responses["409"]["description"]
        assert "422" in responses

    def test_response_schema_has_exactly_the_documented_fields(self) -> None:
        envelope = self._resolve({"$ref": "#/components/schemas/TrackStatusResponse"})
        assert set(envelope["properties"]) == {"data"}
        track = self._resolve(envelope["properties"]["data"])
        assert set(track["properties"]) == TRACK_FIELDS
        assert set(track["required"]) == TRACK_FIELDS
        product = self._resolve(track["properties"]["products"]["items"])
        assert set(product["properties"]) == PRODUCT_FIELDS
        # The only UUID is the Product occurrence locator; no Ticket UUID.
        assert track["properties"]["ticket_id"]["type"] == "string"
        assert "format" not in track["properties"]["ticket_id"]
        assert not any(
            self._resolve(p).get("format") == "uuid"
            for p in track["properties"].values()
        )
        assert [
            name
            for name, p in product["properties"].items()
            if self._resolve(p).get("format") == "uuid"
        ] == ["id"]
