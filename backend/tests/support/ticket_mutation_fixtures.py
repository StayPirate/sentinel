"""Shared pytest fixtures for the Ticket mutation service tests.

A pytest plugin: consumers list `"tests.support.ticket_mutation_fixtures"`
in their module-level `pytest_plugins` and never import this module, so
that pytest imports it first and rewrites its assertions. The plain
helpers and type aliases used with these fixtures live in
`tests/support/ticket_mutations.py`. The fixtures build on the factory
fixtures of `tests/conftest.py`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest

from app.core.enums import PackageStatus, Role
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    RELEASED_AT,
    Prod,
    TreeBuilder,
    UserFactory,
    VAUser,
)


@pytest.fixture
def va_user(
    user_factory: UserFactory,
    user_role_factory: Callable[..., Awaitable[UserRole]],
) -> VAUser:
    """Create a User holding the given roles (default: one VA origin)."""

    async def _create(
        *, active: bool = True, roles: tuple[Role, ...] = (Role.VULNERABILITY_ANALYST,)
    ) -> User:
        user = await user_factory(active=active)
        for index, role in enumerate(roles):
            await user_role_factory(
                user_id=user.id, role=role.value, group_name=f"_origin{index}"
            )
        return user

    return _create


@pytest.fixture
def tree(
    ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
    ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
    ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
    product_factory: Callable[..., Awaitable[Product]],
) -> TreeBuilder:
    """Add one package with one track (and its Products) to a Ticket."""

    async def _add(
        ticket: Ticket,
        *,
        status: PackageStatus = PackageStatus.AFFECTED,
        products: tuple[Prod, ...] = (Prod(),),
        package_excluded: bool = False,
        track_excluded: bool = False,
    ) -> TicketPackageTrack:
        now = datetime.now(UTC)
        package = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=now if package_excluded else None
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            status=status.value,
            deleted_at=now if track_excluded else None,
        )
        for spec in products:
            if not spec.lifecycle:
                gs_end = None
            else:
                gs_end = BEFORE_EVAL if spec.eol else AFTER_EVAL
            product = await product_factory(general_support_end_date=gs_end)
            await ticket_package_product_factory(
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=spec.eligible,
                is_eligible_override=spec.override,
                released_at=RELEASED_AT if spec.released else None,
                deleted_at=now if spec.excluded else None,
            )
        return track

    return _add
