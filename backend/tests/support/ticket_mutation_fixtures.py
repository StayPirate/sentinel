"""Shared pytest fixtures for the Ticket mutation service tests.

A pytest plugin: consumers list `"tests.support.ticket_mutation_fixtures"`
in their module-level `pytest_plugins` and never import this module, so
that pytest imports it first and rewrites its assertions. The plain
helpers and type aliases used with these fixtures live in
`tests/support/ticket_mutations.py` (and, for `cve_with`,
`tests/support/cvss_chain.py`). The fixtures build on the factory
fixtures of `tests/conftest.py`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from app.core.enums import PackageStatus, Role, Severity
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from tests.support.cvss_chain import Assessment
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    REACTIVE_END,
    REACTIVE_EXTENDED_END,
    REACTIVE_GS_END,
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
            extended_end = reactive_end = None
            if not spec.lifecycle:
                gs_end = None
            elif spec.reactive:
                gs_end = REACTIVE_GS_END
                extended_end = REACTIVE_EXTENDED_END
                reactive_end = REACTIVE_END
            else:
                gs_end = BEFORE_EVAL if spec.eol else AFTER_EVAL
            product = await product_factory(
                general_support_end_date=gs_end,
                extended_support_end_date=extended_end,
                reactive_support_end_date=reactive_end,
                cvss_threshold=spec.threshold,
            )
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


@pytest.fixture
def cve_with(
    cve_factory: Callable[..., Awaitable[CVE]],
    cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
) -> Callable[..., Awaitable[CVE]]:
    """Create a CVE with a persisted `severity` and the given assessments.

    The persisted `CVE.severity` is set independently of the assessments,
    so a test can model a stale, converged, or out-of-band state.
    """

    async def _create(*assessments: Assessment, severity: Severity | None) -> CVE:
        cve = await cve_factory(severity=severity.value if severity else None)
        for assessment in assessments:
            await cve_cvss_assessment_factory(
                cve_id=cve.id,
                provider_name=assessment.provider,
                cvss_version=assessment.version,
                score=Decimal(assessment.score),
            )
        return cve

    return _create
