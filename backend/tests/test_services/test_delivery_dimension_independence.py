"""Service-level Dimension-independence rows of the track delivery dimension.

Owning specifications:

- docs/features/packages/package-service.md (Architectural Test
  Requirement: Dimension independence — affectedness, eligibility, track
  delivery, and Product release observations do not mutate or suppress one
  another; the Ticket gate ignores `delivery_status`).
- docs/features/packages/package-model.md (Three Orthogonal Dimensions:
  Axis 3, "neither fact derives the other, and neither changes affectedness
  or eligibility; only Product `released_at`, not track `delivery_status`,
  participates in the Resolved gate"; Affectedness-Delivery Independence).
- docs/features/tickets/tickets.md (Gate: Analysis -> Analyzed and
  Analyzed -> Resolved; `delivery_status` is not a gate input).

The delivery writer's own row (a delivery change mutates no other
dimension) is in `tests/test_services/test_set_track_delivery_status.py`.
This module covers the other direction for the direct dimension writers in
`CASES` in every delivery state, including `RELEASED`, where their own
modules seed only `PENDING` or `IN_PROGRESS`, and the gate rows. The
system affectedness and Product release writers are already covered for
every delivery value through their workflows
(`tests/test_services/test_packages/test_ibs_track_release.py` and
`test_ibs_product_release.py`, Dimension independence), so they are not
repeated here. The reconciliation rows (selection never suppressed by
another dimension) are owned by the shared IBS request reconciliation
(#963).

Every writer Ticket is CVE-less with `severity_manual = High` (the gate
Tickets carry a CVE, see `GATES`), and every Product
is in General Support on `EVAL`, which the services use as their one UTC
evaluation date. Expected values are transcribed from the specifications,
never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Scope,
    Severity,
    TicketStatus,
)
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    recalculate_product_eligibility_for_ticket,
    restore_ticket_package,
    restore_ticket_package_product,
    restore_ticket_package_track,
    set_product_eligibility,
    set_track_status,
    soft_delete_ticket_package,
    soft_delete_ticket_package_product,
    soft_delete_ticket_package_track,
)
from app.services.ticket_mutations import reconcile_ticket_status
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.product_eligibility import only_occurrence
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    lock_ticket,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

DELIVERY = [
    pytest.param(DeliveryStatus.PENDING, id="PENDING"),
    pytest.param(DeliveryStatus.IN_PROGRESS, id="IN_PROGRESS"),
    pytest.param(DeliveryStatus.RELEASED, id="RELEASED"),
]


@pytest.fixture(autouse=True)
def controlled_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the services' one UTC evaluation date to `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(key="default_cvss_version", value="3.1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Tree:
    """One Ticket with one package, one track, and one Product occurrence."""

    ticket: Ticket
    package_id: uuid.UUID
    track: TicketPackageTrack
    occurrence: TicketPackageProduct
    actor: User

    def caller(self) -> TicketCaller:
        return TicketCaller.authenticated(self.actor.id, Scope.ALL)


async def _seed_delivery(
    db: AsyncSession, track: TicketPackageTrack, delivery: DeliveryStatus
) -> None:
    await db.execute(
        update(TicketPackageTrack)
        .where(TicketPackageTrack.id == track.id)
        .values(delivery_status=delivery.value)
    )


async def _delivery(db: AsyncSession, track: TicketPackageTrack) -> str:
    return (
        await db.execute(
            select(TicketPackageTrack.delivery_status).where(
                TicketPackageTrack.id == track.id
            )
        )
    ).scalar_one()


async def _own_dimension(db: AsyncSession, tree: _Tree) -> tuple[Any, ...]:
    """Every value a dimension writer of this module may own: track
    affectedness; occurrence eligibility, override marker, and release
    observation; the package, track, and occurrence markers."""
    row = (
        await db.execute(
            select(
                TicketPackageTrack.status,
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at,
                TicketPackage.deleted_at,
                TicketPackageTrack.deleted_at,
                TicketPackageProduct.deleted_at,
            )
            .select_from(TicketPackageProduct)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackageProduct.id == tree.occurrence.id)
        )
    ).one()
    return tuple(row)


Writer = Callable[[AsyncSession, _Tree], Awaitable[object]]


async def _affectedness_user(db: AsyncSession, tree: _Tree) -> object:
    return await set_track_status(
        db,
        ticket_id=tree.ticket.id,
        package_id=tree.package_id,
        track_id=tree.track.id,
        status=PackageStatus.AFFECTED,
        acting_user_id=tree.actor.id,
        caller=tree.caller(),
        evaluation_date=EVAL,
    )


async def _eligibility_override(db: AsyncSession, tree: _Tree) -> object:
    return await set_product_eligibility(
        db,
        ticket_id=tree.ticket.id,
        package_id=tree.package_id,
        track_id=tree.track.id,
        ticket_package_product_id=tree.occurrence.id,
        eligible=False,
        acting_user_id=tree.actor.id,
        caller=tree.caller(),
        evaluation_date=EVAL,
    )


async def _eligibility_recalculation(db: AsyncSession, tree: _Tree) -> object:
    return await recalculate_product_eligibility_for_ticket(
        db,
        ticket_id=tree.ticket.id,
        catalog_product_id=tree.occurrence.product_id,
        reason="threshold",
        evaluation_date=EVAL,
    )


def _marker(
    operation: Callable[..., Awaitable[object]], level: str
) -> Callable[[AsyncSession, _Tree], Awaitable[object]]:
    async def _call(db: AsyncSession, tree: _Tree) -> object:
        locator: dict[str, uuid.UUID] = {
            "ticket_id": tree.ticket.id,
            "package_id": tree.package_id,
        }
        if level in ("track", "product"):
            locator["track_id"] = tree.track.id
        if level == "product":
            locator["ticket_package_product_id"] = tree.occurrence.id
        return await operation(
            db,
            **locator,
            acting_user_id=tree.actor.id,
            caller=tree.caller(),
            evaluation_date=EVAL,
        )

    return _call


_DEFAULT_PRODUCT = Prod()
"""An automatic, eligible, unreleased, included Product in support."""


@dataclass(frozen=True, slots=True)
class _Case:
    """One dimension writer, the state it starts from, and the one owned
    value it must change (by position in `_own_dimension()`)."""

    writer: Writer
    status: PackageStatus = PackageStatus.AFFECTED
    product: Prod = _DEFAULT_PRODUCT
    package_excluded: bool = False
    track_excluded: bool = False
    changes: tuple[int, ...] = ()


CASES = [
    pytest.param(
        _Case(_affectedness_user, status=PackageStatus.ANALYSIS, changes=(0,)),
        id="affectedness-user",
    ),
    pytest.param(
        _Case(_eligibility_override, changes=(1, 2)), id="eligibility-override"
    ),
    pytest.param(
        _Case(_eligibility_recalculation, product=Prod(eligible=False), changes=(1,)),
        id="eligibility-recalculation",
    ),
    pytest.param(
        _Case(_marker(soft_delete_ticket_package, "package"), changes=(4,)),
        id="package-exclusion",
    ),
    pytest.param(
        _Case(
            _marker(restore_ticket_package, "package"),
            package_excluded=True,
            changes=(4,),
        ),
        id="package-restoration",
    ),
    pytest.param(
        _Case(_marker(soft_delete_ticket_package_track, "track"), changes=(5,)),
        id="track-exclusion",
    ),
    pytest.param(
        _Case(
            _marker(restore_ticket_package_track, "track"),
            track_excluded=True,
            changes=(5,),
        ),
        id="track-restoration",
    ),
    pytest.param(
        _Case(_marker(soft_delete_ticket_package_product, "product"), changes=(6,)),
        id="product-exclusion",
    ),
    pytest.param(
        _Case(
            _marker(restore_ticket_package_product, "product"),
            product=Prod(excluded=True),
            changes=(6,),
        ),
        id="product-restoration",
    ),
]


# ---------------------------------------------------------------------------
# Other dimension writers never write delivery
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOtherWritersLeaveDeliveryUnchanged:
    """package-service.md, Architectural Test Requirement: Dimension
    independence; package-model.md, Axis 3 (track `delivery_status` is
    updated only by the shared IBS request reconciliation). Each writer
    performs one effective change of its own dimension on a track whose
    delivery is `PENDING`, `IN_PROGRESS`, or the irreversible `RELEASED`,
    and the delivery value is unchanged."""

    @pytest.mark.parametrize("delivery", DELIVERY)
    @pytest.mark.parametrize("case", CASES)
    async def test_writer_leaves_delivery_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
        default_setting: SystemSetting,
        case: _Case,
        delivery: DeliveryStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=case.status,
            products=(case.product,),
            package_excluded=case.package_excluded,
            track_excluded=case.track_excluded,
        )
        await _seed_delivery(db_session, track, delivery)
        subject = _Tree(
            ticket,
            track.ticket_package_id,
            track,
            await only_occurrence(db_session, track),
            actor,
        )
        before = await _own_dimension(db_session, subject)

        await case.writer(db_session, subject)

        after = await _own_dimension(db_session, subject)
        changed = tuple(
            i for i, (b, a) in enumerate(zip(before, after, strict=True)) if b != a
        )
        assert changed == case.changes
        assert await _delivery(db_session, track) == delivery.value


# ---------------------------------------------------------------------------
# The Ticket gate ignores delivery
# ---------------------------------------------------------------------------


GATES = [
    pytest.param(
        PackageStatus.ANALYSIS, Prod(), TicketStatus.ANALYSIS, id="ANALYSIS-track"
    ),
    pytest.param(
        PackageStatus.AFFECTED, Prod(), TicketStatus.ANALYZED, id="AFFECTED-track"
    ),
    pytest.param(
        PackageStatus.FIXED,
        Prod(),
        TicketStatus.ANALYZED,
        id="FIXED-eligible-unreleased",
    ),
    pytest.param(
        PackageStatus.FIXED,
        Prod(released=True),
        TicketStatus.RESOLVED,
        id="FIXED-eligible-released",
    ),
]
"""tickets.md, Gate: Analysis -> Analyzed (no actionable `ANALYSIS` track)
and Analyzed -> Resolved (for a Ticket with a CVE, every actionable eligible
Product under a `FIXED` track has `released_at`): a `RELEASED` delivery
never stands in for a Product release, and a `PENDING` delivery never holds
back a resolution. The gate Tickets carry a CVE with severity High and a
SUSE assessment (Gate: Analysis -> Analyzed, conditions 3 and 4)."""


@pytest.mark.integration
class TestGateIgnoresDelivery:
    """package-service.md, Architectural Test Requirement: Dimension
    independence ("the Ticket gate ignores `delivery_status`");
    package-model.md, Axis 3 (only Product `released_at`, not track
    `delivery_status`, participates in the Resolved gate)."""

    @pytest.mark.parametrize("delivery", DELIVERY)
    @pytest.mark.parametrize(("status", "product", "expected"), GATES)
    async def test_gate_result_is_identical_for_every_delivery_value(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        cve_with: CVEBuilder,
        status: PackageStatus,
        product: Prod,
        expected: TicketStatus,
        delivery: DeliveryStatus,
    ) -> None:
        cve = await cve_with(Assessment("9.8"), severity=Severity.HIGH)
        ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)
        track = await tree(ticket, status=status, products=(product,))
        await _seed_delivery(db_session, track, delivery)
        locked = await lock_ticket(db_session, ticket)

        await reconcile_ticket_status(locked, db_session, evaluation_date=EVAL)

        assert TicketStatus(locked.status) is expected
        assert await _delivery(db_session, track) == delivery.value
