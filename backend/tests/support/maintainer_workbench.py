"""Shared seeding helpers for the maintainer workbench tests.

Consumers:

- `tests/test_services/test_maintainer_workbench.py` (the four
  `package_service` workbench queries);
- `tests/test_services/test_maintainer_workbench_races.py` (the
  independent-session races);
- `tests/test_api/test_maintainer_workbench.py` (the four
  `GET /api/v1/my/packages/*` endpoints).

`WorkbenchSeed` builds Tickets, package trees, maintainer associations,
and grants directly through the ORM on one session (flush only), so the
same builder serves the per-test rollback session and committed
independent sessions; `cleanup()` deletes every committed row in FK-safe
order. All identifiers are fictional.

Expected values in the consumers are transcribed from the specifications
(docs/features/packages/maintainer.md, docs/features/tickets/
ticket-deadlines.md); nothing here computes an expectation with the module
under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Final

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.models.cve import CVE
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services.ticket_visibility import TicketCaller

INSTANT: Final = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
"""The evaluation instant of every read unless a test states otherwise."""

EVAL: Final = INSTANT.date()
"""The UTC date of `INSTANT`, the read's `evaluation_date`."""

RECENT: Final = INSTANT - timedelta(days=10)
"""A `created_at` whose 30-day-tier submission due date (+18 days,
ticket-deadlines.md, Formula) is not past at `INSTANT`."""

OLD: Final = INSTANT - timedelta(days=20)
"""A `created_at` whose 30-day-tier submission due date is past at
`INSTANT`."""

EXCLUDED_AT: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
RELEASED_AT: Final = datetime(2026, 9, 20, 8, 0, tzinfo=UTC)
EOL_GS_END: Final = date(2000, 1, 1)
"""A General Support end alone, long before `EVAL`: the Product is `eol`."""

SUBMISSION_OFFSET_30: Final = timedelta(days=18)
"""The submission due offset of the 30-day tier (60 % of 30 days)."""


def owner_caller(user: User, scope: Scope = Scope.NON_CONFIDENTIAL) -> TicketCaller:
    """The authenticated caller of `user` with the given effective scope."""
    return TicketCaller.authenticated(user.id, scope)


@dataclass(frozen=True, slots=True)
class Prod:
    """One Product occurrence below a seeded track.

    `eligible` is the persisted eligibility, `excluded` the occurrence's
    direct marker, `gs_end` the catalog Product's only lifecycle date
    (`None`: lifecycle unavailable, actionable; `EOL_GS_END`: `eol` on
    `EVAL`), and `released` sets `released_at`."""

    eligible: bool = True
    excluded: bool = False
    gs_end: date | None = None
    released: bool = False


ELIGIBLE: Final = Prod()
INELIGIBLE: Final = Prod(eligible=False)
EOL: Final = Prod(gs_end=EOL_GS_END)
EXCLUDED: Final = Prod(excluded=True)


class WorkbenchSeed:
    """Builds workbench fixtures on one session and records them for cleanup."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.product_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []

    async def user(self, *, role: Role | None = None) -> User:
        suffix = uuid.uuid4().hex[:12]
        user = User(
            username=f"dana.maint.{suffix}",
            email=f"dana.maint.{suffix}@example.com",
            full_name="Dana Maintainer",
            password_hash="$2b$12$" + "d" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
            await self.session.flush()
        return user

    async def ticket(
        self,
        *,
        status: TicketStatus = TicketStatus.ANALYSIS,
        severity: Severity | None = Severity.HIGH,
        cve: bool = True,
        confidential: bool = False,
        created_at: datetime = RECENT,
    ) -> Ticket:
        """A Ticket whose resolved severity is `severity`: through its CVE
        when `cve` is true, otherwise through `severity_manual`."""
        columns: dict[str, object] = {
            "status": status.value,
            "is_confidential": confidential,
            "created_at": created_at,
        }
        if cve:
            record = CVE(
                cve_id=f"CVE-2099-{uuid.uuid4().int % 900000 + 100000}",
                severity=severity.value if severity is not None else None,
            )
            self.session.add(record)
            await self.session.flush()
            self.cve_ids.append(record.id)
            columns["cve_id"] = record.id
        else:
            columns["severity_manual"] = (
                severity.value if severity is not None else None
            )
        if status is TicketStatus.DUPLICATED:
            columns["duplicate_of_id"] = (await self.ticket(cve=False)).id
        ticket = Ticket(**columns)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        return ticket

    async def package(
        self,
        ticket: Ticket,
        name: str = "fictional-pkg",
        *,
        maintainers: Sequence[User] = (),
        excluded: bool = False,
    ) -> TicketPackage:
        package = TicketPackage(
            ticket_id=ticket.id,
            package_name=name,
            deleted_at=EXCLUDED_AT if excluded else None,
        )
        self.session.add(package)
        await self.session.flush()
        for user in maintainers:
            await self.maintainer(package, user)
        return package

    async def maintainer(self, package: TicketPackage, user: User) -> None:
        self.session.add(
            TicketPackageMaintainer(ticket_package_id=package.id, user_id=user.id)
        )
        await self.session.flush()

    async def track(
        self,
        package: TicketPackage,
        *,
        status: PackageStatus = PackageStatus.AFFECTED,
        delivery: DeliveryStatus = DeliveryStatus.PENDING,
        workflow: WorkflowType = WorkflowType.IBS,
        reference: str | None = None,
        products: Sequence[Prod] = (ELIGIBLE,),
        excluded: bool = False,
    ) -> TicketPackageTrack:
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type=workflow.value,
            reference=reference or f"Example:Codestream:{uuid.uuid4().hex[:8]}:Update",
            status=status.value,
            delivery_status=delivery.value,
            deleted_at=EXCLUDED_AT if excluded else None,
        )
        self.session.add(track)
        await self.session.flush()
        for product in products:
            await self.occurrence(track, product)
        return track

    async def occurrence(
        self, track: TicketPackageTrack, product: Prod = ELIGIBLE
    ) -> TicketPackageProduct:
        catalog = Product(
            name="Fictional Product",
            version="1",
            display_name="Fictional Product 1",
            cpe=f"cpe:/o:example:workbench:{uuid.uuid4().hex}",
            catalog_last_seen_at=INSTANT,
            general_support_end_date=product.gs_end,
        )
        self.session.add(catalog)
        await self.session.flush()
        self.product_ids.append(catalog.id)
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id,
            product_id=catalog.id,
            eligible=product.eligible,
            released_at=RELEASED_AT if product.released else None,
            deleted_at=EXCLUDED_AT if product.excluded else None,
        )
        self.session.add(occurrence)
        await self.session.flush()
        return occurrence

    async def work(
        self,
        owner: User,
        *,
        name: str = "fictional-pkg",
        ticket: Ticket | None = None,
        status: TicketStatus = TicketStatus.ANALYSIS,
        severity: Severity | None = Severity.HIGH,
        cve: bool = True,
        confidential: bool = False,
        created_at: datetime = RECENT,
        track_status: PackageStatus = PackageStatus.AFFECTED,
        delivery: DeliveryStatus = DeliveryStatus.PENDING,
        workflow: WorkflowType = WorkflowType.IBS,
        reference: str | None = None,
        products: Sequence[Prod] = (ELIGIBLE,),
    ) -> TicketPackageTrack:
        """One owned package with one track on a new (or the given) Ticket."""
        if ticket is None:
            ticket = await self.ticket(
                status=status,
                severity=severity,
                cve=cve,
                confidential=confidential,
                created_at=created_at,
            )
        package = await self.package(ticket, name, maintainers=(owner,))
        return await self.track(
            package,
            status=track_status,
            delivery=delivery,
            workflow=workflow,
            reference=reference,
            products=products,
        )

    async def grant(self, ticket: Ticket, user: User, granted_by: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granted_by.id
            )
        )
        await self.session.flush()

    async def cleanup(self) -> None:
        """Delete every committed row in FK-safe order (committed mode)."""
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        tracks = select(TicketPackageTrack.id).where(
            TicketPackageTrack.ticket_package_id.in_(packages)
        )
        statements = (
            delete(TicketPackageProduct).where(
                TicketPackageProduct.ticket_package_track_id.in_(tracks)
            ),
            delete(TicketPackageTrack).where(
                TicketPackageTrack.ticket_package_id.in_(packages)
            ),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            # Duplicates first: `duplicate_of_id` references another Ticket.
            delete(Ticket).where(
                Ticket.id.in_(self.ticket_ids), Ticket.duplicate_of_id.is_not(None)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(Product).where(Product.id.in_(self.product_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        )
        for statement in statements:
            await self.session.execute(statement)
        await self.session.commit()
