"""Shared independent-session infrastructure for the manual SUSE CVSS
mutation tests.

Consumers:

- `tests/test_services/test_upsert_cvss_assessment_atomicity.py`;
- `tests/test_services/test_delete_cvss_assessment_atomicity.py`;
- `tests/test_services/test_associate_cve_atomicity.py` (which also uses
  `SessionStatementRecorder`, the optional `CommittedWorld.ticket()`
  status/`severity_manual` parameters, and the optional
  `CommittedWorld.affected_product()` `occurrence_id`/`package_name`).

`CommittedWorld` owns committed rows that each consumer deletes explicitly
at teardown (testing-strategy.md, Concurrency Testing); each consumer
defines its own `committed_world` fixture around it. `prepare_loss()`
commits one visibility path and returns the statements that remove it
(testing-strategy.md, Ticket Accessibility: Locked mutations).
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
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
from tests.support.suse_cvss import Vector
from tests.support.ticket_mutations import EVAL, StatementRecorder


class CommittedWorld:
    """Committed rows for the independent-session tests, deleted explicitly
    at teardown (testing-strategy.md, Concurrency Testing).

    The world also owns the racing sessions and tasks, so that teardown
    releases their row locks before deleting.
    """

    def __init__(
        self, factory: Callable[[], Awaitable[AsyncSession]], session: AsyncSession
    ) -> None:
        self._factory = factory
        self.session = session
        self.user_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []
        self.product_ids: list[uuid.UUID] = []
        self._sessions: list[AsyncSession] = []
        self._tasks: list[tuple[AsyncSession, asyncio.Task[Any]]] = []

    async def open_session(self) -> AsyncSession:
        session = await self._factory()
        self._sessions.append(session)
        return session

    def start(self, session: AsyncSession, coroutine: Any) -> asyncio.Task[Any]:
        task: asyncio.Task[Any] = asyncio.create_task(coroutine)
        self._tasks.append((session, task))
        return task

    async def user(self, *, role: Role) -> User:
        prefix = "alice.ra" if role is Role.RESTRICTED_ANALYST else "bob.va"
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"{prefix}.{suffix}",
            email=f"{prefix}.{suffix}@example.com",
            password_hash="$2b$12$" + "r" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def cve(self, *assessments: Vector, severity: Severity | None = None) -> CVE:
        cve = CVE(
            cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}",
            severity=severity.value if severity else None,
        )
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        for vector in assessments:
            self.session.add(
                CVECVSSAssessment(
                    cve_id=cve.id, provider_name="SUSE", **vector.columns()
                )
            )
        await self.session.commit()
        return cve

    async def ticket(
        self,
        *,
        cve_id: uuid.UUID | None,
        is_confidential: bool = False,
        assignee_id: uuid.UUID | None = None,
        priority_auto: str | None = None,
        status: TicketStatus = TicketStatus.ANALYSIS,
        severity_manual: Severity | None = None,
    ) -> Ticket:
        ticket = Ticket(
            status=status.value,
            cve_id=cve_id,
            is_confidential=is_confidential,
            assignee_id=assignee_id,
            priority_auto=priority_auto,
            severity_manual=severity_manual.value if severity_manual else None,
        )
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return ticket

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def maintained_package(self, ticket: Ticket, user: User) -> TicketPackage:
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-race-a")
        self.session.add(package)
        await self.session.flush()
        self.session.add(
            TicketPackageMaintainer(ticket_package_id=package.id, user_id=user.id)
        )
        await self.session.commit()
        return package

    async def affected_product(
        self,
        ticket: Ticket,
        *,
        threshold: Decimal,
        eligible: bool,
        occurrence_id: uuid.UUID | None = None,
        package_name: str = "fictional-race-b",
    ) -> dict[str, str]:
        """One AFFECTED track with one in-support Product occurrence;
        returns the `reason = cvss` event detail of that occurrence.

        `occurrence_id` fixes the `TicketPackageProduct.id` (the Product
        event ordering key) instead of taking the generated one; a second
        call on the same Ticket needs a distinct `package_name`."""
        suffix = uuid.uuid4().hex[:10]
        product = Product(
            name=f"Example Product {suffix}",
            version="1",
            display_name=f"EP {suffix}",
            cpe=f"cpe:/o:example:product:{suffix}",
            catalog_last_seen_at=datetime.now(UTC),
            cvss_threshold=threshold,
            general_support_end_date=EVAL + timedelta(days=365),
        )
        self.session.add(product)
        package = TicketPackage(ticket_id=ticket.id, package_name=package_name)
        self.session.add(package)
        await self.session.flush()
        self.product_ids.append(product.id)
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Codestream:{suffix}:Update",
            status=PackageStatus.AFFECTED.value,
        )
        self.session.add(track)
        await self.session.flush()
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
        )
        if occurrence_id is not None:
            occurrence.id = occurrence_id
        self.session.add(occurrence)
        await self.session.commit()
        return {
            "track": track.reference,
            "package": package.package_name,
            "product_name": product.display_name,
            "product_cpe": product.cpe,
            "reason": "cvss",
        }

    async def _release(self) -> None:
        busy = {id(s) for s, task in self._tasks if not task.done()}
        for session in self._sessions:
            if id(session) not in busy:
                with contextlib.suppress(Exception):
                    await session.rollback()
        for session, task in self._tasks:
            if not task.done():
                try:
                    await asyncio.wait_for(task, timeout=5)
                except Exception, asyncio.CancelledError:
                    task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            with contextlib.suppress(Exception):
                await session.rollback()

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        tracks = select(TicketPackageTrack.id).where(
            TicketPackageTrack.ticket_package_id.in_(packages)
        )
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
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
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVECVSSAssessment).where(CVECVSSAssessment.cve_id.in_(self.cve_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(Product).where(Product.id.in_(self.product_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


class SessionStatementRecorder(StatementRecorder):
    """`StatementRecorder` limited to the statements of one session's own
    connection: independent sessions share the engine, so the engine-level
    recorder would interleave the statements of racing sessions."""

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)
        bind = db.bind
        assert isinstance(bind, AsyncConnection)
        self._engine = bind.sync_connection


async def assert_blocked(task: asyncio.Task[Any]) -> None:
    """The task is still waiting for a row lock after 0.5 s."""
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(asyncio.shield(task), timeout=0.5)


VISIBILITY_LOSSES = [
    "confidentiality-set",
    "grant-revoked",
    "last-package-excluded",
    "association-changed",
]


async def prepare_loss(
    world: CommittedWorld,
    loss: str,
    *assessments: Vector,
    severity: Severity | None = None,
) -> tuple[User, CVE, Ticket, list[Any]]:
    """Commit a CVE (with the given SUSE `assessments` and `severity`)
    accessible to a `restricted_analyst` caller through exactly one path,
    and return the statements (locks first) that remove that path."""
    user = await world.user(role=Role.RESTRICTED_ANALYST)
    cve = await world.cve(*assessments, severity=severity)
    if loss == "association-changed":
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        return (
            user,
            cve,
            ticket,
            [
                select(CVE.id).where(CVE.id == cve.id).with_for_update(),
                select(Ticket.id).where(Ticket.id == ticket.id).with_for_update(),
                update(Ticket).where(Ticket.id == ticket.id).values(cve_id=cve.id),
            ],
        )
    lock = select(Ticket.id).where(Ticket.cve_id == cve.id).with_for_update()
    if loss == "confidentiality-set":
        ticket = await world.ticket(cve_id=cve.id)
        return (
            user,
            cve,
            ticket,
            [
                lock,
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(is_confidential=True),
            ],
        )
    ticket = await world.ticket(cve_id=cve.id, is_confidential=True)
    if loss == "grant-revoked":
        granter = await world.user(role=Role.VULNERABILITY_ANALYST)
        await world.grant(ticket, user, granter)
        return (
            user,
            cve,
            ticket,
            [
                lock,
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                ),
            ],
        )
    package = await world.maintained_package(ticket, user)
    return (
        user,
        cve,
        ticket,
        [
            lock,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
        ],
    )
