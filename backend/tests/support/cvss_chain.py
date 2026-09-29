"""Shared helpers for the `recalculate_cvss_chain()` service tests.

Consumers:

- `tests/test_services/test_recalculate_cvss_chain.py` (eligibility
  formula, association mode, default-version matrix);
- `tests/test_services/test_recalculate_cvss_chain_atomicity.py`
  (classification, idempotency, rollback, evaluation date, locking);
- `tests/test_services/test_cve_root_lock_mode_atomicity.py` (event and
  severity helpers for the CVE root lock mode races).

The `cve_with` fixture lives in the plugin module
`tests/support/ticket_mutation_fixtures.py`. Expected values in the
consumers are transcribed from the specifications; nothing here computes an
expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVSSVersion, EligibilitySource, Severity
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import ticket_mutations
from app.services.cvss import EligibilityResolution, SeverityResolution
from app.services.ticket_mutations import (
    CVSSChainMode,
    CVSSChainResult,
    recalculate_cvss_chain,
)
from tests.support.ticket_mutations import EVAL, EventRow, lock_ticket

DEFAULT_VERSION = "3.1"
"""The persisted `default_cvss_version` setting of the consumers."""


# ---------------------------------------------------------------------------
# Assessments and resolutions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Assessment:
    """One persisted `CVECVSSAssessment` of a test CVE."""

    score: str
    provider: str = "SUSE"
    version: str = DEFAULT_VERSION


CVEBuilder = Callable[..., Awaitable[CVE]]


def label(severity: Severity | None) -> str | None:
    """The stored PascalCase label, or SQL `NULL`."""
    return severity.value if severity is not None else None


def severity_resolution(
    score: str,
    severity: Severity,
    *,
    version: CVSSVersion = CVSSVersion.V3_1,
    provider: str = "SUSE",
) -> SeverityResolution:
    """An expected Severity Resolution Cascade winner."""
    return SeverityResolution(
        score=Decimal(score), version=version, provider=provider, label=severity
    )


def suse_eligibility(score: str) -> EligibilityResolution:
    """An expected Eligibility Score Resolution from the SUSE assessment."""
    return EligibilityResolution(score=Decimal(score), source=EligibilitySource.SUSE)


FALLBACK = EligibilityResolution(
    score=Decimal("10.0"), source=EligibilitySource.FALLBACK
)
"""The expected `10.0` fallback Eligibility Score Resolution."""


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


async def run_chain(
    db: AsyncSession,
    cve_id: uuid.UUID,
    *,
    mode: CVSSChainMode = CVSSChainMode.DEFAULT_VERSION,
    evaluation_date: date | None = EVAL,
    **kwargs: Any,
) -> CVSSChainResult:
    """Invoke the function under test with the fixed `EVAL` by default."""
    return await recalculate_cvss_chain(
        db, cve_id=cve_id, mode=mode, evaluation_date=evaluation_date, **kwargs
    )


async def associate(db: AsyncSession, ticket: Ticket, cve: CVE) -> Ticket:
    """Reproduce the pre-chain part of `associate_cve()`: lock the CVE then
    the Ticket, point the Ticket at the CVE, and clear `severity_manual` in
    the same transaction."""
    await db.execute(
        select(CVE.id).where(CVE.id == cve.id).with_for_update(key_share=True)
    )
    locked = await lock_ticket(db, ticket)
    locked.cve_id = cve.id
    locked.severity_manual = None
    await db.flush()
    return locked


class CallCounter:
    """Wraps a `ticket_mutations` module function, recording each call's
    keyword arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[dict[str, Any]] = []
        original = getattr(ticket_mutations, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(kwargs)
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_mutations, name, _wrapper)


# ---------------------------------------------------------------------------
# Persisted state
# ---------------------------------------------------------------------------


async def cve_severity(db: AsyncSession, cve_id: uuid.UUID) -> str | None:
    """The persisted `CVE.severity`."""
    return (await db.execute(select(CVE.severity).where(CVE.id == cve_id))).scalar_one()


async def ticket_state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None, str | None, str | None, str | None]:
    """The persisted `(status, assignee_id, priority_auto, priority_override,
    severity_manual)` of a Ticket."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.severity_manual,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return (
        row.status,
        row.assignee_id,
        row.priority_auto,
        row.priority_override,
        row.severity_manual,
    )


async def eligibility(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[tuple[bool, bool]]:
    """The persisted `(eligible, is_eligible_override)` of every Product
    occurrence of a Ticket, in ascending `TicketPackageProduct.id` order."""
    rows = await db.execute(
        select(TicketPackageProduct.eligible, TicketPackageProduct.is_eligible_override)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(TicketPackage.ticket_id == ticket_id)
        .order_by(TicketPackageProduct.id)
    )
    return [(row.eligible, row.is_eligible_override) for row in rows]


async def subjects(db: AsyncSession, ticket_id: uuid.UUID) -> list[dict[str, str]]:
    """The raw fixture subject of every Product occurrence of a Ticket, in
    ascending `TicketPackageProduct.id` order, shaped as the
    `product_eligibility_changed` detail with `reason = cvss`
    (ticket-audit-log.md, detail JSONB Schema Contract)."""
    rows = await db.execute(
        select(
            TicketPackageTrack.reference,
            TicketPackage.package_name,
            Product.display_name,
            Product.cpe,
        )
        .select_from(TicketPackageProduct)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Product, Product.id == TicketPackageProduct.product_id)
        .where(TicketPackage.ticket_id == ticket_id)
        .order_by(TicketPackageProduct.id)
    )
    return [
        {
            "track": row.reference,
            "package": row.package_name,
            "product_name": row.display_name,
            "product_cpe": row.cpe,
            "reason": "cvss",
        }
        for row in rows
    ]


async def total_ticket_events(db: AsyncSession) -> int:
    """Every `TicketAuditEvent` visible to the session."""
    return (
        await db.execute(select(func.count()).select_from(TicketAuditEvent))
    ).scalar_one()


async def assessment_snapshot(
    db: AsyncSession, cve_id: uuid.UUID
) -> list[tuple[Any, ...]]:
    """Every persisted column of the CVE's assessments, by `id`."""
    rows = (
        await db.execute(
            select(CVECVSSAssessment)
            .where(CVECVSSAssessment.cve_id == cve_id)
            .order_by(CVECVSSAssessment.id)
            .execution_options(populate_existing=True)
        )
    ).scalars()
    return [
        (
            a.id,
            a.provider_name,
            a.cvss_version,
            a.score,
            a.severity,
            a.vector_string,
            a.created_at,
            a.updated_at,
        )
        for a in rows
    ]


# ---------------------------------------------------------------------------
# Expected events (ticket-audit-log.md, Event Type Contract)
# ---------------------------------------------------------------------------


def severity_event(old: str | None, new: str | None) -> EventRow:
    """The system `severity_changed` event of a CVSS-derived severity."""
    return EventRow("severity_changed", None, old, new, None, None)


def priority_event(old: str | None, new: str | None) -> EventRow:
    """The system `priority_changed` event of the automatic refresh."""
    return EventRow("priority_changed", None, old, new, None, None)


def product_event(subject: dict[str, str], old: bool, new: bool) -> EventRow:
    """The system `product_eligibility_changed` event (`reason = cvss`)."""
    return EventRow(
        "product_eligibility_changed",
        None,
        "true" if old else "false",
        "true" if new else "false",
        None,
        subject,
    )
