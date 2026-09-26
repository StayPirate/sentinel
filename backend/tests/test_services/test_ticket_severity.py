"""Tests for the resolved Ticket severity SQL expression.

Owning specification: `docs/features/tickets/tickets.md` (Severity
Resolution > Resolution Rules): a Ticket with a CVE uses `CVE.severity`
(which may be SQL `NULL`), a CVE-less Ticket uses `severity_manual`, and
otherwise the severity is unresolved. The `None` label is a value distinct
from SQL `NULL`. Every case is evaluated in PostgreSQL over persisted rows.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import Severity
from app.models.ticket import Ticket
from app.services import ticket_severity
from app.services.ticket_severity import resolved_severity_expression
from tests.support.module_imports import APP_ROOT, imported_modules

Factory = Callable[..., Awaitable[Any]]


async def _resolved(db: AsyncSession, ticket: Ticket) -> str | None:
    result = await db.execute(
        select(resolved_severity_expression()).where(Ticket.id == ticket.id)
    )
    value: str | None = result.scalar_one()
    return value


@pytest.mark.integration
class TestResolvedSeverityExpression:
    @pytest.mark.parametrize("severity", [*Severity, None], ids=lambda s: str(s))
    async def test_ticket_with_cve_uses_cve_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
        severity: Severity | None,
    ) -> None:
        cve = await cve_factory(severity=severity.value if severity else None)
        ticket = await ticket_factory(cve_id=cve.id)

        assert await _resolved(db_session, ticket) == (
            severity.value if severity else None
        )

    @pytest.mark.parametrize("severity", [*Severity, None], ids=lambda s: str(s))
    async def test_cve_less_ticket_uses_manual_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        severity: Severity | None,
    ) -> None:
        ticket = await ticket_factory(
            severity_manual=severity.value if severity else None
        )

        assert await _resolved(db_session, ticket) == (
            severity.value if severity else None
        )

    async def test_none_label_is_distinct_from_unresolved(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        none_label = await ticket_factory(severity_manual=Severity.NONE.value)
        unresolved = await ticket_factory()

        result = await db_session.execute(
            select(Ticket.id).where(
                Ticket.id.in_([none_label.id, unresolved.id]),
                resolved_severity_expression().is_(None),
            )
        )

        assert list(result.scalars().all()) == [unresolved.id]

    async def test_expression_filters_orders_and_reads_an_alias_without_row_growth(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        high_cve = await cve_factory(severity=Severity.HIGH.value)
        with_cve = await ticket_factory(cve_id=high_cve.id)
        manual = await ticket_factory(severity_manual=Severity.LOW.value)
        alias = aliased(Ticket)

        result = await db_session.execute(
            select(alias.id, resolved_severity_expression(alias))
            .where(alias.id.in_([with_cve.id, manual.id]))
            .order_by(resolved_severity_expression(alias))
        )

        assert [tuple(row) for row in result.all()] == [
            (with_cve.id, Severity.HIGH.value),
            (manual.id, Severity.LOW.value),
        ]


@pytest.mark.unit
class TestTicketSeverityModuleBoundary:
    def test_imports_only_models_and_core(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_severity.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {
            "app.models.cve",
            "app.models.ticket",
        }

    def test_builder_is_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(
            ticket_severity.resolved_severity_expression
        )
