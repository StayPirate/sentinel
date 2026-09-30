"""Shared helpers for the Ticket-path mutation endpoint e2e tests.

Consumers:

- `tests/test_api/test_ticket_priority_override.py`
  (`PATCH /api/v1/tickets/{ticket_id}/priority`);
- `tests/test_api/test_ticket_assignee.py`
  (`PATCH /api/v1/tickets/{ticket_id}/assignee`);
- `tests/test_api/test_ticket_ignore.py`
  (`POST /api/v1/tickets/{ticket_id}/ignore`);
- `tests/test_api/test_ticket_duplicate.py`
  (`POST /api/v1/tickets/{ticket_id}/duplicate`);
- `tests/test_api/test_ticket_track_status.py`
  (`PATCH /api/v1/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}`).

The complete error bodies are transcribed from docs/api-spec.md (Global
Responses, Ticket Accessibility Check, Manual-Zone Mutability Guard).
`CommittedApp` owns committed rows and an app client whose every request
runs in its own independent session, committed or rolled back like
production `app.database.get_db` (testing-strategy.md, Concurrency Testing:
explicit cleanup of committed rows); each consumer wraps
`committed_app_client()` in its own fixture.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, SessionCreationReason, TicketStatus
from app.core.identifiers import format_ticket_id
from app.database import get_db
from app.main import app
from app.models.session import Session as SessionRow
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services.session_service import create_session

NOT_FOUND = b'{"code":"TICKET_NOT_FOUND","detail":"Ticket not found."}'
UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
NOT_MUTABLE = {"code": "TICKET_NOT_MUTABLE", "detail": "Ticket is not mutable."}
INTERNAL_ERROR = {"code": "INTERNAL_ERROR", "detail": "An unexpected error occurred."}
MAX_SEQUENCE = 2_147_483_647

TICKET_DETAIL_FIELDS = {
    "ticket_id",
    "status",
    "severity",
    "priority",
    "priority_automatic",
    "priority_override",
    "assignee",
    "cve",
    "duplicate_of_ticket_id",
    "is_confidential",
    "coordinated_release_at",
    "triage_due_at",
    "submission_due_at",
    "um_due_at",
    "qa_due_at",
    "release_due_at",
    "packages",
    "created_at",
    "updated_at",
}
"""docs/features/tickets/tickets.md, TicketDetail."""

INVALID_LOCATORS: list[tuple[str, Callable[[Ticket], str]]] = [
    ("lowercase-prefix", lambda t: f"sntl-{t.sequence_id}"),
    ("zero-padded", lambda t: f"SNTL-0{t.sequence_id}"),
    ("overflow", lambda t: f"SNTL-{MAX_SEQUENCE + 1}"),
    ("ticket-uuid", lambda t: str(t.id)),
    ("well-formed-missing", lambda t: f"SNTL-{MAX_SEQUENCE}"),
]
"""The `{ticket_id}` 404 family (testing-strategy.md, Ticket identifier and
read-contract coverage); the parser matrix itself is unit-tested."""


def locator(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def validation_error(*errors: dict[str, Any]) -> dict[str, Any]:
    """The global `422 VALIDATION_ERROR` envelope."""
    return {
        "code": "VALIDATION_ERROR",
        "detail": "Request validation failed",
        "errors": list(errors),
    }


async def ticket_row(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted Ticket columns the consumer endpoints may change."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.duplicate_of_id,
                Ticket.updated_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return dict(row._mapping)


async def event_count(db: AsyncSession, ticket_id: uuid.UUID) -> int:
    return (
        await db.execute(
            select(func.count(TicketAuditEvent.id)).where(
                TicketAuditEvent.ticket_id == ticket_id
            )
        )
    ).scalar_one()


def user_reference(user: User) -> dict[str, Any]:
    """The `UserReference` of a User (docs/api-spec.md, User References in
    Responses)."""
    return {
        "id": str(user.id),
        "username": user.username,
        "full_name": user.full_name,
        "active": user.active,
    }


def force_production_error_page(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render an unhandled exception through the application's generic
    `500 INTERNAL_ERROR` handler even when a local `DEBUG=true` selects
    Starlette's traceback page (mirrors `tests/test_api/test_cves.py`,
    `transmitting_client`): debug is forced off and the cached middleware
    stack is cleared so it is rebuilt; monkeypatch restores both."""
    monkeypatch.setattr(app, "debug", False)
    monkeypatch.setattr(app, "middleware_stack", None)


class Clock:
    """A controlled clock returning one fixed instant, counting its calls."""

    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.instant


class CommittedApp:
    """Committed setup rows, deleted explicitly by `cleanup()` even after a
    failed assertion."""

    def __init__(self, factory: Callable[[], Awaitable[AsyncSession]]) -> None:
        self._factory = factory
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    async def session(self) -> AsyncSession:
        return await self._factory()

    async def user(self, *, role: Role | None, active: bool = True) -> User:
        db = await self.session()
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"carol.va.{suffix}",
            email=f"carol.va.{suffix}@example.com",
            full_name="Carol Analyst",
            password_hash="$2b$12$" + "c" * 53,
            active=active,
        )
        db.add(user)
        await db.flush()
        self.user_ids.append(user.id)
        if role is not None:
            db.add(UserRole(user_id=user.id, role=role.value))
        await db.commit()
        return user

    async def va_headers(
        self, *, role: Role = Role.VULNERABILITY_ANALYST
    ) -> tuple[User, dict[str, str]]:
        """A committed user holding `role` (a vulnerability analyst by
        default) and its Bearer credential."""
        user = await self.user(role=role)
        db = await self.session()
        created = await create_session(
            db, user, SessionCreationReason.LOCAL_LOGIN, expected_password_hash=None
        )
        assert created is not None
        await db.commit()
        return user, {"Authorization": f"Bearer {created.token}"}

    async def ticket(self, **columns: Any) -> Ticket:
        db = await self.session()
        columns.setdefault("status", TicketStatus.NEW.value)
        ticket = Ticket(created_at=datetime(2026, 3, 10, 14, 37, tzinfo=UTC), **columns)
        db.add(ticket)
        await db.flush()
        self.ticket_ids.append(ticket.id)
        await db.commit()
        return ticket

    async def cleanup(self) -> None:
        db = await self.session()
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(SessionRow).where(SessionRow.user_id.in_(self.user_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await db.execute(statement)
        await db.commit()


@asynccontextmanager
async def committed_app_client(
    factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[tuple[CommittedApp, AsyncClient]]:
    """Install a per-request committing `get_db` override and yield the world
    and a client returning the global 500 envelope instead of re-raising."""
    world = CommittedApp(factory)

    async def _override_get_db() -> AsyncIterator[AsyncSession]:
        session = await world.session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            yield world, client
    finally:
        app.dependency_overrides.pop(get_db, None)
        await world.cleanup()
