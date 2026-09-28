"""Single-session service tests for `create_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Acting user convention;
  Concurrency control: creation paragraph; `create_ticket`; Service
  Exceptions; Architectural Test Requirement 13, 19 (creation part), 20
  (creation-with-CRD part)).
- docs/features/tickets/tickets.md (Ticket Creation; CVE Resolution
  Behavior: conflict, normal, already rejected; Coordinated Release Date).
- docs/features/tickets/cve-service.md (`upsert_cve()` Parameter `source`
  label table; On-Demand Fetch: `ensure_cve_exists()`).
- docs/features/tickets/ticket-priority.md (Decision Table; Refresh Points:
  manual Ticket creation; Testing Requirement 3).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `ticket_created`, `assignment`, `severity_changed`,
  `coordinated_release_changed`, `cve_associated`, `priority_changed`;
  Canonical Automatic Comment Vocabulary; Canonical Mutation and No-Event
  Matrix: Ticket creation; Cross-Event Ordering; Testing Requirements 1-7,
  28, 29).
- docs/features/platform/testing-strategy.md (Audit Trail Testing; Ticket
  Accessibility: identifier-only exceptions).

The independent-session races and the whole-transaction rollback tests
live in `tests/test_services/test_create_ticket_atomicity.py`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import CVESourceType, Role, Severity
from app.core.exceptions import ServiceError, SeverityDerivedError, UserNotFoundError
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services.cve_service import CVEIdFormatError
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    TicketCreationSource,
    TicketCVEConflictError,
    TicketServiceError,
    _format_utc_instant,
    create_ticket,
)
from tests.support.ticket_creation import (
    INGESTION_LABELS,
    creation_events,
    ingestion_comment,
)
from tests.support.ticket_mutations import (
    StatementRecorder,
    TicketFactory,
    VAUser,
    ticket_events,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

Factory = Callable[..., Awaitable[Any]]

MANUAL = TicketCreationSource.MANUAL
INGESTION = TicketCreationSource.CVE_INGESTION

CRD_UTC = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
CRD_UTC_VALUE = "2026-10-06T14:00:00Z"
CRD_OFFSET = datetime(2026, 10, 6, 16, 0, tzinfo=timezone(timedelta(hours=2)))
"""The same instant as `CRD_UTC`, supplied with a `+02:00` offset."""

NEW_CVE_ID = "CVE-2099-0101"
"""A CVE-ID with no row: creation inserts a placeholder."""

CREATORS = {
    "active-va": (True, (Role.VULNERABILITY_ANALYST,)),
    "active-va-and-admin": (True, (Role.ADMIN, Role.VULNERABILITY_ANALYST)),
    "inactive-va": (False, (Role.VULNERABILITY_ANALYST,)),
    "restricted-analyst": (True, (Role.RESTRICTED_ANALYST,)),
    "admin": (True, (Role.ADMIN,)),
}
"""Creator kinds: `(active, roles)`. Only an active VA is assigned."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _manual(db: AsyncSession, creator: User, **kwargs: Any) -> Ticket:
    """A manual creation by `creator`, as the POST handler would call it."""
    return await create_ticket(db, acting_user_id=creator.id, source=MANUAL, **kwargs)


async def _ingest(
    db: AsyncSession, cve_id: str, source: CVESourceType = CVESourceType.NVD
) -> Ticket:
    """A system CVE-ingestion creation, as `upsert_cve()` would call it."""
    return await create_ticket(
        db,
        acting_user_id=None,
        cve_id=cve_id,
        source=INGESTION,
        ingestion_source=source,
    )


async def _creator(va_user: VAUser, kind: str) -> User:
    active, roles = CREATORS[kind]
    return await va_user(active=active, roles=roles)


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The persisted creation-relevant columns of a Ticket."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.cve_id,
                Ticket.severity_manual,
                Ticket.is_confidential,
                Ticket.coordinated_release_at,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.duplicate_of_id,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return dict(row._mapping)


async def _sntl(db: AsyncSession, ticket_id: uuid.UUID) -> str:
    """The canonical `SNTL-{n}` of a Ticket, read from the database."""
    sequence = await db.scalar(select(Ticket.sequence_id).where(Ticket.id == ticket_id))
    return f"SNTL-{sequence}"


async def _count(db: AsyncSession, model: type[Any]) -> int:
    return int(await db.scalar(select(func.count()).select_from(model)) or 0)


async def _evidence_cve(cve_factory: Factory, cve_kev_entry_factory: Factory) -> CVE:
    """An existing CVE whose `Critical` severity and KEV listing resolve
    the automatic priority to `P1` (ticket-priority.md, Decision Table)."""
    cve: CVE = await cve_factory(cve_id="CVE-2099-0102", severity="Critical")
    await cve_kev_entry_factory(cve_id=cve.id)
    return cve


def _user_lock_index(statements: list[str]) -> int:
    matches = [
        i for i, s in enumerate(statements) if 'FROM "user"' in s and "FOR SHARE" in s
    ]
    assert len(matches) == 1, statements
    return matches[0]


def _cve_indexes(statements: list[str]) -> list[int]:
    """Indexes of every statement reading or writing the `cve` table."""
    return [
        i
        for i, s in enumerate(statements)
        if "FROM cve" in s or s.startswith("INSERT INTO cve")
    ]


def _ticket_insert_indexes(statements: list[str]) -> list[int]:
    return [i for i, s in enumerate(statements) if s.startswith("INSERT INTO ticket ")]


def _association_read_index(statements: list[str]) -> int:
    matches = [
        i
        for i, s in enumerate(statements)
        if s.startswith("SELECT ticket.sequence_id") and "ticket.cve_id =" in s
    ]
    assert len(matches) == 1, statements
    return matches[0]


# ---------------------------------------------------------------------------
# Exceptions and the audit instant format
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptions:
    def test_conflict_error_carries_the_identifier_with_a_static_message(
        self,
    ) -> None:
        error = TicketCVEConflictError("SNTL-42")

        assert issubclass(TicketServiceError, ServiceError)
        assert isinstance(error, TicketServiceError)
        assert error.existing_ticket_id == "SNTL-42"
        assert str(error) == "CVE is already associated with another Ticket."

    def test_creation_source_values(self) -> None:
        assert [member.value for member in TicketCreationSource] == [
            "manual",
            "cve_ingestion",
        ]


@pytest.mark.unit
class TestFormatUTCInstant:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            pytest.param(CRD_UTC, CRD_UTC_VALUE, id="utc"),
            pytest.param(CRD_OFFSET, CRD_UTC_VALUE, id="offset"),
            pytest.param(
                datetime(2026, 12, 31, 23, 30, tzinfo=timezone(timedelta(hours=-5))),
                "2027-01-01T04:30:00Z",
                id="offset-crossing-midnight",
            ),
            pytest.param(
                datetime(2026, 10, 6, 14, 0, 0, 123456, tzinfo=UTC),
                "2026-10-06T14:00:00.123456Z",
                id="sub-second",
            ),
        ],
    )
    def test_renders_utc_iso_8601_with_z(self, value: datetime, expected: str) -> None:
        assert _format_utc_instant(value) == expected


# ---------------------------------------------------------------------------
# Initial status and creator eligibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInitialStatus:
    @pytest.mark.parametrize("kind", list(CREATORS))
    async def test_only_an_active_va_creator_is_assigned(
        self, db_session: AsyncSession, va_user: VAUser, kind: str
    ) -> None:
        creator = await _creator(va_user, kind)
        assigned = kind in {"active-va", "active-va-and-admin"}

        ticket = await _manual(db_session, creator)

        state = await _state(db_session, ticket.id)
        assert state["status"] == ("Analysis" if assigned else "New")
        assert state["assignee_id"] == (creator.id if assigned else None)
        assert await ticket_events(db_session, ticket) == creation_events(
            creator_id=creator.id,
            assignee_username=creator.username if assigned else None,
        )

    @pytest.mark.parametrize("change", ["deactivated", "role-removed"])
    async def test_eligibility_is_read_from_the_locked_row(
        self, db_session: AsyncSession, va_user: VAUser, change: str
    ) -> None:
        """The identity map holds a stale active-VA copy; the locked read
        refreshes it and the database state wins."""
        creator = await va_user()
        stale = (
            await db_session.execute(
                select(User)
                .where(User.id == creator.id)
                .options(selectinload(User.roles))
            )
        ).scalar_one()
        assert stale.active is True
        assert stale.roles
        if change == "deactivated":
            statement: Any = (
                update(User).where(User.id == creator.id).values(active=False)
            )
        else:
            statement = delete(UserRole).where(UserRole.user_id == creator.id)
        await db_session.execute(statement.execution_options(synchronize_session=False))

        ticket = await _manual(db_session, creator)

        state = await _state(db_session, ticket.id)
        assert (state["status"], state["assignee_id"]) == ("New", None)
        assert await ticket_events(db_session, ticket) == creation_events(
            creator_id=creator.id
        )

    async def test_locked_row_reactivation_is_observed(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user(active=False)
        await db_session.execute(
            update(User)
            .where(User.id == creator.id)
            .values(active=True)
            .execution_options(synchronize_session=False)
        )
        assert creator.active is False

        ticket = await _manual(db_session, creator)

        state = await _state(db_session, ticket.id)
        assert (state["status"], state["assignee_id"]) == ("Analysis", creator.id)

    async def test_unknown_creator_raises_without_insert(
        self, db_session: AsyncSession
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(UserNotFoundError),
        ):
            await create_ticket(db_session, acting_user_id=uuid.uuid4(), source=MANUAL)

        # The session's first statement opens the test savepoint.
        assert [s for s in recorder.writes() if not s.startswith("SAVEPOINT")] == []
        assert _ticket_insert_indexes(recorder.statements) == []


# ---------------------------------------------------------------------------
# Lock order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockOrder:
    async def test_existing_cve_user_share_then_cve_update_then_insert(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
    ) -> None:
        creator = await va_user()
        cve = await _evidence_cve(cve_factory, cve_kev_entry_factory)

        with StatementRecorder(db_session) as recorder:
            await _manual(db_session, creator, cve_id=cve.cve_id)

        statements = recorder.statements
        user_lock = _user_lock_index(statements)
        cve_statements = _cve_indexes(statements)
        first_cve = statements[cve_statements[0]]
        association = _association_read_index(statements)
        (insert,) = _ticket_insert_indexes(statements)
        assert first_cve.startswith("SELECT")
        assert first_cve.rstrip().endswith("FOR UPDATE")
        assert user_lock < cve_statements[0] < association < insert
        assert not any("FROM cve" in s for s in statements[:user_lock])
        assert [s for s in statements if s.startswith("INSERT INTO cve")] == []

    async def test_new_cve_user_share_then_placeholder_then_insert(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user()

        with StatementRecorder(db_session) as recorder:
            await _manual(db_session, creator, cve_id=NEW_CVE_ID)

        statements = recorder.statements
        user_lock = _user_lock_index(statements)
        cve_statements = _cve_indexes(statements)
        association = _association_read_index(statements)
        (insert,) = _ticket_insert_indexes(statements)
        first, placeholder, relock = (statements[i] for i in cve_statements[:3])
        assert first.rstrip().endswith("FOR UPDATE")
        assert placeholder.startswith("INSERT INTO cve")
        assert relock.rstrip().endswith("FOR UPDATE")
        assert user_lock < cve_statements[0] < cve_statements[2] < association < insert

    async def test_cve_less_creation_locks_only_the_user(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user()

        with StatementRecorder(db_session) as recorder:
            await _manual(db_session, creator, severity_manual=Severity.HIGH)

        user_lock = _user_lock_index(recorder.statements)
        (insert,) = _ticket_insert_indexes(recorder.statements)
        assert user_lock < insert
        assert recorder.row_locks() == [recorder.statements[user_lock]]
        assert _cve_indexes(recorder.statements) == []

    async def test_ingestion_has_no_user_root(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
    ) -> None:
        cve = await _evidence_cve(cve_factory, cve_kev_entry_factory)

        with StatementRecorder(db_session) as recorder:
            await _ingest(db_session, cve.cve_id)

        statements = recorder.statements
        assert not any('"user"' in s for s in statements)
        assert not any("FOR SHARE" in s for s in statements)
        cve_statements = _cve_indexes(statements)
        (insert,) = _ticket_insert_indexes(statements)
        assert statements[cve_statements[0]].rstrip().endswith("FOR UPDATE")
        assert cve_statements[0] < _association_read_index(statements) < insert


# ---------------------------------------------------------------------------
# Exact event order and fields
# ---------------------------------------------------------------------------


EVENT_COMBINATIONS = [
    pytest.param(None, None, None, None, id="bare"),
    pytest.param(Severity.HIGH, None, None, "P3", id="severity"),
    pytest.param(None, CRD_UTC, None, None, id="crd"),
    pytest.param(Severity.HIGH, CRD_UTC, None, "P3", id="severity-crd"),
    pytest.param(None, None, "placeholder", None, id="placeholder-cve"),
    pytest.param(None, CRD_UTC, "placeholder", None, id="crd-placeholder-cve"),
    pytest.param(None, None, "evidence", "P1", id="evidence-cve"),
    pytest.param(None, CRD_UTC, "evidence", "P1", id="crd-evidence-cve"),
]
"""`(severity_manual, coordinated_release_at, cve, expected priority)`;
`cve` and `severity_manual` are exclusive. `High` with unknown
exploitation is `P3`; `Critical` with KEV is `P1`; a placeholder and a
bare CVE-less Ticket have a `NULL` priority and create no event."""


@pytest.mark.integration
class TestEventContract:
    @pytest.mark.parametrize("kind", ["active-va", "restricted-analyst"])
    @pytest.mark.parametrize(
        ("severity", "crd", "cve_kind", "priority"), EVENT_COMBINATIONS
    )
    async def test_every_optional_combination(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        kind: str,
        severity: Severity | None,
        crd: datetime | None,
        cve_kind: str | None,
        priority: str | None,
    ) -> None:
        creator = await _creator(va_user, kind)
        assigned = kind == "active-va"
        cve_id: str | None = None
        if cve_kind == "evidence":
            cve_id = (await _evidence_cve(cve_factory, cve_kev_entry_factory)).cve_id
        elif cve_kind == "placeholder":
            cve_id = NEW_CVE_ID

        ticket = await _manual(
            db_session,
            creator,
            cve_id=cve_id,
            severity_manual=severity,
            is_confidential=crd is not None,
            coordinated_release_at=crd,
        )

        assert await ticket_events(db_session, ticket) == creation_events(
            creator_id=creator.id,
            assignee_username=creator.username if assigned else None,
            severity=severity.value if severity is not None else None,
            coordinated_release=CRD_UTC_VALUE if crd is not None else None,
            cve_id=cve_id,
            priority=priority,
        )
        cve_uuid = (
            await db_session.scalar(select(CVE.id).where(CVE.cve_id == cve_id))
            if cve_id is not None
            else None
        )
        assert await _state(db_session, ticket.id) == {
            "status": "Analysis" if assigned else "New",
            "assignee_id": creator.id if assigned else None,
            "cve_id": cve_uuid,
            "severity_manual": severity.value if severity is not None else None,
            "is_confidential": crd is not None,
            "coordinated_release_at": crd,
            "priority_auto": priority,
            "priority_override": None,
            "duplicate_of_id": None,
        }
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_offset_crd_is_stored_and_audited_as_the_utc_instant(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user(roles=(Role.RESTRICTED_ANALYST,))

        ticket = await _manual(
            db_session, creator, is_confidential=True, coordinated_release_at=CRD_OFFSET
        )

        stored = (await _state(db_session, ticket.id))["coordinated_release_at"]
        assert stored == CRD_UTC
        assert await ticket_events(db_session, ticket) == creation_events(
            creator_id=creator.id, coordinated_release=CRD_UTC_VALUE
        )

    async def test_past_crd_is_accepted(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        past = datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)

        ticket = await _manual(
            db_session, creator, is_confidential=True, coordinated_release_at=past
        )

        assert (await _state(db_session, ticket.id))["coordinated_release_at"] == past
        assert (await ticket_events(db_session, ticket))[-1].new_value == (
            "2020-01-02T03:04:05Z"
        )

    async def test_confidential_creation_without_crd_has_no_crd_event(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user(roles=(Role.RESTRICTED_ANALYST,))

        ticket = await _manual(db_session, creator, is_confidential=True)

        assert (await _state(db_session, ticket.id))["is_confidential"] is True
        assert await ticket_events(db_session, ticket) == creation_events(
            creator_id=creator.id
        )

    async def test_placeholder_created_by_manual_creation(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        creator = await va_user()

        ticket = await _manual(db_session, creator, cve_id=NEW_CVE_ID)

        cve = (
            await db_session.execute(select(CVE).where(CVE.cve_id == NEW_CVE_ID))
        ).scalar_one()
        assert (await _state(db_session, ticket.id))["cve_id"] == cve.id
        assert (cve.cve_state, cve.severity, cve.title) == ("PUBLISHED", None, None)
        sources = await db_session.scalar(
            select(func.count())
            .select_from(CVESource)
            .where(CVESource.cve_id == cve.id)
        )
        assert sources == 0


# ---------------------------------------------------------------------------
# CVE ingestion
# ---------------------------------------------------------------------------


GUARD_CASES = [
    pytest.param(
        {"source": MANUAL, "ingestion_source": CVESourceType.NVD},
        ValueError,
        id="manual-with-ingestion-source",
    ),
    pytest.param(
        {"source": INGESTION, "acting_user_id": None, "cve_id": "CVE-2099-0103"},
        ValueError,
        id="ingestion-without-ingestion-source",
    ),
    pytest.param(
        {"source": MANUAL, "acting_user_id": None},
        ValueError,
        id="manual-without-acting-user",
    ),
    pytest.param(
        {
            "source": INGESTION,
            "ingestion_source": CVESourceType.NVD,
            "cve_id": "CVE-2099-0103",
        },
        ValueError,
        id="ingestion-with-acting-user",
    ),
    pytest.param(
        {"source": MANUAL, "coordinated_release_at": CRD_UTC},
        ValueError,
        id="crd-without-confidential",
    ),
    pytest.param(
        {
            "source": INGESTION,
            "acting_user_id": None,
            "ingestion_source": CVESourceType.NVD,
            "cve_id": "CVE-2099-0103",
            "coordinated_release_at": CRD_UTC,
        },
        ValueError,
        id="crd-with-ingestion",
    ),
    pytest.param(
        {
            "source": INGESTION,
            "acting_user_id": None,
            "ingestion_source": CVESourceType.NVD,
            "cve_id": "CVE-2099-0103",
            "is_confidential": True,
            "coordinated_release_at": CRD_UTC,
        },
        ValueError,
        id="crd-with-confidential-ingestion",
    ),
    pytest.param(
        {
            "source": MANUAL,
            "is_confidential": True,
            "coordinated_release_at": CRD_UTC.replace(tzinfo=None),
        },
        ValueError,
        id="naive-crd",
    ),
    pytest.param(
        {
            "source": INGESTION,
            "acting_user_id": None,
            "ingestion_source": CVESourceType.NVD,
        },
        ValueError,
        id="ingestion-without-cve",
    ),
    pytest.param(
        {
            "source": INGESTION,
            "acting_user_id": None,
            "ingestion_source": CVESourceType.NVD,
            "cve_id": "CVE-2099-0103",
            "is_confidential": True,
        },
        ValueError,
        id="confidential-ingestion",
    ),
    pytest.param(
        {
            "source": MANUAL,
            "cve_id": "CVE-2099-0103",
            "severity_manual": Severity.HIGH,
        },
        SeverityDerivedError,
        id="manual-cve-with-severity",
    ),
]


@pytest.mark.integration
class TestIngestion:
    def test_label_table_covers_every_source_member(self) -> None:
        assert set(INGESTION_LABELS) == set(CVESourceType)

    @pytest.mark.parametrize("source", list(CVESourceType))
    async def test_exact_comment_system_actor_and_no_priority_refresh(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        source: CVESourceType,
    ) -> None:
        """The CVE's evidence would resolve `P1`; ingestion leaves the
        refresh to `upsert_cve()`."""
        cve = await _evidence_cve(cve_factory, cve_kev_entry_factory)

        ticket = await _ingest(db_session, cve.cve_id, source)

        events = await ticket_events(db_session, ticket)
        assert events == creation_events(
            creator_id=None, comment=ingestion_comment(source), cve_id=cve.cve_id
        )
        assert events[0].comment == f"CVE ingested from {INGESTION_LABELS[source]}"
        assert await _state(db_session, ticket.id) == {
            "status": "New",
            "assignee_id": None,
            "cve_id": cve.id,
            "severity_manual": None,
            "is_confidential": False,
            "coordinated_release_at": None,
            "priority_auto": None,
            "priority_override": None,
            "duplicate_of_id": None,
        }
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_ingestion_creates_a_placeholder_for_an_unknown_cve(
        self, db_session: AsyncSession
    ) -> None:
        ticket = await _ingest(db_session, NEW_CVE_ID, CVESourceType.MITRE)

        cve_uuid = await db_session.scalar(
            select(CVE.id).where(CVE.cve_id == NEW_CVE_ID)
        )
        assert (await _state(db_session, ticket.id))["cve_id"] == cve_uuid
        assert await ticket_events(db_session, ticket) == creation_events(
            creator_id=None,
            comment="CVE ingested from MITRE",
            cve_id=NEW_CVE_ID,
        )

    @pytest.mark.parametrize(("overrides", "error"), GUARD_CASES)
    async def test_input_guard_raises_before_database_access(
        self,
        db_session: AsyncSession,
        overrides: dict[str, Any],
        error: type[Exception],
    ) -> None:
        kwargs: dict[str, Any] = {"acting_user_id": uuid.uuid4(), **overrides}

        with StatementRecorder(db_session) as recorder, pytest.raises(error):
            await create_ticket(db_session, **kwargs)

        assert recorder.statements == []

    async def test_malformed_ingestion_cve_raises_before_any_statement(
        self, db_session: AsyncSession
    ) -> None:
        with StatementRecorder(db_session) as recorder, pytest.raises(CVEIdFormatError):
            await _ingest(db_session, "CVE-2099-123456789012")

        assert recorder.statements == []

    @pytest.mark.parametrize("cve_id", ["", "CVE-99-1", "CVE-2099-123456789012"])
    async def test_malformed_manual_cve_raises_before_any_statement(
        self, db_session: AsyncSession, va_user: VAUser, cve_id: str
    ) -> None:
        creator = await va_user()

        with StatementRecorder(db_session) as recorder, pytest.raises(CVEIdFormatError):
            await _manual(db_session, creator, cve_id=cve_id)

        assert recorder.statements == []


# ---------------------------------------------------------------------------
# CVE conflict
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConflict:
    @pytest.mark.parametrize(
        "confidential", [False, True], ids=["public", "confidential"]
    )
    @pytest.mark.parametrize("kind", ["active-va", "restricted-analyst"])
    async def test_existing_association_raises_before_any_insert(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        confidential: bool,
        kind: str,
    ) -> None:
        """A confidential conflicting Ticket is inaccessible to a
        `restricted_analyst` creator; its identifier is still returned."""
        creator = await _creator(va_user, kind)
        cve: CVE = await cve_factory(cve_id="CVE-2099-0104")
        existing = await ticket_factory(cve_id=cve.id, is_confidential=confidential)
        expected = await _sntl(db_session, existing.id)
        tickets, events = (
            await _count(db_session, Ticket),
            await _count(db_session, TicketAuditEvent),
        )

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketCVEConflictError) as raised,
        ):
            await _manual(db_session, creator, cve_id=cve.cve_id)

        assert raised.value.existing_ticket_id == expected
        assert expected not in str(raised.value)
        statements = recorder.statements
        cve_lock = _cve_indexes(statements)[0]
        assert statements[cve_lock].rstrip().endswith("FOR UPDATE")
        assert _user_lock_index(statements) < cve_lock
        assert _association_read_index(statements) > cve_lock
        assert _association_read_index(statements) == len(statements) - 1
        assert recorder.writes() == []
        assert await _count(db_session, Ticket) == tickets
        assert await _count(db_session, TicketAuditEvent) == events

    async def test_ingestion_conflict_raises_the_same_error(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-0105")
        existing = await ticket_factory(cve_id=cve.id, is_confidential=True)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketCVEConflictError) as raised,
        ):
            await _ingest(db_session, cve.cve_id)

        assert raised.value.existing_ticket_id == await _sntl(db_session, existing.id)
        assert recorder.writes() == []


# ---------------------------------------------------------------------------
# Already rejected CVE
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRejectedCVE:
    @pytest.mark.parametrize("kind", ["active-va", "restricted-analyst"])
    async def test_manual_creation_keeps_ordinary_status_and_events(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        cve_factory: Factory,
        kind: str,
    ) -> None:
        creator = await _creator(va_user, kind)
        assigned = kind == "active-va"
        cve: CVE = await cve_factory(
            cve_id="CVE-2099-0106",
            cve_state="REJECTED",
            date_rejected=datetime(2099, 3, 4, tzinfo=UTC),
            severity="High",
        )

        ticket = await _manual(db_session, creator, cve_id=cve.cve_id)

        state = await _state(db_session, ticket.id)
        assert state["status"] == ("Analysis" if assigned else "New")
        assert state["assignee_id"] == (creator.id if assigned else None)
        events = await ticket_events(db_session, ticket)
        assert events == creation_events(
            creator_id=creator.id,
            assignee_username=creator.username if assigned else None,
            cve_id=cve.cve_id,
            priority="P3",
        )
        assert all(e.event_type != "status_change" for e in events)
        assert all(e.comment != "CVE rejected" for e in events)
        cve_state = await db_session.scalar(
            select(CVE.cve_state).where(CVE.id == cve.id)
        )
        assert cve_state == "REJECTED"
