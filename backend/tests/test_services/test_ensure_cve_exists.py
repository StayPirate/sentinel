"""Single-session tests for `ensure_cve_exists()`
(backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (On-Demand Fetch:
  `ensure_cve_exists()` — Format guard, Placeholder Records, Concurrency;
  CVE Upsert Serialization > New CVE; Exceptions: `CVEIdFormatError`).
- docs/features/tickets/ticket-service.md (`create_ticket` step 2: the
  lock-aware resolution is the CVE `FOR NO KEY UPDATE` read).

The independent-session races (ensure/ensure winner, rolled-back first
inserter, a conflict loser holding the winner lock) live in
`tests/test_services/test_create_ticket_atomicity.py`.

Expected values are transcribed from the specifications.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ServiceError
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.services.cve_service import (
    CVEIdFormatError,
    CVEServiceError,
    ensure_cve_exists,
)
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[..., Awaitable[Any]]

NEW_CVE_ID = "CVE-2099-0001"
MAX_LENGTH_CVE_ID = "CVE-2099-12345678901"
"""A canonical CVE-ID of exactly 20 characters."""

INVALID_CVE_IDS: list[Any] = [
    pytest.param("cve-2099-0001", id="lowercase"),
    pytest.param("CVE-2099-123456789012", id="21-characters"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
]


def _cve_statements(recorder: StatementRecorder) -> list[str]:
    """Every recorded statement reading or writing the `cve` table."""
    return [
        s
        for s in recorder.statements
        if "FROM cve" in s or "INTO cve " in s or "INTO cve(" in s
    ]


@pytest.mark.unit
class TestExceptions:
    def test_format_error_is_a_static_module_service_error(self) -> None:
        assert issubclass(CVEServiceError, ServiceError)
        assert issubclass(CVEIdFormatError, CVEServiceError)
        assert str(CVEIdFormatError()) == "CVE identifier format is invalid."


@pytest.mark.integration
class TestFormatGuard:
    @pytest.mark.parametrize("cve_id", INVALID_CVE_IDS)
    @pytest.mark.parametrize("lock", [False, True], ids=["plain", "locked"])
    async def test_invalid_identifier_raises_before_any_statement(
        self, db_session: AsyncSession, cve_id: Any, lock: bool
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVEIdFormatError) as raised,
        ):
            await ensure_cve_exists(db_session, cve_id, lock=lock)

        assert recorder.statements == []
        if isinstance(cve_id, str) and cve_id:
            assert cve_id not in str(raised.value)

    async def test_maximum_length_identifier_is_accepted(
        self, db_session: AsyncSession
    ) -> None:
        cve = await ensure_cve_exists(db_session, MAX_LENGTH_CVE_ID)

        assert cve.cve_id == MAX_LENGTH_CVE_ID


@pytest.mark.integration
class TestExistingRow:
    async def test_existing_row_is_returned_unchanged_without_insert(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        existing: CVE = await cve_factory(
            cve_id="CVE-2099-0002",
            title="Fictional title",
            description="Fictional description",
            severity="High",
            cve_state="REJECTED",
            published_date=datetime(2099, 1, 2, tzinfo=UTC),
            date_rejected=datetime(2099, 2, 3, tzinfo=UTC),
        )
        before = (
            await db_session.execute(
                select(CVE.updated_at, CVE.created_at).where(CVE.id == existing.id)
            )
        ).one()

        with StatementRecorder(db_session) as recorder:
            cve = await ensure_cve_exists(db_session, "CVE-2099-0002")

        assert cve is existing
        assert (cve.id, cve.title, cve.description, cve.severity, cve.cve_state) == (
            existing.id,
            "Fictional title",
            "Fictional description",
            "High",
            "REJECTED",
        )
        assert recorder.writes() == []
        assert len(recorder.statements) == 1
        after = (
            await db_session.execute(
                select(CVE.updated_at, CVE.created_at).where(CVE.id == existing.id)
            )
        ).one()
        assert after == before

    async def test_stale_identity_map_copy_is_refreshed(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        existing: CVE = await cve_factory(cve_id="CVE-2099-0003", severity="Low")
        await db_session.execute(
            update(CVE)
            .where(CVE.id == existing.id)
            .values(severity="Critical")
            .execution_options(synchronize_session=False)
        )

        cve = await ensure_cve_exists(db_session, "CVE-2099-0003", lock=True)

        assert cve.severity == "Critical"


@pytest.mark.integration
class TestPlaceholder:
    async def test_placeholder_has_only_the_identifier_and_defaults(
        self, db_session: AsyncSession
    ) -> None:
        cve = await ensure_cve_exists(db_session, NEW_CVE_ID)

        row = (
            await db_session.execute(select(CVE).where(CVE.id == cve.id))
        ).scalar_one()
        assert row.cve_id == NEW_CVE_ID
        assert row.cve_state == "PUBLISHED"
        assert (
            row.title,
            row.description,
            row.severity,
            row.published_date,
            row.modified_date,
            row.date_rejected,
        ) == (None, None, None, None, None, None)
        assert row.created_at is not None
        assert row.updated_at is not None
        sources = await db_session.scalar(
            select(func.count())
            .select_from(CVESource)
            .where(CVESource.cve_id == cve.id)
        )
        assert sources == 0
        count = await db_session.scalar(
            select(func.count()).select_from(CVE).where(CVE.cve_id == NEW_CVE_ID)
        )
        assert count == 1

    async def test_repeated_call_returns_the_same_row(
        self, db_session: AsyncSession
    ) -> None:
        first = await ensure_cve_exists(db_session, NEW_CVE_ID)

        second = await ensure_cve_exists(db_session, NEW_CVE_ID, lock=True)

        assert second.id == first.id

    async def test_insert_is_conflict_aware_and_transaction_stays_usable(
        self, db_session: AsyncSession
    ) -> None:
        with StatementRecorder(db_session) as recorder:
            await ensure_cve_exists(db_session, NEW_CVE_ID)

        inserts = [s for s in recorder.statements if s.startswith("INSERT INTO cve")]
        assert len(inserts) == 1
        assert "ON CONFLICT (cve_id) DO NOTHING" in inserts[0]
        assert await db_session.scalar(text("SELECT 1")) == 1

    async def test_function_does_not_commit(
        self, db_session_factory: Callable[[], Awaitable[AsyncSession]]
    ) -> None:
        """An independent session: rolling back its real transaction
        discards the placeholder, so the function did not commit."""
        session = await db_session_factory()
        cve_id = "CVE-2099-0004"

        await ensure_cve_exists(session, cve_id)
        assert session.in_transaction()
        await session.rollback()

        count = await session.scalar(
            select(func.count()).select_from(CVE).where(CVE.cve_id == cve_id)
        )
        assert count == 0
        await session.rollback()


@pytest.mark.integration
class TestLockAwareForm:
    async def test_existing_row_resolution_is_the_first_locked_read(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        await cve_factory(cve_id="CVE-2099-0005")

        with StatementRecorder(db_session) as recorder:
            await ensure_cve_exists(db_session, "CVE-2099-0005", lock=True)

        statements = _cve_statements(recorder)
        assert len(statements) == 1
        assert statements[0].startswith("SELECT")
        assert statements[0].rstrip().endswith("FOR NO KEY UPDATE")

    async def test_new_row_is_inserted_between_locked_reads(
        self, db_session: AsyncSession
    ) -> None:
        with StatementRecorder(db_session) as recorder:
            await ensure_cve_exists(db_session, NEW_CVE_ID, lock=True)

        statements = _cve_statements(recorder)
        assert len(statements) == 3
        assert statements[0].startswith("SELECT")
        assert statements[0].rstrip().endswith("FOR NO KEY UPDATE")
        assert statements[1].startswith("INSERT INTO cve")
        assert statements[2].startswith("SELECT")
        assert statements[2].rstrip().endswith("FOR NO KEY UPDATE")

    @pytest.mark.parametrize("existing", [True, False], ids=["existing", "new"])
    async def test_plain_form_takes_no_row_lock(
        self, db_session: AsyncSession, cve_factory: Factory, existing: bool
    ) -> None:
        if existing:
            await cve_factory(cve_id=NEW_CVE_ID)

        with StatementRecorder(db_session) as recorder:
            await ensure_cve_exists(db_session, NEW_CVE_ID)

        assert recorder.row_locks() == []
        assert _cve_statements(recorder)
